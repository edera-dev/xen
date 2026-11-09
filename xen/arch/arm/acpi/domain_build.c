/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/compile.h>
#include <xen/fdt-domain-build.h>
#include <xen/fdt-kernel.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/acpi.h>
#include <xen/serial.h>
#include <xen/event.h>
#include <xen/iocap.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/pci.h>
#include <xen/sizes.h>
#include <xen/vmap.h>
#include <acpi/actables.h>

#include <asm/iort.h>
#include <asm/domain_build.h>
#include <asm/io.h>
#include <asm/mmio.h>

/* Override macros from asm/page.h to make them work with mfn_t */
#undef virt_to_mfn
#define virt_to_mfn(va) _mfn(__virt_to_mfn(va))

/*
 * Keep the hardware domain off an SMMUv3's registers. Xen drives the SMMUs,
 * and the IORT the domain is given doesn't describe them, so it has no
 * business there; with access it could reprogram the stream tables that
 * isolate devices passed through to other domains. Deny the full 128K (both
 * register pages), whatever the driver ends up using.
 */
static int __init acpi_deny_smmu_v3(const struct acpi_iort_node *node,
                                    void *arg)
{
    struct domain *d = arg;
    const struct acpi_iort_smmu_v3 *smmu = (const void *)node->node_data;
    paddr_t base = smmu->base_address;
    int rc;

    rc = iomem_deny_access(d, paddr_to_pfn(base),
                           paddr_to_pfn(base + SZ_128K - 1));
    if ( rc )
        printk(XENLOG_ERR "Unable to deny %pd access to the SMMU at %#"PRIpaddr"\n",
               d, base);

    return rc;
}

/* The ECAM page of @bus/@devfn; a window's base is where bus 0 would be. */
static paddr_t __init ecam_page(paddr_t base, unsigned int bus,
                                unsigned int devfn)
{
    return base + ((paddr_t)PCI_BDF(bus, devfn) << 12);
}

/* The MCFG window that covers @seg/@bus: its base, and its first bus. */
static bool __init mcfg_window(unsigned int seg, unsigned int bus,
                               paddr_t *base, unsigned int *root)
{
    struct acpi_table_header *table;
    const struct acpi_table_mcfg *mcfg;
    const struct acpi_mcfg_allocation *alloc;
    unsigned int i, count;

    if ( ACPI_FAILURE(acpi_get_table(ACPI_SIG_MCFG, 0, &table)) ||
         table->length < sizeof(*mcfg) )
        return false;

    mcfg = container_of(table, const struct acpi_table_mcfg, header);
    count = (table->length - sizeof(*mcfg)) / sizeof(*alloc);
    alloc = (const struct acpi_mcfg_allocation *)(mcfg + 1);

    for ( i = 0; i < count; i++, alloc++ )
    {
        if ( alloc->pci_segment == seg && alloc->start_bus_number <= bus &&
             bus <= alloc->end_bus_number )
        {
            *base = alloc->address;
            *root = alloc->start_bus_number;
            return true;
        }
    }

    return false;
}

/* pci_find_cap_offset() for a mapped ECAM page, without CONFIG_HAS_PCI. */
static unsigned int __init ecam_find_pcie_cap(const void __iomem *cfg)
{
    unsigned int ttl = 48, pos = PCI_CAPABILITY_LIST;

    if ( !(readw(cfg + PCI_STATUS) & PCI_STATUS_CAP_LIST) )
        return 0;

    while ( ttl-- )
    {
        unsigned int id;

        pos = readb(cfg + pos);
        if ( pos < 0x40 )
            break;

        pos &= ~3;
        id = readb(cfg + pos + PCI_CAP_LIST_ID);
        if ( id == 0xff )
            break;

        if ( id == PCI_CAP_ID_EXP )
            return pos;

        pos += PCI_CAP_LIST_NEXT;
    }

    return 0;
}

/*
 * Find the bridge whose secondary bus is @bus.  Bridges number their
 * secondary bus above their own, so it sits on a bus from @root up to @bus.
 * Scan those the way Linux does, skipping functions 1-7 of a device whose
 * function 0 is absent or single-function.
 */
static int __init find_parent_bridge(paddr_t base, unsigned int root,
                                     unsigned int bus, unsigned int *pbus,
                                     unsigned int *pdevfn)
{
    unsigned int b, devfn;

    for ( b = root; b < bus; b++ )
    {
        void __iomem *ecam = ioremap_nocache(ecam_page(base, b, 0), SZ_1M);

        if ( !ecam )
            return -ENOMEM;

        for ( devfn = 0; devfn < 256; devfn++ )
        {
            const void __iomem *cfg = ecam + (devfn << 12);
            unsigned int header;

            if ( readw(cfg + PCI_VENDOR_ID) == 0xffff )
            {
                if ( !PCI_FUNC(devfn) )
                    devfn += 7;
                continue;
            }

            header = readb(cfg + PCI_HEADER_TYPE);
            if ( (header & 0x7f) == PCI_HEADER_TYPE_BRIDGE &&
                 readb(cfg + PCI_SECONDARY_BUS) == bus )
            {
                *pbus = b;
                *pdevfn = devfn;
                iounmap(ecam);
                return 0;
            }

            if ( !PCI_FUNC(devfn) && !(header & 0x80) )
                devfn += 7;
        }

        iounmap(ecam);
    }

    return -ENODEV;
}

/*
 * Say why the UART stays visible, and what that leaves open: a driver in the
 * domain finds its registers empty, but the domain can still reset or
 * reconfigure the function under Xen's console.
 */
static void __init spcr_keep(const pci_sbdf_t *sbdf, const char *why)
{
    printk(XENLOG_WARNING
           "SPCR: console %pp stays visible to the hardware domain: %s\n",
           sbdf, why);
}

/*
 * Make the page holding the console's registers at @addr read as all ones,
 * and drop writes to it, except for the bytes that the hardware domain's vuart
 * answers.  The vuart sits on the console's first register, and two handlers
 * must not overlap: find_mmio_handler() could then miss both.
 */
static void __init spcr_empty_page(struct domain *d, paddr_t addr)
{
    paddr_t start = addr & PAGE_MASK, end = start + PAGE_SIZE;

#ifdef CONFIG_HWDOM_VUART
    const struct vuart_info *vuart = d->arch.vuart.info;

    if ( vuart && vuart->base_addr >= start && vuart->base_addr < end )
    {
        if ( vuart->base_addr > start )
            register_unmapped_mmio_handler(d, start, vuart->base_addr - start);
        start = vuart->base_addr + vuart->size;
    }
#endif

    if ( start < end )
        register_unmapped_mmio_handler(d, start, end - start);
}

/*
 * Show the hardware domain the port above the UART at @uart read-only, and
 * without its hotplug capability.  Return -ENODEV, having said why, when that
 * cannot be done and the UART has to stay visible.
 */
static int __init spcr_restrict_port(struct domain *d, paddr_t base,
                                     unsigned int root, const pci_sbdf_t *uart)
{
    unsigned int bus, devfn, pcie;
    pci_sbdf_t port;
    void __iomem *va;
    paddr_t cfg;
    int rc;

    rc = find_parent_bridge(base, root, uart->bus, &bus, &devfn);
    if ( rc == -ENODEV )
        spcr_keep(uart,
                  "no bridge leads to it, and hiding it with its slot unlocked could power the console off");
    if ( rc )
        return rc;

    port = PCI_SBDF(uart->seg, bus, devfn);
    cfg = ecam_page(base, bus, devfn);
    va = ioremap_nocache(cfg, PAGE_SIZE);
    if ( !va )
        return -ENOMEM;
    pcie = ecam_find_pcie_cap(va);
    iounmap(va);

    /*
     * Every PCI Express port has the capability.  A port without it is a
     * conventional PCI bridge, whose slot this code does not know how to lock.
     */
    if ( !pcie )
    {
        spcr_keep(uart,
                  "its port is not a PCI Express port, and hiding it with its slot unlocked could power the console off");
        return -ENODEV;
    }

    /*
     * The view holds only while every access the domain makes to the page
     * traps into Xen.  A stage-2 mapping would let the domain read the real
     * slot registers and write them, power and reset included, past the
     * handler.  So remove any mapping, and deny the page so that the on-demand
     * mapping of ACPI MMIO in try_map_mmio() cannot add one back.
     */
    rc = unmap_mmio_regions(d, _gfn(PFN_DOWN(cfg)), 1, _mfn(PFN_DOWN(cfg)));
    if ( rc )
        return rc;

    rc = iomem_deny_access(d, PFN_DOWN(cfg), PFN_DOWN(cfg));
    if ( rc )
        return rc;

    rc = register_ro_pci_config_handler(d, cfg, pcie + PCI_EXP_SLTCAP,
                                        PCI_EXP_SLTCAP_HPC);
    if ( rc )
        return rc;

    printk("SPCR: port %pp above console %pp is read-only to %pd\n",
           &port, uart, d);

    return 0;
}

/*
 * When the SPCR's UART is a PCI function, take it away from the hardware
 * domain.  Denying its registers is not enough: the domain still enumerates
 * the function, and can reset or reconfigure it under Xen's console.  So hide
 * the function's configuration space, and restrict the port above it: pciehp
 * would otherwise find the slot empty and power it off, console and all.  Any
 * check that fails leaves the function visible.
 */
static int __init acpi_hide_spcr_pci_uart(struct domain *d,
                                          const struct acpi_table_spcr *spcr)
{
    unsigned int devfn = PCI_DEVFN(spcr->pci_device, spcr->pci_function);
    pci_sbdf_t sbdf = PCI_SBDF(spcr->pci_segment, spcr->pci_bus, devfn);
    unsigned int root;
    paddr_t base;
    int rc;

    /* The SPCR's way of saying the UART is not a PCI function. */
    if ( spcr->pci_vendor_id == 0xffff )
        return 0;

    /*
     * A driver that claims the UART while it stays visible would otherwise
     * take a data abort on the denied page, as the domain traps unmapped
     * accesses.  All ones reads as a missing UART instead.
     */
    spcr_empty_page(d, spcr->serial_port.address);

    /* vPCI traps the whole configuration space, and would overlap. */
    if ( has_vpci(d) )
    {
        spcr_keep(&sbdf,
                  "vPCI already emulates its configuration space, and a second handler would overlap");
        return 0;
    }

    if ( !mcfg_window(sbdf.seg, sbdf.bus, &base, &root) )
    {
        spcr_keep(&sbdf,
                  "no MCFG window says where its configuration space is");
        return 0;
    }

    /* A function on the root bus has no port, and no slot, above it. */
    if ( sbdf.bus != root )
    {
        rc = spcr_restrict_port(d, base, root, &sbdf);
        if ( rc )
            return rc == -ENODEV ? 0 : rc;
    }

    rc = hide_pci_function_from_hwdom(d, ecam_page(base, sbdf.bus, devfn));
    if ( rc )
        return rc;

    printk("SPCR: console %pp hidden from %pd\n", &sbdf, d);

    return 0;
}

static int __init acpi_iomem_deny_access(struct domain *d)
{
    acpi_status status;
    struct acpi_table_spcr *spcr = NULL;
    unsigned long mfn;
    int rc;

    /* Firstly permit full MMIO capabilities. */
    rc = iomem_permit_access(d, 0UL, ~0UL);
    if ( rc )
        return rc;

    /* Deny MMIO access for the SMMUs (the GIC, ITS included, follows). */
    rc = iort_for_each_smmu_v3(acpi_deny_smmu_v3, d);
    if ( rc && rc != -ENODEV )
        return rc;

    status = acpi_get_table(ACPI_SIG_SPCR, 0,
                            (struct acpi_table_header **)&spcr);

    if ( ACPI_SUCCESS(status) )
    {
        mfn = spcr->serial_port.address >> PAGE_SHIFT;
        /* Deny MMIO access for UART */
        rc = iomem_deny_access(d, mfn, mfn);
        if ( rc )
            return rc;

        rc = acpi_hide_spcr_pci_uart(d, spcr);
        if ( rc )
            return rc;
    }
    else
    {
        printk("Failed to get SPCR table, Xen console may be unavailable\n");
    }

    /* Deny MMIO access for GIC regions */
    return gic_iomem_deny_access(d);
}

static int __init acpi_route_spis(struct domain *d)
{
    int i, res;
    struct irq_desc *desc;

    /*
     * Route the IRQ to hardware domain and permit the access.
     * The interrupt type will be set by set by the hardware domain.
     */
    for( i = NR_LOCAL_IRQS; i < vgic_num_irqs(d); i++ )
    {
        /*
         * TODO: Exclude the SPIs SMMU uses which should not be routed to
         * the hardware domain.
         */
        desc = irq_to_desc(i);
        if ( desc->action != NULL)
            continue;

        /* XXX: Shall we use a proper devname? */
        res = map_irq_to_domain(d, i, true, "ACPI");
        if ( res )
            return res;
    }

    return 0;
}

static int __init acpi_make_hypervisor_node(const struct kernel_info *kinfo,
                                            struct membank tbl_add[])
{
    const char compat[] =
        "xen,xen-" XEN_VERSION_STRING "\0"
        "xen,xen";
    int res;
    /* Convenience alias */
    void *fdt = kinfo->fdt;

    dt_dprintk("Create hypervisor node\n");

    /* See linux Documentation/devicetree/bindings/arm/xen.txt */
    res = fdt_begin_node(fdt, "hypervisor");
    if ( res )
        return res;

    /* Cannot use fdt_property_string due to embedded nulls */
    res = fdt_property(fdt, "compatible", compat, sizeof(compat));
    if ( res )
        return res;

    /*
     * The grant table region and the extended regions, exactly as the device
     * tree path describes them.  Without the extended regions the domain has
     * no guest-physical address space it can map foreign pages into, and its
     * only remaining option is to balloon its own memory out -- which on
     * arm64 goes through memory hotplug and takes the domain down.
     *
     * A domain booted with ACPI does not unflatten this tree, but it is the
     * tree it is handed, and its early flat scan already reads this node.
     */
    res = make_hypervisor_reg(kinfo->bd.d, kinfo, 2, 2);
    if ( res )
        return res;

    res = acpi_make_efi_nodes(fdt, tbl_add);
    if ( res )
        return res;

    res = fdt_end_node(fdt);

    return res;
}

/*
 * Prepare a minimal DTB for Dom0 which contains bootargs, initrd, memory
 * information, EFI table.
 */
static int __init create_acpi_dtb(struct kernel_info *kinfo,
                                  struct membank tbl_add[])
{
    int new_size;
    int ret;

    dt_dprintk("Prepare a min DTB for DOM0\n");

    /* Allocate min size for DT */
    new_size = ACPI_DOM0_FDT_MIN_SIZE;
    kinfo->fdt = xmalloc_bytes(new_size);

    if ( kinfo->fdt == NULL )
        return -ENOMEM;

    /* Create a new empty DT for DOM0 */
    ret = fdt_create(kinfo->fdt, new_size);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish_reservemap(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_begin_node(kinfo->fdt, "");
    if ( ret < 0 )
        goto err;

    ret = fdt_property_cell(kinfo->fdt, "#address-cells", 2);
    if ( ret )
        return ret;

    /*
     * Two size cells: an extended region can be larger than 4GB, and the
     * hypervisor node's "reg" is read with the root's cells.
     */
    ret = fdt_property_cell(kinfo->fdt, "#size-cells", 2);
    if ( ret )
        return ret;

    /* Create a chosen node for DOM0 */
    ret = make_chosen_node(kinfo);
    if ( ret )
        goto err;

    ret = acpi_make_hypervisor_node(kinfo, tbl_add);
    if ( ret )
        goto err;

    ret = fdt_end_node(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    ret = fdt_finish(kinfo->fdt);
    if ( ret < 0 )
        goto err;

    return 0;

  err:
    printk("Device tree generation failed (%d).\n", ret);
    xfree(kinfo->fdt);
    return -EINVAL;
}

static void __init acpi_map_other_tables(struct domain *d)
{
    int i;
    unsigned long res;
    u64 addr, size;

    /* Map all ACPI tables to Dom0 using 1:1 mappings. */
    for( i = 0; i < acpi_gbl_root_table_list.count; i++ )
    {
        addr = acpi_gbl_root_table_list.tables[i].address;
        size = acpi_gbl_root_table_list.tables[i].length;
        res = map_regions_p2mt(d,
                               gaddr_to_gfn(addr),
                               PFN_UP(size),
                               maddr_to_mfn(addr),
                               p2m_mmio_direct_c);
        if ( res )
        {
             panic(XENLOG_ERR "Unable to map ACPI region 0x%"PRIx64
                   " - 0x%"PRIx64" in domain\n",
                   addr & PAGE_MASK, PAGE_ALIGN(addr + size) - 1);
        }
    }
}

static int __init acpi_create_rsdp(struct domain *d, struct membank tbl_add[])
{

    struct acpi_table_rsdp *rsdp = NULL;
    u64 addr;
    u64 table_size = sizeof(struct acpi_table_rsdp);
    u8 *base_ptr;
    u8 checksum;

    addr = acpi_os_get_root_pointer();
    if ( !addr  )
    {
        printk("Unable to get acpi root pointer\n");
        return -EINVAL;
    }
    rsdp = acpi_os_map_memory(addr, table_size);
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_RSDP);
    memcpy(base_ptr, rsdp, table_size);
    acpi_os_unmap_memory(rsdp, table_size);

    rsdp = (struct acpi_table_rsdp *)base_ptr;
    /* Replace xsdt_physical_address */
    rsdp->xsdt_physical_address = tbl_add[TBL_XSDT].start;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, rsdp), table_size);
    rsdp->checksum = rsdp->checksum - checksum;

    tbl_add[TBL_RSDP].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_RSDP);
    tbl_add[TBL_RSDP].size = table_size;

    return 0;
}

/* Remove the entry for a table from the XSDT; returns whether one was found. */
static bool __init acpi_xsdt_remove_entry(u64 entry[],
                                          unsigned long *entry_count,
                                          const char *signature)
{
    unsigned long i;

    for ( i = 0; i < *entry_count; i++ )
    {
        u64 size = sizeof(struct acpi_table_header);
        struct acpi_table_header *table = acpi_os_map_memory(entry[i], size);
        bool match = ACPI_COMPARE_NAME(table->signature, signature);

        acpi_os_unmap_memory(table, size);
        if ( !match )
            continue;

        memmove(&entry[i], &entry[i + 1],
                (*entry_count - i - 1) * sizeof(entry[0]));
        (*entry_count)--;
        return true;
    }

    return false;
}

static void __init acpi_xsdt_modify_entry(u64 entry[],
                                          unsigned long entry_count,
                                          const char *signature, u64 addr)
{
    int i;
    struct acpi_table_header *table;
    u64 size = sizeof(struct acpi_table_header);

    for( i = 0; i < entry_count; i++ )
    {
        table = acpi_os_map_memory(entry[i], size);
        if ( ACPI_COMPARE_NAME(table->signature, signature) )
        {
            entry[i] = addr;
            acpi_os_unmap_memory(table, size);
            break;
        }
        acpi_os_unmap_memory(table, size);
    }
}

/* Set when the hardware domain must not see the firmware's IORT at all. */
static bool __initdata hwdom_omit_iort;

static int __init acpi_count_smmu_v3(const struct acpi_iort_node *node,
                                     void *arg)
{
    (*(unsigned int *)arg)++;

    return 0;
}

/*
 * Replace the firmware's IORT with one that does not describe the SMMUs, so
 * that the hardware domain does not bind its own IOMMU driver to hardware Xen
 * owns.
 *
 * If that fails, the firmware table can still be left in place when it
 * describes no SMMUv3: there is then nothing in it for the domain to take
 * over. When it does describe some, Xen drives them, and handing it over
 * would have the domain reset them and replace the stream tables isolating
 * other domains' devices. Leave the domain without an IORT instead; it then
 * can't route its PCI MSIs through the ITS, which is visible and fixable,
 * unlike losing isolation.
 */
static int __init acpi_create_iort(struct domain *d, struct membank tbl_add[])
{
    uint32_t offset = acpi_get_table_offset(tbl_add, TBL_IORT);
    uint8_t *base_ptr = d->arch.efi_acpi_table + offset;
    struct acpi_table_header *iort;
    uint32_t len;
    uint8_t checksum;
    int rc;

    rc = iort_make_hwdom_table(base_ptr, d->arch.efi_acpi_len - offset, &len);
    if ( rc )
    {
        unsigned int smmus = 0;

        iort_for_each_smmu_v3(acpi_count_smmu_v3, &smmus);
        if ( smmus )
        {
            printk(XENLOG_ERR
                   "Unable to rewrite the IORT (%d); it describes %u SMMUv3 Xen uses, so the hardware domain gets no IORT\n",
                   rc, smmus);
            hwdom_omit_iort = true;
        }
        else if ( rc != -ENODEV )
            printk(XENLOG_WARNING
                   "Unable to rewrite the IORT (%d), the hardware domain will see the firmware's\n",
                   rc);
        return rc;
    }

    iort = (struct acpi_table_header *)base_ptr;
    iort->checksum = 0;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, iort), len);
    iort->checksum -= checksum;

    tbl_add[TBL_IORT].start = d->arch.efi_acpi_gpa + offset;
    tbl_add[TBL_IORT].size = len;

    return 0;
}

static int __init acpi_create_xsdt(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_rsdp *rsdp_tbl;
    struct acpi_table_xsdt *xsdt = NULL;
    u64 table_size, addr;
    unsigned long entry_count;
    u8 *base_ptr;
    u8 checksum;

    addr = acpi_os_get_root_pointer();
    if ( !addr )
    {
        printk("Unable to get acpi root pointer\n");
        return -EINVAL;
    }
    rsdp_tbl = acpi_os_map_memory(addr, sizeof(struct acpi_table_rsdp));
    table = acpi_os_map_memory(rsdp_tbl->xsdt_physical_address,
                               sizeof(struct acpi_table_header));

    /* Add places for the tables Xen appends rather than replaces. */
    table_size = table->length + sizeof(u64);
    if ( tbl_add[TBL_SSDT].size )
        table_size += sizeof(u64);
    entry_count = (table->length - sizeof(struct acpi_table_header))
                  / sizeof(u64);
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_XSDT);
    memcpy(base_ptr, table, table->length);
    acpi_os_unmap_memory(table, sizeof(struct acpi_table_header));
    acpi_os_unmap_memory(rsdp_tbl, sizeof(struct acpi_table_rsdp));

    xsdt = (struct acpi_table_xsdt *)base_ptr;
    acpi_xsdt_modify_entry(xsdt->table_offset_entry, entry_count,
                           ACPI_SIG_FADT, tbl_add[TBL_FADT].start);
    acpi_xsdt_modify_entry(xsdt->table_offset_entry, entry_count,
                           ACPI_SIG_MADT, tbl_add[TBL_MADT].start);
    if ( tbl_add[TBL_IORT].size )
        acpi_xsdt_modify_entry(xsdt->table_offset_entry, entry_count,
                               ACPI_SIG_IORT, tbl_add[TBL_IORT].start);
    else if ( hwdom_omit_iort &&
              acpi_xsdt_remove_entry(xsdt->table_offset_entry, &entry_count,
                                     ACPI_SIG_IORT) )
        table_size -= sizeof(u64);
    xsdt->table_offset_entry[entry_count++] = tbl_add[TBL_STAO].start;
    if ( tbl_add[TBL_SSDT].size )
        xsdt->table_offset_entry[entry_count++] = tbl_add[TBL_SSDT].start;

    xsdt->header.length = table_size;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, xsdt), table_size);
    xsdt->header.checksum -= checksum;

    tbl_add[TBL_XSDT].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_XSDT);
    tbl_add[TBL_XSDT].size = table_size;

    return 0;
}

static int __init acpi_create_stao(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL, *spcr = NULL;
    struct acpi_table_stao *stao = NULL;
    u32 table_size = sizeof(struct acpi_table_stao);
    u32 offset = acpi_get_table_offset(tbl_add, TBL_STAO);
    acpi_status status;
    u8 *base_ptr, checksum;

    /* Copy OEM and ASL compiler fields from another table, use MADT */
    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        printk("STAO: Failed to get MADT table, %s\n", msg);
        return -EINVAL;
    }

    base_ptr = d->arch.efi_acpi_table + offset;
    memcpy(base_ptr, table, sizeof(struct acpi_table_header));

    stao = (struct acpi_table_stao *)base_ptr;
    memcpy(stao->header.signature, ACPI_SIG_STAO, 4);
    stao->header.revision = 1;
    stao->header.length = table_size;

    /*
     * ignore_uart says "the UART the SPCR describes belongs to the hypervisor,
     * leave it alone".  Only say it where there is an SPCR to describe one:
     * Xen's console on such a machine is that UART, because the SPCR is the
     * only ACPI console binding uart_init() knows, but a machine that declares
     * no SPCR has no UART for the claim to be about.  Claiming it anyway sends
     * the hardware domain looking for a table that is not there, which is what
     * Linux's "STAO table present, but SPCR is missing" warning is.
     */
    stao->ignore_uart = !ACPI_FAILURE(acpi_get_table(ACPI_SIG_SPCR, 0, &spcr));

    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, stao), table_size);
    stao->header.checksum -= checksum;

    tbl_add[TBL_STAO].start = d->arch.efi_acpi_gpa + offset;
    tbl_add[TBL_STAO].size = table_size;

    return 0;
}

/*
 * A supplementary SSDT giving the PCI host bridge a "PCI Boot Configuration"
 * _DSM, which tells the hardware domain to keep the BAR assignments it was
 * handed rather than making its own.
 *
 * This is the ACPI counterpart of the "linux,pci-probe-only" property Xen puts
 * in a device-tree hardware domain's /chosen, and it is needed for the same
 * reason: where Xen's console is a PCI function, the domain must not move it.
 * It matters more here than it does there.  Xen hides the function it owns, so
 * the domain cannot see it at all, and an allocator that reassigns every BAR
 * will happily give the address behind that hole to some other device -- which
 * then decodes the same addresses as Xen's console.
 *
 * The device tree form cannot be used on this path: a domain booted with ACPI
 * never unflattens the device tree, so nothing reads /chosen.  Function 5 of
 * the PCI Firmware Specification's _DSM is the mechanism that exists for this,
 * and returning zero from it is what asks for the firmware's assignment to be
 * preserved.
 *
 * Emitted only when Xen owns a PCI function, since it constrains the domain's
 * resource allocation for every device on the bridge.
 *
 * Regenerate with `iasl -p pci-preserve pci-preserve.asl` from:
 *
 *   DefinitionBlock ("", "SSDT", 2, "XenARM", "PCIPRSV", 0x00000001)
 *   {
 *       External (\_SB.PCI0, DeviceObj)
 *
 *       Scope (\_SB.PCI0)
 *       {
 *           Method (_DSM, 4, NotSerialized)
 *           {
 *               If ((Arg0 == ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d")))
 *               {
 *                   If ((Arg2 == Zero))
 *                   {
 *                       Return (Buffer (One) { 0x21 })   // functions 0 and 5
 *                   }
 *
 *                   If ((Arg2 == 0x05))
 *                   {
 *                       Return (Zero)                    // preserve
 *                   }
 *               }
 *
 *               Return (Buffer (One) { 0x00 })
 *           }
 *       }
 *   }
 */
static const uint8_t __initconst pci_preserve_ssdt[] =
{
    0x53, 0x53, 0x44, 0x54, 0x77, 0x00, 0x00, 0x00, 0x02, 0x2a, 0x58, 0x65,
    0x6e, 0x41, 0x52, 0x4d, 0x50, 0x43, 0x49, 0x50, 0x52, 0x53, 0x56, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x49, 0x4e, 0x54, 0x4c, 0x08, 0x04, 0x26, 0x20,
    0xa0, 0x0f, 0x00, 0x15, 0x5c, 0x2e, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43,
    0x49, 0x30, 0x06, 0x00, 0x10, 0x42, 0x04, 0x5c, 0x2e, 0x5f, 0x53, 0x42,
    0x5f, 0x50, 0x43, 0x49, 0x30, 0x14, 0x35, 0x5f, 0x44, 0x53, 0x4d, 0x04,
    0xa0, 0x29, 0x93, 0x68, 0x11, 0x13, 0x0a, 0x10, 0xd0, 0x37, 0xc9, 0xe5,
    0x53, 0x35, 0x7a, 0x4d, 0x91, 0x17, 0xea, 0x4d, 0x19, 0xc3, 0x43, 0x4d,
    0xa0, 0x09, 0x93, 0x6a, 0x00, 0xa4, 0x11, 0x03, 0x01, 0x21, 0xa0, 0x07,
    0x93, 0x6a, 0x0a, 0x05, 0xa4, 0x00, 0xa4, 0x11, 0x03, 0x01, 0x00,
};

static int __init acpi_create_ssdt(struct domain *d, struct membank tbl_add[])
{
    u32 table_size = sizeof(pci_preserve_ssdt);
    u32 offset = acpi_get_table_offset(tbl_add, TBL_SSDT);
    struct acpi_table_header *ssdt;
    u8 *base_ptr, checksum;

    if ( !vtcon_in_use() )
        return 0;

    base_ptr = d->arch.efi_acpi_table + offset;
    memcpy(base_ptr, pci_preserve_ssdt, table_size);

    ssdt = (struct acpi_table_header *)base_ptr;
    ssdt->checksum = 0;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, ssdt), table_size);
    ssdt->checksum -= checksum;

    tbl_add[TBL_SSDT].start = d->arch.efi_acpi_gpa + offset;
    tbl_add[TBL_SSDT].size = table_size;

    return 0;
}

static int __init acpi_create_madt(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_madt *madt = NULL;
    struct acpi_subtable_header *header;
    struct acpi_madt_generic_distributor *gicd;
    u32 table_size = sizeof(struct acpi_table_madt);
    u32 offset = acpi_get_table_offset(tbl_add, TBL_MADT);
    int ret;
    acpi_status status;
    u8 *base_ptr, checksum;

    status = acpi_get_table(ACPI_SIG_MADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        printk("Failed to get MADT table, %s\n", msg);
        return -EINVAL;
    }

    base_ptr = d->arch.efi_acpi_table + offset;
    memcpy(base_ptr, table, table_size);

    /* Add Generic Distributor. */
    header = acpi_table_get_entry_madt(ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR, 0);
    if ( !header )
    {
        printk("Can't get GICD entry\n");
        return -EINVAL;
    }
    gicd = container_of(header, struct acpi_madt_generic_distributor, header);
    memcpy(base_ptr + table_size, gicd,
                sizeof(struct acpi_madt_generic_distributor));
    table_size += sizeof(struct acpi_madt_generic_distributor);

    /* Add other subtables. */
    ret = gic_make_hwdom_madt(d, offset + table_size);
    if ( ret < 0 )
    {
        printk("Failed to get other subtables\n");
        return -EINVAL;
    }
    table_size += ret;

    madt = (struct acpi_table_madt *)base_ptr;
    madt->header.length = table_size;
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, madt), table_size);
    madt->header.checksum -= checksum;

    tbl_add[TBL_MADT].start = d->arch.efi_acpi_gpa + offset;
    tbl_add[TBL_MADT].size = table_size;

    return 0;
}

static int __init acpi_create_fadt(struct domain *d, struct membank tbl_add[])
{
    struct acpi_table_header *table = NULL;
    struct acpi_table_fadt *fadt = NULL;
    u64 table_size;
    acpi_status status;
    u8 *base_ptr;
    u8 checksum;

    status = acpi_get_table(ACPI_SIG_FADT, 0, &table);

    if ( ACPI_FAILURE(status) )
    {
        const char *msg = acpi_format_exception(status);

        printk("Failed to get FADT table, %s\n", msg);
        return -EINVAL;
    }

    table_size = table->length;
    base_ptr = d->arch.efi_acpi_table
               + acpi_get_table_offset(tbl_add, TBL_FADT);
    memcpy(base_ptr, table, table_size);
    fadt = (struct acpi_table_fadt *)base_ptr;

    /* Set PSCI_COMPLIANT and PSCI_USE_HVC */
    fadt->arm_boot_flags |= (ACPI_FADT_PSCI_COMPLIANT | ACPI_FADT_PSCI_USE_HVC);
    checksum = acpi_tb_checksum(ACPI_CAST_PTR(u8, fadt), table_size);
    fadt->header.checksum -= checksum;

    tbl_add[TBL_FADT].start = d->arch.efi_acpi_gpa
                              + acpi_get_table_offset(tbl_add, TBL_FADT);
    tbl_add[TBL_FADT].size = table_size;

    return 0;
}

static int __init estimate_acpi_efi_size(struct domain *d,
                                         const struct kernel_info *kinfo)
{
    size_t efi_size, acpi_len, madt_size;
    uint32_t iort_size;
    u64 addr;
    struct acpi_table_rsdp *rsdp_tbl;
    struct acpi_table_header *table;

    efi_size = estimate_efi_size(kernel_info_get_mem_const(kinfo)->nr_banks);

    acpi_len = ROUNDUP(sizeof(struct acpi_table_fadt), 8);
    acpi_len += ROUNDUP(sizeof(struct acpi_table_stao), 8);
    acpi_len += ROUNDUP(sizeof(pci_preserve_ssdt), 8);

    madt_size = gic_get_hwdom_madt_size(d);
    acpi_len += ROUNDUP(madt_size, 8);

    if ( !iort_hwdom_size(&iort_size) )
        acpi_len += ROUNDUP(iort_size, 8);

    addr = acpi_os_get_root_pointer();
    if ( !addr )
    {
        printk("Unable to get acpi root pointer\n");
        return -EINVAL;
    }

    rsdp_tbl = acpi_os_map_memory(addr, sizeof(struct acpi_table_rsdp));
    if ( !rsdp_tbl )
    {
        printk("Unable to map RSDP table\n");
        return -EINVAL;
    }

    table = acpi_os_map_memory(rsdp_tbl->xsdt_physical_address,
                               sizeof(struct acpi_table_header));
    acpi_os_unmap_memory(rsdp_tbl, sizeof(struct acpi_table_rsdp));
    if ( !table )
    {
        printk("Unable to map XSDT table\n");
        return -EINVAL;
    }

    /* Add places for the tables Xen appends to the XSDT. */
    acpi_len += ROUNDUP(table->length + 2 * sizeof(u64), 8);
    acpi_os_unmap_memory(table, sizeof(struct acpi_table_header));

    acpi_len += ROUNDUP(sizeof(struct acpi_table_rsdp), 8);
    d->arch.efi_acpi_len = PAGE_ALIGN(ROUNDUP(efi_size, 8)
                                      + ROUNDUP(acpi_len, 8));

    return 0;
}

int __init prepare_acpi(struct domain *d, struct kernel_info *kinfo)
{
    int rc = 0;
    int order;
    struct membank tbl_add[TBL_MMAX] = {};

    rc = estimate_acpi_efi_size(d, kinfo);
    if ( rc != 0 )
        return rc;

    order = get_order_from_bytes(d->arch.efi_acpi_len);
    d->arch.efi_acpi_table = alloc_xenheap_pages(order, 0);
    if ( d->arch.efi_acpi_table == NULL )
    {
        printk("unable to allocate memory!\n");
        return -ENOMEM;
    }
    memset(d->arch.efi_acpi_table, 0, d->arch.efi_acpi_len);

    /*
     * For ACPI, Dom0 doesn't use kinfo->gnttab_start to get the grant table
     * region. So we use it as the ACPI table mapped address. Also it needs to
     * check if the size of grant table region is enough for those ACPI tables.
     */
    d->arch.efi_acpi_gpa = kinfo->gnttab_start;
    if ( kinfo->gnttab_size < d->arch.efi_acpi_len )
    {
        printk("The grant table region is not enough to fit the ACPI tables!\n");
        return -EINVAL;
    }

    rc = acpi_create_fadt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_madt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_stao(d, tbl_add);
    if ( rc != 0 )
        return rc;

    /* A failure here is not fatal; see the comment on acpi_create_iort(). */
    acpi_create_iort(d, tbl_add);

    rc = acpi_create_ssdt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_xsdt(d, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_create_rsdp(d, tbl_add);
    if ( rc != 0 )
        return rc;

    acpi_map_other_tables(d);
    acpi_create_efi_system_table(d, tbl_add);
    acpi_create_efi_mmap_table(d, kernel_info_get_mem(kinfo), tbl_add);

    /* Map the EFI and ACPI tables to Dom0 */
    rc = map_regions_p2mt(d,
                          gaddr_to_gfn(d->arch.efi_acpi_gpa),
                          PFN_UP(d->arch.efi_acpi_len),
                          virt_to_mfn(d->arch.efi_acpi_table),
                          p2m_mmio_direct_c);
    if ( rc != 0 )
    {
        printk(XENLOG_ERR "Unable to map EFI/ACPI table 0x%"PRIx64
               " - 0x%"PRIx64" in domain %d\n",
               d->arch.efi_acpi_gpa & PAGE_MASK,
               PAGE_ALIGN(d->arch.efi_acpi_gpa + d->arch.efi_acpi_len) - 1,
               d->domain_id);
        return rc;
    }

    /*
     * Flush the cache for this region, otherwise DOM0 may read wrong data when
     * the cache is disabled.
     */
    clean_and_invalidate_dcache_va_range(d->arch.efi_acpi_table,
                                         d->arch.efi_acpi_len);

    rc = create_acpi_dtb(kinfo, tbl_add);
    if ( rc != 0 )
        return rc;

    rc = acpi_route_spis(d);
    if ( rc != 0 )
        return rc;

    rc = acpi_iomem_deny_access(d);
    if ( rc != 0 )
        return rc;

    /*
     * All PPIs have been registered, allocate the event channel
     * interrupts.
     */
    evtchn_allocate(d);

    return 0;
}
