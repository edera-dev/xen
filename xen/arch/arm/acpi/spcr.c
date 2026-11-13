/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hide the PCI UART that the SPCR names, Xen's console, from the hardware
 * domain.
 */

#include <xen/acpi.h>
#include <xen/iocap.h>
#include <xen/mm.h>
#include <xen/pci.h>
#include <xen/sched.h>
#include <xen/serial.h>
#include <xen/sizes.h>
#include <xen/vmap.h>

#include <asm/domain_build.h>
#include <asm/io.h>
#include <asm/mmio.h>

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
 * cannot be done and the UART has to stay visible.  Everything beneath the
 * port is locked with it, so this assumes that the port leads to the UART
 * alone.
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
int __init acpi_hide_spcr_pci_uart(struct domain *d,
                                   const struct acpi_table_spcr *spcr)
{
    unsigned int devfn = PCI_DEVFN(spcr->pci_device, spcr->pci_function);
    pci_sbdf_t sbdf = PCI_SBDF(spcr->pci_segment, spcr->pci_bus, devfn);
    unsigned int root, header;
    paddr_t base, cfg;
    void __iomem *va;
    uint32_t id;
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

    cfg = ecam_page(base, sbdf.bus, devfn);
    va = ioremap_nocache(cfg, PAGE_SIZE);
    if ( !va )
        return -ENOMEM;
    id = readl(va + PCI_VENDOR_ID);
    header = readb(va + PCI_HEADER_TYPE);
    iounmap(va);

    /*
     * Nothing but this code relies on the SPCR's PCI fields, so nothing else
     * would show them to be wrong.  A page that holds some other device would
     * hide that device instead.
     */
    if ( id != (((uint32_t)spcr->pci_device_id << 16) | spcr->pci_vendor_id) )
    {
        spcr_keep(&sbdf,
                  "the function at its configuration space has other IDs, so hiding it could hide some other device");
        return 0;
    }

    /*
     * The UART must be its device's only function: Linux skips functions 1-7
     * of a device whose function 0 is missing, and any other function sits
     * behind the port that is about to be locked.
     */
    if ( PCI_FUNC(devfn) || (header & 0x80) )
    {
        spcr_keep(&sbdf,
                  "it is one of several functions of its device, and the others would be hidden with it or locked behind its port");
        return 0;
    }

    /* A function on the root bus has no port, and no slot, above it. */
    if ( sbdf.bus != root )
    {
        rc = spcr_restrict_port(d, base, root, &sbdf);
        if ( rc )
            return rc == -ENODEV ? 0 : rc;
    }

    rc = hide_pci_function_from_hwdom(d, cfg);
    if ( rc )
        return rc;

    printk("SPCR: console %pp hidden from %pd\n", &sbdf, d);

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
