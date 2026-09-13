/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/gic-v2m.c
 *
 * GICv2m MSI frames, for the benefit of the hardware domain.
 *
 * A GICv2m frame is a page of the interrupt controller that turns a memory
 * write into a shared peripheral interrupt: a device sends its MSI to
 * frame_base + V2M_MSI_SETSPI_NS carrying the SPI number as data, and the
 * distributor makes that SPI pending.  It owns a contiguous block of SPIs,
 * which it reports in V2M_MSI_TYPER and which the device tree may also state
 * outright.
 *
 * Xen has no use for MSIs of its own, so this file exists entirely to let a
 * hardware domain use them.  Three things have to happen for that, and none of
 * them fall out of the normal device-tree walk, because a v2m frame is a child
 * of the interrupt controller node and handle_node() replaces that node
 * wholesale with Xen's own virtual GIC:
 *
 *  - the frame's page must be mapped into the domain, so that the doorbell
 *    write lands on real hardware.  The hardware domain is direct-mapped, so
 *    the guest address is the host one and the device needs no translation.
 *
 *  - the SPIs the frame owns must be routed to the domain.  They cannot be
 *    routed later on demand: which SPI a device ends up using is decided by
 *    the domain's own MSI allocator long after Xen has finished building it,
 *    and nothing tells Xen about it.  So route the whole block up front.  That
 *    is cheaper than it sounds: route_irq_to_guest() does not enable anything,
 *    so an SPI that is routed but never used costs two small allocations and a
 *    reserved vIRQ, and stays disabled at the distributor.  The domain's write
 *    to GICD_ISENABLER is what enables it, and vgic_enable_irqs() programs the
 *    trigger type from the domain's GICD_ICFGR view immediately before doing
 *    so -- which is also why the type is not set here.
 *
 *  - the frame must be re-advertised inside the virtual GIC node, keeping the
 *    host phandle, because the PCI host bridge node handed to the domain
 *    refers to it by phandle in "msi-parent".
 *
 * On a machine that also has an ITS none of this is wanted; Xen drives the ITS
 * itself and gives the domain a translated view.  This code only ever looks at
 * v2m frames, so the two coexist, but see gicv2m_hwdom_dt_nodes() for the one
 * property they have to agree about.
 *
 * The motivating platform is Apple's Virtualization.framework, whose only MSI
 * controller is a single v2m frame and whose PCI _PRT routes no pin that any
 * device actually asserts -- so without this the hardware domain's virtio
 * devices cannot raise an interrupt at all.
 */

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/libfdt/libfdt.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/vmap.h>

#include <asm/gic.h>
#include <asm/io.h>
#include <asm/setup.h>

#define V2M_MSI_TYPER               0x008
#define V2M_MSI_TYPER_BASE_SPI(x)   (((x) >> 16) & 0x3ff)
#define V2M_MSI_TYPER_NUM_SPI(x)    ((x) & 0x3ff)

static const struct dt_device_match v2m_matches[] __initconst =
{
    DT_MATCH_COMPATIBLE("arm,gic-v2m-frame"),
    { /* sentinel */ },
};

static const struct dt_device_match its_matches[] __initconst =
{
    DT_MATCH_COMPATIBLE("arm,gic-v3-its"),
    { /* sentinel */ },
};

struct v2m_frame {
    paddr_t base;
    paddr_t size;
    unsigned int spi_base;
    unsigned int nr_spis;
};

/*
 * Describe one frame.  "arm,msi-base-spi" and "arm,msi-num-spis" are optional
 * in the binding, so fall back to reading V2M_MSI_TYPER, which is where the
 * information really lives -- and which is what Linux does, so a tree that
 * omits the properties still describes the same block to both.
 */
static int __init v2m_frame_info(const struct dt_device_node *node,
                                 struct v2m_frame *frame)
{
    uint32_t base, nr;
    int res;

    res = dt_device_get_paddr(node, 0, &frame->base, &frame->size);
    if ( res )
    {
        printk(XENLOG_ERR "%s: no address\n", dt_node_full_name(node));
        return res;
    }

    if ( dt_property_read_u32(node, "arm,msi-base-spi", &base) &&
         dt_property_read_u32(node, "arm,msi-num-spis", &nr) )
    {
        frame->spi_base = base;
        frame->nr_spis = nr;
    }
    else
    {
        void __iomem *regs = ioremap_nocache(frame->base, PAGE_SIZE);
        uint32_t typer;

        if ( !regs )
        {
            printk(XENLOG_ERR "%s: cannot map %#"PRIpaddr"\n",
                   dt_node_full_name(node), frame->base);
            return -ENOMEM;
        }

        typer = readl(regs + V2M_MSI_TYPER);
        iounmap(regs);

        frame->spi_base = V2M_MSI_TYPER_BASE_SPI(typer);
        frame->nr_spis = V2M_MSI_TYPER_NUM_SPI(typer);
    }

    if ( !frame->nr_spis || !gic_is_spi(frame->spi_base) ||
         !gic_is_spi(frame->spi_base + frame->nr_spis - 1) )
    {
        printk(XENLOG_ERR "%s: SPI range %u+%u is not usable\n",
               dt_node_full_name(node), frame->spi_base, frame->nr_spis);
        return -ERANGE;
    }

    return 0;
}

/*
 * Map every frame under @gic to @d and route the SPIs it owns.
 *
 * Called alongside the interrupt controller's own handling, which never hands
 * the controller over as itself, so handle_device() is never reached for it.
 *
 * Errors abort the domain build, as they do in handle_device().  The
 * alternative -- carry on without MSIs -- would give a domain whose device
 * tree advertises an MSI controller that Xen has not routed anything for, and
 * a device whose completion interrupt silently never arrives is a much harder
 * thing to diagnose than a build that stopped and said why.
 */
int __init gicv2m_hwdom_setup(struct domain *d,
                              const struct dt_device_node *gic,
                              p2m_type_t p2mt)
{
    const struct dt_device_node *child;
    unsigned int nr_frames = 0;

    dt_for_each_child_node(gic, child)
    {
        /*
         * The p2m type comes from the caller so that the frame is mapped the
         * same way as every other device the domain is given, rather than
         * this one page quietly differing from the rest.
         */
        struct map_range_data mr_data = {
            .d = d,
            .p2mt = p2mt,
            .skip_mapping = false,
        };
        struct v2m_frame frame;
        unsigned int spi;
        int res;

        if ( !dt_match_node(v2m_matches, child) )
            continue;

        res = v2m_frame_info(child, &frame);
        if ( res )
            return res;

        res = map_range_to_domain(child, 0, frame.base, frame.size, &mr_data);
        if ( res )
            return res;

        for ( spi = frame.spi_base; spi < frame.spi_base + frame.nr_spis;
              spi++ )
        {
            /*
             * need_mapping is true: this is a real SPI that must reach the
             * domain, not merely one the domain is allowed to touch.
             */
            res = map_irq_to_domain(d, spi, true, dt_node_name(child));
            if ( res )
                return res;
        }

        printk("GICv2m: %pd: frame %#"PRIpaddr", SPIs %u-%u\n",
               d, frame.base, frame.spi_base,
               frame.spi_base + frame.nr_spis - 1);
        nr_frames++;
    }

    if ( !nr_frames )
        printk(XENLOG_INFO "GICv2m: no MSI frame in %s\n",
               dt_node_full_name(gic));

    return 0;
}

/*
 * Re-emit the frames as children of the domain's virtual GIC node.
 *
 * Must be called from the interrupt controller's make_hwdom_dt_node hook, with
 * the node open and its own properties already written.
 *
 * @emit_ranges says whether this call owns the parent's "ranges" property.
 * Child nodes of the GIC cannot be addressed without it, but fdt rejects a
 * duplicate, and gicv3_its_make_hwdom_dt_nodes() emits it too -- exactly when
 * the host tree has an ITS.  So look for one rather than being told, which
 * keeps the decision next to the reason for it.
 */
int __init gicv2m_hwdom_dt_nodes(const struct domain *d,
                                 const struct dt_device_node *gic,
                                 void *fdt)
{
    const struct dt_device_node *child;
    bool emit_ranges = true, seen_v2m = false;
    int res;

    dt_for_each_child_node(gic, child)
    {
        if ( dt_match_node(its_matches, child) )
            emit_ranges = false;
        if ( dt_match_node(v2m_matches, child) )
            seen_v2m = true;
    }

    if ( !seen_v2m )
        return 0;

    if ( emit_ranges )
    {
        const void *prop;
        uint32_t len;

        prop = dt_get_property(gic, "ranges", &len);
        if ( !prop )
        {
            printk(XENLOG_ERR "%s: MSI frame needs the gic node's ranges\n",
                   dt_node_full_name(gic));
            return -FDT_ERR_XEN(ENOENT);
        }

        res = fdt_property(fdt, "ranges", prop, len);
        if ( res )
            return res;
    }

    dt_for_each_child_node(gic, child)
    {
        struct v2m_frame frame;
        const void *reg;
        const char *name;
        uint32_t len;

        if ( !dt_match_node(v2m_matches, child) )
            continue;

        res = v2m_frame_info(child, &frame);
        if ( res )
            return res;

        /*
         * Use the name with its unit address, the way handle_node() does, not
         * dt_node_name()'s bare "v2m": two frames would otherwise collide as
         * duplicate sibling nodes.
         */
        name = strrchr(dt_node_full_name(child), '/');
        name = name ? name + 1 : dt_node_full_name(child);

        res = fdt_begin_node(fdt, name);
        if ( res )
            return res;

        res = fdt_property_string(fdt, "compatible", "arm,gic-v2m-frame");
        if ( res )
            return res;

        res = fdt_property(fdt, "msi-controller", NULL, 0);
        if ( res )
            return res;

        /*
         * The phandle has to survive: the PCI host bridge node is copied to
         * the domain with its "msi-parent" intact, and that is a reference to
         * this node.
         */
        if ( child->phandle )
        {
            res = fdt_property_cell(fdt, "phandle", child->phandle);
            if ( res )
                return res;
        }

        /*
         * Copy "reg" rather than re-encoding it.  make_gic_node() copies the
         * host gic node's #address-cells/#size-cells, so the host encoding is
         * the right one, and the frame is direct-mapped at its host address.
         */
        reg = dt_get_property(child, "reg", &len);
        if ( !reg )
            return -FDT_ERR_XEN(ENOENT);

        res = fdt_property(fdt, "reg", reg, len);
        if ( res )
            return res;

        /*
         * State the SPI block explicitly even where the host tree left it to
         * V2M_MSI_TYPER, so that what the domain allocates from cannot drift
         * from what gicv2m_hwdom_setup() routed.
         */
        res = fdt_property_cell(fdt, "arm,msi-base-spi", frame.spi_base);
        if ( res )
            return res;

        res = fdt_property_cell(fdt, "arm,msi-num-spis", frame.nr_spis);
        if ( res )
            return res;

        res = fdt_end_node(fdt);
        if ( res )
            return res;
    }

    return 0;
}

#ifdef CONFIG_ACPI

/*
 * The ACPI path needs far less than the device-tree one, because the generic
 * ACPI hardware-domain build already does most of it: acpi_route_spis() routes
 * every SPI to the domain, and acpi_iomem_deny_access() permits the whole
 * address space bar the GIC's own regions, which a v2m frame is not one of.
 *
 * What is missing is the description.  gicv3_make_hwdom_madt() copies the GICC
 * and GICR entries and nothing else, so the domain's MADT names no MSI
 * controller at all and its devices have no way to raise an interrupt.
 *
 * Copy the host's entries through unchanged.  A frame is not virtualised --
 * the domain writes to the real doorbell and gets the real SPI, which is the
 * same arrangement the device-tree path describes -- so the base address and
 * the SPI block it advertises are true as they stand.
 */
static const struct acpi_madt_generic_msi_frame *__init v2m_madt_frame(
    unsigned int idx)
{
    struct acpi_subtable_header *header;

    header = acpi_table_get_entry_madt(ACPI_MADT_TYPE_GENERIC_MSI_FRAME, idx);
    if ( !header )
        return NULL;

    return container_of(header, const struct acpi_madt_generic_msi_frame,
                        header);
}

unsigned long __init gicv2m_get_hwdom_madt_size(void)
{
    unsigned long size = 0;
    unsigned int i;

    for ( i = 0; v2m_madt_frame(i); i++ )
        size += sizeof(struct acpi_madt_generic_msi_frame);

    return size;
}

unsigned long __init gicv2m_make_hwdom_madt(const struct domain *d, void *base)
{
    unsigned long len = 0;
    unsigned int i;

    for ( i = 0; ; i++ )
    {
        const struct acpi_madt_generic_msi_frame *host = v2m_madt_frame(i);
        struct acpi_madt_generic_msi_frame *frame;

        if ( !host )
            break;

        frame = base + len;
        memcpy(frame, host, sizeof(*frame));
        frame->header.length = sizeof(*frame);
        len += sizeof(*frame);

        printk("GICv2m: %pd: frame %#"PRIx64", SPIs %u-%u\n",
               d, host->base_address, host->spi_base,
               host->spi_base + host->spi_count - 1);
    }

    return len;
}

#endif /* CONFIG_ACPI */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
