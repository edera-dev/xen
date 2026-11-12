/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/iommu.h>
#include <xen/param.h>
#include <xen/pci.h>

#include <asm/gic_v3_its.h>

/*
 * PIRQ event channels are not supported on Arm, so nothing to do.
 */
int arch_pci_clean_pirqs(struct domain *d)
{
    return 0;
}

struct pci_dev *dev_to_pci(struct device *dev)
{
    ASSERT(dev->type == DEV_PCI);

    return container_of(dev, struct pci_dev, arch.dev);
}

void arch_pci_init_pdev(struct pci_dev *pdev)
{
    pci_to_dev(pdev)->type = DEV_PCI;
}

/* A device is leaving domain d: drop what d mapped for it in its vITS. */
void arch_pci_release_device(struct domain *d, struct pci_dev *pdev)
{
    vgic_v3_its_release_pci_device(d, pdev);
}

static int __init dt_pci_init(void)
{
    struct dt_device_node *np;
    int rc;

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_PCI_HOSTBRIDGE, NULL);
        /*
         * Ignore the following error codes:
         *   - EBADF: Indicate the current device is not a pci device.
         *   - ENODEV: The pci device is not present or cannot be used by
         *     Xen.
         */
        if( !rc || rc == -EBADF || rc == -ENODEV )
            continue;

        return rc;
    }

    return 0;
}

#ifdef CONFIG_ACPI
/*
 * Register a host bridge for every MCFG allocation.  Xen does not assign BARs
 * on an ACPI system: it leaves them to the firmware and the hardware domain,
 * which reports the devices back through PHYSDEVOP_pci_device_add.
 */
static int __init acpi_pci_init(void)
{
    struct acpi_table_header *table;
    const struct acpi_table_mcfg *mcfg;
    const struct acpi_mcfg_allocation *alloc;
    unsigned int i, count;
    acpi_status status;
    int rc = -ENODEV;

    status = acpi_get_table(ACPI_SIG_MCFG, 0, &table);
    if ( ACPI_FAILURE(status) )
    {
        printk(XENLOG_ERR "PCI: no MCFG table, no host bridge can be found\n");
        return -ENODEV;
    }

    if ( table->length < sizeof(*mcfg) )
    {
        printk(XENLOG_ERR "PCI: MCFG table is too short\n");
        return -EINVAL;
    }

    mcfg = container_of(table, const struct acpi_table_mcfg, header);
    count = (table->length - sizeof(*mcfg)) / sizeof(*alloc);
    if ( !count )
    {
        printk(XENLOG_ERR "PCI: MCFG table describes no allocation\n");
        return -ENODEV;
    }

    alloc = (const struct acpi_mcfg_allocation *)(mcfg + 1);
    for ( i = 0; i < count; i++, alloc++ )
    {
        struct pci_host_bridge *bridge;

        bridge = pci_host_acpi_probe(alloc->pci_segment, alloc->address,
                                     alloc->start_bus_number,
                                     alloc->end_bus_number,
                                     &pci_generic_ecam_ops);
        if ( IS_ERR(bridge) )
        {
            printk(XENLOG_ERR
                   "PCI: failed to register segment %04x [bus %02x-%02x]: %ld\n",
                   alloc->pci_segment, alloc->start_bus_number,
                   alloc->end_bus_number, PTR_ERR(bridge));
            continue;
        }

        rc = 0;
    }

    return rc;
}
#else
static int __init acpi_pci_init(void)
{
    return -EINVAL;
}
#endif

/*
 * Platform-specific PCI host dependencies require dom0 to handle
 * initialization and issue PHYSDEVOP_pci_device_add/remove calls for SMMU
 * device registration. This check is used to enable the minimal PCI
 * subsystem required for dom0 operation when PCI passthrough is disabled.
 */
bool arch_pci_device_physdevop(void)
{
    return iommu_enabled;
}

/* By default pci passthrough is disabled. */
bool __read_mostly pci_passthrough_enabled;
boolean_param("pci-passthrough", pci_passthrough_enabled);

/* By default pci scan is disabled. */
bool __read_mostly pci_scan_enabled;
boolean_param("pci-scan", pci_scan_enabled);

static int __init pci_init(void)
{
    int ret;

    /*
     * pci-scan gives the hardware domain a host bridge that Xen emulates in
     * place of the real ones, and Xen can describe that bridge only in a
     * device tree. With ACPI, the hardware domain finds the devices itself,
     * as on x86. Clear the flag, not only skip the scan: the hardware
     * domain's vPCI, its vITS and its PHYSDEVOP calls read it too. They read
     * it only once dom0 is built, after the initcalls, so this is early
     * enough.
     */
    if ( pci_scan_enabled && !acpi_disabled )
    {
        printk(XENLOG_WARNING
               "PCI: pci-scan is not supported with ACPI, ignoring it\n");
        pci_scan_enabled = false;
    }

    /*
     * Enable PCI passthrough when has been enabled explicitly
     * (pci-passthrough=on).
     */
    if ( !is_pci_passthrough_enabled() && !arch_pci_device_physdevop() )
        return 0;

    if ( pci_add_segment(0) )
        panic("Could not initialize PCI segment 0\n");

    if ( acpi_disabled )
        ret = dt_pci_init();
    else
        ret = acpi_pci_init();

    if ( ret < 0 )
        return ret;

    if ( is_pci_scan_enabled() )
    {
        ret = scan_pci_devices();

        if ( ret < 0 )
            return ret;

        pci_fixup_bars();

        add_discovered_pci_devices();

#ifdef CONFIG_PCI_DEVICE_DEBUG
        dump_pci_devices('c');
#endif
    }

    return 0;
}
__initcall(pci_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
