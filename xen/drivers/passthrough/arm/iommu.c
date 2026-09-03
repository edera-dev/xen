/*
 * Generic IOMMU framework via the device tree
 *
 * Julien Grall <julien.grall@linaro.org>
 * Copyright (c) 2014 Linaro Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/iommu.h>
#include <xen/lib.h>

#include <asm/device.h>
#include <asm/iommu_fwspec.h>
#include <asm/iort.h>

/*
 * Deferred probe list is used to keep track of devices for which driver
 * requested deferred probing (returned -EAGAIN).
 */
static __initdata LIST_HEAD(deferred_probe_list);

static const struct iommu_ops *iommu_ops;

const struct iommu_ops *iommu_get_ops(void)
{
    return iommu_ops;
}

void __init iommu_set_ops(const struct iommu_ops *ops)
{
    BUG_ON(ops == NULL);

    if ( iommu_ops && iommu_ops != ops )
    {
        printk("WARNING: Cannot set IOMMU ops, already set to a different value\n");
        return;
    }

    iommu_ops = ops;
}

#ifdef CONFIG_ACPI
static int __init iommu_acpi_probe_smmu(const struct acpi_iort_node *node,
                                        void *arg)
{
    unsigned int *num_iommus = arg;
    int rc;

    rc = acpi_device_init(DEVICE_IOMMU, node, ACPI_IORT_NODE_SMMU_V3);
    if ( !rc )
        (*num_iommus)++;
    /*
     * -EBADF means no driver claimed this node, which is not fatal: the
     * system may simply have been built without that driver.
     */
    else if ( rc != -EBADF && rc != -ENODEV )
        return rc;

    return 0;
}

/* Instantiate every SMMU the IORT describes. */
static int __init iommu_acpi_hardware_setup(void)
{
    unsigned int num_iommus = 0;
    int rc;

    rc = iort_for_each_smmu_v3(iommu_acpi_probe_smmu, &num_iommus);
    if ( rc )
        return rc;

    return num_iommus ? 0 : -ENODEV;
}
#else
static int __init iommu_acpi_hardware_setup(void)
{
    return -ENODEV;
}
#endif

int __init iommu_hardware_setup(void)
{
    struct dt_device_node *np, *tmp;
    int rc;
    unsigned int num_iommus = 0;

    if ( !acpi_disabled )
        return iommu_acpi_hardware_setup();

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_IOMMU, NULL);
        if ( !rc )
            num_iommus++;
        else if ( rc == -EAGAIN )
        {
            /*
             * Nobody should use device's domain_list at such early stage,
             * so we can re-use it to link the device in the deferred list to
             * avoid introducing extra list_head field in struct dt_device_node.
             */
            ASSERT(list_empty(&np->domain_list));

            /*
             * Driver requested deferred probing, so add this device to
             * the deferred list for further processing.
             */
            list_add(&np->domain_list, &deferred_probe_list);
        }
        /*
         * Ignore the following error codes:
         *   - EBADF: Indicate the current is not an IOMMU
         *   - ENODEV: The IOMMU is not present or cannot be used by
         *     Xen.
         */
        else if ( rc != -EBADF && rc != -ENODEV )
            return rc;
    }

    /* Return immediately if there are no initialized devices. */
    if ( !num_iommus )
        return list_empty(&deferred_probe_list) ? -ENODEV : -EAGAIN;

    rc = 0;

    /*
     * Process devices in the deferred list if it is not empty.
     * Check that at least one device is initialized at each loop, otherwise
     * we may get an infinite loop. Also stop processing if we got an error
     * other than -EAGAIN.
     */
    while ( !list_empty(&deferred_probe_list) && num_iommus )
    {
        num_iommus = 0;

        list_for_each_entry_safe ( np, tmp, &deferred_probe_list, domain_list )
        {
            rc = device_init(np, DEVICE_IOMMU, NULL);
            if ( !rc )
            {
                num_iommus++;

                /* Remove initialized device from the deferred list. */
                list_del_init(&np->domain_list);
            }
            else if ( rc != -EAGAIN )
                return rc;
        }
    }

    return rc;
}

void __hwdom_init arch_iommu_check_autotranslated_hwdom(struct domain *d)
{
    /* ARM doesn't require specific check for hwdom */
    return;
}

int arch_iommu_domain_init(struct domain *d)
{
    return iommu_dt_domain_init(d);
}

void arch_iommu_domain_destroy(struct domain *d)
{
}

void __hwdom_init arch_iommu_hwdom_init(struct domain *d)
{
    /* Set to false options not supported on ARM. */
    if ( iommu_hwdom_inclusive )
        printk(XENLOG_WARNING "map-inclusive dom0-iommu option is not supported on ARM\n");
    iommu_hwdom_inclusive = false;
    if ( iommu_hwdom_reserved == 1 )
        printk(XENLOG_WARNING "map-reserved dom0-iommu option is not supported on ARM\n");
    iommu_hwdom_reserved = 0;
}

/*
 * Unlike x86, Arm doesn't support mem-sharing, mem-paging and log-dirty (yet).
 * So there is no restriction to use the IOMMU.
 */
bool arch_iommu_use_permitted(const struct domain *d)
{
    return true;
}

#if defined(CONFIG_HAS_PCI) && defined(CONFIG_ACPI)
/*
 * The IORT counterpart of iommu_add_dt_pci_sideband_ids(): translate the
 * device's requester ID into the StreamID its SMMU sees, and hand both to the
 * driver.
 */
static int iommu_add_iort_pci_sideband_ids(struct pci_dev *pdev)
{
    const struct iommu_ops *ops = iommu_get_ops();
    struct device *dev = pci_to_dev(pdev);
    unsigned int devfn = pdev->devfn;
    int rc;

    if ( !iommu_enabled )
        return 1;

    if ( !ops || !ops->acpi_xlate )
        return -EINVAL;

    if ( dev_iommu_fwspec_get(dev) )
        return -EEXIST;

    do {
        const struct acpi_iort_node *node;
        uint32_t streamid;

        rc = iort_map_rid(pdev->seg, PCI_BDF(pdev->bus, devfn),
                          ACPI_IORT_NODE_SMMU_V3, &streamid, &node);
        if ( rc )
            /*
             * A device the IORT does not route to an SMMU is not an error;
             * it simply is not translated.
             */
            return (rc == -ENODEV) ? 1 : rc;

        rc = ops->acpi_xlate(dev, node, streamid);
        if ( rc < 0 )
        {
            iommu_fwspec_free(dev);
            return -EINVAL;
        }

        devfn += pdev->phantom_stride;
    }
    while ( (devfn != pdev->devfn) &&
            (PCI_SLOT(devfn) == PCI_SLOT(pdev->devfn)) );

    return rc;
}
#endif

int iommu_add_pci_sideband_ids(struct pci_dev *pdev)
{
    int ret = -EOPNOTSUPP;

#ifdef CONFIG_HAS_PCI
    if ( acpi_disabled )
        ret = iommu_add_dt_pci_sideband_ids(pdev);
#ifdef CONFIG_ACPI
    else
        ret = iommu_add_iort_pci_sideband_ids(pdev);
#endif
#endif

    return ret;
}
