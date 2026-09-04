/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_ARM_ACPI_DSDT_H__
#define __ASM_ARM_ACPI_DSDT_H__

#include <xen/errno.h>
#include <xen/types.h>

struct rangeset;

#ifdef CONFIG_ACPI

/*
 * Add the memory windows the PCI host bridge on @segment decodes, taken from
 * its _CRS, to @windows.  Returns -ENODEV when the DSDT does not describe them
 * in a form that can be read without an AML interpreter, which leaves @windows
 * as it was.
 */
int acpi_pci_get_host_bridge_windows(uint16_t segment,
                                     struct rangeset *windows);

#else

static inline int acpi_pci_get_host_bridge_windows(uint16_t segment,
                                                   struct rangeset *windows)
{
    return -ENODEV;
}

#endif /* CONFIG_ACPI */

#endif /* __ASM_ARM_ACPI_DSDT_H__ */
