/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IO Remapping Table (IORT) support
 *
 * The IORT describes how the IDs a device emits are translated on their way to
 * an SMMU or a GIC ITS.  It is the ACPI counterpart of the device tree's
 * "iommu-map" and "msi-map" properties, and is consumed here for the same two
 * purposes: finding the StreamID an SMMU sees, and the DeviceID an ITS sees.
 */
#ifndef __ASM_ARM_IORT_H__
#define __ASM_ARM_IORT_H__

#include <xen/errno.h>
#include <xen/types.h>

struct acpi_iort_node;

#ifdef CONFIG_ACPI

#include <xen/acpi.h>

/*
 * Locate and validate the IORT.  Safe to call on a system without one, in
 * which case every lookup below fails with -ENODEV.
 */
void iort_init(void);

/*
 * Translate a PCI requester ID through the ID mappings of its root complex
 * until a node of type @target_type is reached.
 *
 * @id_out receives the translated ID, and @target, if non-NULL, the node it
 * came out of.  Returns -ENODEV when the segment, or a mapping for that RID,
 * is not described.
 */
int iort_map_rid(uint16_t segment, uint32_t rid, uint8_t target_type,
                 uint32_t *id_out, const struct acpi_iort_node **target);

/*
 * Physical base address of the ITS serving @rid on @segment.  The IORT names
 * an ITS by identifier only, so the address is then looked up in the MADT.
 */
int iort_get_msi_base(uint16_t segment, uint32_t rid, paddr_t *base);

/*
 * Size, and then build, the IORT handed to the hardware domain.  It omits the
 * SMMU nodes so that the domain does not drive hardware Xen owns, while still
 * describing the ITS, which Linux needs in order to have an MSI domain at all.
 */
int iort_hwdom_size(uint32_t *size);
int iort_make_hwdom_table(void *base, size_t size, uint32_t *len);

/* Invoke @cb for every SMMUv3 node in the table, stopping on a non-zero return. */
int iort_for_each_smmu_v3(int (*cb)(const struct acpi_iort_node *node,
                                    void *arg), void *arg);

#else /* !CONFIG_ACPI */

static inline void iort_init(void) {}

static inline int iort_map_rid(uint16_t segment, uint32_t rid,
                               uint8_t target_type, uint32_t *id_out,
                               const struct acpi_iort_node **target)
{
    return -ENODEV;
}

static inline int iort_get_msi_base(uint16_t segment, uint32_t rid,
                                    paddr_t *base)
{
    return -ENODEV;
}

#endif /* CONFIG_ACPI */

#endif /* __ASM_ARM_IORT_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
