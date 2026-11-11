/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for the IORT parser.
 */

#ifndef _TEST_HARNESS_
#define _TEST_HARNESS_

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <xen-tools/common-macros.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t paddr_t;

/*
 * The tables are laid out by Xen's own ACPICA headers, so the test reads them
 * as the hypervisor does.  These stand in for ACPICA's platform header.
 */
#define ACPI_MACHINE_WIDTH        64
#define COMPILER_DEPENDENT_UINT64 uint64_t
#define COMPILER_DEPENDENT_INT64  int64_t

#include <acpi/actypes.h>
#include <acpi/acconfig.h>
#include <acpi/actbl.h>

#define __init
#define __read_mostly

#define XENLOG_INFO    ""
#define XENLOG_WARNING ""
#define printk         printf

#define AE_OK                0
#define AE_NOT_FOUND         5
#define ACPI_FAILURE(status) ((status) != AE_OK)

#define acpi_disabled false

acpi_status acpi_get_table(const char *signature, u32 instance,
                           struct acpi_table_header **out_table);
struct acpi_subtable_header *acpi_table_get_entry_madt(enum acpi_madt_type id,
                                                       unsigned int entry_id);

void iort_init(void);
int iort_map_rid(uint16_t segment, uint32_t rid, uint8_t target_type,
                 uint32_t *id_out, const struct acpi_iort_node **target);
int iort_get_msi_base(uint16_t segment, uint32_t rid, paddr_t *base);
int iort_hwdom_size(uint32_t *size);
int iort_make_hwdom_table(void *base, size_t size, uint32_t *len);
int iort_for_each_smmu_v3(int (*cb)(const struct acpi_iort_node *node,
                                    void *arg), void *arg);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
