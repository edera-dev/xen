/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for reading the PCI host bridge windows from the DSDT.
 */

#ifndef _TEST_HARNESS_
#define _TEST_HARNESS_

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define __init

static inline uint32_t get_unaligned_le32(const void *p)
{
    const uint8_t *b = p;

    return b[0] | (b[1] << 8) | (b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* ACPICA packs its table structures, so a table needs no alignment. */
struct __attribute__((__packed__)) acpi_table_header {
    char     signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    char     asl_compiler_id[4];
    uint32_t asl_compiler_revision;
};

typedef uint32_t acpi_status;

#define AE_OK                0
#define AE_NOT_FOUND         5
#define ACPI_FAILURE(status) ((status) != AE_OK)
#define ACPI_SIG_DSDT        "DSDT"

acpi_status acpi_get_table(const char *signature, uint32_t instance,
                           struct acpi_table_header **out_table);

/* Records each range added, in order, without merging them. */
struct rangeset {
    unsigned int nr;
    struct {
        unsigned long start, end;
    } ranges[4];
};

int rangeset_add_range(struct rangeset *r, unsigned long s, unsigned long e);

int acpi_pci_get_host_bridge_windows(uint16_t segment,
                                     struct rangeset *windows);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
