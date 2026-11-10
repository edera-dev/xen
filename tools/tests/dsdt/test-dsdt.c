/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for reading the PCI host bridge windows from the DSDT.
 *
 * Each table is copied to the end of a page that is followed by one that
 * cannot be read, so that a read past the end of the table stops the test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <xen-tools/common-macros.h>

#include "harness.h"

#include "bridges.h"
#include "virt.h"

/*
 * A Device that ends, with the table, one byte into a string _HID:
 *     Device (PCI0) { Name (_HID, "P
 */
static const struct __attribute__((__packed__)) {
    struct acpi_table_header header;
    uint8_t aml[14];
} cut_hid = {
    .header.length = sizeof(cut_hid),
    .aml = {
        0x5b, 0x82, 0x0c, 'P', 'C', 'I', '0',   /* Device, 12 bytes */
        0x08, '_', 'H', 'I', 'D',               /* Name (_HID, */
        0x0d, 'P',                              /* "P */
    },
};

/*
 * A Device that ends, with the table, three bytes into an EisaId _HID:
 *     Device (PCI0) { Name (_HID, EisaId ("PNP0A08") without its last byte
 */
static const struct __attribute__((__packed__)) {
    struct acpi_table_header header;
    uint8_t aml[16];
} cut_eisaid = {
    .header.length = sizeof(cut_eisaid),
    .aml = {
        0x5b, 0x82, 0x0e, 'P', 'C', 'I', '0',   /* Device, 14 bytes */
        0x08, '_', 'H', 'I', 'D',               /* Name (_HID, */
        0x0c, 0x41, 0xd0, 0x0a,                 /* DWord, 3 of its 4 bytes */
    },
};

static const struct test {
    const char *name;
    const void *table;
    size_t size;
    uint16_t segment;
    int rc;
    struct rangeset windows;
} tests[] = {
    {
        "QEMU virt: the bridge's two memory windows",
        virt, sizeof(virt), 0, 0,
        { 2, { { 0x10000000, 0x3efeffff }, { 0x8000000000, 0xffffffffff } } },
    },
    {
        "no _SEG is segment 0",
        bridges, sizeof(bridges), 0, 0, { 1, { { 0x10000000, 0x1fffffff } } },
    },
    {
        "_SEG of One",
        bridges, sizeof(bridges), 1, 0, { 1, { { 0x60000000, 0x6fffffff } } },
    },
    {
        "_SEG in a byte",
        bridges, sizeof(bridges), 2, 0, { 1, { { 0x20000000, 0x2fffffff } } },
    },
    {
        "_SEG in a word",
        bridges, sizeof(bridges), 0x100, 0,
        { 1, { { 0x80000000, 0x8fffffff } } },
    },
    {
        "host bridge by _CID",
        bridges, sizeof(bridges), 3, 0, { 1, { { 0x30000000, 0x3fffffff } } },
    },
    {
        "EisaId _HID",
        bridges, sizeof(bridges), 5, 0, { 1, { { 0x50000000, 0x5fffffff } } },
    },
    {
        "EisaId _CID",
        bridges, sizeof(bridges), 6, 0, { 1, { { 0x70000000, 0x7fffffff } } },
    },
    {
        "_CRS from a Method",
        bridges, sizeof(bridges), 4, -ENODEV, { 0 },
    },
    {
        "string _HID cut by the end of the table",
        &cut_hid, sizeof(cut_hid), 0, -ENODEV, { 0 },
    },
    {
        "EisaId _HID cut by the end of the table",
        &cut_eisaid, sizeof(cut_eisaid), 0, -ENODEV, { 0 },
    },
};

static struct acpi_table_header *dsdt;

acpi_status acpi_get_table(const char *signature, uint32_t instance,
                           struct acpi_table_header **out_table)
{
    if ( strcmp(signature, ACPI_SIG_DSDT) || instance || !dsdt )
        return AE_NOT_FOUND;

    *out_table = dsdt;

    return AE_OK;
}

int rangeset_add_range(struct rangeset *r, unsigned long s, unsigned long e)
{
    if ( r->nr == ARRAY_SIZE(r->ranges) )
        return -ENOMEM;

    r->ranges[r->nr].start = s;
    r->ranges[r->nr].end = e;
    r->nr++;

    return 0;
}

/* Make @table the DSDT, ending where a page that cannot be read begins. */
static void load_dsdt(const void *table, size_t size)
{
    static uint8_t *pages;
    size_t page = sysconf(_SC_PAGESIZE);

    if ( !pages )
    {
        pages = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if ( pages == MAP_FAILED || mprotect(pages + page, page, PROT_NONE) )
        {
            perror("guard page");
            exit(1);
        }
    }

    if ( size > page )
    {
        fprintf(stderr, "a %zu-byte table does not fit in a page\n", size);
        exit(1);
    }

    dsdt = memcpy(pages + page - size, table, size);
}

static unsigned int failures;

#define report(fmt, args...) do { printf(fmt, ## args); failures++; } while ( 0 )

static void check(const struct test *t)
{
    const struct rangeset *want = &t->windows;
    struct rangeset got = { 0 };
    unsigned int i;
    int rc;

    /* Named first, so that a read past the table's end shows which test. */
    printf("%s\n", t->name);
    fflush(stdout);

    load_dsdt(t->table, t->size);
    rc = acpi_pci_get_host_bridge_windows(t->segment, &got);

    if ( rc != t->rc )
        report("%s: returned %d, want %d\n", t->name, rc, t->rc);

    if ( got.nr != want->nr )
    {
        report("%s: %u windows, want %u\n", t->name, got.nr, want->nr);
        return;
    }

    for ( i = 0; i < want->nr; i++ )
        if ( got.ranges[i].start != want->ranges[i].start ||
             got.ranges[i].end != want->ranges[i].end )
            report("%s: window %u is [%#lx, %#lx], want [%#lx, %#lx]\n",
                   t->name, i, got.ranges[i].start, got.ranges[i].end,
                   want->ranges[i].start, want->ranges[i].end);
}

int main(void)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
        check(&tests[i]);

    printf("%s\n", failures ? "FAIL" : "PASS");

    return failures != 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
