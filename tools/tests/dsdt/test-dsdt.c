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

struct window {
    unsigned long start, end;
};

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

static const struct test {
    const char *name;
    const void *table;
    size_t size;
    uint16_t segment;
    int rc;
    struct window windows[2];
} tests[] = {
    {
        "QEMU virt: the bridge's two memory windows",
        virt, sizeof(virt), 0, 0,
        { { 0x10000000, 0x3efeffff }, { 0x8000000000, 0xffffffffff } },
    },
    {
        "no _SEG is segment 0",
        bridges, sizeof(bridges), 0, 0, { { 0x10000000, 0x1fffffff } },
    },
    {
        "_SEG of One",
        bridges, sizeof(bridges), 1, 0, { { 0x60000000, 0x6fffffff } },
    },
    {
        "_SEG in a byte",
        bridges, sizeof(bridges), 2, 0, { { 0x20000000, 0x2fffffff } },
    },
    {
        "_SEG in a word",
        bridges, sizeof(bridges), 0x100, 0, { { 0x80000000, 0x8fffffff } },
    },
    {
        "host bridge by _CID",
        bridges, sizeof(bridges), 3, 0, { { 0x30000000, 0x3fffffff } },
    },
    {
        "EisaId _HID",
        bridges, sizeof(bridges), 5, 0, { { 0x50000000, 0x5fffffff } },
    },
    {
        "_CRS from a Method",
        bridges, sizeof(bridges), 4, -ENODEV,
    },
    {
        "string _HID cut by the end of the table",
        &cut_hid, sizeof(cut_hid), 0, -ENODEV,
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
    struct rangeset windows = { 0 };
    unsigned int i, nr = 0;
    int rc;

    /* Named first, so that a read past the table's end shows which test. */
    printf("%s\n", t->name);
    fflush(stdout);

    load_dsdt(t->table, t->size);
    rc = acpi_pci_get_host_bridge_windows(t->segment, &windows);

    while ( nr < ARRAY_SIZE(t->windows) && t->windows[nr].end )
        nr++;

    if ( rc != t->rc )
        report("%s: returned %d, want %d\n", t->name, rc, t->rc);

    if ( windows.nr != nr )
    {
        report("%s: %u windows, want %u\n", t->name, windows.nr, nr);
        return;
    }

    for ( i = 0; i < nr; i++ )
        if ( windows.ranges[i].start != t->windows[i].start ||
             windows.ranges[i].end != t->windows[i].end )
            report("%s: window %u is [%#lx, %#lx], want [%#lx, %#lx]\n",
                   t->name, i, windows.ranges[i].start, windows.ranges[i].end,
                   t->windows[i].start, t->windows[i].end);
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
