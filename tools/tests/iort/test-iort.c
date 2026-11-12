/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for the IORT parser: translating a PCI requester ID through the
 * table, and the table built for the hardware domain.
 *
 * Most tables are built here from Xen's ACPICA structures; the IORTs of real
 * platforms are kept as their firmware gives them.  The parser reads each
 * table from the end of a page that is followed by one that cannot be
 * touched, and the hardware domain's table is built in such a buffer too, so
 * a read past a table, or a write past the size the parser asked for, stops
 * the test.
 */

#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "harness.h"

/* Included, not linked, so that load_iort() can drop the previous table. */
#include "iort.c"

/* The IORTs of real platforms, as their firmware gives them. */
#include "graviton3.h"

/* QEMU virt's SMMUv3 and ITS, and a second ITS beside it. */
#define SMMU_V3_BASE 0x09050000
#define ITS_BASE     0x08080000
#define ITS_7_BASE   0x080a0000

/* The table being built: the IORT header, then each node in turn. */
static uint8_t table[1024];
static uint32_t table_len;

static struct acpi_table_iort *table_iort(void)
{
    return (struct acpi_table_iort *)table;
}

static void table_start(void)
{
    memset(table, 0, sizeof(table));
    table_len = sizeof(struct acpi_table_iort);
    memcpy(table_iort()->header.signature, ACPI_SIG_IORT, ACPI_NAME_SIZE);
    table_iort()->header.length = table_len;
    table_iort()->node_offset = table_len;
}

/* The offset the next node will have, for a mapping that refers to it. */
static uint32_t next_node(void)
{
    return table_len;
}

/*
 * Append a node with @data as its node data, followed by the @nr_maps
 * mappings at @maps.  Returns its offset, which is how the mappings of other
 * nodes refer to it.
 */
static uint32_t add_node(uint8_t type, const void *data, size_t data_len,
                         const struct acpi_iort_id_mapping *maps,
                         unsigned int nr_maps)
{
    struct acpi_iort_node *node = (struct acpi_iort_node *)(table + table_len);
    size_t head = offsetof(struct acpi_iort_node, node_data);
    size_t maps_len = nr_maps * sizeof(*maps);
    uint32_t offset = table_len;

    if ( table_len + head + data_len + maps_len > sizeof(table) )
    {
        fprintf(stderr, "the table does not fit in %zu bytes\n", sizeof(table));
        exit(1);
    }

    node->type = type;
    node->mapping_count = nr_maps;
    node->mapping_offset = head + data_len;
    node->length = head + data_len + maps_len;
    memcpy(node->node_data, data, data_len);
    if ( nr_maps )
        memcpy((uint8_t *)node + node->mapping_offset, maps, maps_len);

    table_len += node->length;
    table_iort()->header.length = table_len;
    table_iort()->node_count++;

    return offset;
}

/* An array, and how many elements it has, as two arguments. */
#define MAPS(...)                                                       \
    (const struct acpi_iort_id_mapping[]){ __VA_ARGS__ },               \
    ARRAY_SIZE(((const struct acpi_iort_id_mapping[]){ __VA_ARGS__ }))
#define IDS(...)                                                        \
    (const uint32_t[]){ __VA_ARGS__ },                                  \
    ARRAY_SIZE(((const uint32_t[]){ __VA_ARGS__ }))
#define NO_MAPS NULL, 0

/* A mapping of @ids IDs from @in to @out, on the node at offset @ref. */
static struct acpi_iort_id_mapping map(uint32_t in, uint32_t ids, uint32_t out,
                                       uint32_t ref)
{
    /* id_count is the number of IDs less one: the offset of the last. */
    return (struct acpi_iort_id_mapping){
        .input_base = in,
        .id_count = ids - 1,
        .output_base = out,
        .output_reference = ref,
    };
}

/* A single mapping of @ids IDs from @in: each of them goes to @out. */
static struct acpi_iort_id_mapping single_map(uint32_t in, uint32_t ids,
                                              uint32_t out, uint32_t ref)
{
    struct acpi_iort_id_mapping single = map(in, ids, out, ref);

    single.flags = ACPI_IORT_ID_SINGLE_MAPPING;

    return single;
}

/* An ITS group of the @nr_ids ITS identifiers at @ids. */
static uint32_t add_its_group(const uint32_t *ids, unsigned int nr_ids)
{
    uint32_t data[1 + 8];

    if ( nr_ids > ARRAY_SIZE(data) - 1 )
    {
        fprintf(stderr, "an ITS group of %u ITSes is more than %zu\n", nr_ids,
                ARRAY_SIZE(data) - 1);
        exit(1);
    }

    data[0] = nr_ids;
    memcpy(&data[1], ids, nr_ids * sizeof(*ids));

    return add_node(ACPI_IORT_NODE_ITS_GROUP, data,
                    (1 + nr_ids) * sizeof(*data), NO_MAPS);
}

static uint32_t add_smmu_v3(const struct acpi_iort_id_mapping *maps,
                            unsigned int nr_maps)
{
    const struct acpi_iort_smmu_v3 smmu = { .base_address = SMMU_V3_BASE };

    return add_node(ACPI_IORT_NODE_SMMU_V3, &smmu, sizeof(smmu), maps,
                    nr_maps);
}

static uint32_t add_root_complex(uint16_t segment,
                                 const struct acpi_iort_id_mapping *maps,
                                 unsigned int nr_maps)
{
    const struct acpi_iort_root_complex rc = { .pci_segment_number = segment };

    return add_node(ACPI_IORT_NODE_PCI_ROOT_COMPLEX, &rc, sizeof(rc), maps,
                    nr_maps);
}

/*
 * Two pages, each followed by one that cannot be touched: one for the
 * firmware's IORT, and one for the hardware domain's.
 */
static size_t page_size;
static uint8_t *firmware_page, *hwdom_page;

static uint8_t *guarded_page(void)
{
    uint8_t *p = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if ( p == MAP_FAILED || mprotect(p + page_size, page_size, PROT_NONE) )
    {
        perror("guard page");
        exit(1);
    }

    return p;
}

/* The last @size bytes of @page, which end where its guard page begins. */
static void *page_end(uint8_t *page, size_t size)
{
    if ( size > page_size )
    {
        fprintf(stderr, "a %zu-byte table does not fit in a page\n", size);
        exit(1);
    }

    return page + page_size - size;
}

static struct acpi_table_header *firmware_iort;

acpi_status acpi_get_table(const char *signature, u32 instance,
                           struct acpi_table_header **out_table)
{
    if ( strcmp(signature, ACPI_SIG_IORT) || instance || !firmware_iort )
        return AE_NOT_FOUND;

    *out_table = firmware_iort;

    return AE_OK;
}

/*
 * Make the @len bytes at @iort the firmware's IORT, and have the parser take
 * it.  iort_init() keeps the previous table when it refuses a new one, which
 * Xen, loading one table, never sees; drop it so that no case runs against
 * the table of the one before.
 */
static void load_iort(const void *iort, uint32_t len)
{
    firmware_iort = memcpy(page_end(firmware_page, len), iort, len);
    iort_table = NULL;
    iort_init();
}

/* The MADT describes ITS 7, then ITS 4. */
#define MADT_ITS(id, base) {                                            \
    .header = {                                                         \
        .type = ACPI_MADT_TYPE_GENERIC_TRANSLATOR,                      \
        .length = sizeof(struct acpi_madt_generic_translator),          \
    },                                                                  \
    .translation_id = (id),                                             \
    .base_address = (base),                                             \
}

static struct acpi_madt_generic_translator madt_its[] = {
    MADT_ITS(7, ITS_7_BASE),
    MADT_ITS(4, ITS_BASE),
};

struct acpi_subtable_header *acpi_table_get_entry_madt(enum acpi_madt_type id,
                                                       unsigned int entry_id)
{
    if ( id != ACPI_MADT_TYPE_GENERIC_TRANSLATOR ||
         entry_id >= ARRAY_SIZE(madt_its) )
        return NULL;

    return &madt_its[entry_id].header;
}

/* The case being run, for the messages about it. */
static const char *test_name;

static bool expect_rid(uint16_t segment, uint32_t rid, uint8_t target_type,
                       int want_rc, uint32_t want_id)
{
    uint32_t id = 0;
    int rc = iort_map_rid(segment, rid, target_type, &id, NULL);

    if ( rc != want_rc || (!rc && id != want_id) )
    {
        printf("%s: RID %#x on segment %u gives %#x and %d, want %#x and %d\n",
               test_name, rid, segment, id, rc, want_id, want_rc);
        return false;
    }

    return true;
}

/* That RID on @segment reaches the ITS group of ITS @want_its as @want_id. */
static bool expect_its(uint16_t segment, uint32_t rid, uint32_t want_id,
                       uint32_t want_its)
{
    const struct acpi_iort_its_group *group;
    const struct acpi_iort_node *node;
    uint32_t id = 0;
    int rc;

    rc = iort_map_rid(segment, rid, ACPI_IORT_NODE_ITS_GROUP, &id, &node);
    if ( rc )
    {
        printf("%s: RID %#x on segment %u returned %d\n", test_name, rid,
               segment, rc);
        return false;
    }

    group = (const struct acpi_iort_its_group *)node->node_data;
    if ( id != want_id || group->identifiers[0] != want_its )
    {
        printf("%s: RID %#x, segment %u: %#x on ITS %u, want %#x on ITS %u\n",
               test_name, rid, segment, id, group->identifiers[0], want_id,
               want_its);
        return false;
    }

    return true;
}

/*
 * Build the hardware domain's IORT from the loaded one, in a buffer of the
 * size the parser asks for.
 */
static int make_hwdom_iort(void **iort, uint32_t *len)
{
    uint32_t size;
    int rc;

    rc = iort_hwdom_size(&size);
    if ( rc )
        return rc;

    *iort = page_end(hwdom_page, size);

    return iort_make_hwdom_table(*iort, size, len);
}

/*
 * Build the hardware domain's IORT from the loaded one, and load it in its
 * place.  It keeps only the ITS groups and the root complexes: @want_nodes
 * nodes, as its header counts them and as a walk finds them, none of them an
 * SMMUv3.
 */
static bool load_hwdom_iort(unsigned int want_nodes)
{
    const struct acpi_iort_node *node;
    unsigned int walked = 0, smmus = 0;
    uint32_t len;
    void *hwdom;
    int rc;

    rc = make_hwdom_iort(&hwdom, &len);
    if ( rc )
    {
        printf("%s: building the hardware domain's IORT returned %d\n",
               test_name, rc);
        return false;
    }

    load_iort(hwdom, len);
    if ( !iort_table )
    {
        printf("%s: the parser refused the hardware domain's IORT\n",
               test_name);
        return false;
    }

    /* The walk stops at the first node that does not fit in the table. */
    iort_for_each_node(node)
    {
        walked++;
        if ( node->type == ACPI_IORT_NODE_SMMU_V3 )
            smmus++;
    }

    if ( iort_table->node_count != want_nodes || walked != want_nodes )
    {
        printf("%s: the hardware domain's IORT counts %u nodes, and a walk "
               "finds %u, want %u\n", test_name, iort_table->node_count,
               walked, want_nodes);
        return false;
    }

    if ( smmus )
    {
        printf("%s: the hardware domain's IORT has %u SMMUv3 nodes, want "
               "none\n", test_name, smmus);
        return false;
    }

    return true;
}

/*
 * An SMMUv3 between the root complex and the ITS, as on QEMU virt with
 * iommu=smmuv3.  Each mapping moves the IDs, so that a hop missed or taken
 * twice shows: RID r is StreamID 0x10000 + r and DeviceID 0x20000 + r.
 */
static void build_smmu_between(void)
{
    uint32_t its, smmu;

    table_start();
    its = add_its_group(IDS(0));
    smmu = add_smmu_v3(MAPS(map(0x10000, 0x10000, 0x20000, its)));
    add_root_complex(0, MAPS(map(0, 0x10000, 0x10000, smmu)));
}

static bool test_rid_through_smmu(void)
{
    bool pass = true;

    build_smmu_between();
    load_iort(table, table_len);

    pass &= expect_rid(0, 0x10, ACPI_IORT_NODE_SMMU_V3, 0, 0x10010);
    pass &= expect_rid(0, 0x10, ACPI_IORT_NODE_ITS_GROUP, 0, 0x20010);
    pass &= expect_rid(0, 0xffff, ACPI_IORT_NODE_ITS_GROUP, 0, 0x2ffff);
    pass &= expect_rid(0, 0x10000, ACPI_IORT_NODE_ITS_GROUP, -ENODEV, 0);

    return pass;
}

static bool test_hwdom_same_device_ids(void)
{
    bool pass = true;

    build_smmu_between();
    load_iort(table, table_len);

    if ( !load_hwdom_iort(2) )
        return false;

    pass &= expect_rid(0, 0, ACPI_IORT_NODE_ITS_GROUP, 0, 0x20000);
    pass &= expect_rid(0, 0x10, ACPI_IORT_NODE_ITS_GROUP, 0, 0x20010);
    pass &= expect_rid(0, 0xffff, ACPI_IORT_NODE_ITS_GROUP, 0, 0x2ffff);

    return pass;
}

/*
 * The SMMU sends the two halves of the root complex's range to DeviceIDs far
 * apart, which one mapping from the root complex cannot express.
 */
static bool test_hwdom_split_range(void)
{
    uint32_t its, smmu, len;
    void *hwdom;
    int rc;

    table_start();
    its = add_its_group(IDS(0));
    smmu = add_smmu_v3(MAPS(map(0, 0x8000, 0, its),
                            map(0x8000, 0x8000, 0x100000, its)));
    add_root_complex(0, MAPS(map(0, 0x10000, 0, smmu)));
    load_iort(table, table_len);

    rc = make_hwdom_iort(&hwdom, &len);
    if ( rc != -ENXIO )
    {
        printf("%s: building it returned %d, want %d\n", test_name, rc,
               -ENXIO);
        return false;
    }

    return true;
}

/*
 * The SMMU sends only the middle of the root complex's range elsewhere, so the
 * first and last IDs are still 0xffff DeviceIDs apart, as if contiguous.
 */
static bool test_hwdom_split_middle(void)
{
    uint32_t its, smmu, len;
    void *hwdom;
    int rc;

    table_start();
    its = add_its_group(IDS(0));
    smmu = add_smmu_v3(MAPS(map(0, 0x4000, 0, its),
                            map(0x4000, 0x8000, 0x100000, its),
                            map(0xc000, 0x4000, 0xc000, its)));
    add_root_complex(0, MAPS(map(0, 0x10000, 0, smmu)));
    load_iort(table, table_len);

    rc = make_hwdom_iort(&hwdom, &len);
    if ( rc != -ENXIO )
    {
        printf("%s: building it returned %d, want %d\n", test_name, rc,
               -ENXIO);
        return false;
    }

    return true;
}

/*
 * QEMU virt with iommu=smmuv3 gives the root complex's first mapping an
 * id_count one too large, so it ends on 0x100, the first ID of the mapping
 * that bypasses the SMMU.  The two lead to different DeviceIDs, so that
 * taking the wrong one for 0x100 shows.  The SMMU splits its IDs at 0x100,
 * so the hardware domain's IORT can be built only if the first mapping gives
 * 0x100 up.  A mapping of one ID, on segment 1, has nothing to give up.
 */
static bool test_id_count_one_too_many(void)
{
    uint32_t its, smmu;
    bool pass = true;

    table_start();
    its = add_its_group(IDS(0));
    smmu = add_smmu_v3(MAPS(map(0, 0x100, 0x20000, its),
                            map(0x100, 0xff00, 0x40100, its)));
    add_root_complex(0, MAPS(map(0, 0x101, 0, smmu),
                             map(0x100, 0xff00, 0x30100, its)));
    add_root_complex(1, MAPS(map(0x10, 0x1, 0x50010, its)));
    load_iort(table, table_len);

    pass &= expect_rid(0, 0x100, ACPI_IORT_NODE_ITS_GROUP, 0, 0x30100);

    if ( !load_hwdom_iort(3) )
        return false;

    pass &= expect_rid(0, 0xff, ACPI_IORT_NODE_ITS_GROUP, 0, 0x200ff);
    pass &= expect_rid(0, 0x100, ACPI_IORT_NODE_ITS_GROUP, 0, 0x30100);
    pass &= expect_rid(1, 0x10, ACPI_IORT_NODE_ITS_GROUP, 0, 0x50010);

    return pass;
}

/*
 * An ID that two mappings claim, as in Linux.  A later range takes it from
 * one that ends on it only by starting on it, and a range of one ID ends
 * where it starts.  A single mapping takes any ID it is reached with, both
 * from the range that ends on it (segment 1) and on its own range's last ID
 * (segment 2).
 */
static bool test_id_claimed_twice(void)
{
    bool pass = true;
    uint32_t its;

    table_start();
    its = add_its_group(IDS(0));
    add_root_complex(0, MAPS(map(0x000, 0x101, 0x10000, its),
                             map(0x080, 0x100, 0x20080, its),
                             map(0x200, 0x1, 0x30200, its),
                             map(0x200, 0x100, 0x40200, its)));
    add_root_complex(1, MAPS(map(0x000, 0x101, 0x10000, its),
                             single_map(0, 0x1, 0x50000, its)));
    add_root_complex(2, MAPS(single_map(0x300, 0x11, 0x60000, its),
                             map(0x310, 0x10, 0x70310, its)));
    load_iort(table, table_len);

    pass &= expect_rid(0, 0x100, ACPI_IORT_NODE_ITS_GROUP, 0, 0x10100);
    pass &= expect_rid(0, 0x200, ACPI_IORT_NODE_ITS_GROUP, 0, 0x30200);
    pass &= expect_rid(1, 0x100, ACPI_IORT_NODE_ITS_GROUP, 0, 0x50000);
    pass &= expect_rid(2, 0x310, ACPI_IORT_NODE_ITS_GROUP, 0, 0x60000);

    return pass;
}

/* Two ITS groups, one for each segment. */
static bool test_hwdom_two_its_groups(void)
{
    uint32_t its_a, its_b;
    bool pass = true;

    table_start();
    its_a = add_its_group(IDS(0));
    its_b = add_its_group(IDS(1));
    add_root_complex(0, MAPS(map(0, 0x10000, 0, its_a)));
    add_root_complex(1, MAPS(map(0, 0x10000, 0x10000, its_b)));
    load_iort(table, table_len);

    if ( !load_hwdom_iort(4) )
        return false;

    pass &= expect_its(0, 0x10, 0x10, 0);
    pass &= expect_its(1, 0x10, 0x10010, 1);

    return pass;
}

/* An SMMU that maps IDs to itself. */
static bool test_mapping_loop(void)
{
    uint32_t smmu;

    table_start();
    add_its_group(IDS(0));
    smmu = next_node();
    add_smmu_v3(MAPS(map(0, 0x10000, 0, smmu)));
    add_root_complex(0, MAPS(map(0, 0x10000, 0, smmu)));
    load_iort(table, table_len);

    return expect_rid(0, 0x10, ACPI_IORT_NODE_ITS_GROUP, -EINVAL, 0);
}

/*
 * A root complex, last in the table, with no mappings and a mapping offset
 * past the end of the table.  The hardware domain's table copies a root
 * complex up to its mapping offset, so the node must not be walked.
 */
static bool test_mapping_offset_past_table(void)
{
    uint32_t rc_node;

    table_start();
    add_its_group(IDS(0));
    rc_node = add_root_complex(0, NO_MAPS);
    ((struct acpi_iort_node *)(table + rc_node))->mapping_offset = 0x1000;
    load_iort(table, table_len);

    return load_hwdom_iort(1);
}

/*
 * The group lists ITS 3, 4 and 7, and the MADT describes 7 and then 4: the
 * base is ITS 4's, not that of the MADT's first ITS or the group's last.
 */
static bool test_msi_base(void)
{
    paddr_t base = 0;
    uint32_t its;
    int rc;

    table_start();
    its = add_its_group(IDS(3, 4, 7));
    add_root_complex(0, MAPS(map(0, 0x10000, 0, its)));
    load_iort(table, table_len);

    rc = iort_get_msi_base(0, 0x10, &base);
    if ( rc || base != ITS_BASE )
    {
        printf("%s: returned %d and %#" PRIx64 ", want 0 and %#x\n",
               test_name, rc, base, ITS_BASE);
        return false;
    }

    return true;
}

/*
 * The @len bytes at @iort are the IORT of a real platform, whose root complex
 * on @segment gives RIDs 0 to 0xffff the DeviceIDs from @devid on ITS @its.
 * The hardware domain's IORT keeps only the ITS group and the root complex,
 * gives the RIDs the same DeviceIDs, and keeps the root complex's revision
 * and node data, which Linux reads its DMA limit and ATS support from.
 */
static bool expect_platform(const uint8_t *iort, size_t len, uint16_t segment,
                            uint32_t devid, uint32_t its)
{
    const struct acpi_iort_node *fw, *hw;
    bool pass = true;

    load_iort(iort, len);

    fw = iort_table ? iort_find_rc_node(segment) : NULL;
    if ( !fw )
    {
        printf("%s: the firmware's IORT has no root complex for segment %u\n",
               test_name, segment);
        return false;
    }

    /* The same node in @iort, as loading another table replaces this copy. */
    fw = (const void *)(iort + ((const uint8_t *)fw -
                                (const uint8_t *)firmware_iort));

    if ( !load_hwdom_iort(2) )
        return false;

    hw = iort_find_rc_node(segment);
    if ( !hw || hw->revision != fw->revision ||
         hw->mapping_offset != fw->mapping_offset ||
         memcmp(hw->node_data, fw->node_data,
                fw->mapping_offset - offsetof(struct acpi_iort_node,
                                              node_data)) )
    {
        printf("%s: the hardware domain's root complex differs from the "
               "firmware's ahead of its mappings\n", test_name);
        pass = false;
    }

    pass &= expect_its(segment, 0, devid, its);
    pass &= expect_its(segment, 0xffff, devid + 0xffff, its);

    return pass;
}

static bool test_graviton3(void)
{
    return expect_platform(graviton3_iort, sizeof(graviton3_iort), 1, 0, 1);
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "RID through an SMMUv3 to the ITS", test_rid_through_smmu },
    { "hardware domain's IORT: no SMMUv3, same DeviceIDs",
      test_hwdom_same_device_ids },
    { "hardware domain's IORT: a range split apart cannot be expressed",
      test_hwdom_split_range },
    { "hardware domain's IORT: nor one split only in the middle",
      test_hwdom_split_middle },
    { "an id_count one too large: the range starting on the ID takes it",
      test_id_count_one_too_many },
    { "an ID that two mappings claim", test_id_claimed_twice },
    { "hardware domain's IORT: each segment keeps its ITS group",
      test_hwdom_two_its_groups },
    { "a mapping loop ends", test_mapping_loop },
    { "root complex with its mapping offset past the table",
      test_mapping_offset_past_table },
    { "MSI base from the first ITS that the MADT describes", test_msi_base },
    { "Graviton3's IORT, and the hardware domain's", test_graviton3 },
};

int main(void)
{
    unsigned int i, failed = 0;

    /* A walk that never ends stops the test here, not at the CI timeout. */
    alarm(10);

    page_size = sysconf(_SC_PAGESIZE);
    firmware_page = guarded_page();
    hwdom_page = guarded_page();

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        /* Named first, so that a fault shows which test it was. */
        test_name = tests[i].name;
        printf("%s\n", test_name);
        fflush(stdout);

        if ( !tests[i].run() )
            failed++;
    }

    printf("%s\n", failed ? "FAIL" : "PASS");

    return failed != 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
