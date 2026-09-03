/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IO Remapping Table (IORT) support
 *
 * Only the parts Xen needs are implemented: translating a PCI requester ID
 * into the DeviceID an ITS sees, or the StreamID an SMMU sees, and finding the
 * SMMUv3 nodes so the driver can be instantiated.  Everything the IORT can
 * describe beyond that, in particular named components and SMMUv2, is ignored.
 */

#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>

#include <asm/iort.h>

static const struct acpi_table_iort *__read_mostly iort_table;

static const struct acpi_iort_node *iort_node_first(void)
{
    return (const struct acpi_iort_node *)((const char *)iort_table +
                                           iort_table->node_offset);
}

static const struct acpi_iort_node *iort_node_next(
    const struct acpi_iort_node *node)
{
    return (const struct acpi_iort_node *)((const char *)node + node->length);
}

/* True when @node lies entirely within the table. */
static bool iort_node_valid(const struct acpi_iort_node *node)
{
    const char *start = (const char *)iort_table;
    const char *end = start + iort_table->header.length;
    const char *p = (const char *)node;

    if ( p < start || p + sizeof(*node) > end )
        return false;

    if ( node->length < sizeof(*node) || p + node->length > end )
        return false;

    /* The mapping array has to be inside the node too. */
    if ( node->mapping_count &&
         ((uint64_t)node->mapping_offset +
          (uint64_t)node->mapping_count * sizeof(struct acpi_iort_id_mapping) >
          node->length) )
        return false;

    return true;
}

#define iort_for_each_node(node)                                        \
    for ( (node) = iort_node_first(); iort_node_valid(node);            \
          (node) = iort_node_next(node) )

void __init iort_init(void)
{
    struct acpi_table_header *table;
    acpi_status status;

    if ( acpi_disabled )
        return;

    status = acpi_get_table(ACPI_SIG_IORT, 0, &table);
    if ( ACPI_FAILURE(status) )
        return;

    if ( table->length < sizeof(struct acpi_table_iort) )
    {
        printk(XENLOG_WARNING "IORT: table too short, ignoring it\n");
        return;
    }

    iort_table = container_of(table, const struct acpi_table_iort, header);

    if ( iort_table->node_offset < sizeof(struct acpi_table_iort) ||
         iort_table->node_offset > table->length )
    {
        printk(XENLOG_WARNING "IORT: bad node offset, ignoring the table\n");
        iort_table = NULL;
        return;
    }

    printk(XENLOG_INFO "IORT: %u nodes\n", iort_table->node_count);
}

/* Resolve an output_reference, which is an offset from the start of the table. */
static const struct acpi_iort_node *iort_node_at_offset(uint32_t offset)
{
    const struct acpi_iort_node *node;

    if ( offset < iort_table->node_offset ||
         offset > iort_table->header.length )
        return NULL;

    node = (const struct acpi_iort_node *)((const char *)iort_table + offset);

    return iort_node_valid(node) ? node : NULL;
}

static const struct acpi_iort_node *iort_find_rc_node(uint16_t segment)
{
    const struct acpi_iort_node *node;

    iort_for_each_node(node)
    {
        const struct acpi_iort_root_complex *rc;

        if ( node->type != ACPI_IORT_NODE_PCI_ROOT_COMPLEX )
            continue;

        if ( node->length < offsetof(struct acpi_iort_node, node_data) +
                            sizeof(*rc) )
            continue;

        rc = (const struct acpi_iort_root_complex *)node->node_data;
        if ( rc->pci_segment_number == segment )
            return node;
    }

    return NULL;
}

/*
 * Push @id through one node's ID mappings.  On success @id is replaced by the
 * translated value and the node it maps to is returned.
 */
static const struct acpi_iort_node *iort_node_map_id(
    const struct acpi_iort_node *node, uint32_t *id)
{
    const struct acpi_iort_id_mapping *map;
    unsigned int i;

    map = (const struct acpi_iort_id_mapping *)((const char *)node +
                                                node->mapping_offset);

    for ( i = 0; i < node->mapping_count; i++, map++ )
    {
        const struct acpi_iort_node *out;

        /*
         * A single mapping ignores the input range entirely and sends every
         * ID to output_base; otherwise the ID has to fall inside the range.
         * id_count is the last offset in the range, not the number of IDs.
         */
        if ( !(map->flags & ACPI_IORT_ID_SINGLE_MAPPING) &&
             (*id < map->input_base ||
              *id > (uint64_t)map->input_base + map->id_count) )
            continue;

        out = iort_node_at_offset(map->output_reference);
        if ( !out )
            continue;

        *id = (map->flags & ACPI_IORT_ID_SINGLE_MAPPING)
              ? map->output_base
              : map->output_base + (*id - map->input_base);

        return out;
    }

    return NULL;
}

int iort_map_rid(uint16_t segment, uint32_t rid, uint8_t target_type,
                 uint32_t *id_out, const struct acpi_iort_node **target)
{
    const struct acpi_iort_node *node;
    unsigned int hops = 0;
    uint32_t id = rid;

    if ( !iort_table )
        return -ENODEV;

    node = iort_find_rc_node(segment);
    if ( !node )
        return -ENODEV;

    /*
     * Walk towards the target.  node_count bounds the number of hops, so a
     * table whose output references form a loop terminates rather than
     * spinning here.
     */
    while ( node && node->type != target_type )
    {
        if ( hops++ > iort_table->node_count )
        {
            printk(XENLOG_WARNING
                   "IORT: mapping loop for segment %u RID %#x\n", segment, rid);
            return -EINVAL;
        }

        node = iort_node_map_id(node, &id);
    }

    if ( !node )
        return -ENODEV;

    *id_out = id;
    if ( target )
        *target = node;

    return 0;
}

int iort_get_msi_base(uint16_t segment, uint32_t rid, paddr_t *base)
{
    const struct acpi_iort_node *node;
    const struct acpi_iort_its_group *its;
    unsigned int i;
    uint32_t devid;
    int rc;

    rc = iort_map_rid(segment, rid, ACPI_IORT_NODE_ITS_GROUP, &devid, &node);
    if ( rc )
        return rc;

    if ( node->length < offsetof(struct acpi_iort_node, node_data) +
                        sizeof(*its) )
        return -EINVAL;

    its = (const struct acpi_iort_its_group *)node->node_data;
    if ( !its->its_count )
        return -ENODEV;

    /*
     * The group names ITSes by identifier; the address lives in the MADT.
     * A group may list several, all of which can serve the device, so take
     * the first one that the MADT actually describes.
     */
    for ( i = 0; i < its->its_count; i++ )
    {
        unsigned int j;

        for ( j = 0; ; j++ )
        {
            const struct acpi_subtable_header *header;
            const struct acpi_madt_generic_translator *madt_its;

            header = acpi_table_get_entry_madt(
                ACPI_MADT_TYPE_GENERIC_TRANSLATOR, j);
            if ( !header )
                break;

            madt_its = container_of(header,
                                    const struct acpi_madt_generic_translator,
                                    header);
            if ( madt_its->translation_id == its->identifiers[i] )
            {
                *base = madt_its->base_address;
                return 0;
            }
        }
    }

    return -ENODEV;
}

int iort_for_each_smmu_v3(int (*cb)(const struct acpi_iort_node *node,
                                    void *arg), void *arg)
{
    const struct acpi_iort_node *node;

    if ( !iort_table )
        return -ENODEV;

    iort_for_each_node(node)
    {
        int rc;

        if ( node->type != ACPI_IORT_NODE_SMMU_V3 )
            continue;

        if ( node->length < offsetof(struct acpi_iort_node, node_data) +
                            sizeof(struct acpi_iort_smmu_v3) )
            continue;

        rc = cb(node, arg);
        if ( rc )
            return rc;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
