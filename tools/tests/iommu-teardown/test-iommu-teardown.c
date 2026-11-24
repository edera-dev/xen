/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for a domain's default IOMMU context at domain teardown, on
 * VT-d and on AMD.  Teardown must return the context's DIDs and free its DID
 * and device-count arrays and its identity maps.  The domain's p2m is torn
 * down after that, and its IOTLB flushes still reach the context, so a flush
 * after teardown must send nothing.  A context that is still in use must be
 * flushed on each IOMMU it has devices behind, under its DID.
 */

#include "harness.h"

#define NR_IOMMUS 2

/* The DID the default context holds on IOMMU i. */
#define DID(i) (5 + (i))

static const char *test_name;

static struct domain dom = { .domain_id = 1 };
struct domain *dom_xen;
bool ats_enabled;

LIST_HEAD(acpi_drhd_units);
LIST_HEAD(amd_iommu_head);

static struct vtd_iommu vtd_iommus[NR_IOMMUS];
static struct acpi_drhd_unit drhds[NR_IOMMUS];
static struct amd_iommu amd_iommus[NR_IOMMUS];

/* Which DIDs each IOMMU has handed out, one bit each. */
static unsigned long dids[NR_IOMMUS];

/* Allocations made for the context and not freed. */
static int live;

/* The flushes sent, and the DID of the last one. */
static unsigned int flushes;
static unsigned int last_did;

static void *alloc(size_t size)
{
    void *p = calloc(1, size);

    assert(p);
    live++;

    return p;
}

void xfree(void *p)
{
    if ( !p )
        return;

    free(p);
    live--;
}

void iommu_free_domid(domid_t domid, unsigned long *map)
{
    if ( domid == UINT16_MAX )
        return;

    assert(*map & (1UL << domid));
    *map &= ~(1UL << domid);
}

unsigned int get_order_from_pages(unsigned long nr_pages)
{
    unsigned int order = 0;

    while ( (1UL << order) < nr_pages )
        order++;

    return order;
}

static void flushed(unsigned int did)
{
    flushes++;
    last_did = did;
}

int iommu_flush_iotlb_dsi(struct vtd_iommu *iommu, u16 did,
                          bool flush_non_present_entry)
{
    flushed(did);

    return 0;
}

int iommu_flush_iotlb_psi(struct vtd_iommu *iommu, u16 did, u64 addr,
                          unsigned int order, bool flush_non_present_entry)
{
    flushed(did);

    return 0;
}

void iommu_flush_write_buffer(struct vtd_iommu *iommu)
{
}

void invalidate_iommu_pages(struct amd_iommu *iommu, u64 io_addr,
                            u16 domain_id, unsigned int order)
{
    flushed(domain_id);
}

void flush_command_buffer(struct amd_iommu *iommu, unsigned int timeout_base)
{
}

void amd_iommu_flush_all_iotlbs(const struct domain *d, daddr_t daddr,
                                unsigned int order)
{
}

/*
 * The default context as context init leaves it: holding DID(i) on IOMMU i,
 * with devs[i] devices behind it (none when devs is NULL) and nr_maps
 * identity maps.
 */
static struct iommu_context *context(bool amd, const unsigned long *devs,
                                     unsigned int nr_maps)
{
    struct iommu_context *ctx = iommu_default_context(&dom);
    domid_t *didmap = alloc(NR_IOMMUS * sizeof(*didmap));
    unsigned long *dev_cnt = alloc(NR_IOMMUS * sizeof(*dev_cnt));
    unsigned int i;

    memset(ctx, 0, sizeof(*ctx));
    INIT_LIST_HEAD(&ctx->arch.identity_maps);

    for ( i = 0; i < NR_IOMMUS; i++ )
    {
        didmap[i] = DID(i);
        dids[i] = 1UL << DID(i);
        dev_cnt[i] = devs ? devs[i] : 0;
    }

    for ( i = 0; i < nr_maps; i++ )
    {
        struct identity_map *map = alloc(sizeof(*map));

        list_add(&map->list, &ctx->arch.identity_maps);
    }

    if ( amd )
    {
        ctx->arch.amd.didmap = didmap;
        ctx->arch.amd.iommu_dev_cnt = dev_cnt;
    }
    else
    {
        ctx->arch.vtd.didmap = didmap;
        ctx->arch.vtd.iommu_dev_cnt = dev_cnt;
    }

    return ctx;
}

/* Everything the context held is back: its DIDs, arrays and identity maps. */
static bool released(const struct iommu_context *ctx, bool amd)
{
    const void *didmap = amd ? (void *)ctx->arch.amd.didmap
                             : (void *)ctx->arch.vtd.didmap;
    const void *dev_cnt = amd ? (void *)ctx->arch.amd.iommu_dev_cnt
                              : (void *)ctx->arch.vtd.iommu_dev_cnt;

    if ( !didmap && !dev_cnt && list_empty(&ctx->arch.identity_maps) &&
         !dids[0] && !dids[1] && !live )
        return true;

    printf("%s: didmap %s, device counts %s, identity maps %s, DIDs %#lx and "
           "%#lx still held, %d allocations not freed\n", test_name,
           didmap ? "kept" : "freed", dev_cnt ? "kept" : "freed",
           list_empty(&ctx->arch.identity_maps) ? "freed" : "kept", dids[0],
           dids[1], live);
    return false;
}

static bool sent(int rc, unsigned int want, unsigned int did)
{
    if ( !rc && flushes == want && (!want || last_did == did) )
        return true;

    printf("%s: rc %d, %u flushes sent, want %u, the last under DID %u\n",
           test_name, rc, flushes, want, last_did);
    return false;
}

static bool test_vtd_teardown(void)
{
    struct iommu_context *ctx = context(false, NULL, 2);

    iommu_domain_teardown(&dom);

    return released(ctx, false);
}

static bool test_vtd_flush_after_teardown(void)
{
    struct iommu_context *ctx = context(false, NULL, 0);
    int rc;

    iommu_domain_teardown(&dom);
    rc = iommu_flush_iotlb(&dom, ctx, _dfn(0x100), 1, IOMMU_FLUSHF_added);
    rc = rc ?: iommu_flush_iotlb(&dom, ctx, INVALID_DFN, 0, IOMMU_FLUSHF_all);

    return sent(rc, 0, 0);
}

static bool test_vtd_flush(void)
{
    static const unsigned long devs[NR_IOMMUS] = { 0, 1 };
    struct iommu_context *ctx = context(false, devs, 0);
    int rc = iommu_flush_iotlb(&dom, ctx, _dfn(0x100), 1, IOMMU_FLUSHF_added);

    return sent(rc, 1, DID(1));
}

static bool test_amd_teardown(void)
{
    struct iommu_context *ctx = context(true, NULL, 2);

    amd_iommu_domain_destroy(&dom);

    return released(ctx, true);
}

static bool test_amd_flush_after_teardown(void)
{
    struct iommu_context *ctx = context(true, NULL, 0);

    amd_iommu_domain_destroy(&dom);
    _amd_iommu_flush_pages(&dom, ctx, 0x100000, 0);

    return sent(0, 0, 0);
}

static bool test_amd_flush(void)
{
    static const unsigned long devs[NR_IOMMUS] = { 0, 1 };
    struct iommu_context *ctx = context(true, devs, 0);

    _amd_iommu_flush_pages(&dom, ctx, 0x100000, 0);

    return sent(0, 1, DID(1));
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "VT-d teardown: the default context's DIDs, arrays and identity maps "
      "freed", test_vtd_teardown },
    { "VT-d flush after teardown: nothing sent", test_vtd_flush_after_teardown },
    { "VT-d flush of a live context: sent to the IOMMU with devices, under "
      "its DID", test_vtd_flush },
    { "AMD teardown: the default context's DIDs, arrays and identity maps "
      "freed", test_amd_teardown },
    { "AMD flush after teardown: nothing sent", test_amd_flush_after_teardown },
    { "AMD flush of a live context: sent to the IOMMU with devices, under "
      "its DID", test_amd_flush },
};

int main(void)
{
    unsigned int i, j, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        INIT_LIST_HEAD(&acpi_drhd_units);
        INIT_LIST_HEAD(&amd_iommu_head);
        for ( j = 0; j < NR_IOMMUS; j++ )
        {
            vtd_iommus[j] = (struct vtd_iommu){
                .index = j, .domid_bitmap = &dids[j],
            };
            drhds[j].iommu = &vtd_iommus[j];
            list_add_tail(&drhds[j].list, &acpi_drhd_units);

            amd_iommus[j].index = j;
            amd_iommus[j].domid_map = &dids[j];
            list_add_tail(&amd_iommus[j].list, &amd_iommu_head);
        }
        live = 0;
        flushes = 0;
        last_did = 0;

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
