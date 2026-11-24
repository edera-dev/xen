/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for a domain's default IOMMU context on VT-d and on AMD, from
 * context init to domain teardown.  Each case sets the context up with the
 * driver's own init, failing it at one step when the case asks, and then
 * tears the domain down.  Teardown must leave nothing behind: no
 * allocation, page-table page, DID, identity map or root, whether the init
 * failed, the domain's resources were relinquished first, or they were not
 * because the domain's creation failed after the context was set up.  The
 * p2m is torn down after that and its IOTLB flushes still reach the
 * context, so a flush after teardown must send nothing, while a context in
 * use must be flushed on each IOMMU it has devices behind, under its DID.
 */

#include "harness.h"

#define NR_IOMMUS 2

/* Where the p2m's page tables start, for a context that shares them. */
#define P2M_ROOT   0x1000
/* Where a context's own root table is. */
#define ROOT_MADDR 0x2000

static const char *test_name;

static struct domain dom;
struct domain *dom_xen;
bool ats_enabled;

LIST_HEAD(acpi_drhd_units);
LIST_HEAD(amd_iommu_head);

unsigned int nr_iommus = NR_IOMMUS;
unsigned int min_pt_levels = 3;
unsigned int nr_amd_iommus = NR_IOMMUS;
unsigned int amd_iommu_guest_pt_levels;
int amd_iommu_min_paging_mode = 1;

static struct vtd_iommu vtd_iommus[NR_IOMMUS];
static struct acpi_drhd_unit drhds[NR_IOMMUS];
static struct amd_iommu amd_iommus[NR_IOMMUS];

/* Which DIDs each IOMMU has handed out, one bit each. */
static unsigned long dids[NR_IOMMUS];

/* Whether the case is for AMD rather than VT-d. */
static bool amd;

/*
 * Allocations still live, so that one freed twice, or never, shows.  The
 * allocations made by the code under test are numbered from 1, and the one
 * numbered fail_at fails.
 */
#define MAX_LIVE 16
static void *live[MAX_LIVE];
static unsigned int nr_allocs, fail_at;

/* Page-table pages the context holds. */
static unsigned int pgtables;

/* The flushes sent, and the DID of the last one. */
static unsigned int flushes;
static unsigned int last_did;

static bool fails_now(void)
{
    return ++nr_allocs == fail_at;
}

void *test_alloc(size_t size)
{
    unsigned int i;
    void *p;

    if ( fails_now() )
        return NULL;

    p = calloc(1, size);
    assert(p);

    for ( i = 0; i < MAX_LIVE && live[i]; i++ )
        ;
    assert(i < MAX_LIVE);
    live[i] = p;

    return p;
}

void xfree(void *p)
{
    unsigned int i;

    if ( !p )
        return;

    /* Not allocated, or freed already. */
    for ( i = 0; i < MAX_LIVE && live[i] != p; i++ )
        ;
    assert(i < MAX_LIVE);
    live[i] = NULL;

    free(p);
}

static unsigned int allocated(void)
{
    unsigned int i, n = 0;

    for ( i = 0; i < MAX_LIVE; i++ )
        n += !!live[i];

    return n;
}

domid_t iommu_alloc_domid(unsigned long *map, unsigned int nr)
{
    unsigned int i;

    for ( i = 0; i < nr && i < sizeof(*map) * 8; i++ )
        if ( !(*map & (1UL << i)) )
        {
            *map |= 1UL << i;
            return i;
        }

    return UINT16_MAX;
}

void iommu_free_domid(domid_t domid, unsigned long *map)
{
    if ( domid == UINT16_MAX )
        return;

    assert(*map & (1UL << domid));
    *map &= ~(1UL << domid);
}

struct page_info *iommu_alloc_pgtable(struct domain_iommu *hd,
                                      struct iommu_context *ctx,
                                      uint64_t contig_mask)
{
    static char page;

    if ( fails_now() )
        return NULL;

    pgtables++;

    return (struct page_info *)&page;
}

/* Allocates the root table, which is all that context init asks of it. */
uint64_t addr_to_dma_page_maddr(struct domain *domain,
                                struct iommu_context *ctx, daddr_t addr,
                                unsigned int target,
                                unsigned int *flush_flags, bool alloc)
{
    assert(alloc && !ctx->arch.vtd.pgd_maddr);

    /* As Xen's: the level it failed at, below PAGE_SIZE. */
    if ( fails_now() )
        return target + 1;

    pgtables++;
    ctx->arch.vtd.pgd_maddr = ROOT_MADDR;

    return ROOT_MADDR;
}

/* As Xen's: clear the root, then free every page-table page. */
int iommu_free_pgtables(struct domain *d, struct iommu_context *ctx)
{
    if ( amd )
        ctx->arch.amd.root_table = NULL;
    else
        ctx->arch.vtd.pgd_maddr = 0;

    pgtables = 0;

    return 0;
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

static struct iommu_context *ctx(void)
{
    return iommu_default_context(&dom);
}

static domid_t *didmap(void)
{
    return amd ? ctx()->arch.amd.didmap : ctx()->arch.vtd.didmap;
}

static unsigned long *dev_cnt(void)
{
    return amd ? ctx()->arch.amd.iommu_dev_cnt : ctx()->arch.vtd.iommu_dev_cnt;
}

static bool has_root(void)
{
    return amd ? !!ctx()->arch.amd.root_table : !!ctx()->arch.vtd.pgd_maddr;
}

/* The domain's default context set up as iommu_domain_init() does it. */
static int init(void)
{
    return amd ? amd_iommu_context_init(&dom, ctx(), IOMMU_CONTEXT_INIT_default)
               : intel_iommu_context_init(&dom, ctx(),
                                          IOMMU_CONTEXT_INIT_default);
}

static void teardown(void)
{
    if ( amd )
        amd_iommu_domain_destroy(&dom);
    else
        iommu_domain_teardown(&dom);
}

/*
 * Nothing the context held is left: no allocation, page-table page or root,
 * and every DID it took is back.  owned[i] is what IOMMU i had handed out
 * to others before the case began.
 */
static bool released(const unsigned long *owned)
{
    if ( !didmap() && !dev_cnt() && !has_root() && !pgtables &&
         !allocated() && dids[0] == owned[0] && dids[1] == owned[1] )
        return true;

    printf("%s: didmap %s, device counts %s, root %s, %u page-table pages "
           "and %u allocations left, DIDs %#lx and %#lx held, want %#lx "
           "and %#lx\n", test_name, didmap() ? "kept" : "freed",
           dev_cnt() ? "kept" : "freed", has_root() ? "kept" : "cleared",
           pgtables, allocated(), dids[0], dids[1], owned[0], owned[1]);
    return false;
}

/* Teardown after init failed at allocation number at, or succeeded. */
static bool init_then_teardown(unsigned int at, int want)
{
    static const unsigned long none[NR_IOMMUS];
    int rc;

    fail_at = at;
    rc = init();
    fail_at = 0;

    if ( rc != want )
    {
        printf("%s: init returned %d, want %d\n", test_name, rc, want);
        return false;
    }

    teardown();

    return released(none);
}

static bool test_relinquished(void)
{
    static const unsigned long none[NR_IOMMUS];
    unsigned int i;

    if ( init() )
        return false;

    /* Two identity maps, as RMRRs leave behind. */
    for ( i = 0; i < 2; i++ )
    {
        struct identity_map *map = test_alloc(sizeof(*map));

        list_add(&map->list, &ctx()->arch.identity_maps);
    }

    /* As domain_relinquish_resources() does. */
    if ( iommu_free_pgtables(&dom, ctx()) )
        return false;

    teardown();

    return released(none) && list_empty(&ctx()->arch.identity_maps);
}

static bool test_creation_failed(void)
{
    return init_then_teardown(0, 0);
}

static bool test_didmap_fails(void)
{
    return init_then_teardown(1, -ENOMEM);
}

static bool test_dev_cnt_fails(void)
{
    return init_then_teardown(2, -ENOMEM);
}

static bool test_root_fails(void)
{
    return init_then_teardown(3, -ENOMEM);
}

static bool test_no_did(void)
{
    static const unsigned long owned[NR_IOMMUS] = { 0, ~0UL };
    int rc;

    dids[1] = owned[1];
    rc = init();
    if ( rc != -ENOSPC )
    {
        printf("%s: init returned %d, want %d\n", test_name, rc, -ENOSPC);
        return false;
    }

    teardown();

    return released(owned);
}

static bool test_shared_no_did(void)
{
    dom.hap_pt_share = true;

    return test_no_did();
}

static bool test_shared_creation_failed(void)
{
    dom.hap_pt_share = true;

    return test_creation_failed();
}

static bool sent(int rc, unsigned int want, unsigned int did)
{
    if ( !rc && flushes == want && (!want || last_did == did) )
        return true;

    printf("%s: rc %d, %u flushes sent, want %u, the last under DID %u\n",
           test_name, rc, flushes, want, last_did);
    return false;
}

static int flush(void)
{
    if ( amd )
    {
        _amd_iommu_flush_pages(&dom, ctx(), 0x100000, 0);
        return 0;
    }

    return iommu_flush_iotlb(&dom, ctx(), _dfn(0x100), 1, IOMMU_FLUSHF_added) ?:
           iommu_flush_iotlb(&dom, ctx(), INVALID_DFN, 0, IOMMU_FLUSHF_all);
}

static bool test_flush_after_teardown(void)
{
    int rc;

    if ( init() || iommu_free_pgtables(&dom, ctx()) )
        return false;

    teardown();
    rc = flush();

    return sent(rc, 0, 0);
}

static bool test_flush(void)
{
    unsigned int did;

    if ( init() )
        return false;

    /* A device behind the second IOMMU. */
    dev_cnt()[1] = 1;
    did = didmap()[1];

    return sent(flush(), amd ? 1 : 2, did);
}

static const struct {
    const char *name;
    bool (*run)(void);
    bool amd;
} tests[] = {
#define BOTH(name, fn)                       \
    { "VT-d: " name, fn, false },            \
    { "AMD: " name, fn, true }
    BOTH("destroyed after relinquishing: arrays, DIDs and identity maps "
         "freed", test_relinquished),
    BOTH("destroyed after its creation failed, not relinquished: its page "
         "tables freed too", test_creation_failed),
    BOTH("init failing at the DID map: teardown frees nothing twice",
         test_didmap_fails),
    BOTH("init failing at the device counts: teardown frees nothing twice",
         test_dev_cnt_fails),
    BOTH("init failing at the root table: nothing left", test_root_fails),
    BOTH("init failing for want of a DID: the DIDs it took returned",
         test_no_did),
    { "VT-d: sharing the p2m's tables, init failing for want of a DID: the "
      "root cleared", test_shared_no_did, false },
    { "VT-d: sharing the p2m's tables, destroyed after its creation failed: "
      "the root cleared", test_shared_creation_failed, false },
    BOTH("flush after teardown: nothing sent", test_flush_after_teardown),
    BOTH("flush of a context in use: sent to the IOMMU with a device, under "
         "its DID", test_flush),
#undef BOTH
};

int main(void)
{
    unsigned int i, j, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        /* A new domain, zeroed as Xen allocates it. */
        memset(&dom, 0, sizeof(dom));
        dom.domain_id = 1;
        dom.p2m_root = P2M_ROOT;
        dom.iommu.arch.amd.paging_mode = 4;

        INIT_LIST_HEAD(&acpi_drhd_units);
        INIT_LIST_HEAD(&amd_iommu_head);
        for ( j = 0; j < NR_IOMMUS; j++ )
        {
            dids[j] = 0;

            vtd_iommus[j] = (struct vtd_iommu){
                .index = j, .domid_bitmap = &dids[j],
                .cap = sizeof(dids[j]) * 8,
            };
            drhds[j].iommu = &vtd_iommus[j];
            list_add_tail(&drhds[j].list, &acpi_drhd_units);

            amd_iommus[j].index = j;
            amd_iommus[j].domid_map = &dids[j];
            list_add_tail(&amd_iommus[j].list, &amd_iommu_head);
        }

        amd = tests[i].amd;
        memset(live, 0, sizeof(live));
        nr_allocs = 0;
        fail_at = 0;
        pgtables = 0;
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
