/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for IOMMU_map_pages and IOMMU_unmap_pages.  Most cases map one
 * frame into the calling domain's one context.  The rest map or unmap
 * hundreds of pages, with Xen preempting the call each time it checks and the
 * test issuing it again as a guest would.  Each case checks what the hypercall
 * returned, what the caller's request holds afterwards, the IOMMU entries it
 * wrote, the page references it kept and that it put back every gfn it got.
 */

#include <stdarg.h>

#include "harness.h"

#define CTX      1
#define NR_GFNS  1024
#define GFN      1
#define DFN      0x100

/* Preempted after 256 pages and after 512. */
#define NR_PAGES 600

/* Bounds a call that Xen preempts every time it checks. */
#define MAX_CONTINUATIONS 4096

static struct domain dom = {
    .domain_id = 1,
    .iommu_enabled = true,
    .iommu = { .other_contexts.count = 1, .allow_pv_iommu = true },
};
static struct domain other = { .domain_id = 2 };
/* The hardware domain, which maps into dom with IOMMU_remote_cmd. */
static struct domain hwdom = {
    .domain_id = 0,
    .iommu_enabled = true,
    .iommu = { .allow_pv_iommu = true },
};
static struct vcpu vcpu = { .domain = &dom };
struct vcpu *current = &vcpu;

static struct iommu_context ctx = { .id = CTX };
static struct page_info frames[NR_GFNS];
struct rangeset *mmio_ro_ranges;

static const char *test_name;

/* The IOMMU entries the hypercall wrote. */
static struct {
    unsigned int nr;
    unsigned int flags;    /* of the last one */
} entries;

/* Contexts got with iommu_get_context() and not put back. */
static unsigned int contexts_held;

/* Gfns got with get_gfn_type() and not put back. */
static int gfns_held;

/* What each dfn from DFN on maps, as an mfn + 1, or 0 for nothing. */
static unsigned long mapping[NR_GFNS];

/* How many times the IOTLB was flushed for each dfn from DFN on. */
static unsigned int flushes[NR_GFNS];

/* Whether Xen preempts a map or unmap each time it checks. */
static bool preempt;

/* The continuations Xen created, and the arguments of the last one. */
static unsigned int continuations;
static struct {
    unsigned int subop;
    XEN_GUEST_HANDLE_PARAM(void) arg;
} cont;

static unsigned long *entry(dfn_t dfn)
{
    return dfn >= DFN && dfn - DFN < NR_GFNS ? &mapping[dfn - DFN] : NULL;
}

struct iommu_context *iommu_get_context(struct domain *d, uint16_t ctx_id)
{
    if ( d != &dom || ctx_id != CTX )
        return NULL;

    contexts_held++;
    return &ctx;
}

void iommu_put_context(struct iommu_context *c)
{
    contexts_held--;
}

uint64_t iommu_get_max_iova(struct domain *d)
{
    return 1ULL << 39;
}

bool iommu_identity_map_check(struct domain *d, struct iommu_context *c,
                              mfn_t mfn)
{
    return false;
}

int iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                      unsigned int *flags, uint16_t ctx_id)
{
    unsigned long *e = entry(dfn);

    if ( !e || !*e )
        return -ENOENT;

    *mfn = *e - 1;
    *flags = IOMMUF_readable | IOMMUF_writable;

    return 0;
}

int iommu_map(struct domain *d, dfn_t dfn, mfn_t mfn,
              unsigned long page_count, unsigned int flags,
              unsigned int *flush_flags, uint16_t ctx_id)
{
    unsigned long *e = entry(dfn);

    /* As the drivers refuse it for IOMMUF_no_replace. */
    if ( e && *e )
        return -EEXIST;

    if ( e )
        *e = mfn + 1;
    entries.nr += page_count;
    entries.flags = flags;

    return 0;
}

int iommu_unmap(struct domain *d, dfn_t dfn, unsigned long page_count,
                unsigned int flags, unsigned int *flush_flags,
                uint16_t ctx_id)
{
    unsigned long *e = entry(dfn);

    if ( !e || !*e )
        return -ENOENT;

    *e = 0;

    return 0;
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                      unsigned int flush_flags, uint16_t ctx_id)
{
    unsigned long i;

    for ( i = 0; i < page_count; i++ )
    {
        unsigned long *e = entry(dfn + i);

        if ( e )
            flushes[e - mapping]++;
    }

    return 0;
}

int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx,
                              uint32_t arena_order)
{
    return -EOPNOTSUPP;
}

int iommu_context_alloc(struct domain *d, uint16_t *ctx_id,
                        unsigned int flags)
{
    return -EOPNOTSUPP;
}

int iommu_context_free(struct domain *d, uint16_t ctx_id, uint32_t flags)
{
    return -EOPNOTSUPP;
}

bool iommu_get_mapped_page_type(struct page_info *pg)
{
    return true;
}

void iommu_put_mapped_page(struct page_info *pg)
{
    pg->refs--;
}

mfn_t get_gfn_type(struct domain *d, unsigned long gfn, p2m_type_t *t,
                   p2m_query_t q)
{
    gfns_held++;

    if ( gfn >= NR_GFNS )
    {
        *t = p2m_invalid;
        return INVALID_MFN;
    }

    *t = p2m_ram_rw;
    return gfn;
}

void put_gfn(struct domain *d, unsigned long gfn)
{
    gfns_held--;
}

bool mfn_valid(mfn_t mfn)
{
    return mfn < NR_GFNS;
}

struct page_info *mfn_to_page(mfn_t mfn)
{
    return &frames[mfn];
}

/* As Xen's: a free frame has a count of 0, and no reference is taken. */
struct domain *page_get_owner_and_reference(struct page_info *pg)
{
    if ( !pg->owner )
        return NULL;

    pg->refs++;

    return pg->owner;
}

void put_page(struct page_info *pg)
{
    pg->refs--;
}

bool rangeset_contains_singleton(struct rangeset *r, unsigned long s)
{
    return false;
}

bool iomem_access_permitted(struct domain *d, unsigned long s,
                            unsigned long e)
{
    return false;
}

struct domain *get_domain_by_id(domid_t domid)
{
    return domid == dom.domain_id ? &dom : NULL;
}

void put_domain(struct domain *d)
{
}

bool hypercall_preempt_check(void)
{
    return preempt;
}

long hypercall_create_continuation(unsigned int op, const char *format, ...)
{
    va_list args;

    assert(op == __HYPERVISOR_iommu_op && !strcmp(format, "ih"));

    va_start(args, format);
    cont.subop = va_arg(args, unsigned int);
    cont.arg = va_arg(args, XEN_GUEST_HANDLE_PARAM(void));
    va_end(args);
    continuations++;

    return -ERESTART;
}

/*
 * Makes the hypercall as a guest does: when Xen preempts it, the guest makes
 * it again with the continuation's arguments, until it finishes.
 */
static long iommu_op(unsigned int subop, void *arg)
{
    XEN_GUEST_HANDLE_PARAM(void) hnd = { .p = arg };
    long rc = do_iommu_op(subop, hnd);

    while ( rc == -ERESTART && continuations < MAX_CONTINUATIONS )
        rc = do_iommu_op(cont.subop, cont.arg);

    return rc;
}

static int references(void)
{
    unsigned int i;
    int refs = 0;

    for ( i = 0; i < NR_GFNS; i++ )
        refs += frames[i].refs;

    return refs;
}

/*
 * The nr dfns from DFN + from map the gfns from GFN + from, which are their
 * own mfns here, and no other dfn maps anything.
 */
static bool only_mapped(unsigned int from, unsigned int nr)
{
    unsigned int i;

    for ( i = 0; i < NR_GFNS; i++ )
        if ( mapping[i] != (i >= from && i - from < nr ? GFN + i + 1 : 0) )
            return false;

    return true;
}

/* The IOTLB was flushed once for each of those dfns, and for no other. */
static bool flushed_once(unsigned int from, unsigned int nr)
{
    unsigned int i;

    for ( i = 0; i < NR_GFNS; i++ )
        if ( flushes[i] != (i >= from && i - from < nr) )
            return false;

    return true;
}

static struct pv_iommu_map_pages map_request(unsigned int from,
                                             unsigned int nr)
{
    return (struct pv_iommu_map_pages){
        .ctx_no = CTX, .gfn = GFN + from, .dfn = DFN + from,
        .map_flags = IOMMU_MAP_readable | IOMMU_MAP_writeable,
        .pgsize = PAGE_SIZE_4K, .nr_pages = nr,
    };
}

/* The request holds what the caller passed, with added added to mapped. */
static bool map_as_passed(const struct pv_iommu_map_pages *map,
                          const struct pv_iommu_map_pages *passed,
                          unsigned int added)
{
    return map->ctx_no == passed->ctx_no && map->gfn == passed->gfn &&
           map->dfn == passed->dfn && map->map_flags == passed->map_flags &&
           map->pgsize == passed->pgsize &&
           map->nr_pages == passed->nr_pages &&
           map->mapped == passed->mapped + added;
}

static bool map_failed(long rc, const struct pv_iommu_map_pages *map)
{
    printf("%s: rc %ld after %u continuations; gfn %#"PRIx64", dfn %#"PRIx64
           ", nr_pages %u, mapped %u; %d references kept, %d gfns held, "
           "%u contexts held\n", test_name, rc, continuations,
           (uint64_t)map->gfn, (uint64_t)map->dfn, map->nr_pages, map->mapped,
           references(), gfns_held, contexts_held);
    return false;
}

static long map_one(uint32_t map_flags, struct pv_iommu_map_pages *map)
{
    XEN_GUEST_HANDLE_PARAM(void) arg = { .p = map };

    *map = (struct pv_iommu_map_pages){
        .ctx_no = CTX, .gfn = GFN, .dfn = DFN, .map_flags = map_flags,
        .pgsize = PAGE_SIZE_4K, .nr_pages = 1,
    };

    return do_iommu_op(IOMMU_map_pages, arg);
}

/*
 * VT-d treats an entry with neither permission as not present, so neither
 * unmap nor teardown would find it to return the reference behind it.
 */
static bool refused(uint32_t map_flags)
{
    struct pv_iommu_map_pages map;
    long rc = map_one(map_flags, &map);

    if ( rc == -EINVAL && !map.mapped && !entries.nr && !references() &&
         !gfns_held && !contexts_held )
        return true;

    printf("%s: rc %ld, mapped %u, %u entries written, %d references kept, "
           "%d gfns held, %u contexts held\n", test_name, rc, map.mapped,
           entries.nr, references(), gfns_held, contexts_held);
    return false;
}

static bool mapped(uint32_t map_flags, unsigned int want)
{
    struct pv_iommu_map_pages map;
    long rc = map_one(map_flags, &map);

    if ( !rc && map.mapped == 1 && entries.nr == 1 && references() == 1 &&
         !gfns_held && !contexts_held && !IOMMUF_order(entries.flags) &&
         (entries.flags & (IOMMUF_readable | IOMMUF_writable)) == want )
        return true;

    printf("%s: rc %ld, mapped %u, %u entries written with flags %#x, "
           "%d references kept, %d gfns held, %u contexts held\n", test_name,
           rc, map.mapped, entries.nr, entries.flags, references(), gfns_held,
           contexts_held);
    return false;
}

/*
 * A frame the caller may not map: refused, with any reference taken on it
 * returned and its gfn put back.
 */
static bool frame_refused(void)
{
    struct pv_iommu_map_pages map;
    long rc = map_one(IOMMU_MAP_readable | IOMMU_MAP_writeable, &map);

    if ( rc == -EPERM && !map.mapped && !entries.nr && !references() &&
         !gfns_held && !contexts_held )
        return true;

    printf("%s: rc %ld, mapped %u, %u entries written, %d references kept, "
           "%d gfns held, %u contexts held\n", test_name, rc, map.mapped,
           entries.nr, references(), gfns_held, contexts_held);
    return false;
}

static bool test_no_access(void)
{
    return refused(0);
}

static bool test_no_flush_alone(void)
{
    return refused(IOMMU_MAP_no_flush);
}

static bool test_cache_alone(void)
{
    return refused(IOMMU_MAP_cache);
}

static bool test_readable(void)
{
    return mapped(IOMMU_MAP_readable, IOMMUF_readable);
}

static bool test_writeable(void)
{
    return mapped(IOMMU_MAP_writeable, IOMMUF_writable);
}

static bool test_readable_writeable(void)
{
    return mapped(IOMMU_MAP_readable | IOMMU_MAP_writeable,
                  IOMMUF_readable | IOMMUF_writable);
}

static bool test_free_frame(void)
{
    frames[GFN].owner = NULL;

    return frame_refused();
}

static bool test_foreign_frame(void)
{
    frames[GFN].owner = &other;

    return frame_refused();
}

static bool test_map_preempted(void)
{
    struct pv_iommu_map_pages passed = map_request(0, NR_PAGES), map = passed;
    long rc;

    preempt = true;
    rc = iommu_op(IOMMU_map_pages, &map);

    if ( !rc && continuations == 2 && map_as_passed(&map, &passed, NR_PAGES) &&
         only_mapped(0, NR_PAGES) && flushed_once(0, NR_PAGES) &&
         references() == NR_PAGES && !gfns_held && !contexts_held )
        return true;

    return map_failed(rc, &map);
}

static bool test_map_not_preempted_at_end(void)
{
    struct pv_iommu_map_pages passed = map_request(0, 512), map = passed;
    long rc;

    preempt = true;
    rc = iommu_op(IOMMU_map_pages, &map);

    if ( !rc && continuations == 1 && map_as_passed(&map, &passed, 512) &&
         only_mapped(0, 512) && flushed_once(0, 512) &&
         references() == 512 && !gfns_held && !contexts_held )
        return true;

    return map_failed(rc, &map);
}

/*
 * Linux maps a scattered buffer one run of contiguous frames at a time, with
 * one request it sets mapped to 0 in only once, and reads the total from it.
 */
static bool test_map_runs_add_up(void)
{
    struct pv_iommu_map_pages passed = map_request(0, 300), map = passed;
    long rc;

    preempt = true;
    rc = iommu_op(IOMMU_map_pages, &map);
    if ( rc || !map_as_passed(&map, &passed, 300) )
        return map_failed(rc, &map);

    map.gfn = GFN + 300;
    map.dfn = DFN + 300;
    map.nr_pages = 300;
    passed = map;
    rc = iommu_op(IOMMU_map_pages, &map);

    if ( !rc && continuations == 2 && map_as_passed(&map, &passed, 300) &&
         map.mapped == 600 && only_mapped(0, 600) && flushed_once(0, 600) &&
         references() == 600 && !gfns_held && !contexts_held )
        return true;

    return map_failed(rc, &map);
}

static bool test_map_refused_after_preemption(void)
{
    struct pv_iommu_map_pages passed = map_request(0, 300), map = passed;
    long rc;

    frames[GFN + 280].owner = &other;
    preempt = true;
    rc = iommu_op(IOMMU_map_pages, &map);

    if ( rc == -EPERM && continuations == 1 &&
         map_as_passed(&map, &passed, 280) && only_mapped(0, 280) &&
         flushed_once(0, 280) && references() == 280 && !gfns_held &&
         !contexts_held )
        return true;

    return map_failed(rc, &map);
}

static bool test_unmap_preempted(void)
{
    struct pv_iommu_map_pages map = map_request(0, NR_PAGES);
    struct pv_iommu_unmap_pages passed = {
        .ctx_no = CTX, .dfn = DFN, .pgsize = PAGE_SIZE_4K,
        .nr_pages = NR_PAGES,
    }, unmap = passed;
    long rc = iommu_op(IOMMU_map_pages, &map);

    if ( rc )
        return map_failed(rc, &map);

    memset(flushes, 0, sizeof(flushes));
    preempt = true;
    rc = iommu_op(IOMMU_unmap_pages, &unmap);

    if ( !rc && continuations == 2 && unmap.ctx_no == passed.ctx_no &&
         unmap.dfn == passed.dfn && unmap.pgsize == passed.pgsize &&
         unmap.nr_pages == passed.nr_pages && unmap.unmapped == NR_PAGES &&
         only_mapped(0, 0) && flushed_once(0, NR_PAGES) && !references() &&
         !gfns_held && !contexts_held )
        return true;

    printf("%s: rc %ld after %u continuations; dfn %#"PRIx64", nr_pages %u, "
           "unmapped %u; %d references kept, %u contexts held\n", test_name,
           rc, continuations, (uint64_t)unmap.dfn, unmap.nr_pages,
           unmap.unmapped, references(), contexts_held);
    return false;
}

/* As the hardware domain maps into a domain it built. */
static bool test_remote_map_preempted(void)
{
    struct pv_iommu_map_pages passed = map_request(0, NR_PAGES), map = passed;
    struct pv_iommu_remote_cmd cmd = {
        .domid = 1, .subop = IOMMU_map_pages,
    };
    long rc;

    set_xen_guest_handle(cmd.arg, &map);
    vcpu.domain = &hwdom;
    preempt = true;
    rc = iommu_op(IOMMU_remote_cmd, &cmd);

    if ( !rc && continuations == 2 && map_as_passed(&map, &passed, NR_PAGES) &&
         only_mapped(0, NR_PAGES) && flushed_once(0, NR_PAGES) &&
         references() == NR_PAGES && !gfns_held && !contexts_held )
        return true;

    return map_failed(rc, &map);
}

/*
 * The bits above the subop number are only ever set by Xen, to resume a map
 * or unmap before its last page.
 */
static bool test_resume_bits_refused(void)
{
    struct pv_iommu_map_pages passed = map_request(0, 1), map = passed;
    XEN_GUEST_HANDLE_PARAM(void) arg = { .p = &map };
    long noop = do_iommu_op(IOMMU_noop | 0x100, arg);
    long rc = do_iommu_op(IOMMU_map_pages | 0x100, arg);

    if ( noop == -EOPNOTSUPP && rc == -EINVAL &&
         map_as_passed(&map, &passed, 0) && only_mapped(0, 0) &&
         !references() && !gfns_held && !contexts_held )
        return true;

    printf("%s: noop rc %ld, map rc %ld\n", test_name, noop, rc);
    return map_failed(rc, &map);
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "no access flags: refused, and nothing referenced", test_no_access },
    { "IOMMU_MAP_no_flush alone: refused, and nothing referenced",
      test_no_flush_alone },
    { "IOMMU_MAP_cache alone: refused, and nothing referenced",
      test_cache_alone },
    { "readable: mapped read-only", test_readable },
    { "writeable: mapped write-only", test_writeable },
    { "readable and writeable: mapped read-write", test_readable_writeable },
    { "free frame: refused, no reference dropped, and the gfn put back",
      test_free_frame },
    { "frame another domain owns: refused, its reference returned, and the "
      "gfn put back", test_foreign_frame },
    { "map of 600 pages preempted twice: each page mapped once, and the "
      "request as passed", test_map_preempted },
    { "map of 512 pages: preempted after 256 but not after the last",
      test_map_not_preempted_at_end },
    { "two runs mapped with one request: mapped holds both, and the request "
      "as passed", test_map_runs_add_up },
    { "map refused at page 280 after a preemption: mapped 280, and the "
      "request as passed", test_map_refused_after_preemption },
    { "unmap of 600 pages preempted twice: each page unmapped once, and the "
      "request as passed", test_unmap_preempted },
    { "remote map of 600 pages preempted twice: resumed as a remote map, and "
      "the request as passed", test_remote_map_preempted },
    { "resume bits on a noop, or past a map's last page: refused",
      test_resume_bits_refused },
};

int main(void)
{
    unsigned int i, j, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        memset(frames, 0, sizeof(frames));
        for ( j = 0; j < NR_GFNS; j++ )
            frames[j].owner = &dom;
        memset(&entries, 0, sizeof(entries));
        memset(mapping, 0, sizeof(mapping));
        memset(flushes, 0, sizeof(flushes));
        contexts_held = 0;
        gfns_held = 0;
        preempt = false;
        continuations = 0;
        vcpu.domain = &dom;

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
