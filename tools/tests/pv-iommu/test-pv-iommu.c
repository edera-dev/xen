/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for IOMMU_map_pages.  Each case maps one frame of the calling
 * domain into its one context, and checks what the hypercall returned, the
 * IOMMU entries it wrote and the page references it kept.
 */

#include "harness.h"

#define CTX     1
#define NR_GFNS 4
#define GFN     1
#define DFN     0x100

static struct domain dom = {
    .domain_id = 1,
    .iommu_enabled = true,
    .iommu = { .other_contexts.count = 1, .allow_pv_iommu = true },
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

struct iommu_context *iommu_get_context(struct domain *d, uint16_t ctx_id)
{
    return d == &dom && ctx_id == CTX ? &ctx : NULL;
}

void iommu_put_context(struct iommu_context *c)
{
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
    return -ENOENT;
}

int iommu_map(struct domain *d, dfn_t dfn, mfn_t mfn,
              unsigned long page_count, unsigned int flags,
              unsigned int *flush_flags, uint16_t ctx_id)
{
    entries.nr += page_count;
    entries.flags = flags;

    return 0;
}

int iommu_unmap(struct domain *d, dfn_t dfn, unsigned long page_count,
                unsigned int flags, unsigned int *flush_flags,
                uint16_t ctx_id)
{
    return -ENOENT;
}

int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                      unsigned int flush_flags, uint16_t ctx_id)
{
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
    if ( gfn >= NR_GFNS )
    {
        *t = p2m_invalid;
        return INVALID_MFN;
    }

    *t = p2m_ram_rw;
    return gfn;
}

bool mfn_valid(mfn_t mfn)
{
    return mfn < NR_GFNS;
}

struct page_info *mfn_to_page(mfn_t mfn)
{
    return &frames[mfn];
}

struct domain *page_get_owner_and_reference(struct page_info *pg)
{
    pg->refs++;

    return &dom;
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
    return NULL;
}

void put_domain(struct domain *d)
{
}

bool hypercall_preempt_check(void)
{
    return false;
}

long hypercall_create_continuation(unsigned int op, const char *format, ...)
{
    return -ERESTART;
}

static unsigned int references(void)
{
    unsigned int i, refs = 0;

    for ( i = 0; i < NR_GFNS; i++ )
        refs += frames[i].refs;

    return refs;
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

    if ( rc == -EINVAL && !map.mapped && !entries.nr && !references() )
        return true;

    printf("%s: rc %ld, mapped %u, %u entries written, %u references kept\n",
           test_name, rc, map.mapped, entries.nr, references());
    return false;
}

static bool mapped(uint32_t map_flags, unsigned int want)
{
    struct pv_iommu_map_pages map;
    long rc = map_one(map_flags, &map);

    if ( !rc && map.mapped == 1 && entries.nr == 1 && references() == 1 &&
         (entries.flags & (IOMMUF_readable | IOMMUF_writable)) == want )
        return true;

    printf("%s: rc %ld, mapped %u, %u entries written with flags %#x, "
           "%u references kept\n", test_name, rc, map.mapped, entries.nr,
           entries.flags, references());
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
};

int main(void)
{
    unsigned int i, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        memset(frames, 0, sizeof(frames));
        memset(&entries, 0, sizeof(entries));

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
