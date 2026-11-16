/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for iommu_domain_pviommu_init().  A refused initialisation must
 * free what it allocated and leave the domain free to try again, and a
 * successful one must refuse any later attempt.
 */

#include "harness.h"

/* The default context and four more. */
#define NB_CTX 5
#define ORDER  4

static struct domain dom = { .domain_id = 1 };

static const char *test_name;

/* How many allocations succeed before one fails, or -1 for all of them. */
static int allocs_ok;
static unsigned int allocs_live;

/* What arch_iommu_pviommu_init() returns for an arena it accepts. */
static int arch_rc;

void *test_zalloc(size_t size)
{
    if ( allocs_ok == 0 )
        return NULL;

    if ( allocs_ok > 0 )
        allocs_ok--;
    allocs_live++;

    return calloc(1, size);
}

void test_free(void *p)
{
    if ( p )
        allocs_live--;
    free(p);
}

/* As x86's: an arena of order 0 is refused. */
int arch_iommu_pviommu_init(struct domain *d, uint16_t nb_ctx,
                            uint32_t arena_order)
{
    return arena_order ? arch_rc : -EINVAL;
}

static bool init(uint16_t nb_ctx, uint32_t order, int want)
{
    int rc = iommu_domain_pviommu_init(&dom, nb_ctx, order);

    if ( rc == want )
        return true;

    printf("%s: init of %u contexts with an arena of order %u: rc %d, "
           "want %d\n", test_name, nb_ctx, order, rc, want);
    return false;
}

/* Nothing allocated and no contexts advertised. */
static bool clean(void)
{
    const struct domain_iommu *hd = dom_iommu(&dom);

    if ( !allocs_live && !hd->other_contexts.count &&
         !hd->other_contexts.bitmap && !hd->other_contexts.map )
        return true;

    printf("%s: after the refusal, %u allocations live and %u contexts "
           "advertised\n", test_name, allocs_live, hd->other_contexts.count);
    return false;
}

/* The contexts of one successful init, and nothing more. */
static bool ready(void)
{
    const struct domain_iommu *hd = dom_iommu(&dom);

    if ( hd->other_contexts.count == NB_CTX - 1 && allocs_live == 2 &&
         hd->other_contexts.bitmap && hd->other_contexts.map )
        return true;

    printf("%s: %u contexts advertised and %u allocations live, want %u "
           "and 2\n", test_name, hd->other_contexts.count, allocs_live,
           NB_CTX - 1);
    return false;
}

static bool test_order_0(void)
{
    return init(NB_CTX, 0, -EINVAL) && clean() &&
           init(NB_CTX, ORDER, 0) && ready();
}

static bool test_arena_fails(void)
{
    arch_rc = -ENOMEM;
    if ( !init(NB_CTX, ORDER, -ENOMEM) || !clean() )
        return false;

    arch_rc = 0;
    return init(NB_CTX, ORDER, 0) && ready();
}

static bool test_bitmap_fails(void)
{
    allocs_ok = 0;
    if ( !init(NB_CTX, ORDER, -ENOMEM) || !clean() )
        return false;

    allocs_ok = -1;
    return init(NB_CTX, ORDER, 0) && ready();
}

static bool test_table_fails(void)
{
    allocs_ok = 1;
    if ( !init(NB_CTX, ORDER, -ENOMEM) || !clean() )
        return false;

    allocs_ok = -1;
    return init(NB_CTX, ORDER, 0) && ready();
}

static bool test_no_contexts(void)
{
    return init(0, ORDER, -EINVAL) && clean() &&
           init(NB_CTX, ORDER, 0) && ready();
}

static bool test_second_init(void)
{
    return init(NB_CTX, ORDER, 0) && init(NB_CTX, ORDER, -EACCES) &&
           ready();
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "arena of order 0: refused, and a valid init after it succeeds",
      test_order_0 },
    { "arena allocation fails: refused, and a retry succeeds",
      test_arena_fails },
    { "context bitmap allocation fails: refused, and a retry succeeds",
      test_bitmap_fails },
    { "context table allocation fails: the bitmap is freed, and a retry "
      "succeeds", test_table_fails },
    { "no contexts: refused, and a valid init after it succeeds",
      test_no_contexts },
    { "a second init after a successful one: refused, and the first kept",
      test_second_init },
};

int main(void)
{
    unsigned int i, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        free(dom.iommu.other_contexts.bitmap);
        free(dom.iommu.other_contexts.map);
        memset(&dom.iommu, 0, sizeof(dom.iommu));
        allocs_ok = -1;
        allocs_live = 0;
        arch_rc = 0;

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
