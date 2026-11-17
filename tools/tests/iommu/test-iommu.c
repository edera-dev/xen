/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for iommu_domain_pviommu_init() and iommu_context_teardown().
 * A refused initialisation must free what it allocated and leave the domain
 * free to try again, and a successful one must refuse any later attempt.  A
 * refused context free must leave the context usable, and a teardown that
 * goes ahead must mark the context dying before the platform frees it.
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

static struct iommu_context ctx, default_ctx;
static struct pci_dev devices[2];

/* What a test makes the platform's teardown and a device move return. */
static int teardown_rc, reattach_rc;
static int pcidevs_held;

/* The platform teardowns that ran, and whether the context was dying. */
static struct {
    unsigned int nr;
    bool dying;
} platform;

static int platform_teardown(struct domain *d, struct iommu_context *c,
                             u32 flags)
{
    platform.nr++;
    platform.dying = c->dying;

    return teardown_rc;
}

static const struct iommu_ops ops = {
    .context_teardown = platform_teardown,
};

void pcidevs_lock(void)
{
    pcidevs_held++;
}

void pcidevs_unlock(void)
{
    pcidevs_held--;
}

/* As the real one does when it succeeds: the device joins context 0. */
int iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                           struct pci_dev *pdev, uint16_t ctx_id)
{
    if ( reattach_rc )
        return reattach_rc;

    list_del(&pdev->context_list);
    list_add(&pdev->context_list, &default_ctx.devices);

    return 0;
}

static void add_devices(unsigned int nr)
{
    unsigned int i;

    for ( i = 0; i < nr; i++ )
        list_add_tail(&devices[i].context_list, &ctx.devices);
}

static unsigned int count(const struct list_head *head)
{
    const struct list_head *pos;
    unsigned int nr = 0;

    list_for_each(pos, head)
        nr++;

    return nr;
}

static bool refused(u32 flags, int want, unsigned int devices_left)
{
    int rc = iommu_context_teardown(&dom, &ctx, flags);

    if ( rc == want && !ctx.dying && !platform.nr && !pcidevs_held &&
         count(&ctx.devices) == devices_left )
        return true;

    printf("%s: rc %d, want %d; context %sdying with %u devices, %u "
           "platform teardowns, pcidevs lock %sheld\n", test_name, rc, want,
           ctx.dying ? "" : "not ", count(&ctx.devices), platform.nr,
           pcidevs_held ? "" : "not ");
    return false;
}

static bool torn_down(u32 flags, int want)
{
    int rc = iommu_context_teardown(&dom, &ctx, flags);

    if ( rc == want && platform.nr == 1 && platform.dying && ctx.dying &&
         !pcidevs_held && list_empty(&ctx.devices) )
        return true;

    printf("%s: rc %d, want %d; %u platform teardowns, context %sdying "
           "when they ran and %sdying after, %u devices left, pcidevs lock "
           "%sheld\n", test_name, rc, want, platform.nr,
           platform.dying ? "" : "not ", ctx.dying ? "" : "not ",
           count(&ctx.devices), pcidevs_held ? "" : "not ");
    return false;
}

static bool test_device_left(void)
{
    add_devices(1);

    return refused(0, -EBUSY, 1);
}

static bool test_device_stuck(void)
{
    add_devices(1);
    reattach_rc = -EIO;

    return refused(IOMMU_TEARDOWN_REATTACH_DEFAULT, -EIO, 1);
}

static bool test_devices_moved(void)
{
    add_devices(2);

    if ( !torn_down(IOMMU_TEARDOWN_REATTACH_DEFAULT, 0) )
        return false;

    if ( count(&default_ctx.devices) == 2 )
        return true;

    printf("%s: %u devices in context 0, want 2\n", test_name,
           count(&default_ctx.devices));
    return false;
}

static bool test_empty(void)
{
    return torn_down(0, 0);
}

static bool test_preempted(void)
{
    teardown_rc = -ERESTART;

    return torn_down(IOMMU_TEARDOWN_PREEMPT, -ERESTART);
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
    { "free with a device left in the context: refused, and the context is "
      "not left dying", test_device_left },
    { "free that cannot move a device out: refused, and the context is not "
      "left dying", test_device_stuck },
    { "free that moves every device out: torn down", test_devices_moved },
    { "free of an empty context: torn down", test_empty },
    { "preempted teardown: the context stays dying until it is finished",
      test_preempted },
};

int main(void)
{
    unsigned int i, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        free(dom.iommu.other_contexts.bitmap);
        free(dom.iommu.other_contexts.map);
        memset(&dom.iommu, 0, sizeof(dom.iommu));
        dom.iommu.platform_ops = &ops;
        allocs_ok = -1;
        allocs_live = 0;
        arch_rc = 0;

        memset(&ctx, 0, sizeof(ctx));
        INIT_LIST_HEAD(&ctx.devices);
        INIT_LIST_HEAD(&default_ctx.devices);
        memset(&platform, 0, sizeof(platform));
        teardown_rc = 0;
        reattach_rc = 0;
        pcidevs_held = 0;

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
