/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for iommu_domain_pviommu_init(), which IOMMU_init calls, and
 * iommu_context_teardown(), which IOMMU_free_context calls, built on their
 * own from xen/drivers/passthrough/iommu.c.  The allocator, the arch and
 * platform hooks, and moving a device between contexts are stand-ins a test
 * can make fail.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xen-tools/common-macros.h>

#define CONFIG_HAS_PCI

#define cf_check
#define XENLOG_INFO ""
#define printk      printf

#define BUG_ON(x) assert(!(x))
#define ASSERT(x) assert(x)

#define BITS_PER_LONG       (sizeof(long) * 8)
#define BITS_TO_LONGS(bits) (((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)

#define smp_mb()  __sync_synchronize()
#define smp_wmb() __sync_synchronize()

#include "list.h"

typedef uint32_t u32;

typedef struct {
    int counter;
} atomic_t;

static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
    return __sync_val_compare_and_swap(&v->counter, old, new);
}

static inline void atomic_set(atomic_t *v, int i)
{
    v->counter = i;
}

typedef bool rspinlock_t;
#define rspin_lock_init(l) (*(l) = false)

struct pci_dev {
    struct list_head context_list;
};

struct iommu_context {
    rspinlock_t lock;
    bool dying;
    struct list_head devices;
};

struct domain;

struct iommu_ops {
    int (*context_teardown)(struct domain *d, struct iommu_context *ctx,
                            u32 flags);
};

#define iommu_call(ops, fn, args...) ((ops)->fn(args))

/* As xen/include/xen/iommu.h defines them. */
#define IOMMU_TEARDOWN_REATTACH_DEFAULT (1 << 0)
#define IOMMU_TEARDOWN_PREEMPT          (1 << 1)

struct domain_iommu {
    struct {
        atomic_t initialized;
        unsigned int count;
        unsigned long *bitmap;
        struct iommu_context *map;
    } other_contexts;
    const struct iommu_ops *platform_ops;
};

struct domain {
    uint16_t domain_id;
    struct domain_iommu iommu;
};

#define dom_iommu(d) (&(d)->iommu)

void *test_zalloc(size_t size);
void test_free(void *p);

#define xzalloc_array(type, nr) ((type *)test_zalloc(sizeof(type) * (nr)))
#define xfree(p)                test_free(p)

void pcidevs_lock(void);
void pcidevs_unlock(void);
int iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                           struct pci_dev *pdev, uint16_t ctx_id);

int arch_iommu_pviommu_init(struct domain *d, uint16_t nb_ctx,
                            uint32_t arena_order);
int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx,
                              uint32_t arena_order);
int iommu_context_teardown(struct domain *d, struct iommu_context *ctx,
                           u32 flags);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
