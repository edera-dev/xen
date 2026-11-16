/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for iommu_domain_pviommu_init() in
 * xen/drivers/passthrough/iommu.c, which IOMMU_init calls.  The function is
 * built on its own, and the allocator and the arch hook are stand-ins a test
 * can make fail.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xen-tools/common-macros.h>

#define XENLOG_INFO ""
#define printk      printf

#define BITS_PER_LONG       (sizeof(long) * 8)
#define BITS_TO_LONGS(bits) (((bits) + BITS_PER_LONG - 1) / BITS_PER_LONG)

#define smp_mb()  __sync_synchronize()
#define smp_wmb() __sync_synchronize()

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

struct iommu_context {
    rspinlock_t lock;
};

struct domain_iommu {
    struct {
        atomic_t initialized;
        unsigned int count;
        unsigned long *bitmap;
        struct iommu_context *map;
    } other_contexts;
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

int arch_iommu_pviommu_init(struct domain *d, uint16_t nb_ctx,
                            uint32_t arena_order);
int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx,
                              uint32_t arena_order);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
