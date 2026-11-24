/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for a domain's default IOMMU context on VT-d and AMD, from
 * context init to domain teardown, built from the drivers' context init,
 * teardown and IOTLB flush functions and x86's list setup and identity map
 * teardown.  The IOMMUs are entries on a list, each with a DID map.  The
 * allocators can be made to fail, and the test counts the allocations,
 * page-table pages, DIDs and flushes the code under test leaves behind.
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

#include <xen/xen.h>

#define cf_check

#define ASSERT(p) assert(p)
#define BUG()     assert(!"BUG")

/* For Xen's list.h. */
#define smp_wmb()            __sync_synchronize()
#define rcu_dereference(p)   (p)

#include "list.h"

/* glibc's sys/types.h has a daddr_t of its own. */
#define daddr_t xen_daddr_t

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t paddr_t;
typedef uint64_t daddr_t;
typedef unsigned int p2m_access_t;

typedef unsigned long dfn_t;
#define _dfn(x)         (x)
#define dfn_x(x)        (x)
#define dfn_eq(a, b)    ((a) == (b))
#define INVALID_DFN     (~0UL)
#define dfn_to_daddr(d) ((daddr_t)(d) << 12)

/* As xen/include/xen/iommu.h defines them. */
#define IOMMU_FLUSHF_added    (1u << 0)
#define IOMMU_FLUSHF_modified (1u << 1)
#define IOMMU_FLUSHF_all      (1u << 2)
#define IOMMU_CONTEXT_INIT_default (1 << 0)

unsigned int get_order_from_pages(unsigned long nr_pages);

struct page_info;

struct page_list_head {
    struct page_info *next, *tail;
};
#define INIT_PAGE_LIST_HEAD(head) ((head)->next = (head)->tail = NULL)

/* The parts of struct iommu_context the drivers use here. */
struct iommu_context {
    uint16_t id;
    bool opaque;
    struct {
        struct page_list_head pgtables;
        struct list_head identity_maps;
        union {
            struct {
                uint64_t pgd_maddr;
                domid_t *didmap;
                unsigned long *iommu_dev_cnt;
                uint32_t superpage_progress;
            } vtd;
            struct {
                struct page_info *root_table;
                domid_t *didmap;
                unsigned long *iommu_dev_cnt;
                unsigned int paging_mode;
            } amd;
        };
    } arch;
};

struct domain_iommu {
    struct {
        struct {
            unsigned int paging_mode;
        } amd;
    } arch;
};

typedef struct {
    paddr_t root;
} pagetable_t;

struct domain {
    domid_t domain_id;
    struct domain_iommu iommu;
    struct iommu_context default_ctx;
    /* Whether the IOMMU uses the p2m's page tables, and their root. */
    bool hap_pt_share;
    paddr_t p2m_root;
};

#define dom_iommu(d)               (&(d)->iommu)
#define iommu_default_context(d)   (&(d)->default_ctx)
#define is_hardware_domain(d)      ((d)->domain_id == 0)
#define iommu_use_hap_pt(d)        ((d)->hap_pt_share)
#define p2m_get_hostp2m(d)         (d)
#define p2m_get_pagetable(p2m)     ((pagetable_t){ (p2m)->p2m_root })
#define pagetable_get_paddr(pgt)   ((pgt).root)

extern struct domain *dom_xen;

/* Allocate from, and free to, the test's own counted allocator. */
void *test_alloc(size_t size);
void xfree(void *p);
#define xmalloc_array(type, nr)  ((type *)test_alloc(sizeof(type) * (nr)))
#define xzalloc_array(type, nr)  ((type *)test_alloc(sizeof(type) * (nr)))
#define XFREE(p) do { xfree(p); (p) = NULL; } while ( false )

domid_t iommu_alloc_domid(unsigned long *map, unsigned int nr);
void iommu_free_domid(domid_t domid, unsigned long *map);

struct page_info *iommu_alloc_pgtable(struct domain_iommu *hd,
                                      struct iommu_context *ctx,
                                      uint64_t contig_mask);
int iommu_free_pgtables(struct domain *d, struct iommu_context *ctx);

#include "identity_map.h"

int arch_iommu_context_init(struct domain *d, struct iommu_context *ctx,
                            u32 flags);
void iommu_identity_map_teardown(struct domain *d, struct iommu_context *ctx);

/* VT-d */
struct vtd_iommu {
    unsigned int index;
    unsigned long *domid_bitmap;
    unsigned long cap;
};

/* The number of DIDs, kept in the whole of cap here. */
#define cap_ndoms(cap) (cap)

struct acpi_drhd_unit {
    struct list_head list;
    struct vtd_iommu *iommu;
};

extern struct list_head acpi_drhd_units;
#define for_each_drhd_unit(drhd) \
    list_for_each_entry(drhd, &acpi_drhd_units, list)

extern unsigned int nr_iommus;
extern unsigned int min_pt_levels;

uint64_t addr_to_dma_page_maddr(struct domain *domain,
                                struct iommu_context *ctx, daddr_t addr,
                                unsigned int target,
                                unsigned int *flush_flags, bool alloc);
int iommu_flush_iotlb_dsi(struct vtd_iommu *iommu, u16 did,
                          bool flush_non_present_entry);
int iommu_flush_iotlb_psi(struct vtd_iommu *iommu, u16 did, u64 addr,
                          unsigned int order, bool flush_non_present_entry);
void iommu_flush_write_buffer(struct vtd_iommu *iommu);

void intel_iommu_free_dids(struct iommu_context *ctx);
int intel_iommu_context_init(struct domain *d, struct iommu_context *ctx,
                             u32 flags);
int __must_check iommu_flush_iotlb(struct domain *d, struct iommu_context *ctx,
                                   dfn_t dfn, unsigned long page_count,
                                   unsigned int flush_flags);
void iommu_domain_teardown(struct domain *d);

/* AMD */
struct amd_iommu {
    struct list_head list;
    unsigned int index;
    unsigned long *domid_map;
};

extern struct list_head amd_iommu_head;
#define for_each_amd_iommu(amd_iommu) \
    list_for_each_entry(amd_iommu, &amd_iommu_head, list)

#define IOMMU_DOMID_MAP_SIZE (sizeof(unsigned long) * 8)

extern unsigned int nr_amd_iommus;
extern unsigned int amd_iommu_guest_pt_levels;
extern int amd_iommu_min_paging_mode;
extern bool ats_enabled;

void invalidate_iommu_pages(struct amd_iommu *iommu, u64 io_addr,
                            u16 domain_id, unsigned int order);
void flush_command_buffer(struct amd_iommu *iommu, unsigned int timeout_base);
void amd_iommu_flush_all_iotlbs(const struct domain *d, daddr_t daddr,
                                unsigned int order);

void amd_iommu_free_dids(struct iommu_context *ctx);
int amd_iommu_context_init(struct domain *d, struct iommu_context *ctx,
                           u32 flags);
void amd_iommu_domain_destroy(struct domain *d);
void _amd_iommu_flush_pages(struct domain *d, struct iommu_context *ctx,
                            daddr_t daddr, unsigned int order);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
