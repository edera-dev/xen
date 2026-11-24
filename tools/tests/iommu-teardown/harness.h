/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for what the VT-d and AMD IOMMU drivers do with a domain's
 * default context when the domain is torn down, built from the drivers'
 * teardown and IOTLB flush functions and x86's identity map teardown.  The
 * IOMMUs are entries on a list, each with a DID map, and the test counts the
 * flushes sent, the DIDs returned and the allocations freed.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <assert.h>
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

unsigned int get_order_from_pages(unsigned long nr_pages);

/* The parts of struct iommu_context the drivers' teardown uses. */
struct iommu_context {
    uint16_t id;
    struct {
        struct list_head identity_maps;
        union {
            struct {
                uint64_t pgd_maddr;
                domid_t *didmap;
                unsigned long *iommu_dev_cnt;
            } vtd;
            struct {
                void *root_table;
                domid_t *didmap;
                unsigned long *iommu_dev_cnt;
            } amd;
        };
    } arch;
};

struct domain {
    domid_t domain_id;
    struct iommu_context default_ctx;
};

#define iommu_default_context(d) (&(d)->default_ctx)
#define is_hardware_domain(d)    ((d)->domain_id == 0)

extern struct domain *dom_xen;

/* Counts what it frees, as the test made the allocations. */
void xfree(void *p);
#define XFREE(p) do { xfree(p); (p) = NULL; } while ( false )

void iommu_free_domid(domid_t domid, unsigned long *map);

#include "identity_map.h"

void iommu_identity_map_teardown(struct domain *d, struct iommu_context *ctx);

/* VT-d */
struct vtd_iommu {
    unsigned int index;
    unsigned long *domid_bitmap;
};

struct acpi_drhd_unit {
    struct list_head list;
    struct vtd_iommu *iommu;
};

extern struct list_head acpi_drhd_units;
#define for_each_drhd_unit(drhd) \
    list_for_each_entry(drhd, &acpi_drhd_units, list)

int iommu_flush_iotlb_dsi(struct vtd_iommu *iommu, u16 did,
                          bool flush_non_present_entry);
int iommu_flush_iotlb_psi(struct vtd_iommu *iommu, u16 did, u64 addr,
                          unsigned int order, bool flush_non_present_entry);
void iommu_flush_write_buffer(struct vtd_iommu *iommu);

void intel_iommu_free_dids(struct iommu_context *ctx);
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

extern bool ats_enabled;

void invalidate_iommu_pages(struct amd_iommu *iommu, u64 io_addr,
                            u16 domain_id, unsigned int order);
void flush_command_buffer(struct amd_iommu *iommu, unsigned int timeout_base);
void amd_iommu_flush_all_iotlbs(const struct domain *d, daddr_t daddr,
                                unsigned int order);

void amd_iommu_free_dids(struct iommu_context *ctx);
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
