/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for the PV-IOMMU hypercalls in xen/common/pv-iommu.c, built as
 * for x86 without PCI.  The IOMMU core and the p2m are stand-ins: every frame
 * is RAM, owned by the calling domain unless a test frees it or gives it to
 * another domain, and the test counts the page references the hypercalls take,
 * the gfns they get and the entries they write.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <xen-tools/common-macros.h>

#include <xen/xen.h>
#include <xen/pv-iommu.h>

#define CONFIG_X86

#define __read_mostly
#define boolean_param(name, var)
#define unlikely(x) (x)

#define XENLOG_INFO      ""
#define XENLOG_WARNING   ""
#define XENLOG_G_WARNING ""
#define printk           printf
#define gprintk(lvl, fmt, args...)  printf(fmt, ## args)
#define gdprintk(lvl, fmt, args...) printf(fmt, ## args)

#define PAGE_SHIFT   12
#define PAGE_SIZE_4K (1UL << PAGE_SHIFT)

typedef unsigned long mfn_t;
typedef unsigned long gfn_t;
typedef unsigned long dfn_t;

#define _mfn(x)       (x)
#define mfn_x(x)      (x)
#define _gfn(x)       (x)
#define gfn_x(x)      (x)
#define _dfn(x)       (x)
#define dfn_x(x)      (x)
#define dfn_add(d, n) ((d) + (n))
#define mfn_eq(a, b)  ((a) == (b))
#define INVALID_MFN   (~0UL)
#define PRI_mfn       "05lx"
#define PRI_gfn       "05lx"

typedef enum {
    p2m_invalid,
    p2m_ram_rw,
    p2m_ram_ro,
    p2m_mmio_direct,
} p2m_type_t;

typedef unsigned int p2m_query_t;
#define P2M_ALLOC   (1u << 0)
#define P2M_UNSHARE (1u << 1)

#define p2m_is_any_ram(t) ((t) == p2m_ram_rw || (t) == p2m_ram_ro)
#define p2m_is_mmio(t)    ((t) == p2m_mmio_direct)

struct domain;

struct page_info {
    /* References taken and not yet returned. */
    int refs;
    /* NULL for a free frame, which has no reference to take. */
    struct domain *owner;
};

struct domain_iommu {
    struct {
        unsigned int count;
    } other_contexts;
    bool allow_pv_iommu;
    bool no_dma;
};

struct domain {
    domid_t domain_id;
    bool is_dying;
    bool iommu_enabled;
    struct domain_iommu iommu;
};

struct vcpu {
    struct domain *domain;
};

extern struct vcpu *current;

#define dom_iommu(d)        (&(d)->iommu)
#define is_iommu_enabled(d) ((d)->iommu_enabled)
#define is_hardware_domain(d) ((d)->domain_id == 0)

struct iommu_context {
    uint16_t id;
    bool dying;
};

/* As xen/include/xen/iommu.h defines them. */
#define IOMMUF_order(n)   ((n) & 0x3f)
#define IOMMUF_readable   (1u << 6)
#define IOMMUF_writable   (1u << 7)
#define IOMMUF_no_replace (1u << 9)

#define IOMMU_FLUSHF_added    (1u << 0)
#define IOMMU_FLUSHF_modified (1u << 1)

#define IOMMU_TEARDOWN_REATTACH_DEFAULT (1 << 0)
#define IOMMU_TEARDOWN_PREEMPT          (1 << 1)

struct iommu_context *iommu_get_context(struct domain *d, uint16_t ctx_id);
void iommu_put_context(struct iommu_context *ctx);
uint64_t iommu_get_max_iova(struct domain *d);
bool iommu_identity_map_check(struct domain *d, struct iommu_context *ctx,
                              mfn_t mfn);
int iommu_lookup_page(struct domain *d, dfn_t dfn, mfn_t *mfn,
                      unsigned int *flags, uint16_t ctx_id);
int iommu_map(struct domain *d, dfn_t dfn, mfn_t mfn,
              unsigned long page_count, unsigned int flags,
              unsigned int *flush_flags, uint16_t ctx_id);
int iommu_unmap(struct domain *d, dfn_t dfn, unsigned long page_count,
                unsigned int flags, unsigned int *flush_flags,
                uint16_t ctx_id);
int iommu_iotlb_flush(struct domain *d, dfn_t dfn, unsigned long page_count,
                      unsigned int flush_flags, uint16_t ctx_id);
int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx,
                              uint32_t arena_order);
int iommu_context_alloc(struct domain *d, uint16_t *ctx_id,
                        unsigned int flags);
int iommu_context_free(struct domain *d, uint16_t ctx_id, uint32_t flags);
bool iommu_get_mapped_page_type(struct page_info *pg);
void iommu_put_mapped_page(struct page_info *pg);

mfn_t get_gfn_type(struct domain *d, unsigned long gfn, p2m_type_t *t,
                   p2m_query_t q);
void put_gfn(struct domain *d, unsigned long gfn);
bool mfn_valid(mfn_t mfn);
struct page_info *mfn_to_page(mfn_t mfn);
struct domain *page_get_owner_and_reference(struct page_info *pg);
void put_page(struct page_info *pg);

struct rangeset;
extern struct rangeset *mmio_ro_ranges;
bool rangeset_contains_singleton(struct rangeset *r, unsigned long s);
bool iomem_access_permitted(struct domain *d, unsigned long s,
                            unsigned long e);

struct domain *get_domain_by_id(domid_t domid);
void put_domain(struct domain *d);

/* Arm's public headers define it, and x86's leave it to the hypervisor. */
#ifndef XEN_GUEST_HANDLE_PARAM
#define XEN_GUEST_HANDLE_PARAM(type)      XEN_GUEST_HANDLE(type)
#endif
#define guest_handle_to_param(hnd, type) \
    ((XEN_GUEST_HANDLE_PARAM(type)){ (hnd).p })
#define copy_from_guest(ptr, hnd, nr) \
    (memcpy(ptr, (hnd).p, (nr) * sizeof(*(ptr))), 0)
#define copy_to_guest(hnd, ptr, nr) \
    (memcpy((hnd).p, ptr, (nr) * sizeof(*(ptr))), 0)

bool hypercall_preempt_check(void);
long hypercall_create_continuation(unsigned int op, const char *format, ...);

long do_iommu_op(unsigned int subop, XEN_GUEST_HANDLE_PARAM(void) arg);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
