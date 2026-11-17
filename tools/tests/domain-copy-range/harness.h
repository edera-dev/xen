/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for XENMEM_domain_copy_range, built from domain_copy_range() in
 * xen/common/memory.c.  The target domain's frames and the caller's memory are
 * arrays in the test, and a page lookup takes references the test counts.  A
 * copy from the caller's memory fails at a page the test makes unreadable, as
 * x86 does: for a PV vCPU zero-filling what it did not copy, and for an HVM
 * vCPU leaving it, having copied the pages before.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <xen-tools/common-macros.h>

#include <xen/xen.h>
#include <xen/memory.h>

/* As xen/include/xen/hypercall.h defines it. */
#define MEMOP_EXTENT_SHIFT 6

#define PAGE_SHIFT 12
/* Some libcs define PAGE_SIZE in limits.h. */
#undef  PAGE_SIZE
#define PAGE_SIZE  (1UL << PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE - 1))

typedef unsigned long gfn_t;
#define _gfn(x) (x)

typedef enum {
    p2m_invalid,
    p2m_ram_rw,
    p2m_ram_ro,
} p2m_type_t;

#define p2m_is_ram(t) ((t) == p2m_ram_rw || (t) == p2m_ram_ro)

#define PGT_writable_page 1

struct page_info {
    /* General and type references taken and not yet returned. */
    int refs;
    int type_refs;
};

struct domain {
    domid_t domain_id;
};

struct vcpu {
    struct domain *domain;
    bool pv;
};

extern struct vcpu *current;

#define is_pv_vcpu(v) ((v)->pv)

#define XSM_TARGET 0
int xsm_add_to_physmap(int action, struct domain *d1, struct domain *d2);

int rcu_lock_remote_domain_by_id(domid_t dom, struct domain **d);
void rcu_unlock_domain(struct domain *d);

int check_get_page_from_gfn(struct domain *d, gfn_t gfn, bool readonly,
                            p2m_type_t *p2mt_p, struct page_info **page_p);
void put_page(struct page_info *page);
bool get_page_type(struct page_info *page, unsigned long type);
void put_page_and_type(struct page_info *page);

void *__map_domain_page(struct page_info *page);
void unmap_domain_page(const void *va);

/* Arm's public headers define it, and x86's leave it to the hypervisor. */
#ifndef XEN_GUEST_HANDLE_PARAM
#define XEN_GUEST_HANDLE_PARAM(type) XEN_GUEST_HANDLE(type)
#endif
#define guest_handle_is_null(hnd) ((hnd).p == NULL)

/* Each returns how many bytes it did not copy, as Xen's copies do. */
unsigned long test_copy_from_guest(void *to, const void *from,
                                   unsigned long n);
unsigned long test_copy_to_guest(void *to, const void *from,
                                 unsigned long n);

#define copy_from_guest_offset(ptr, hnd, off, nr) \
    test_copy_from_guest(ptr, (hnd).p + (off), (nr) * sizeof(*(hnd).p))
#define copy_from_guest(ptr, hnd, nr) copy_from_guest_offset(ptr, hnd, 0, nr)
#define copy_to_guest_offset(hnd, off, ptr, nr) \
    test_copy_to_guest((hnd).p + (off), ptr, (nr) * sizeof(*(hnd).p))

bool hypercall_preempt_check(void);
long hypercall_create_continuation(unsigned int op, const char *format, ...);

int domain_copy_range(XEN_GUEST_HANDLE_PARAM(xen_domain_copy_range_t) arg,
                      unsigned long start_extent);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
