/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/hvm/grant_table.c
 *
 * Grant table interfaces for HVM guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 */

#include <xen/domain_page.h>
#include <xen/sched.h>
#include <xen/types.h>

#include <asm/altp2m.h>
#include <asm/hap.h>
#include <asm/hvm/grant_table.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/io.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/p2m.h>
#include <asm/paging.h>

int create_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                             unsigned int flags,
                             unsigned int cache_flags)
{
    p2m_type_t p2mt;
    int rc;

    if ( cache_flags || (flags & ~GNTMAP_readonly) != GNTMAP_host_map )
        return GNTST_general_error;

    if ( flags & GNTMAP_readonly )
        p2mt = p2m_grant_map_ro;
    else
        p2mt = p2m_grant_map_rw;
    rc = p2m_add_page(current->domain, _gfn(addr >> PAGE_SHIFT),
                      frame, PAGE_ORDER_4K, p2mt);
    if ( rc )
        return GNTST_general_error;
    else
        return GNTST_okay;
}

int replace_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                              uint64_t new_addr, unsigned int flags)
{
    unsigned long gfn = (unsigned long)(addr >> PAGE_SHIFT);
    p2m_type_t type;
    mfn_t old_mfn;
    struct domain *d = current->domain;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct hvm_grant_unmap_batch *batch = &current->arch.hvm.grant_unmap_batch;
    int rc;

    if ( new_addr != 0 || (flags & GNTMAP_contains_pte) )
        return GNTST_general_error;

    old_mfn = get_gfn_query(d, gfn, &type);
    if ( !p2m_is_grant(type) || !mfn_eq(old_mfn, frame) )
    {
        put_gfn(d, gfn);
        gdprintk(XENLOG_WARNING,
                 "old mapping invalid (type %d, mfn %" PRI_mfn ", frame %"PRI_mfn")\n",
                 type, mfn_x(old_mfn), mfn_x(frame));
        return GNTST_general_error;
    }

    /* Only around the removal, as the guest copies can change the p2m too. */
    if ( batch->open )
    {
        this_cpu(iommu_skipped_flush_flags) = 0;
        this_cpu(iommu_dont_flush_iotlb) = true;
    }

    rc = p2m_remove_page(d, _gfn(gfn), frame, PAGE_ORDER_4K);

    if ( batch->open )
    {
        this_cpu(iommu_dont_flush_iotlb) = false;
        batch->iommu_flags |= this_cpu(iommu_skipped_flush_flags);
        batch->gfn_lo = min(batch->gfn_lo, gfn);
        batch->gfn_hi = max(batch->gfn_hi, gfn);
        batch->tlb_flush |= p2m->need_flush;
        p2m->need_flush = false;
    }

    if ( rc )
    {
        put_gfn(d, gfn);
        return GNTST_general_error;
    }

    put_gfn(d, gfn);
    return GNTST_okay;
}

void grant_p2m_unmap_batch_begin(void)
{
    struct hvm_grant_unmap_batch *batch = &current->arch.hvm.grant_unmap_batch;

    ASSERT(!batch->open);
    *batch = (struct hvm_grant_unmap_batch){ .open = true, .gfn_lo = ~0UL };
}

int grant_p2m_unmap_batch_end(void)
{
    struct domain *d = current->domain;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct hvm_grant_unmap_batch *batch = &current->arch.hvm.grant_unmap_batch;
    unsigned long lo = batch->gfn_lo, hi = batch->gfn_hi;
    unsigned int order = flsl(lo ^ hi);

    batch->open = false;
    if ( batch->tlb_flush )
        p2m->tlb_flush(p2m);

    if ( !batch->iommu_flags )
        return 0;

    /* VT-d flushes any range but an aligned power of two as a whole domain. */
    return iommu_iotlb_flush(d, _dfn(lo & ~((1UL << order) - 1)), 1UL << order,
                             batch->iommu_flags, 0);
}

/*
 * Returns a mapping of the page at linear address @addr, or NULL when the
 * caller has to reach it through the guest access helpers instead.
 */
void *grant_ops_pin(struct gnttab_ops_pin *pin, unsigned long addr)
{
    struct vcpu *curr = current;
    struct domain *d = curr->domain;
    p2m_type_t p2mt;

    if ( !hap_enabled(d) || !hvm_long_mode_active(curr) || curr->hcall_compat ||
         nestedhvm_enabled(d) || altp2m_active(d) )
        return NULL;

    if ( !hap_walk_write_4_levels(curr, addr, &pin->gfn, pin->pt) ||
         hvm_mmio_internal(gfn_to_gaddr(pin->gfn)) )
        return NULL;

    pin->page = get_page_from_gfn(d, gfn_x(pin->gfn), &p2mt, P2M_UNSHARE);
    if ( !pin->page )
        return NULL;

    /* Every other type has write semantics only the guest access helpers know. */
    if ( p2mt != p2m_ram_rw )
    {
        put_page(pin->page);
        return NULL;
    }

    pin->va = map_domain_page(page_to_mfn(pin->page));

    return pin->va;
}

void grant_ops_unpin(struct gnttab_ops_pin *pin)
{
    unmap_domain_page(pin->va);
    paging_mark_pfn_dirty(current->domain, _pfn(gfn_x(pin->gfn)));
    put_page(pin->page);
}

/* Whether a write to @written changed a frame the pin's translation came from. */
bool grant_ops_pin_stale(const struct gnttab_ops_pin *pin, mfn_t written)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(pin->pt); i++ )
        if ( mfn_eq(pin->pt[i], written) )
            return true;

    return false;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
