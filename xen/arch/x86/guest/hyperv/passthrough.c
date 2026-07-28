/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/hyperv/passthrough.c
 *
 * Forward (proxy) the underlying L0 Hyper-V enlightenments to a Xen domain
 * (a PV dom0 running nested under Hyper-V), so its stock Linux VMBus stack can
 * drive the host's synthetic devices.  This is the dom0-facing half of the
 * proxy: it intercepts the Hyper-V synthetic MSRs the guest accesses and holds
 * the per-domain / per-vcpu enlightenment state.  The L0-facing half (issuing
 * the real hypercalls, SynIC bring-up) lives alongside in this directory.
 *
 * Copyright (c) 2026 Edera, Inc.
 */
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/event.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>

#include <asm/guest/hyperv.h>
#include <asm/guest/hyperv-hcall.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/msr.h>
#include <asm/p2m.h>

#include "private.h"

/*
 * Depth of the per-vcpu queue buffering L0 SynIC messages awaiting delivery
 * into the dom0 vcpu's single SIMP slot.  Must absorb the VMBus channel-offer
 * burst; Azure offers a few dozen channels.
 */
#define HV_PT_MSG_QUEUE_SIZE 64

/* Per-vcpu Hyper-V passthrough state (SynIC and VP assist). */
struct hyperv_pt_vcpu {
    uint64_t vp_assist_msr;
    uint64_t scontrol;
    uint64_t siefp;
    uint64_t simp;
    uint64_t sint[16];

    /*
     * L0 SynIC messages are drained into this ring and delivered into the dom0
     * vcpu's SIMP slot one at a time (the SynIC has a single slot per SINT).
     * dom0 signals consumption of a message with an EOM MSR write, which Xen
     * intercepts to push the next queued message.  Protected by @msgq_lock
     * (irqsave: taken from both the SynIC interrupt and the EOM MSR trap).
     */
    spinlock_t msgq_lock;
    unsigned int msgq_head, msgq_tail;
    struct hv_message msgq[HV_PT_MSG_QUEUE_SIZE];
};

/* Per-domain (partition-wide) Hyper-V passthrough state. */
struct hyperv_pt_domain {
    uint64_t guest_os_id;
    uint64_t hypercall_msr;
    bool hypercall_ready;
    struct hyperv_pt_vcpu vcpu[];
};

int hyperv_pt_domain_init(struct domain *d)
{
    struct hyperv_pt_domain *pt;
    unsigned int i;

    ASSERT(is_hyperv_passthrough_domain(d));

    pt = xzalloc_flex_struct(struct hyperv_pt_domain, vcpu, d->max_vcpus);
    if ( !pt )
        return -ENOMEM;

    for ( i = 0; i < d->max_vcpus; i++ )
        spin_lock_init(&pt->vcpu[i].msgq_lock);

    d->arch.hyperv_pt = pt;

    return 0;
}

void hyperv_pt_domain_destroy(struct domain *d)
{
    XFREE(d->arch.hyperv_pt);
}

bool hyperv_pt_hypercall_ready(const struct domain *d)
{
    return d->arch.hyperv_pt && d->arch.hyperv_pt->hypercall_ready;
}

/*
 * Deliver at most one queued message into the dom0 vcpu's SIMP slot, honouring
 * the SynIC single-slot protocol: only write when dom0 has consumed (cleared)
 * the previous message.  Set msg_pending so dom0 issues an EOM (which we
 * intercept) to pull the next queued message.  Safe to call from both the
 * SynIC interrupt and the EOM MSR trap.
 */
static void hyperv_pt_try_deliver(struct vcpu *v)
{
    struct hyperv_pt_domain *pt = v->domain->arch.hyperv_pt;
    struct hyperv_pt_vcpu *vp = &pt->vcpu[v->vcpu_id];
    union hv_synic_simp simp = { .as_uint64 = vp->simp };
    struct hv_message_page *dom0_simp;
    struct hv_message *slot;
    struct page_info *pg;
    p2m_type_t t;
    unsigned long flags;
    bool notify = false;

    if ( !simp.simp_enabled )
        return;

    pg = get_page_from_gfn(v->domain, simp.base_simp_gpa, &t, P2M_ALLOC);
    if ( !pg )
        return;
    if ( !p2m_is_ram(t) )
    {
        put_page(pg);
        return;
    }

    dom0_simp = __map_domain_page(pg);
    slot = &dom0_simp->sint_message[VMBUS_MESSAGE_SINT];

    spin_lock_irqsave(&vp->msgq_lock, flags);
    if ( slot->header.message_type == HVMSG_NONE &&
         vp->msgq_head != vp->msgq_tail )
    {
        *slot = vp->msgq[vp->msgq_tail];
        vp->msgq_tail = (vp->msgq_tail + 1) % HV_PT_MSG_QUEUE_SIZE;
        /*
         * Always flag msg_pending so dom0 issues an EOM after consuming this
         * message; that EOM (which Xen intercepts) is our reliable trigger to
         * push the next queued message.  A spurious EOM when the queue is
         * empty is a harmless no-op, and this closes the race where a message
         * enqueued just after a msg_pending=0 delivery would otherwise stall.
         */
        slot->header.message_flags.msg_pending = 1;
        notify = true;
    }
    spin_unlock_irqrestore(&vp->msgq_lock, flags);

    unmap_domain_page(dom0_simp);
    put_page(pg);

    if ( notify )
    {
        smp_wmb();
        send_guest_vcpu_virq(v, VIRQ_HYPERV_VMBUS);
    }
}

/*
 * Relay L0 SynIC event flags (VMBus channel-ring "doorbell" interrupts) into
 * the dom0 vcpu's SIEFP.  @flags is a snapshot of Xen's SIEFP event-flag longs
 * for VMBUS_MESSAGE_SINT (already read-and-cleared by the caller).  dom0's
 * vmbus_isr scans its own SIEFP slot for set channel relids, so OR the bits in
 * atomically (dom0 clears them concurrently) and raise the VIRQ.
 */
void hyperv_pt_relay_event_flags(struct vcpu *v, const unsigned long *flags,
                                 unsigned int nlongs)
{
    struct hyperv_pt_domain *pt = v->domain->arch.hyperv_pt;
    struct hyperv_pt_vcpu *vp;
    union hv_synic_siefp siefp;
    union hv_synic_event_flags *dom0_ev;
    struct page_info *pg;
    p2m_type_t t;
    void *map;
    unsigned int i;
    bool any = false;

    if ( !pt )
        return;

    vp = &pt->vcpu[v->vcpu_id];
    siefp.as_uint64 = vp->siefp;
    if ( !siefp.siefp_enabled )
        return;

    pg = get_page_from_gfn(v->domain, siefp.base_siefp_gpa, &t, P2M_ALLOC);
    if ( !pg )
        return;
    if ( !p2m_is_ram(t) )
    {
        put_page(pg);
        return;
    }

    map = __map_domain_page(pg);
    dom0_ev = &((union hv_synic_event_flags *)map)[VMBUS_MESSAGE_SINT];

    for ( i = 0; i < nlongs; i++ )
    {
        unsigned long w = flags[i];

        while ( w )
        {
            unsigned int b = __builtin_ctzl(w);

            set_bit(i * BITS_PER_LONG + b, dom0_ev->flags);
            w &= w - 1;
            any = true;
        }
    }

    unmap_domain_page(map);
    put_page(pg);

    if ( any )
    {
        smp_wmb();
        send_guest_vcpu_virq(v, VIRQ_HYPERV_VMBUS);
    }
}

void hyperv_pt_relay_message(struct vcpu *v, const struct hv_message *msg)
{
    struct hyperv_pt_domain *pt = v->domain->arch.hyperv_pt;
    struct hyperv_pt_vcpu *vp;
    unsigned int next;
    unsigned long flags;

    if ( !pt )
        return;

    vp = &pt->vcpu[v->vcpu_id];

    /* Drain the L0 message into the per-vcpu queue (keeps L0's SynIC flowing). */
    spin_lock_irqsave(&vp->msgq_lock, flags);
    next = (vp->msgq_head + 1) % HV_PT_MSG_QUEUE_SIZE;
    if ( next == vp->msgq_tail )
    {
        spin_unlock_irqrestore(&vp->msgq_lock, flags);
        gprintk(XENLOG_WARNING,
                "hv-pt: vcpu%u SynIC message queue full, dropping\n",
                v->vcpu_id);
        return;
    }
    vp->msgq[vp->msgq_head] = *msg;
    vp->msgq_head = next;
    spin_unlock_irqrestore(&vp->msgq_lock, flags);

    /* Feed dom0's slot if it is free. */
    hyperv_pt_try_deliver(v);
}

/*
 * Fill the guest's hypercall page with a trap stub: ud2 + "hvc" signature +
 * ret.  The guest CALLs the page (Hyper-V ABI); the ud2 faults into
 * pv_emulate_invalid_op(), which recognises the signature, services the call,
 * and skips to the trailing ret so the guest returns to its caller with the
 * status in rax.  (PV guests cannot vmcall, so we cannot use the real Hyper-V
 * hypercall page.)
 */
static void hyperv_pt_fill_hypercall_page(struct domain *d, uint64_t gpa)
{
    static const uint8_t stub[] = { 0x0f, 0x0b, 'h', 'v', 'c', 0xc3 };
    unsigned int off = gpa & ~PAGE_MASK;
    struct page_info *pg;
    p2m_type_t t;
    void *map;

    /* The stub must not straddle a page boundary. */
    if ( off + sizeof(stub) > PAGE_SIZE )
        return;

    pg = get_page_from_gfn(d, PFN_DOWN(gpa), &t, P2M_ALLOC);
    if ( !pg )
        return;
    if ( !p2m_is_ram(t) )
    {
        put_page(pg);
        return;
    }

    map = __map_domain_page(pg);
    memcpy(map + off, stub, sizeof(stub));
    unmap_domain_page(map);
    put_page(pg);
}

/*
 * Forward a Hyper-V hypercall issued by the passthrough domain to the
 * underlying L0 host.  Only the VMBus messaging primitives and vPCI interrupt
 * retargeting are forwarded; the guest's input parameter block (a guest-physical
 * address) is marshalled into Xen's per-cpu input page so L0 sees a machine
 * address it owns.
 */
uint64_t hyperv_pt_do_hypercall(struct vcpu *v, uint64_t control,
                                uint64_t input, uint64_t output)
{
    struct domain *d = v->domain;
    uint16_t code = control & 0xffff;
    void *xen_in;
    struct page_info *pg;
    p2m_type_t t;
    void *map;
    uint64_t status;

    switch ( code )
    {
    case HVCALL_POST_MESSAGE:
    case HVCALL_SIGNAL_EVENT:
        break;

    /*
     * vPCI device interrupt affinity.  The guest names VP indices, which equal
     * pcpu numbers because its vcpus are pinned 1:1, and a vector Xen owns (see
     * hyperv_pt_vpci_vector()), so the parameter block needs no rewriting.  Its
     * variable-size count lives in @control and is forwarded untouched.
     */
    case HVCALL_RETARGET_INTERRUPT:
        break;

    default:
        /* Not (yet) proxied. */
        status = HV_STATUS_INVALID_HYPERCALL_CODE;
        goto out;
    }

    /* Fast hypercalls carry their parameters in registers - forward as-is. */
    if ( control & HV_HYPERCALL_FAST_BIT )
    {
        status = hv_do_hypercall(control, input, output);
        goto out;
    }

    xen_in = this_cpu(hv_input_page);
    if ( !xen_in )
    {
        status = HV_STATUS_INVALID_PARAMETER;
        goto out;
    }

    pg = get_page_from_gfn(d, PFN_DOWN(input), &t, P2M_ALLOC);
    if ( !pg || !p2m_is_ram(t) )
    {
        if ( pg )
            put_page(pg);
        status = HV_STATUS_INVALID_PARAMETER;
        goto out;
    }

    /*
     * Copy the whole page and forward the machine address at the same offset;
     * the TLFS requires the input block not to cross a page boundary.
     */
    map = __map_domain_page(pg);
    memcpy(xen_in, map, PAGE_SIZE);
    unmap_domain_page(map);
    put_page(pg);

    status = hv_do_hypercall(control,
                             virt_to_maddr(xen_in) + (input & ~PAGE_MASK), 0);

 out:
    return status;
}

int guest_rdmsr_hyperv_pt(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    const struct hyperv_pt_domain *pt = v->domain->arch.hyperv_pt;
    const struct hyperv_pt_vcpu *vp;

    if ( !pt )
        return X86EMUL_EXCEPTION;

    vp = &pt->vcpu[v->vcpu_id];

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        *val = pt->guest_os_id;
        break;

    case HV_X64_MSR_HYPERCALL:
        *val = pt->hypercall_msr;
        break;

    case HV_X64_MSR_VP_INDEX:
        /* VP index matches the vcpu id (dom0 vcpus are pinned 1:1 to pcpus). */
        *val = v->vcpu_id;
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        *val = vp->vp_assist_msr;
        break;

    case HV_X64_MSR_SCONTROL:
        *val = vp->scontrol;
        break;

    case HV_X64_MSR_SVERSION:
        *val = 1; /* SynIC version 1, per the TLFS. */
        break;

    case HV_X64_MSR_SIEFP:
        *val = vp->siefp;
        break;

    case HV_X64_MSR_SIMP:
        *val = vp->simp;
        break;

    case HV_X64_MSR_EOM:
        *val = 0; /* Write-only in effect; reads as zero. */
        break;

    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT0 + 15:
        *val = vp->sint[idx - HV_X64_MSR_SINT0];
        break;

    default:
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int guest_wrmsr_hyperv_pt(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct domain *d = v->domain;
    struct hyperv_pt_domain *pt = d->arch.hyperv_pt;
    struct hyperv_pt_vcpu *vp;

    if ( !pt )
        return X86EMUL_EXCEPTION;

    vp = &pt->vcpu[v->vcpu_id];

    switch ( idx )
    {
    case HV_X64_MSR_GUEST_OS_ID:
        pt->guest_os_id = val;
        /* Clearing the guest OS id tears down the hypercall interface. */
        if ( !val )
            pt->hypercall_ready = false;
        break;

    case HV_X64_MSR_HYPERCALL:
    {
        /* The guest programs the GPA of its hypercall page here. */
        union hv_x64_msr_hypercall_contents m = { .as_uint64 = val };

        pt->hypercall_msr = val;
        if ( m.enable && !pt->hypercall_ready )
        {
            hyperv_pt_fill_hypercall_page(
                d, (uint64_t)m.guest_physical_address << HV_HYP_PAGE_SHIFT);
            pt->hypercall_ready = true;
        }
        break;
    }

    case HV_X64_MSR_VP_INDEX:
    case HV_X64_MSR_SVERSION:
        /* Read-only. */
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        vp->vp_assist_msr = val;
        break;

    case HV_X64_MSR_SCONTROL:
        vp->scontrol = val;
        break;

    case HV_X64_MSR_SIEFP:
        vp->siefp = val;
        break;

    case HV_X64_MSR_SIMP:
        vp->simp = val;
        break;

    case HV_X64_MSR_EOM:
        /* dom0 consumed its SIMP slot: push the next queued message, if any. */
        hyperv_pt_try_deliver(v);
        break;

    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT0 + 15:
        vp->sint[idx - HV_X64_MSR_SINT0] = val;
        break;

    default:
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
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
