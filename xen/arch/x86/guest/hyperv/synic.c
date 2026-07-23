/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/hyperv/synic.c
 *
 * L0-facing SynIC bring-up.  When Xen runs nested under Hyper-V and forwards
 * VMBus to a passthrough dom0, it must receive the host's synthetic interrupts
 * itself (dom0 cannot own the single VMBus connection).  This sets up Xen's own
 * per-pcpu SynIC (message + event-flag pages, SINT routing) and takes the
 * SynIC interrupt; incoming messages are then relayed to the owning dom0 vcpu
 * (the relay itself is the interrupt-bridge work, M4).
 *
 * Gated behind the "hyperv-vmbus" boot option: it programs real per-pcpu
 * Hyper-V MSRs on the boot path and is only meaningful once the dom0 relay and
 * the Linux side are brought up, so it stays off until explicitly enabled for
 * hardware bring-up.
 *
 * Copyright (c) 2026 Edera, Inc.
 */
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/percpu.h>
#include <xen/sched.h>

#include <asm/apic.h>
#include <asm/guest/hyperv.h>
#include <asm/guest/hyperv-tlfs.h>
#include <asm/irq.h>
#include <asm/msr.h>

#include "private.h"

bool __ro_after_init opt_hyperv_vmbus;
boolean_param("hyperv-vmbus", opt_hyperv_vmbus);

static uint8_t __ro_after_init synic_vector;

static DEFINE_PER_CPU(struct hv_message_page *, synic_message_page);
static DEFINE_PER_CPU(void *, synic_event_page);

static void cf_check hyperv_synic_interrupt(void)
{
    struct hv_message_page *msg_page = this_cpu(synic_message_page);
    void *event_page = this_cpu(synic_event_page);
    struct domain *d = hardware_domain;
    struct vcpu *v = NULL;

    /*
     * Relay to the dom0 vcpu that owns this VP.  dom0 vcpus are pinned 1:1 to
     * pcpus (== L0 VPs), so vcpu id == this pcpu.
     */
    if ( d && is_hyperv_passthrough_domain(d) &&
         smp_processor_id() < d->max_vcpus && d->vcpu )
        v = d->vcpu[smp_processor_id()];

    /* Message page (SIMP): VMBus control messages (offers, open results). */
    if ( msg_page )
    {
        struct hv_message *msg = &msg_page->sint_message[VMBUS_MESSAGE_SINT];

        if ( msg->header.message_type != HVMSG_NONE )
        {
            if ( v )
                hyperv_pt_relay_message(v, msg);

            /* Consume the message and acknowledge if more are pending. */
            msg->header.message_type = HVMSG_NONE;
            smp_mb();
            if ( msg->header.message_flags.msg_pending )
                wrmsrl(HV_X64_MSR_EOM, 0);
        }
    }

    /* Event-flags page (SIEFP): VMBus channel-ring interrupts. */
    if ( event_page && v )
    {
        union hv_synic_event_flags *ev =
            &((union hv_synic_event_flags *)event_page)[VMBUS_MESSAGE_SINT];
        unsigned long snapshot[HV_EVENT_FLAGS_LONG_COUNT];
        bool any = false;
        unsigned int i;

        for ( i = 0; i < HV_EVENT_FLAGS_LONG_COUNT; i++ )
        {
            snapshot[i] = xchg(&ev->flags[i], 0UL);
            if ( snapshot[i] )
                any = true;
        }

        if ( any )
            hyperv_pt_relay_event_flags(v, snapshot, HV_EVENT_FLAGS_LONG_COUNT);
    }

    ack_APIC_irq();
}

/* One-time (boot cpu) allocation of the SynIC interrupt vector. */
void __init hyperv_synic_vector_init(void)
{
    alloc_direct_apic_vector(&synic_vector, hyperv_synic_interrupt);
}

/* Per-pcpu SynIC bring-up. */
int hyperv_synic_setup(void)
{
    union hv_synic_simp simp;
    union hv_synic_siefp siefp;
    union hv_synic_scontrol scontrol;
    union hv_synic_sint sint;
    void *simp_page, *siefp_page;

    if ( !this_cpu(synic_message_page) )
    {
        simp_page = alloc_xenheap_page();
        if ( !simp_page )
            return -ENOMEM;
        clear_page(simp_page);
        this_cpu(synic_message_page) = simp_page;
    }

    if ( !this_cpu(synic_event_page) )
    {
        siefp_page = alloc_xenheap_page();
        if ( !siefp_page )
            return -ENOMEM;
        clear_page(siefp_page);
        this_cpu(synic_event_page) = siefp_page;
    }

    /* Program the message page (SIMP) with our machine-frame address. */
    rdmsrl(HV_X64_MSR_SIMP, simp.as_uint64);
    simp.simp_enabled = 1;
    simp.base_simp_gpa = virt_to_mfn(this_cpu(synic_message_page));
    wrmsrl(HV_X64_MSR_SIMP, simp.as_uint64);

    /* Program the event-flags page (SIEFP). */
    rdmsrl(HV_X64_MSR_SIEFP, siefp.as_uint64);
    siefp.siefp_enabled = 1;
    siefp.base_siefp_gpa = virt_to_mfn(this_cpu(synic_event_page));
    wrmsrl(HV_X64_MSR_SIEFP, siefp.as_uint64);

    /* Route the VMBus SINT to our vector, unmasked. */
    rdmsrl(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, sint.as_uint64);
    sint.vector = synic_vector;
    sint.masked = 0;
    sint.auto_eoi = 0;
    wrmsrl(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, sint.as_uint64);

    /* Enable the SynIC. */
    rdmsrl(HV_X64_MSR_SCONTROL, scontrol.as_uint64);
    scontrol.enable = 1;
    wrmsrl(HV_X64_MSR_SCONTROL, scontrol.as_uint64);

    return 0;
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
