/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/hyperv/synic.c
 *
 * L0-facing interrupt bring-up.  When Xen runs nested under Hyper-V and forwards
 * VMBus to a passthrough dom0, it must receive the host's synthetic interrupts
 * itself (dom0 cannot own the single VMBus connection).  This sets up Xen's own
 * per-pcpu SynIC (message + event-flag pages, SINT routing) and takes the
 * SynIC interrupt; incoming messages are then relayed to the owning dom0 vcpu.
 *
 * It also owns the vector the host delivers vPCI (VMBus-assigned PCI device)
 * MSIs to, for the same reason: those interrupts arrive as ordinary vector
 * deliveries to the VP, which is Xen's, not dom0's.
 *
 * Gated behind the "hyperv-vmbus" boot option: it programs real per-pcpu
 * Hyper-V MSRs on the boot path and is only meaningful once the dom0 relay and
 * the Linux side are brought up, so it stays off until explicitly enabled for
 * hardware bring-up.
 *
 * Copyright (c) 2026 Edera, Inc.
 */
#include <xen/event.h>
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
static uint8_t __ro_after_init vpci_vector;

static DEFINE_PER_CPU(struct hv_message_page *, synic_message_page);
static DEFINE_PER_CPU(void *, synic_event_page);

/*
 * The passthrough dom0 vcpu that owns this VP, or NULL.  dom0 vcpus are pinned
 * 1:1 to pcpus (== L0 VPs), so vcpu id == this pcpu.
 */
static struct vcpu *this_vp_owner(void)
{
    struct domain *d = hardware_domain;

    if ( !d || !is_hyperv_passthrough_domain(d) || !d->vcpu ||
         smp_processor_id() >= d->max_vcpus )
        return NULL;

    return d->vcpu[smp_processor_id()];
}

static void cf_check hyperv_synic_interrupt(void)
{
    struct hv_message_page *msg_page = this_cpu(synic_message_page);
    void *event_page = this_cpu(synic_event_page);
    struct vcpu *v = this_vp_owner();

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

/*
 * A vPCI device interrupt: the host delivered the MSI of a VMBus-assigned PCI
 * device to this VP.  Xen cannot tell which device it came from - the vPCI
 * protocol messages that assign the MSIs travel in dom0's channel ring buffers,
 * which Xen does not inspect - so every vPCI device shares this vector and dom0
 * demultiplexes among the interrupts it composed.
 */
static void cf_check hyperv_vpci_interrupt(void)
{
    struct vcpu *v = this_vp_owner();

    if ( v )
        send_guest_vcpu_virq(v, VIRQ_HYPERV_VPCI);

    ack_APIC_irq();
}

/* One-time (boot cpu) allocation of the vectors the host delivers to Xen. */
void __init hyperv_relay_vector_init(void)
{
    alloc_direct_apic_vector(&synic_vector, hyperv_synic_interrupt);
    alloc_direct_apic_vector(&vpci_vector, hyperv_vpci_interrupt);
}

/*
 * The vector a passthrough dom0 must compose its vPCI device MSIs with, so that
 * the host delivers them to Xen for relaying.  Reported to dom0 via
 * PHYSDEVOP_hyperv_vpci_vector.
 */
int hyperv_pt_vpci_vector(uint32_t *vector)
{
    if ( !opt_hyperv_vmbus || !vpci_vector )
        return -ENODEV;

    *vector = vpci_vector;

    return 0;
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
