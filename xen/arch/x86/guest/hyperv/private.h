/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/hyperv/private.h
 *
 * Definitions / declarations only useful to Hyper-V code.
 *
 * Copyright (c) 2020 Microsoft.
 */

#ifndef __XEN_HYPERV_PRIVIATE_H__
#define __XEN_HYPERV_PRIVIATE_H__

#include <xen/cpumask.h>
#include <xen/percpu.h>

DECLARE_PER_CPU(void *, hv_input_page);
DECLARE_PER_CPU(void *, hv_vp_assist);
DECLARE_PER_CPU(unsigned int, hv_vp_index);
extern unsigned int hv_max_vp_index;

static inline unsigned int hv_vp_index(unsigned int cpu)
{
    return per_cpu(hv_vp_index, cpu);
}

int hyperv_flush_tlb(const cpumask_t *mask, const void *va,
                     unsigned int flags);

/* SINT index Linux/Hyper-V use for VMBus messages. */
#define VMBUS_MESSAGE_SINT 2

/*
 * L0-facing SynIC and vPCI interrupt vectors (synic.c), gated behind the
 * "hyperv-vmbus" boot option.
 */
extern bool opt_hyperv_vmbus;
void hyperv_relay_vector_init(void);
int hyperv_synic_setup(void);

/*
 * Relay an L0 SynIC message to the passthrough dom0 vcpu @v: copy it into the
 * vcpu's registered SIMP page and raise VIRQ_HYPERV_VMBUS.  (passthrough.c)
 */
struct hv_message;
void hyperv_pt_relay_message(struct vcpu *v, const struct hv_message *msg);
void hyperv_pt_relay_event_flags(struct vcpu *v, const unsigned long *flags,
                                 unsigned int nlongs);

/* Returns number of banks, -ev if error */
int cpumask_to_vpset(struct hv_vpset *vpset, const cpumask_t *mask);

#endif /* __XEN_HYPERV_PRIVIATE_H__  */
