/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/guest/hyperv.h
 *
 * Copyright (c) 2019 Microsoft.
 */

#ifndef __X86_GUEST_HYPERV_H__
#define __X86_GUEST_HYPERV_H__

#include <xen/types.h>

struct vcpu;
struct cpuid_leaf;

/*
 * The specification says: "The partition reference time is computed
 * by the following formula:
 *
 * ReferenceTime = ((VirtualTsc * TscScale) >> 64) + TscOffset
 *
 * The multiplication is a 64 bit multiplication, which results in a
 * 128 bit number which is then shifted 64 times to the right to obtain
 * the high 64 bits."
 */
static inline uint64_t hv_scale_tsc(uint64_t tsc, uint64_t scale,
                                    int64_t offset)
{
    uint64_t result;

    /*
     * Quadword MUL takes an implicit operand in RAX, and puts the result
     * in RDX:RAX. Because we only want the result of the multiplication
     * after shifting right by 64 bits, we therefore only need the content
     * of RDX.
     */
    asm ( "mulq %[scale]"
          : "+a" (tsc), "=d" (result)
          : [scale] "rm" (scale) );

    return result + offset;
}

#ifdef CONFIG_HYPERV_GUEST

#include <asm/guest/hypervisor.h>

struct ms_hyperv_info {
    uint32_t features;
    uint32_t misc_features;
    uint32_t hints;
    uint32_t nested_features;
    uint32_t max_vp_index;
    uint32_t max_lp_index;
};
extern struct ms_hyperv_info ms_hyperv;

/* True when Xen has detected that it is running as a Hyper-V guest. */
extern bool hyperv_guest;

const struct hypervisor_ops *hyperv_probe(void);

#else

#define hyperv_guest 0

static inline const struct hypervisor_ops *hyperv_probe(void) { return NULL; }

#endif /* CONFIG_HYPERV_GUEST */

/*
 * Synthesize the Hyper-V ("Microsoft Hv") CPUID leaves at 0x40000000 for a
 * domain configured for Hyper-V passthrough, reflecting the enlightenments the
 * Xen proxy actually forwards to the underlying L0 host.  Only ever called for
 * a Hyper-V-passthrough domain, which requires CONFIG_HYPERV_GUEST.
 */
void cpuid_hyperv_passthrough_leaves(const struct vcpu *v, uint32_t leaf,
                                     uint32_t subleaf, struct cpuid_leaf *res);

/*
 * Per-domain Hyper-V passthrough state lifecycle, and the synthetic-MSR
 * interception hooks (dispatched from guest_{rd,wr}msr() for a passthrough
 * domain).  Only ever reached for a passthrough domain, which requires
 * CONFIG_HYPERV_GUEST.
 */
struct domain;
int hyperv_pt_domain_init(struct domain *d);
void hyperv_pt_domain_destroy(struct domain *d);
int guest_rdmsr_hyperv_pt(const struct vcpu *v, uint32_t idx, uint64_t *val);
int guest_wrmsr_hyperv_pt(struct vcpu *v, uint32_t idx, uint64_t val);

/* True once the guest has enabled its (Xen-trapped) hypercall page. */
bool hyperv_pt_hypercall_ready(const struct domain *d);

/*
 * Forward a Hyper-V hypercall from a passthrough guest to the L0 host.
 * @control/@input/@output follow the Hyper-V hypercall register ABI; returns
 * an HV_STATUS_* value.
 */
uint64_t hyperv_pt_do_hypercall(struct vcpu *v, uint64_t control,
                                uint64_t input, uint64_t output);

/*
 * The vector a passthrough domain must compose its Hyper-V vPCI device MSIs
 * with; the host then delivers them to Xen, which relays them to the target
 * vcpu as VIRQ_HYPERV_VPCI.  Returns -ENODEV when the VMBus relay is not
 * enabled.  Reported to the domain by PHYSDEVOP_hyperv_vpci_vector.
 */
int hyperv_pt_vpci_vector(uint32_t *vector);

/*
 * True when Xen forwards the L0 Hyper-V enlightenments to this domain.  A
 * compile-time false without CONFIG_HYPERV_GUEST, so callers' passthrough
 * paths are dead-code eliminated.
 */
#define is_hyperv_passthrough_domain(d) \
    (IS_ENABLED(CONFIG_HYPERV_GUEST) && (d)->arch.hyperv_passthrough)
#endif /* __X86_GUEST_HYPERV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
