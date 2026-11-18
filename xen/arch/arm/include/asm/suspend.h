/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ARM_SUSPEND_H
#define ARM_SUSPEND_H

struct domain;
struct vcpu;
struct vcpu_guest_context;

#ifdef CONFIG_VPSCI_SYSTEM_SUSPEND
struct resume_info {
    struct vcpu_guest_context *ctxt;
    struct vcpu *wake_cpu;
};

void arch_domain_resume(struct domain *d);
#else
static inline void arch_domain_resume(struct domain *d) {}
#endif

#endif /* ARM_SUSPEND_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
