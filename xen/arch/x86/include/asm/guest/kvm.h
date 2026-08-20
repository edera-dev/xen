/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asm-x86/guest/kvm.h
 *
 * Support for running Xen as a guest of KVM.
 */
#ifndef __X86_GUEST_KVM_H__
#define __X86_GUEST_KVM_H__

#include <xen/types.h>

#include <asm/guest/hypervisor.h>

#ifdef CONFIG_KVM_GUEST

extern bool kvm_guest;

const struct hypervisor_ops *kvm_probe(void);

/*
 * The pvclock reference this CPU should read, or NULL when KVM did not give us
 * one.  Same layout as Xen's own vcpu_time_info -- both descend from the same
 * pvclock design -- so the reader in time.c is shared.
 */
const struct vcpu_time_info *kvm_pvclock(void);

/* Whether KVM guarantees the pvclock is usable as one global counter. */
bool kvm_pvclock_stable(void);

#else

#define kvm_guest false

static inline const struct hypervisor_ops *kvm_probe(void) { return NULL; }
static inline const struct vcpu_time_info *kvm_pvclock(void) { return NULL; }
static inline bool kvm_pvclock_stable(void) { return false; }

#endif /* CONFIG_KVM_GUEST */

#endif /* __X86_GUEST_KVM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
