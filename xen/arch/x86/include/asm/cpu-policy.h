/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef X86_CPU_POLICY_H
#define X86_CPU_POLICY_H

#include <xen/types.h>

struct cpu_policy;
struct domain;

extern struct cpu_policy     raw_cpu_policy;
extern struct cpu_policy    host_cpu_policy;
extern struct cpu_policy  pv_max_cpu_policy;
extern struct cpu_policy  pv_def_cpu_policy;
extern struct cpu_policy hvm_max_cpu_policy;
extern struct cpu_policy hvm_def_cpu_policy;

/* Initialise the guest cpu_policy objects. */
void init_guest_cpu_policies(void);

/* Allocate and initialise a CPU policy suitable for the domain. */
int init_domain_cpu_policy(struct domain *d);

/* Apply dom0-specific tweaks to the CPUID policy. */
void init_dom0_cpuid_policy(struct domain *d);

/* Clamp the CPUID policy to reality. */
void recalculate_cpuid_policy(struct domain *d);

/*
 * Collect the raw CPUID and MSR values.  Called during boot, and after late
 * microcode loading.
 */
void calculate_raw_cpu_policy(void);

/*
 * Compute the x2APIC identifier assigned to a guest vCPU.  When the domain
 * has a multi-vnode vNUMA topology and the CPU policy has been patched by
 * recalculate_vnuma_topo(), the ID encodes (vnode_index, intra_pkg_offset)
 * so the package boundary in CPUID 0xB falls on a clean bit and APIC IDs do
 * not collide across packages — including for non-power-of-two and
 * unbalanced per-vnode vCPU counts.  Otherwise the legacy vcpu_id * 2
 * encoding is returned.
 *
 * All call sites that produce a guest-observable APIC ID (CPUID leaves 0x1
 * EBX[31:24], 0xB EDX, and vlapic register state) must use this helper so
 * the guest never observes inconsistent APIC IDs between interfaces.
 */
uint32_t guest_vcpu_x2apic_id(const struct domain *d, unsigned int vcpu_id);

#endif /* X86_CPU_POLICY_H */
