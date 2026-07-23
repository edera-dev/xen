/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/pv/emul-inv-op.c
 *
 * Emulate invalid op for PV guests
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
 */

#include <asm/guest/hyperv.h>
#include <asm/pv/trace.h>
#include <asm/pv/traps.h>

#include "emulate.h"

static int emulate_forced_invalid_op(struct cpu_user_regs *regs)
{
    char sig[5], instr[2];
    unsigned long eip, rc;
    struct cpuid_leaf res;
    const struct vcpu_msrs *msrs = current->arch.msrs;

    eip = regs->rip;

    /* Check for forced emulation signature: ud2 ; .ascii "xen". */
    if ( (rc = copy_from_guest_pv(sig, (char __user *)eip, sizeof(sig))) != 0 )
    {
        pv_inject_page_fault(0, eip + sizeof(sig) - rc);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(sig, "\xf\xb" "xen", sizeof(sig)) )
        return 0;
    eip += sizeof(sig);

    /* We only emulate CPUID. */
    if ( (rc = copy_from_guest_pv(instr, (char __user *)eip,
                                  sizeof(instr))) != 0 )
    {
        pv_inject_page_fault(0, eip + sizeof(instr) - rc);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(instr, "\xf\xa2", sizeof(instr)) )
        return 0;

    /* If cpuid faulting is enabled and CPL>0 inject a #GP in place of #UD. */
    if ( msrs->misc_features_enables.cpuid_faulting &&
         !guest_kernel_mode(current, regs) )
    {
        regs->rip = eip;
        pv_inject_hw_exception(X86_EXC_GP, regs->error_code);
        return EXCRET_fault_fixed;
    }

    eip += sizeof(instr);

    guest_cpuid(current, regs->eax, regs->ecx, &res);

    regs->rax = res.a;
    regs->rbx = res.b;
    regs->rcx = res.c;
    regs->rdx = res.d;

    pv_emul_instruction_done(regs, eip);

    trace_trap_one_addr(TRC_PV_FORCED_INVALID_OP, regs->rip);

    return EXCRET_fault_fixed;
}

/*
 * A passthrough (Hyper-V-on-Xen) dom0 makes Hyper-V hypercalls by CALLing its
 * hypercall page, which Xen filled with "ud2; \"hvc\"; ret".  Recognise that
 * signature here, forward the call (rcx=control, rdx=input, r8=output) to the
 * L0 host, and skip to the trailing ret so the guest returns with the status
 * in rax.
 */
static int emulate_hyperv_hypercall(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    char sig[5];
    unsigned long eip = regs->rip, rc;

    if ( !is_hyperv_passthrough_domain(curr->domain) ||
         !hyperv_pt_hypercall_ready(curr->domain) )
        return 0;

    if ( (rc = copy_from_guest_pv(sig, (char __user *)eip, sizeof(sig))) != 0 )
    {
        pv_inject_page_fault(0, eip + sizeof(sig) - rc);
        return EXCRET_fault_fixed;
    }
    if ( memcmp(sig, "\xf\xb" "hvc", sizeof(sig)) )
        return 0;

    regs->rax = hyperv_pt_do_hypercall(curr, regs->rcx, regs->rdx, regs->r8);

    /* Skip ud2 + signature; the guest's trailing ret returns to the caller. */
    pv_emul_instruction_done(regs, eip + sizeof(sig));

    return EXCRET_fault_fixed;
}

bool pv_emulate_invalid_op(struct cpu_user_regs *regs)
{
    return !(emulate_forced_invalid_op(regs) || emulate_hyperv_hypercall(regs));
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
