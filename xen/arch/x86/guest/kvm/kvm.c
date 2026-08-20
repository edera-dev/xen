/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * arch/x86/guest/kvm/kvm.c
 *
 * Support for detecting and running under KVM.
 *
 * Xen nested under KVM has no accurate time of its own to work from.  Its
 * platform timers are all emulated by the L0 VMM: reading one costs a VM exit,
 * and calibrating the TSC against something that jittery leaves Xen's notion of
 * system time -- and therefore every guest's pvclock -- drifting with host
 * scheduling.  A guest that is descheduled long enough sees its TSC condemned
 * by Linux's timekeeping watchdog and switches clocksource underneath a running
 * workload.
 *
 * KVM already publishes an authoritative timeline: kvmclock, a shared page per
 * vCPU maintained by L0, monotonic and free of VM exits to read.  This makes
 * Xen a consumer of it, so the time Xen hands to its own guests descends from
 * the outermost hypervisor rather than from emulated hardware.
 */
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/percpu.h>
#include <xen/types.h>

#include <asm/guest.h>
#include <asm/msr.h>
#include <asm/processor.h>

bool __ro_after_init kvm_guest;

static uint32_t __ro_after_init kvm_cpuid_base;

/*
 * Hypervisors advertise themselves in the CPUID range reserved for them,
 * starting at 0x40000000, one signature per 0x100 leaves.  KVM's is
 * "KVMKVMKVM\0\0\0".
 */
#define KVM_CPUID_FIRST_LEAF 0x40000000
#define KVM_CPUID_LAST_LEAF  0x40010000
#define KVM_SIGNATURE_EBX    0x4b4d564bU /* "KVMK" */
#define KVM_SIGNATURE_ECX    0x564b4d56U /* "VMKV" */
#define KVM_SIGNATURE_EDX    0x0000004dU /* "M"    */

/*
 * KVM's pvclock page, one per CPU.  Allocated rather than static so that the
 * MSR can be pointed at a page-aligned address without reserving one per
 * possible CPU in the image.
 */
static DEFINE_PER_CPU(struct vcpu_time_info *, kvm_time);

static void __init find_kvm_leaves(void)
{
    uint32_t base, eax, ebx, ecx, edx;

    for ( base = KVM_CPUID_FIRST_LEAF; base < KVM_CPUID_LAST_LEAF;
          base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx);

        if ( ebx == KVM_SIGNATURE_EBX && ecx == KVM_SIGNATURE_ECX &&
             edx == KVM_SIGNATURE_EDX && (eax - base) >= 1 )
        {
            kvm_cpuid_base = base;
            return;
        }
    }
}

/*
 * Point this CPU's KVM_SYSTEM_TIME MSR at a page we own.  KVM keeps writing
 * that page for as long as the enable bit is set, so the mapping outlives this
 * call and every later read is a plain memory read.
 */
static int setup_pvclock(void)
{
    struct vcpu_time_info *info = this_cpu(kvm_time);

    if ( !info )
    {
        info = alloc_xenheap_page();
        if ( !info )
            return -ENOMEM;

        clear_page(info);
        this_cpu(kvm_time) = info;
    }

    wrmsrl(MSR_KVM_SYSTEM_TIME_NEW, virt_to_maddr(info) | KVM_MSR_ENABLED);

    return 0;
}

const struct vcpu_time_info *kvm_pvclock(void)
{
    return this_cpu(kvm_time);
}

bool kvm_pvclock_stable(void)
{
    /*
     * The host's promise that the guest TSC -- and therefore every vCPU's
     * pvclock derived from it -- is stable and synchronised.  Taken from CPUID
     * rather than from the flags in the page: this decides whether the clock is
     * fit to be a single global counter, which is a property of the host, not
     * of one update.
     */
    return kvm_cpuid_base &&
           (cpuid_eax(kvm_cpuid_base + 1) & KVM_FEATURE_CLOCKSOURCE_STABLE_BIT);
}

static void __init cf_check setup(void)
{
    if ( setup_pvclock() )
        printk(XENLOG_WARNING "KVM: no pvclock for the boot CPU\n");
}

static int cf_check ap_setup(void)
{
    /*
     * An AP without a pvclock would read a zeroed page and report a system time
     * of 0, which is worse than a slow clock: fail the CPU rather than let it
     * corrupt the platform timer.
     */
    return setup_pvclock();
}

static void cf_check resume(void)
{
    /*
     * The MSR does not survive a suspend, and the page contents are stale until
     * L0 writes them again.  Re-arm before anything reads the clock; the
     * platform timer's own resume hook drops the monotonic floor it kept.
     */
    if ( setup_pvclock() )
        printk(XENLOG_WARNING "KVM: could not restore pvclock after resume\n");
}

static const struct hypervisor_ops __initconst_cf_clobber ops = {
    .name = "KVM",
    .setup = setup,
    .ap_setup = ap_setup,
    .resume = resume,
};

const struct hypervisor_ops *__init kvm_probe(void)
{
    if ( kvm_guest )
        return &ops;

    find_kvm_leaves();

    if ( !kvm_cpuid_base )
        return NULL;

    /*
     * Only claim to be running under KVM when it offers the clock we came for.
     * Everything else Xen needs it already has, so a KVM without
     * CLOCKSOURCE2 is better left looking like bare metal.
     */
    if ( !(cpuid_eax(kvm_cpuid_base + 1) & KVM_FEATURE_CLOCKSOURCE2) )
        return NULL;

    kvm_guest = true;

    return &ops;
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
