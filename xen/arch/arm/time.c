/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/time.c
 *
 * Time and timer support, using the ARM Generic Timer interfaces
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
 */

#include <xen/acpi.h>
#include <xen/console.h>
#include <xen/cpu.h>
#include <xen/delay.h>
#include <xen/device_tree.h>
#include <xen/event.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/mm.h>
#include <xen/muldiv64.h>
#include <xen/notifier.h>
#include <xen/sched.h>
#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/timer.h>

#include <asm/cpufeature.h>
#include <asm/platform.h>
#include <asm/system.h>
#include <asm/vgic.h>
#include <asm/vtimer.h>

uint64_t __read_mostly boot_count;

/* For fine-grained timekeeping, we use the ARM "Generic Timer", a
 * register-mapped time source in the SoC. */
unsigned long __read_mostly cpu_khz;  /* CPU clock frequency in kHz. */

uint32_t __read_mostly timer_dt_clock_frequency;

static unsigned int timer_irq[MAX_TIMER_PPI];

unsigned int timer_get_irq(enum timer_ppi ppi)
{
    ASSERT(ppi >= TIMER_PHYS_SECURE_PPI && ppi < MAX_TIMER_PPI);

    return timer_irq[ppi];
}

static __initdata struct dt_device_node *timer;

#ifdef CONFIG_ACPI
static u32 __init acpi_get_timer_irq_type(u32 flags)
{
    return (flags & ACPI_GTDT_INTERRUPT_MODE) ? IRQ_TYPE_EDGE_BOTH
                                              : IRQ_TYPE_LEVEL_MASK;
}

/* Initialize per-processor generic timer */
static int __init arch_timer_acpi_init(struct acpi_table_header *header)
{
    u32 irq_type;
    struct acpi_table_gtdt *gtdt;

    gtdt = container_of(header, struct acpi_table_gtdt, header);

    /* Initialize all the generic timer IRQ variable from GTDT table */
    irq_type = acpi_get_timer_irq_type(gtdt->non_secure_el1_flags);
    irq_set_type(gtdt->non_secure_el1_interrupt, irq_type);
    timer_irq[TIMER_PHYS_NONSECURE_PPI] = gtdt->non_secure_el1_interrupt;

    irq_type = acpi_get_timer_irq_type(gtdt->virtual_timer_flags);
    irq_set_type(gtdt->virtual_timer_interrupt, irq_type);
    timer_irq[TIMER_VIRT_PPI] = gtdt->virtual_timer_interrupt;

    irq_type = acpi_get_timer_irq_type(gtdt->non_secure_el2_flags);
    irq_set_type(gtdt->non_secure_el2_interrupt, irq_type);
    timer_irq[TIMER_HYP_PPI] = gtdt->non_secure_el2_interrupt;

    return 0;
}

static void __init preinit_acpi_xen_time(void)
{
    acpi_table_parse(ACPI_SIG_GTDT, arch_timer_acpi_init);
}
#else
static void __init preinit_acpi_xen_time(void) { }
#endif

static void __init validate_timer_frequency(void)
{
    /*
     * ARM ARM does not impose any strict limit on the range of allowable
     * system counter frequencies. However, we operate under the assumption
     * that cpu_khz must not be 0.
     */
    if ( !cpu_khz )
        panic("Timer frequency is less than 1 KHz\n");
}

/* Set up the timer on the boot CPU (early init function) */
static void __init preinit_dt_xen_time(void)
{
    static const struct dt_device_match timer_ids[] __initconst =
    {
        DT_MATCH_TIMER,
        { /* sentinel */ },
    };
    int res;
    u32 rate;

    timer = dt_find_matching_node(NULL, timer_ids);
    if ( !timer )
        panic("Unable to find a compatible timer in the device tree\n");

    dt_device_set_used_by(timer, DOMID_XEN);

    res = dt_property_read_u32(timer, "clock-frequency", &rate);
    if ( res )
    {
        cpu_khz = DIV_ROUND(rate, 1000);
        validate_timer_frequency();
        timer_dt_clock_frequency = rate;
    }
}

void __init preinit_xen_time(void)
{
    int res;

    /* Initialize all the generic timers presented in GTDT */
    if ( acpi_disabled )
        preinit_dt_xen_time();
    else
        preinit_acpi_xen_time();

    if ( !cpu_khz )
    {
        cpu_khz = DIV_ROUND(READ_SYSREG(CNTFRQ_EL0) & CNTFRQ_MASK, 1000);
        validate_timer_frequency();
    }

    res = platform_init_time();
    if ( res )
        panic("Timer: Cannot initialize platform timer\n");

    boot_count = get_cycles();
}

static void __init init_dt_xen_time(void)
{
    int res;
    unsigned int i;
    bool has_names;
    static const char * const timer_irq_names[MAX_TIMER_PPI] __initconst = {
        [TIMER_PHYS_SECURE_PPI] = "sec-phys",
        [TIMER_PHYS_NONSECURE_PPI] = "phys",
        [TIMER_VIRT_PPI] = "virt",
        [TIMER_HYP_PPI] = "hyp-phys",
        [TIMER_HYP_VIRT_PPI] = "hyp-virt",
    };

    has_names = dt_property_read_bool(timer, "interrupt-names");

    /* Retrieve all IRQs for the timer */
    for ( i = TIMER_PHYS_SECURE_PPI; i < MAX_TIMER_PPI; i++ )
    {
        if ( has_names )
            res = platform_get_irq_byname(timer, timer_irq_names[i]);
        else
            res = platform_get_irq(timer, i);

        if ( res > 0 )
            timer_irq[i] = res;
        /*
         * Do not panic if "hyp-virt" PPI is not found, since it's not
         * currently used.
         *
         * "sec-phys" is likewise not required: the arm,armv8-timer binding
         * makes it optional, and a system with no Secure world simply has no
         * secure physical timer to describe.  Apple Silicon has no EL3, so its
         * timer node lists only phys/virt/hyp-phys/hyp-virt.  Consumers of
         * this PPI substitute GUEST_TIMER_PHYS_S_PPI when it is absent.
         */
        else if ( i != TIMER_HYP_VIRT_PPI && i != TIMER_PHYS_SECURE_PPI )
            panic("Timer: Unable to retrieve IRQ %u from the device tree\n", i);
    }
}

/* Set up the timer on the boot CPU (late init function) */
int __init init_xen_time(void)
{
    if ( acpi_disabled )
        init_dt_xen_time();

    /* Check that this CPU supports the Generic Timer interface */
    if ( !cpu_has_gentimer )
        panic("CPU does not support the Generic Timer v1 interface\n");

    printk("Generic Timer IRQ: phys=%u hyp=%u virt=%u Freq: %lu KHz\n",
           timer_irq[TIMER_PHYS_NONSECURE_PPI],
           timer_irq[TIMER_HYP_PPI],
           timer_irq[TIMER_VIRT_PPI],
           cpu_khz);

    return 0;
}

/* Return number of nanoseconds since boot */
s_time_t get_s_time(void)
{
    uint64_t ticks = get_cycles() - boot_count;
    return ticks_to_ns(ticks);
}

/* Set the timer to wake us up at a particular time.
 * Timeout is a Xen system time (nanoseconds since boot); 0 disables the timer.
 * Returns 1 on success; 0 if the timeout is too soon or is in the past. */
int reprogram_timer(s_time_t timeout)
{
    uint64_t deadline;

    if ( timeout == 0 )
    {
        WRITE_SYSREG(0, CNTHP_CTL_EL2);
        return 1;
    }

    deadline = ns_to_ticks(timeout) + boot_count;
    WRITE_SYSREG64(deadline, CNTHP_CVAL_EL2);
    WRITE_SYSREG(CNTx_CTL_ENABLE, CNTHP_CTL_EL2);
    isb();

    /* No need to check for timers in the past; the Generic Timer fires
     * on a signed 63-bit comparison. */
    return 1;
}

/* Handle the firing timer */
static void htimer_interrupt(int irq, void *dev_id)
{
    if ( unlikely(!(READ_SYSREG(CNTHP_CTL_EL2) & CNTx_CTL_PENDING)) )
        return;

    perfc_incr(hyp_timer_irqs);

    /* Signal the generic timer code to do its work */
    raise_softirq(TIMER_SOFTIRQ);

    /* Disable the timer to avoid more interrupts */
    WRITE_SYSREG(0, CNTHP_CTL_EL2);
}

/*
 * How long the virtual timer's PPI stays disabled at the GIC once it has been
 * caught asserting with nothing left to deliver.  It bounds the wasted
 * interrupt rate, and it bounds the delay added to a guest timer interrupt
 * that becomes deliverable while the PPI is off -- a millisecond, which no
 * part of a guest's boot can tell from jitter.
 */
#define VTIMER_QUIESCE_PERIOD  MILLISECS(1)

static DEFINE_PER_CPU(struct timer, vtimer_requiesce);
static DEFINE_PER_CPU(bool, vtimer_requiesce_ready);

static void vtimer_ppi_set_enabled(bool enable)
{
    struct irq_desc *desc = irq_to_desc(timer_irq[TIMER_VIRT_PPI]);
    unsigned long flags;

    spin_lock_irqsave(&desc->lock, flags);
    if ( enable )
        desc->handler->enable(desc);
    else
        desc->handler->disable(desc);
    spin_unlock_irqrestore(&desc->lock, flags);
}

static void cf_check vtimer_requiesce_expired(void *unused)
{
    vtimer_ppi_set_enabled(true);
}

/*
 * Nothing Xen can write to the timer stops the line, so stop listening to it
 * instead, and look again in a millisecond.  The guest is owed exactly one
 * virtual timer interrupt and already has it queued in its vGIC, so there is
 * nothing to deliver in the meantime.
 */
static void vtimer_ppi_quiesce(void)
{
    struct timer *t = &this_cpu(vtimer_requiesce);

    perfc_incr(virt_timer_quiesce);

    vtimer_ppi_set_enabled(false);

    /*
     * Initialised here rather than in init_timer_interrupt(), which runs on
     * each CPU before the timer subsystem is usable.  Nothing can reach this
     * until a guest is running, by which point it long since is.
     */
    if ( unlikely(!this_cpu(vtimer_requiesce_ready)) )
    {
        init_timer(t, vtimer_requiesce_expired, NULL, smp_processor_id());
        this_cpu(vtimer_requiesce_ready) = true;
    }

    set_timer(t, NOW() + VTIMER_QUIESCE_PERIOD);
}

/*
 * Say this with everything needed to tell the failures apart: a platform that
 * ignores the write, a platform that takes the write but drives the interrupt
 * line from somewhere else, and a platform where Xen is not writing the copy
 * of the register the guest is using -- for which CNTV_CVAL is the tell, since
 * Xen never programs it and the guest always does.
 *
 * Repeat it rather than saying it once.  The first of these happens seconds
 * into a boot, at the top of a log that is the easiest part to lose.
 */
static void vtimer_report_stuck(register_t before, register_t after)
{
    static unsigned long count;
    unsigned long n = ++count;

    if ( n > 4 && (n & 0xfff) )
        return;

    printk(XENLOG_ERR
           "CPU%u: %pv's virtual timer fired again with IMASK already set (#%lu)\n",
           smp_processor_id(), current, n);
    printk(XENLOG_ERR
           "  CNTV_CTL %"PRIregister" -> %"PRIregister", CNTVCT %016"PRIx64", CNTV_CVAL %016"PRIx64", CNTVOFF %016"PRIx64"\n",
           before, after, READ_SYSREG64(CNTVCT_EL0),
           READ_SYSREG64_EL0(CNTV_CVAL), READ_SYSREG64(CNTVOFF_EL2));
    printk(XENLOG_ERR "  %s\n",
           (after & CNTx_CTL_PENDING)
           ? "ISTATUS still reads set with the deadline in the future: this read is not live"
           : "ISTATUS cleared with the deadline; the guest re-arms it itself");
}

static void vtimer_interrupt(int irq, void *dev_id)
{
    register_t ctl;

    /*
     * Edge-triggered interrupts can be used for the virtual timer. Even
     * if the timer output signal is masked in the context switch, the
     * GIC will keep track that of any interrupts raised while IRQS are
     * disabled. As soon as IRQs are re-enabled, the virtual interrupt
     * will be injected to Xen.
     *
     * No guest on this pCPU, so there is nobody to inject into -- but there
     * is still a line to quiet.  Ignoring it is what upstream does, and it is
     * right on a platform where virt_timer_save()'s clearing of ENABLE stops
     * the timer; here it does not, because the output follows the comparator
     * and nothing else, so the guest's expired deadline keeps the line up
     * with the idle vCPU in front of it.  Boot 18 took 9,609,700 of these on
     * CPU0 in thirty seconds -- 330,000 a second, uncounted because this
     * return is above the counter -- and starved the runnable dom0 vCPU that
     * was waiting for that very pCPU to reach its scheduler.
     *
     * Push the deadline out, the same lever that works for a running guest.
     * Nothing is lost: the guest's real deadline is already saved in
     * v->arch.virt_timer.cval and virt_timer_restore() writes it back before
     * the guest runs again.
     */
    if ( unlikely(is_idle_vcpu(current)) )
    {
        perfc_incr(virt_timer_no_guest);

        WRITE_SYSREG64_EL0(VTIMER_CVAL_PUSHED, CNTV_CVAL);
        WRITE_SYSREG_EL0(READ_SYSREG_EL0(CNTV_CTL) | CNTx_CTL_MASK, CNTV_CTL);
        isb();

        return;
    }

    perfc_incr(virt_timer_irqs);

    ctl = READ_SYSREG_EL0(CNTV_CTL);

    /*
     * IMASK is set here by Xen and by nobody else: a guest that wants its
     * timer quiet clears ENABLE, and a guest that has taken the interrupt
     * re-arms with IMASK clear.  So finding it already set means the line
     * asserted while masked, and the mask is not what gates it on this
     * platform.  Masking again would return straight back here -- boot 7 of
     * the Virtualization.framework bring-up counted 15.5 million of these on
     * the one pCPU running dom0 in fifty seconds, one every time the handler
     * returned, which is why dom0 appeared to hang.
     *
     * Take the timer's other lever instead and clear ENABLE.  The guest gets
     * nothing it has not already been given: the first interrupt is queued in
     * its vGIC, and its handler re-arms the timer with an untrapped write to
     * CNTV_CTL_EL0.
     */
    if ( unlikely(ctl & CNTx_CTL_MASK) )
    {
        perfc_incr(virt_timer_stuck);

        if ( ctl & CNTx_CTL_ENABLE )
            perfc_incr(virt_timer_stuck_on);

        /*
         * Boot 9 measured what the line actually follows.  Neither IMASK nor
         * ENABLE: boot 8 cleared ENABLE on every one of nine million of these
         * and the next one arrived anyway.  That leaves ISTATUS, the only
         * other input to the timer's output, and the only way to clear it from
         * here is to move the deadline the guest set.
         *
         * Do that rather than clearing ENABLE.  Clearing ENABLE was not merely
         * useless, it was harmful: virt_timer_save() arms the software
         * fallback timer only for a vCPU whose timer is enabled and unmasked,
         * so a vCPU descheduled after one of these had no timer left at all.
         * Pushing the deadline out leaves both bits as the guest set them, and
         * the guest un-pushes the deadline itself when it re-arms -- it is
         * about to, because the interrupt this is all about is already queued
         * in its vGIC.
         *
         * Boot 10 says this is the lever: two of these in a whole boot, where
         * boot 9 had a hundred and twelve and ten million interrupts behind
         * them.  It also says not to trust the read-back -- ISTATUS still
         * reads set immediately after a deadline twenty-four thousand years
         * out -- so the register Xen reads and the comparison the interrupt
         * line is derived from are not the same thing.  The write reaches the
         * one that matters.
         */
        current->arch.virt_timer.cval = READ_SYSREG64_EL0(CNTV_CVAL);
        WRITE_SYSREG64_EL0(VTIMER_CVAL_PUSHED, CNTV_CVAL);
        WRITE_SYSREG_EL0(ctl | CNTx_CTL_MASK, CNTV_CTL);
        isb();
        vtimer_report_stuck(ctl, READ_SYSREG_EL0(CNTV_CTL));

        /*
         * Still mask the PPI as a backstop, for the case where the line is not
         * this timer's output at all.  "IRQs taken while disabled at the GIC"
         * says whether that mask is being honoured -- boot 9 left ten million
         * interrupts unaccounted for, and the silent drop here is where they
         * would have gone.
         */
        vtimer_ppi_quiesce();

        return;
    }

    current->arch.virt_timer.ctl = ctl;
    WRITE_SYSREG_EL0(ctl | CNTx_CTL_MASK, CNTV_CTL);
    vgic_inject_irq(current->domain, current, current->arch.virt_timer.irq, true);
}

/*
 * Arch timer interrupt really ought to be level triggered, since the
 * design of the timer/comparator mechanism is based around that
 * concept.
 *
 * However some firmware (incorrectly) describes the interrupts as
 * edge triggered and, worse, some hardware allows us to program the
 * interrupt controller as edge triggered.
 *
 * Check each interrupt and warn if we find ourselves in this situation.
 */
static void check_timer_irq_cfg(unsigned int irq, const char *which)
{
    struct irq_desc *desc = irq_to_desc(irq);

    /*
     * The interrupt controller driver will update desc->arch.type with
     * the actual type which ended up configured in the hardware.
     */
    if ( desc->arch.type & IRQ_TYPE_LEVEL_MASK )
        return;

    printk(XENLOG_WARNING
           "WARNING: %s-timer IRQ%u is not level triggered.\n", which, irq);
}

static DEFINE_PER_CPU_READ_MOSTLY(struct irqaction, irq_hyp);
static DEFINE_PER_CPU_READ_MOSTLY(struct irqaction, irq_virt);

/* Set up the timer interrupt on this CPU */
void init_timer_interrupt(void)
{
    struct irqaction *hyp_action = &this_cpu(irq_hyp);
    struct irqaction *virt_action = &this_cpu(irq_virt);

    /* Sensible defaults */
    WRITE_SYSREG64(0, CNTVOFF_EL2);     /* No VM-specific offset */
    /* Do not let the VMs program the physical timer, only read the physical counter */
    WRITE_SYSREG(CNTHCTL_EL2_EL1PCTEN, CNTHCTL_EL2);
    WRITE_SYSREG_EL0(0, CNTP_CTL);    /* Physical timer disabled */
    WRITE_SYSREG(0, CNTHP_CTL_EL2);   /* Hypervisor's timer disabled */
    isb();

    hyp_action->name = "hyptimer";
    hyp_action->handler = htimer_interrupt;
    hyp_action->dev_id = NULL;
    hyp_action->free_on_release = 0;
    setup_irq(timer_irq[TIMER_HYP_PPI], 0, hyp_action);

    virt_action->name = "virtimer";
    virt_action->handler = vtimer_interrupt;
    virt_action->dev_id = NULL;
    virt_action->free_on_release = 0;
    setup_irq(timer_irq[TIMER_VIRT_PPI], 0, virt_action);

    check_timer_irq_cfg(timer_irq[TIMER_HYP_PPI], "hypervisor");
    check_timer_irq_cfg(timer_irq[TIMER_VIRT_PPI], "virtual");
    check_timer_irq_cfg(timer_irq[TIMER_PHYS_NONSECURE_PPI], "NS-physical");
}

static void __init cf_check timer_selftest_fired(void *data)
{
    write_atomic((bool *)data, true);
}

/*
 * Everything Xen does after boot that is not driven by a guest rests on the
 * hypervisor timer's PPI arriving: the scheduler tick, every polled console
 * driver -- so console *input*, and with it the debug keys -- and every
 * timeout in the tree.  Nothing during boot needs it, though, because the
 * boot path reads the counter rather than waiting on the interrupt.  So a
 * machine that does not deliver it boots to the very end looking healthy and
 * then quietly stops, with no console left to ask about it.
 *
 * That is not hypothetical: an EL2 whose outer hypervisor has to emulate
 * CNTHP_EL2 for a nested guest may well not, since the obvious thing to run
 * nested -- Linux with KVM in nVHE mode -- never programs it.
 *
 * So spend 10ms here proving the interrupt arrives, while there is still a
 * console to say so on.  The wait polls softirqs by hand because a timer
 * fires from TIMER_SOFTIRQ, which nothing would otherwise run this early.
 */
void __init check_timer_interrupt_delivery(void)
{
    static bool __initdata fired;
    struct timer t;
    s_time_t give_up;

    init_timer(&t, timer_selftest_fired, &fired, smp_processor_id());
    set_timer(&t, NOW() + MILLISECS(10));

    give_up = NOW() + SECONDS(1);
    while ( !read_atomic(&fired) && NOW() < give_up )
        process_pending_softirqs();

    kill_timer(&t);

    if ( read_atomic(&fired) )
    {
        printk("Hypervisor timer IRQ%u works\n", timer_irq[TIMER_HYP_PPI]);
        return;
    }

    printk(XENLOG_ERR
           "Hypervisor timer IRQ%u never fired.  Xen has no working timer:\n"
           "  - the scheduler will never preempt a guest;\n"
           "  - polled consoles will never poll, so no input reaches Xen and\n"
           "    'CTRL-a' three times followed by a debug key will do nothing;\n"
           "  - a guest waiting on its own first timer interrupt will hang.\n",
           timer_irq[TIMER_HYP_PPI]);
}

/*
 * Revert actions done in init_timer_interrupt that are required to properly
 * disable this CPU.
 */
static void deinit_timer_interrupt(void)
{
    WRITE_SYSREG_EL0(0, CNTP_CTL);    /* Disable physical timer */
    WRITE_SYSREG(0, CNTHP_CTL_EL2);   /* Disable hypervisor's timer */
    isb();

    release_irq(timer_irq[TIMER_HYP_PPI], NULL);
    release_irq(timer_irq[TIMER_VIRT_PPI], NULL);
}

/* Wait a set number of microseconds */
void udelay(unsigned long usecs)
{
    s_time_t deadline = get_s_time() + 1000 * (s_time_t) usecs;
    while ( get_s_time() - deadline < 0 )
        ;
    dsb(sy);
    isb();
}

/* VCPU PV timers. */
void send_timer_event(struct vcpu *v)
{
    send_guest_vcpu_virq(v, VIRQ_TIMER);
}

/* VCPU PV clock. */
void update_vcpu_system_time(struct vcpu *v)
{
    /* XXX update shared_info->wc_* */
}

void force_update_vcpu_system_time(struct vcpu *v)
{
    update_vcpu_system_time(v);
}

void domain_set_time_offset(struct domain *d, int64_t time_offset_seconds)
{
    d->time_offset.seconds = time_offset_seconds;
    d->time_offset.set = true;
    /* XXX update guest visible wallclock time */
}

static int cpu_time_callback(struct notifier_block *nfb,
                             unsigned long action,
                             void *hcpu)
{
    switch ( action )
    {
    case CPU_DYING:
        deinit_timer_interrupt();
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpu_time_nfb = {
    .notifier_call = cpu_time_callback,
};

static int __init cpu_time_notifier_init(void)
{
    register_cpu_notifier(&cpu_time_nfb);

    return 0;
}
__initcall(cpu_time_notifier_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
