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
         * secure physical timer to describe.  A platform with no EL3 lists
         * only phys/virt/hyp-phys/hyp-virt in its timer node.  Consumers of
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
 * How long the virtual timer's PPI stays masked once it has been caught
 * asserting with nothing left to deliver.  It is a floor under every guest
 * timer: a deadline falling inside the window is not delivered until the
 * window ends, so it has to stay well under what a guest arming a short
 * hrtimer would notice.
 *
 * The cost of being too short is one more spurious interrupt, which the
 * virt_timer_* performance counters show and which is bounded by how long the
 * guest takes to service the one it already has.
 */
#define VTIMER_QUIESCE_PERIOD  MICROSECS(50)

static DEFINE_PER_CPU(struct timer, vtimer_poll);
static DEFINE_PER_CPU(bool, vtimer_poll_ready);
static DEFINE_PER_CPU(bool, vtimer_ppi_masked);

static void vtimer_ppi_set_enabled(bool enable)
{
    struct irq_desc *desc = irq_to_desc(timer_irq[TIMER_VIRT_PPI]);
    unsigned long flags;

    /* Idempotent: several callers reach for this. */
    if ( this_cpu(vtimer_ppi_masked) == !enable )
        return;

    spin_lock_irqsave(&desc->lock, flags);
    if ( enable )
        desc->handler->enable(desc);
    else
        desc->handler->disable(desc);
    spin_unlock_irqrestore(&desc->lock, flags);

    this_cpu(vtimer_ppi_masked) = !enable;
}

static void cf_check vtimer_poll_expired(void *unused);

/*
 * Ask again in a little while.  A Xen timer rather than an interrupt, so while
 * the PPI is held down the pCPU costs a softirq every so often instead of an
 * exception every few microseconds, and the guest gets the CPU it needs to
 * re-arm.
 *
 * Initialised on first use rather than in init_timer_interrupt(), which runs
 * on each CPU before the timer subsystem is usable.  Nothing reaches this
 * until a guest is running, by which point it long since is.
 */
static void vtimer_ppi_poll_again(void)
{
    struct timer *t = &this_cpu(vtimer_poll);

    if ( unlikely(!this_cpu(vtimer_poll_ready)) )
    {
        init_timer(t, vtimer_poll_expired, NULL, smp_processor_id());
        this_cpu(vtimer_poll_ready) = true;
    }

    set_timer(t, NOW() + VTIMER_QUIESCE_PERIOD);
}

/*
 * Every path that wants the PPI back -- virt_timer_restore() on the pCPU a
 * guest is about to run on, the retire hook when the guest finishes with the
 * interrupt, and the poll above -- comes through here, and none of them may
 * have it while IMASK is still set.
 *
 * IMASK is Xen's marker for an interrupt injected and not yet acknowledged, so
 * unmasking under it puts a line that does not follow IMASK straight back into
 * the handler, and the vCPU never runs long enough to re-arm the deadline that
 * would have stopped it.  Defer instead, and keep polling, because only the
 * guest can end this and it can only do so by running.
 */
void vtimer_ppi_unmask(void)
{
    if ( likely(!this_cpu(vtimer_ppi_masked)) )
        return;

    if ( READ_SYSREG(CNTV_CTL_EL0) & CNTx_CTL_MASK )
    {
        perfc_incr(virt_timer_unmask_no);
        vtimer_ppi_poll_again();
        return;
    }

    perfc_incr(virt_timer_unmask);
    vtimer_ppi_set_enabled(true);
}

static void cf_check vtimer_poll_expired(void *unused)
{
    vtimer_ppi_unmask();
}

/*
 * Stop listening to the line and look again shortly.  The guest is owed
 * exactly one virtual timer interrupt and already has it queued in its vGIC,
 * so there is nothing to deliver in the meantime.
 */
static void vtimer_ppi_quiesce(void)
{
    perfc_incr(virt_timer_quiesce);

    vtimer_ppi_set_enabled(false);
    vtimer_ppi_poll_again();
}

static DEFINE_PER_CPU(unsigned long, vtimer_noise);
static DEFINE_PER_CPU(s_time_t, vtimer_noise_window);
static DEFINE_PER_CPU(s_time_t, vtimer_noise_said);

/*
 * Report a line that will not quiet, with enough state to tell the failure
 * modes apart: a platform that ignores the write, a platform that takes the
 * write but drives the line from somewhere else, and a platform where Xen is
 * not writing the copy of the register the guest is using -- for which
 * CNTV_CVAL is the tell, since Xen never programs it and the guest always
 * does.
 *
 * One spurious assertion per guest tick is the expected shape of this, so a
 * count is not news and a line per interrupt would be a storm of its own.  A
 * *rate* is news.  Say the first one, then at most one line a second for as
 * long as the rate stays pathological, and nothing at all in between.
 *
 * The clock read is taken once every 4096 interrupts rather than on each one.
 * At any rate worth reporting that is far more often than once a second; at a
 * sane one it costs nothing that matters.
 */
static void vtimer_note(const char *what)
{
    unsigned long n = ++this_cpu(vtimer_noise);
    s_time_t now;

    if ( likely(n != 1 && (n & 0xfff)) )
        return;

    now = NOW();

    if ( n == 1 ||
         (now - this_cpu(vtimer_noise_window) < SECONDS(1) &&
          now - this_cpu(vtimer_noise_said) >= SECONDS(1)) )
    {
        printk(XENLOG_ERR "CPU%u: virtual timer %s (#%lu)\n",
               smp_processor_id(), what, n);
        printk(XENLOG_ERR
               "  CNTV_CTL %"PRIregister", CNTVCT %016"PRIx64", CNTV_CVAL %016"PRIx64", CNTVOFF %016"PRIx64"\n",
               READ_SYSREG(CNTV_CTL_EL0), READ_SYSREG64(CNTVCT_EL0),
               READ_SYSREG64(CNTV_CVAL_EL0), READ_SYSREG64(CNTVOFF_EL2));

        this_cpu(vtimer_noise_said) = now;
    }

    this_cpu(vtimer_noise_window) = now;
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
     * If an IDLE vCPU was scheduled next there is nobody to inject into --
     * but there may still be a line to quiet.  Ignoring it is right where
     * virt_timer_save()'s clearing of ENABLE stops the timer; where it does
     * not, the guest's expired deadline keeps the line up with the idle vCPU
     * in front of it and the handler returns straight into the same
     * interrupt, starving the pCPU.
     *
     * Mask the PPI instead.  Nothing is lost by holding it: Xen does not use
     * the virtual timer for itself, and virt_timer_restore() unmasks it before
     * a guest runs here again.
     */
    if ( unlikely(is_idle_vcpu(current)) )
    {
        perfc_incr(virt_timer_no_guest);
        vtimer_note("asserted with no guest on the pCPU");
        vtimer_ppi_set_enabled(false);

        return;
    }

    perfc_incr(virt_timer_irqs);

    ctl = READ_SYSREG(CNTV_CTL_EL0);

    /*
     * IMASK is set here by Xen and by nobody else: a guest that wants its
     * timer quiet clears ENABLE, and a guest that has taken the interrupt
     * re-arms with IMASK clear.  So finding it already set means the line
     * asserted while masked, and the mask is not what gates it on this
     * platform.  Masking again would return straight back here.
     *
     * The guest is owed nothing it has not already been given: its interrupt
     * is queued in its vGIC, and its handler re-arms the timer with an
     * untrapped write to CNTV_CTL_EL0, which is the only thing that clears
     * IMASK again.  There is nothing to inject and nothing useful to write --
     * in particular not CNTV_CVAL, whose read need not return what the guest
     * programmed, so saving it would replace the guest's deadline with
     * whatever Xen last wrote and virt_timer_restore() would then hand that
     * back to the guest.  Mask the PPI and let the quiesce timer bring it
     * back.
     */
    if ( unlikely(ctl & CNTx_CTL_MASK) )
    {
        perfc_incr(virt_timer_stuck);
        vtimer_note("asserted again while masked");
        vtimer_ppi_quiesce();

        return;
    }

    current->arch.virt_timer.ctl = ctl;
    WRITE_SYSREG(ctl | CNTx_CTL_MASK, CNTV_CTL_EL0);
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
    WRITE_SYSREG(0, CNTP_CTL_EL0);    /* Physical timer disabled */
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

/*
 * Revert actions done in init_timer_interrupt that are required to properly
 * disable this CPU.
 */
static void deinit_timer_interrupt(void)
{
    WRITE_SYSREG(0, CNTP_CTL_EL0);    /* Disable physical timer */
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
