/*
 * xen/arch/arm/aic.c
 *
 * Apple Interrupt Controller (AIC) driver -- physical layer.
 *
 * Apple Silicon has no ARM GIC; interrupts are managed by the AIC, an MMIO +
 * IMP-DEF-sysreg controller with a completely different model (see
 * plans/asahi/03-interrupt-controller-aic.md).  This file is the physical-side
 * driver.  It:
 *   - matches the "apple,aic" (v1) and "apple,aic2" (v2/v3) interrupt
 *     controllers,
 *   - maps their MMIO windows and probes version / IRQ count / die count,
 *   - derives the per-IRQ register layout (mask/sw arrays, die stride) exactly
 *     as the Asahi Linux driver does,
 *   - registers as the system interrupt controller through the physical half
 *     of the split interface (struct intc_hw_operations): event-register
 *     acknowledge, per-IRQ mask/unmask/EOI, per-CPU init, and DT interrupt
 *     translation for the 3/4-cell AIC specifiers,
 *   - sends IPIs via the IMP-DEF fast-IPI system registers, multiplexing
 *     Xen's logical SGIs over the single hardware IPI with a per-CPU pending
 *     bitmap, and
 *   - provides the FIQ root dispatcher (fast IPIs, EL0/EL2 timers) that
 *     do_trap_fiq() invokes through the handle_fiq hook.
 *
 * Hardware IRQs on die 0 are mapped to Xen linear IRQs at
 * AIC_HWIRQ_BASE + n; FIQ sources (timers, PMU), which have no event number,
 * are given pseudo IDs in the local-IRQ (PPI) range by the DT translation.
 *
 * NOT yet implemented (hardware-gated or later-phase work, see plans/asahi):
 *   - guest interrupt injection (reuse of the GICv3 virtual CPU interface
 *     the cores implement, doc 04) and the maintenance-interrupt FIQ source;
 *   - dispatching timer/PMU FIQs through do_IRQ()/request_irq (doc 04
 *     section 6); the dispatcher currently raises TIMER_SOFTIRQ directly;
 *   - IRQs on dies other than 0 (multi-die M1 Pro/Max/Ultra);
 *   - core/uncore PMU FIQ handling.
 * Register definitions and the layout derivation are ported from the Asahi
 * Linux driver drivers/irqchip/irq-apple-aic.c.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/init.h>
#include <xen/compiler.h>
#include <xen/cpumask.h>
#include <xen/errno.h>
#include <xen/iocap.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/types.h>
#include <xen/device_tree.h>
#include <xen/libfdt/libfdt.h>
#include <xen/xmalloc.h>
#include <asm/device.h>
#include <asm/gic.h>
#include <asm/io.h>
#include <asm/processor.h>
#include <asm/sysregs.h>
#include <asm/system.h>

/*
 * AIC v1 registers (MMIO), single MMIO window, "this CPU" view by default.
 */
#define AIC_INFO                0x0004
#define AIC_INFO_NR_IRQ_MASK    0xffffU

#define AIC_WHOAMI              0x2000
#define AIC_EVENT               0x2004
/* event register fields */
#define AIC_EVENT_DIE_SHIFT     24
#define AIC_EVENT_DIE_MASK      0xffU
#define AIC_EVENT_TYPE_SHIFT    16
#define AIC_EVENT_TYPE_MASK     0xffU
#define AIC_EVENT_NUM_MASK      0xffffU

#define AIC_EVENT_TYPE_FIQ      0   /* software use */
#define AIC_EVENT_TYPE_IRQ      1
#define AIC_EVENT_TYPE_IPI      4

#define AIC_IPI_SEND            0x2008
#define AIC_IPI_ACK             0x200c
#define AIC_IPI_MASK_SET        0x2024
#define AIC_IPI_MASK_CLR        0x2028

/* v1 legacy MMIO IPI types (Xen uses the fast-IPI sysregs instead) */
#define AIC_IPI_OTHER           (1U << 0)
#define AIC_IPI_SELF            (1U << 31)

#define AIC_TARGET_CPU          0x3000
#define AIC_MAX_IRQ             0x400

/*
 * AIC v2/v3 registers (MMIO).  The config window and the per-die "event"
 * window are separate DT reg entries because the implemented die count is not
 * discoverable from a single window.
 */
#define AIC2_VERSION            0x0000
#define AIC2_VERSION_VER_MASK   0xffU
#define AIC2_INFO1              0x0004
#define AIC2_INFO1_NR_IRQ_MASK  0xffffU
#define AIC2_INFO1_LAST_DIE_SHIFT 24
#define AIC2_INFO1_LAST_DIE_MASK  0xfU
#define AIC2_INFO3              0x000c
#define AIC2_INFO3_MAX_IRQ_MASK   0xffffU
#define AIC2_INFO3_MAX_DIE_SHIFT  24
#define AIC2_INFO3_MAX_DIE_MASK   0xfU
#define AIC2_CONFIG             0x0014
#define AIC2_CONFIG_ENABLE      (1U << 0)
#define AIC2_IRQ_CFG            0x2000
#define AIC3_IRQ_CFG            0x10000

/*
 * Per-IRQ mask/sw/hw-state registers are arrays of u32 bitmaps indexed by IRQ.
 * These helpers give the word offset and bit within the array for a given IRQ.
 */
#define AIC_MASK_REG(irq)       (4 * ((irq) >> 5))
#define AIC_MASK_BIT(irq)       (1U << ((irq) & 0x1f))

/*
 * Apple IMP-DEF system registers used for "fast IPIs", the guest-timer FIQ
 * enable, and the core/uncore PMU.  These are the sys_reg(op0,op1,crn,crm,op2)
 * encodings from the Asahi driver, written as the S<op0>_<op1>_C<crn>_C<crm>_<op2>
 * tokens the assembler accepts.
 */
#define SYS_IMP_APL_IPI_RR_LOCAL_EL1    S3_5_C15_C0_0
#define SYS_IMP_APL_IPI_RR_GLOBAL_EL1   S3_5_C15_C0_1
#define SYS_IMP_APL_IPI_SR_EL1          S3_5_C15_C1_1
#define SYS_IMP_APL_IPI_CR_EL1          S3_5_C15_C3_1
#define SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2  S3_5_C15_C1_3
#define SYS_IMP_APL_PMCR0_EL1           S3_1_C15_C0_0
#define SYS_IMP_APL_UPMCR0_EL1          S3_7_C15_C0_4
#define SYS_IMP_APL_UPMSR_EL1           S3_7_C15_C6_4

#define IPI_RR_CPU_MASK         0xffU           /* target CPU in cluster [7:0] */
#define IPI_RR_CLUSTER_SHIFT    16              /* target cluster [23:16]      */
#define IPI_SR_PENDING          (1U << 0)

#define VM_TMR_FIQ_ENABLE_V     (1U << 0)
#define VM_TMR_FIQ_ENABLE_P     (1U << 1)

#define PMCR0_IMODE_MASK        (0x7U << 16)
#define PMCR0_IMODE_OFF         (0U << 16)
#define PMCR0_IACT              (1U << 0)

#define UPMCR0_IMODE_MASK       (0x7U << 16)
#define UPMCR0_IMODE_OFF        (0U << 16)

/* ARM generic-timer control bits (CNT{P,V}_CTL_EL0). */
#define TMR_CTL_ENABLE          (1U << 0)
#define TMR_CTL_IMASK           (1U << 1)
#define TMR_CTL_ISTATUS         (1U << 2)
#define TMR_FIRING(ctl)         (((ctl) & (TMR_CTL_ENABLE | TMR_CTL_IMASK | \
                                           TMR_CTL_ISTATUS)) == \
                                 (TMR_CTL_ENABLE | TMR_CTL_ISTATUS))

/*
 * Xen linear IRQ numbering: 0-31 are the per-CPU "local" IRQs (SGI/PPI space
 * on a GIC).  Apple has no PPIs, so die-0 AIC hardware IRQ n becomes Xen IRQ
 * AIC_HWIRQ_BASE + n, and the FIQ sources (timers, PMU), which have no event
 * number at all, are given pseudo IDs in the PPI range (16 + index) by
 * aic_irq_xlate() so the standard request_irq() flow can be used for them.
 */
#define AIC_HWIRQ_BASE          NR_GIC_LOCAL_IRQS

/*
 * AIC event numbers are dense from 0, but the Xen/GIC INTID space they are
 * mapped into is not: 1020-1023 are reserved, so only events below
 * AIC_NR_SPI_EVENTS fit as plain SPIs.  Everything above goes into the GICv3.1
 * extended SPI range at ESPI_BASE_INTID, in order, so the two ranges together
 * cover every event the controller has:
 *
 *   event < AIC_NR_SPI_EVENTS : INTID = AIC_HWIRQ_BASE + event
 *   event >= AIC_NR_SPI_EVENTS: INTID = ESPI_BASE_INTID +
 *                                       (event - AIC_NR_SPI_EVENTS)
 *
 * On an M2 the only events past the SPI range belong to the USB controllers
 * and their DARTs.
 */
#define AIC_NR_SPI_EVENTS       (1020U - AIC_HWIRQ_BASE)

static inline bool aic_event_is_espi(unsigned int event)
{
    return IS_ENABLED(CONFIG_GICV3_ESPI) && event >= AIC_NR_SPI_EVENTS;
}

/* AIC event number -> Xen INTID.  The caller must have range-checked event. */
static inline unsigned int aic_event_to_irq(unsigned int event)
{
    if ( aic_event_is_espi(event) )
        return espi_idx_to_intid(event - AIC_NR_SPI_EVENTS);

    return AIC_HWIRQ_BASE + event;
}

/* Xen INTID -> AIC event number; the inverse of aic_event_to_irq(). */
static inline unsigned int aic_irq_to_event(unsigned int irq)
{
    if ( is_espi(irq) )
        return AIC_NR_SPI_EVENTS + espi_intid_to_idx(irq);

    return irq - AIC_HWIRQ_BASE;
}
#define AIC_FIQ_PSEUDO_BASE     16

/* AIC FIQ source indexes (dt-bindings/interrupt-controller/apple-aic.h). */
#define AIC_TMR_HV_PHYS         0
#define AIC_TMR_HV_VIRT         1
#define AIC_TMR_GUEST_PHYS      2
#define AIC_TMR_GUEST_VIRT      3
#define AIC_CPU_PMU_E           4
#define AIC_CPU_PMU_P           5
/*
 * The vGIC maintenance interrupt is not an AIC event and is not described in
 * the device tree; it is signalled by the CPU interface through ICH_MISR_EL2.
 * Give it an FIQ index anyway so it can be requested and dispatched like any
 * other per-CPU source, exactly as the Asahi driver does.
 */
#define AIC_VGIC_MI             6
#define AIC_NR_FIQ              7

/* Cell 0 of an AIC DT interrupt specifier. */
#define AIC_SPEC_IRQ            0
#define AIC_SPEC_FIQ            1

/* Sentinel returned by aic_read_irq() when no event is pending. */
#define AIC_SPURIOUS_IRQ        1023

struct aic {
    void __iomem *base;         /* config / main MMIO window            */
    void __iomem *event;        /* window holding the event register    */
    unsigned int event_off;     /* offset of event register in .event   */
    unsigned int version;       /* 1, 2 or 3                            */
    unsigned int nr_irq;        /* implemented hardware IRQs            */
    unsigned int max_irq;       /* IRQ register-array sizing            */
    unsigned int nr_die;        /* implemented dies (1 on v1)           */
    /* Derived per-IRQ register bases (see plans/asahi/03 section 4). */
    unsigned int sw_set;
    unsigned int sw_clr;
    unsigned int mask_set;
    unsigned int mask_clr;
    unsigned int die_stride;
    /* Physical MMIO windows, for hwdom iomem denial. */
    paddr_t base_paddr, base_size;
    paddr_t event_paddr, event_size;
    struct dt_device_node *node;
};

static struct aic aic __read_mostly;

static struct intc_info aic_intc_info;

/*
 * struct intc_info carries nr_espi only when CONFIG_GICV3_ESPI is set, so read
 * and write it through these; with the option off the extended range does not
 * exist and every ESPI branch folds away.
 */
static inline unsigned int aic_nr_espi(void)
{
#ifdef CONFIG_GICV3_ESPI
    return aic_intc_info.nr_espi;
#else
    return 0;
#endif
}

static inline void aic_set_nr_espi(unsigned int nr)
{
#ifdef CONFIG_GICV3_ESPI
    aic_intc_info.nr_espi = nr;
#else
    ASSERT(!nr);
#endif
}

/*
 * Xen's logical SGIs (enum gic_sgi) multiplexed over the single hardware
 * fast IPI: senders set bits here, the FIQ dispatcher demuxes them.
 */
static DEFINE_PER_CPU(unsigned long, aic_ipi_pending);

/* Counts received fast IPIs; only read by the boot-time self-test below. */
static DEFINE_PER_CPU(unsigned int, aic_ipi_seen);

static inline uint32_t aic_read(unsigned int reg)
{
    return readl(aic.base + reg);
}

static inline void aic_write(unsigned int reg, uint32_t val)
{
    writel(val, aic.base + reg);
}

/*
 * Read and decode the AIC event register.  Reading it atomically returns the
 * highest-priority pending event AND acks+masks it in hardware, so it must be
 * read exactly once per event.  Returns the raw event (0 => none pending);
 * callers decode with the aic_event_* helpers.
 */
static inline uint32_t aic_read_event(void)
{
    return readl(aic.event + aic.event_off);
}

static inline unsigned int aic_event_type(uint32_t ev)
{
    return (ev >> AIC_EVENT_TYPE_SHIFT) & AIC_EVENT_TYPE_MASK;
}

static inline unsigned int aic_event_num(uint32_t ev)
{
    return ev & AIC_EVENT_NUM_MASK;
}

static inline unsigned int aic_event_die(uint32_t ev)
{
    return (ev >> AIC_EVENT_DIE_SHIFT) & AIC_EVENT_DIE_MASK;
}

/*
 * Per-IRQ mask/unmask and software trigger.  These operate on a (die, irq)
 * pair, matching the hardware's per-die register banks.  Only die 0 is
 * routable for now (multi-die encoding of the linear IRQ space is TODO).
 */
static void aic_mask_irq(unsigned int die, unsigned int irq)
{
    unsigned int off = die * aic.die_stride;

    aic_write(aic.mask_set + off + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

static void aic_unmask_irq(unsigned int die, unsigned int irq)
{
    unsigned int off = die * aic.die_stride;

    aic_write(aic.mask_clr + off + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

static void __maybe_unused aic_sw_set_irq(unsigned int die, unsigned int irq)
{
    unsigned int off = die * aic.die_stride;

    aic_write(aic.sw_set + off + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

static void __maybe_unused aic_sw_clr_irq(unsigned int die, unsigned int irq)
{
    unsigned int off = die * aic.die_stride;

    aic_write(aic.sw_clr + off + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

/*
 * Only Xen IRQs at AIC_HWIRQ_BASE and above are backed by AIC hardware-IRQ
 * registers.  The FIQ pseudo IRQs in the PPI range have no event number and
 * no mask bits; masking them means programming the source itself (timer
 * IMASK, VM_TMR_FIQ_ENA, PMCR0), which their consumers do.
 */
static inline bool aic_is_hw_irq(const struct irq_desc *desc)
{
    return desc->irq >= AIC_HWIRQ_BASE;
}

static inline unsigned int aic_hwirq(const struct irq_desc *desc)
{
    ASSERT(aic_is_hw_irq(desc));
    return aic_irq_to_event(desc->irq);
}

static void aic_irq_enable(struct irq_desc *desc)
{
    ASSERT(spin_is_locked(&desc->lock));

    clear_bit(_IRQ_DISABLED, &desc->status);
    dsb(sy);
    if ( aic_is_hw_irq(desc) )
        aic_unmask_irq(0, aic_hwirq(desc));
}

static void aic_irq_disable(struct irq_desc *desc)
{
    ASSERT(spin_is_locked(&desc->lock));

    if ( aic_is_hw_irq(desc) )
        aic_mask_irq(0, aic_hwirq(desc));
    set_bit(_IRQ_DISABLED, &desc->status);
}

static unsigned int aic_irq_startup(struct irq_desc *desc)
{
    aic_irq_enable(desc);

    return 0;
}

static void aic_irq_shutdown(struct irq_desc *desc)
{
    aic_irq_disable(desc);
}

static void aic_irq_ack(struct irq_desc *desc)
{
    /* No ACK -- reading the event register has acked (and masked) for us */
}

/*
 * Reading the event register auto-acked and auto-masked the line, so both
 * "EOI" (priority drop) and "deactivate" collapse into re-unmasking it.  The
 * host flow unmasks in .end; the guest flow keeps the line masked until the
 * vGIC deactivates it (deactivate_irq) once the guest EOIs.
 */
static void aic_host_irq_end(struct irq_desc *desc)
{
    if ( !test_bit(_IRQ_DISABLED, &desc->status) && aic_is_hw_irq(desc) )
        aic_unmask_irq(0, aic_hwirq(desc));
}

static void aic_guest_irq_end(struct irq_desc *desc)
{
    /* Deactivation (re-unmask) happens when the guest EOIs the vIRQ. */
}

static void aic_eoi_irq(struct irq_desc *desc)
{
    if ( aic_is_hw_irq(desc) )
        aic_unmask_irq(0, aic_hwirq(desc));
}

static void aic_deactivate_irq(struct irq_desc *desc)
{
    if ( aic_is_hw_irq(desc) )
        aic_unmask_irq(0, aic_hwirq(desc));
}

static void aic_irq_set_affinity(struct irq_desc *desc, const cpumask_t *mask)
{
    unsigned int cpu;

    if ( !aic_is_hw_irq(desc) )
        return;

    /*
     * Only AIC v1 has the per-IRQ TARGET_CPU array.  v2/v3 route by "delay
     * groups" / prefer-pcpu in IRQ_CFG; teaching Xen those is TODO, the
     * hardware default routing is used until then.
     */
    if ( aic.version != 1 )
        return;

    ASSERT(!cpumask_empty(mask));

    /* The WHOAMI check in aic_cpu_init() ensures AIC index == logical id. */
    cpu = cpumask_first(mask);
    if ( cpu < 32 )
        aic_write(AIC_TARGET_CPU + 4 * aic_hwirq(desc), 1U << cpu);
}

static hw_irq_controller aic_host_irq_type = {
    .typename     = "aic",
    .startup      = aic_irq_startup,
    .shutdown     = aic_irq_shutdown,
    .enable       = aic_irq_enable,
    .disable      = aic_irq_disable,
    .ack          = aic_irq_ack,
    .end          = aic_host_irq_end,
    .set_affinity = aic_irq_set_affinity,
};

static hw_irq_controller aic_guest_irq_type = {
    .typename     = "aic",
    .startup      = aic_irq_startup,
    .shutdown     = aic_irq_shutdown,
    .enable       = aic_irq_enable,
    .disable      = aic_irq_disable,
    .ack          = aic_irq_ack,
    .end          = aic_guest_irq_end,
    .set_affinity = aic_irq_set_affinity,
};

/*
 * Acknowledge the next pending event and return its Xen linear IRQ, or
 * AIC_SPURIOUS_IRQ when nothing (dispatchable) is pending.  Events that Xen
 * cannot dispatch yet (dies other than 0, legacy MMIO IPIs) are drained and
 * dropped so they cannot wedge the event register.
 */
static unsigned int aic_read_irq(void)
{
    uint32_t ev;

    while ( (ev = aic_read_event()) != 0 )
    {
        unsigned int type = aic_event_type(ev);
        unsigned int num = aic_event_num(ev);
        unsigned int die = aic_event_die(ev);

        if ( likely(type == AIC_EVENT_TYPE_IRQ && die == 0 &&
                    num < aic.nr_irq &&
                    (!aic_event_is_espi(num) ||
                     num - AIC_NR_SPI_EVENTS < aic_nr_espi())) )
            return aic_event_to_irq(num);

        if ( type == AIC_EVENT_TYPE_IPI )
        {
            /* Legacy v1 MMIO IPI; Xen only sends fast IPIs. Ack and drop. */
            aic_write(AIC_IPI_ACK, AIC_IPI_OTHER | AIC_IPI_SELF);
            continue;
        }

        printk_once(XENLOG_WARNING
                    "AIC: dropping undispatchable event %#"PRIx32
                    " (type %u die %u num %u)\n", ev, type, die, num);
    }

    return AIC_SPURIOUS_IRQ;
}

/*
 * Fast IPI: deliver an IPI to another physical CPU via the IMP-DEF IPI request
 * registers.  Same-cluster targets use the LOCAL register, cross-cluster the
 * GLOBAL register.  The IPI arrives on the target as an FIQ.
 */
static void aic_send_ipi(unsigned int cpu)
{
    register_t mpidr = cpu_logical_map(cpu);
    unsigned int tcpu = mpidr & IPI_RR_CPU_MASK;
    unsigned int tcluster = (mpidr >> 8) & 0xff;
    unsigned int scluster = (READ_SYSREG(MPIDR_EL1) >> 8) & 0xff;

    if ( tcluster == scluster )
        WRITE_SYSREG(tcpu, SYS_IMP_APL_IPI_RR_LOCAL_EL1);
    else
        WRITE_SYSREG(tcpu | (tcluster << IPI_RR_CLUSTER_SHIFT),
                     SYS_IMP_APL_IPI_RR_GLOBAL_EL1);
    isb();
}

static void aic_ack_ipi(void)
{
    WRITE_SYSREG(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);
    isb();
}

/*
 * Send one of Xen's logical SGIs.  There are only two hardware IPIs per CPU,
 * so, like Linux, Xen multiplexes: set the logical IPI in the target's
 * pending bitmap, then ring the one fast IPI.
 */
static void aic_send_SGI(enum gic_sgi sgi, enum gic_sgi_mode mode,
                         const cpumask_t *mask)
{
    unsigned int cpu;
    cpumask_t targets;

    BUILD_BUG_ON(GIC_SGI_STATIC_MAX > BITS_PER_LONG);

    switch ( mode )
    {
    case SGI_TARGET_LIST:
        cpumask_and(&targets, mask, &cpu_online_map);
        break;
    case SGI_TARGET_OTHERS:
        cpumask_andnot(&targets, &cpu_online_map,
                       cpumask_of(smp_processor_id()));
        break;
    case SGI_TARGET_SELF:
        cpumask_copy(&targets, cpumask_of(smp_processor_id()));
        break;
    default:
        BUG();
    }

    for_each_cpu ( cpu, &targets )
    {
        set_bit(sgi, &per_cpu(aic_ipi_pending, cpu));
        /* Order the pending-bit write before ringing the doorbell. */
        dsb(sy);
        aic_send_ipi(cpu);
    }
}

/* Demux and run the logical SGIs behind a received fast IPI. */
static void aic_handle_ipi(struct cpu_user_regs *regs)
{
    unsigned long pending = xchg(&this_cpu(aic_ipi_pending), 0);

    perfc_incr(ipis);
    this_cpu(aic_ipi_seen)++;

    /*
     * Ensure any shared data written by the sender is read after its
     * pending bit.  Matches the dsb in aic_send_SGI().
     */
    smp_rmb();

    if ( test_bit(GIC_SGI_EVENT_CHECK, &pending) )
    {
        /* Nothing to do, will check for events on return path */
    }

    if ( test_bit(GIC_SGI_DUMP_STATE, &pending) )
        dump_execstate(regs);

    if ( test_bit(GIC_SGI_CALL_FUNCTION, &pending) )
        smp_call_function_interrupt();
}

/*
 * Recursion depth of the FIQ dispatcher on this CPU.  do_IRQ() releases the
 * descriptor lock with spin_unlock_irq(), which unmasks I *and* F (see
 * DAIF_IRQ_BITS under CONFIG_APPLE_AIC), so a source still asserted when a
 * handler runs re-enters this dispatcher.  Legitimate nesting is shallow --
 * one level per distinct source -- so anything deeper means a source is not
 * being cleared, which would otherwise spin here forever with no output at
 * all.  Report it and quiesce, so a missed source names itself.
 */
static DEFINE_PER_CPU(unsigned int, fiq_depth);

static void aic_quiesce_fiq_sources(void);

#define AIC_FIQ_MAX_DEPTH   (AIC_NR_FIQ + 1)

static void aic_report_fiq_storm(void)
{
    printk(XENLOG_ERR
           "AIC: FIQ dispatcher re-entered %u deep on CPU %u; a source is not "
           "being cleared.  IPI_SR=%#"PRIregister" CNTP_CTL_EL0=%#"PRIregister
           " CNTV_CTL_EL0=%#"PRIregister" CNTP_CTL_EL02=%#"PRIregister
           " CNTV_CTL_EL02=%#"PRIregister" ICH_HCR_EL2=%#"PRIregister
           " ICH_MISR_EL2=%#"PRIregister" PMCR0=%#"PRIregister"\n",
           this_cpu(fiq_depth), smp_processor_id(),
           READ_SYSREG(SYS_IMP_APL_IPI_SR_EL1),
           READ_SYSREG(CNTP_CTL_EL0), READ_SYSREG(CNTV_CTL_EL0),
           READ_SYSREG(CNTP_CTL_EL02), READ_SYSREG(CNTV_CTL_EL02),
           READ_SYSREG(ICH_HCR_EL2), READ_SYSREG(ICH_MISR_EL2),
           READ_SYSREG(SYS_IMP_APL_PMCR0_EL1));
}

/*
 * FIQ root dispatcher, invoked from do_trap_fiq() via the handle_fiq hook.
 * Unlike a GIC IRQ, an FIQ carries no source id, so every possible source is
 * polled (matching the Asahi driver): the fast IPI, the EL0/EL2 architected
 * timers, and eventually the core/uncore PMU and the vGIC maintenance
 * interrupt.
 *
 * Every source must be silenced *before* its handler is dispatched, not by the
 * handler: do_IRQ() unmasks FIQ while the handler runs, and an FIQ has no
 * acknowledge register, so a source left asserted re-enters immediately.
 */
static void aic_handle_fiq(struct cpu_user_regs *regs)
{
    register_t ctl;

    if ( unlikely(this_cpu(fiq_depth) >= AIC_FIQ_MAX_DEPTH) )
    {
        static bool __read_mostly reported;

        if ( !reported )
        {
            reported = true;
            aic_report_fiq_storm();
        }
        /*
         * Mask every per-CPU source, and take the guest timer route down too:
         * aic_quiesce_fiq_sources() deliberately leaves it armed for normal
         * operation, which is no use when the point is to stop the storm.
         */
        aic_quiesce_fiq_sources();
        WRITE_SYSREG(0, SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2);
        isb();
        return;
    }
    this_cpu(fiq_depth)++;

    if ( READ_SYSREG(SYS_IMP_APL_IPI_SR_EL1) & IPI_SR_PENDING )
    {
        aic_ack_ipi();
        aic_handle_ipi(regs);
    }

    /*
     * There are four timer FIQ sources, and which register names them depends
     * on the exception level they belong to.  Under forced VHE (E2H=1) the
     * unsuffixed accessors reach EL2's own timers and the _EL02 ones reach the
     * guest's, so:
     *
     *   CNTP_CTL_EL0   -> CNTHP_CTL_EL2, the timer Xen programs  (AIC FIQ 0)
     *   CNTV_CTL_EL0   -> CNTHV_CTL_EL2, EL2 virtual, unused     (AIC FIQ 1)
     *   CNTP_CTL_EL02  -> the guest's physical timer             (AIC FIQ 2)
     *   CNTV_CTL_EL02  -> the guest's virtual timer              (AIC FIQ 3)
     *
     * Apple's device tree names FIQ 0 "hyp-phys" and FIQ 3 "virt", which is
     * exactly how time.c looks them up, so both can go through do_IRQ() to the
     * handlers it registered.  An FIQ has no acknowledge register, so anything
     * left asserted on the way out would re-enter immediately; every source
     * therefore has to be masked or disabled by the time we return.
     */
    ctl = READ_SYSREG(CNTP_CTL_EL0);
    if ( TMR_FIRING(ctl) )
    {
        WRITE_SYSREG(ctl | TMR_CTL_IMASK, CNTP_CTL_EL0);
        do_IRQ(regs, AIC_FIQ_PSEUDO_BASE + AIC_TMR_HV_PHYS, 1);
    }

    ctl = READ_SYSREG(CNTV_CTL_EL0);
    if ( TMR_FIRING(ctl) )
    {
        /* Xen never arms this one; mask it so it cannot storm. */
        WRITE_SYSREG(ctl | TMR_CTL_IMASK, CNTV_CTL_EL0);
    }

    ctl = READ_SYSREG(CNTV_CTL_EL02);
    if ( TMR_FIRING(ctl) )
    {
        /*
         * vtimer_interrupt() sets IMASK too, but only after do_IRQ() has
         * already unmasked FIQ.  Masking here is what keeps this from
         * re-entering; the guest clears it again when it re-arms its timer.
         */
        WRITE_SYSREG(ctl | TMR_CTL_IMASK, CNTV_CTL_EL02);
        do_IRQ(regs, AIC_FIQ_PSEUDO_BASE + AIC_TMR_GUEST_VIRT, 1);
    }

    ctl = READ_SYSREG(CNTP_CTL_EL02);
    if ( TMR_FIRING(ctl) )
    {
        /*
         * Xen emulates the guest physical timer in software and leaves the
         * hardware one disabled, so this should not fire.  Mask it rather than
         * livelock if a guest manages to arm it.
         */
        WRITE_SYSREG(ctl | TMR_CTL_IMASK, CNTP_CTL_EL02);
    }

    /*
     * vGIC maintenance.  Xen asks for this when it runs out of list registers
     * for a vCPU; receiving it is what makes gic_inject() run again on the way
     * back to the guest.  Deliver it as the pseudo IRQ named by
     * gic_hw_ops->info->maintenance_irq so the normal handler runs.
     */
    if ( gic_hw_ops && (READ_SYSREG(ICH_HCR_EL2) & GICH_HCR_EN) &&
         READ_SYSREG(ICH_MISR_EL2) )
    {
        /*
         * UIE is the only maintenance cause Xen arms (gic-vgic.c), so clearing
         * it silences the source before dispatch.  Nothing is lost: the handler
         * is a stub whose whole purpose is to make gic_inject() run on the way
         * back to the guest, and gic_inject() re-arms UIE if the list registers
         * are still full.
         */
        WRITE_SYSREG(READ_SYSREG(ICH_HCR_EL2) & ~(register_t)GICH_HCR_UIE,
                     ICH_HCR_EL2);
        do_IRQ(regs, AIC_FIQ_PSEUDO_BASE + AIC_VGIC_MI, 1);

        /*
         * If it is still asserted nothing consumed it, and because an FIQ has
         * no acknowledge register we would spin here forever.  Shut the
         * interface down rather than livelock, and say so.
         */
        if ( unlikely((READ_SYSREG(ICH_HCR_EL2) & GICH_HCR_EN) &&
                      READ_SYSREG(ICH_MISR_EL2)) )
        {
            printk_once(XENLOG_ERR
                        "AIC: vGIC maintenance interrupt not handled "
                        "(MISR=%#"PRIregister"), disabling the interface\n",
                        READ_SYSREG(ICH_MISR_EL2));
            WRITE_SYSREG(READ_SYSREG(ICH_HCR_EL2) & ~(register_t)GICH_HCR_EN,
                         ICH_HCR_EL2);
        }
    }

    /*
     * TODO: core PMU (SYS_IMP_APL_PMCR0_EL1 IMODE==FIQ && IACT) and uncore PMU
     * (SYS_IMP_APL_UPMCR0_EL1 / UPMSR).
     */

    this_cpu(fiq_depth)--;
}

/*
 * Quiesce every per-CPU FIQ source so nothing fires until a Xen consumer
 * explicitly enables it, mirroring aic_init_cpu() in the Asahi driver.
 */
static void aic_quiesce_fiq_sources(void)
{
    /* Ack any pending fast IPI. */
    WRITE_SYSREG(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);

    /* Mask the per-CPU timer FIQs; the timer code re-enables what it uses. */
    WRITE_SYSREG(READ_SYSREG(CNTP_CTL_EL0) | TMR_CTL_IMASK, CNTP_CTL_EL0);
    WRITE_SYSREG(READ_SYSREG(CNTV_CTL_EL0) | TMR_CTL_IMASK, CNTV_CTL_EL0);

    /*
     * Route the guest virtual timer's FIQ to us: vtimer_interrupt() consumes it
     * and injects the interrupt into the guest through the vGIC, and without
     * this a guest never receives a tick.  It stays gated by CNTV_CTL_EL02's
     * own enable bit, which virt_timer_{save,restore}() manage per vCPU, so
     * leaving the route open costs nothing while no guest has armed it.  The
     * guest physical timer is emulated, so its FIQ stays off.
     */
    WRITE_SYSREG(VM_TMR_FIQ_ENABLE_V, SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2);

    /* Turn off the core PMU FIQ. */
    WRITE_SYSREG((READ_SYSREG(SYS_IMP_APL_PMCR0_EL1) & ~(register_t)PMCR0_IMODE_MASK) |
                 PMCR0_IMODE_OFF, SYS_IMP_APL_PMCR0_EL1);

    isb();
}

/* Per-CPU init (boot CPU and each secondary). */
static void aic_cpu_init(void)
{
    aic_quiesce_fiq_sources();

    if ( aic.version == 1 )
    {
        /*
         * The affinity code assumes AIC CPU index == Xen logical CPU id;
         * fail loudly if the boot protocol delivered CPUs out of order.
         */
        uint32_t whoami = aic_read(AIC_WHOAMI);

        if ( whoami != smp_processor_id() )
            printk(XENLOG_ERR
                   "AIC: CPU%u sees WHOAMI %"PRIu32"; affinity will be wrong\n",
                   smp_processor_id(), whoami);

        /* Quiesce the legacy MMIO IPIs; Xen only uses fast IPIs. */
        aic_write(AIC_IPI_ACK, AIC_IPI_OTHER | AIC_IPI_SELF);
        aic_write(AIC_IPI_MASK_SET, AIC_IPI_OTHER | AIC_IPI_SELF);
    }
}

static int aic_secondary_init(void)
{
    aic_cpu_init();

    /*
     * The GICv3 virtualisation registers are per-CPU, so every CPU that may
     * run a guest needs its own interface enabled.
     */
    gicv3_vcpuif_init();

    return 0;
}

/*
 * The vGIC maintenance interrupt is the one FIQ source with no device tree
 * node, so nothing has given its descriptor a trigger type and setup_irq()
 * would trip the ASSERT in gic_set_irq_type().  Declare it here, from the
 * driver that knows AIC lines are level-high.
 *
 * This has to happen after init_IRQ() has created the descriptors and before
 * init_maintenance_interrupt() requests the IRQ, which is why it lives in the
 * intc .init callback rather than beside the registration in the preinit.
 */
static void __init aic_init_maintenance_irq_type(void)
{
    unsigned int irq = AIC_FIQ_PSEUDO_BASE + AIC_VGIC_MI;
    int res = irq_set_type(irq, IRQ_TYPE_LEVEL_HIGH);

    if ( res )
        printk(XENLOG_WARNING
               "AIC: failed to set the type of maintenance IRQ %u (%d)\n",
               irq, res);
}

static void aic_disable_interface(void)
{
    aic_quiesce_fiq_sources();
}

static int __init aic_init(void)
{
    unsigned int die, i;

    /* Mask every hardware IRQ on every die; consumers unmask what they use. */
    for ( die = 0; die < aic.nr_die; die++ )
        for ( i = 0; i < aic.max_irq >> 5; i++ )
            aic_write(aic.mask_set + die * aic.die_stride + 4 * i, ~0U);

    /* v1: route every IRQ to CPU0 by default, as the Linux driver does. */
    if ( aic.version == 1 )
        for ( i = 0; i < aic.nr_irq; i++ )
            aic_write(AIC_TARGET_CPU + 4 * i, 1U);

    if ( aic.version >= 2 )
        aic_write(AIC2_CONFIG, aic_read(AIC2_CONFIG) | AIC2_CONFIG_ENABLE);

    aic_cpu_init();

    aic_init_maintenance_irq_type();

    return 0;
}

static void aic_set_irq_type(struct irq_desc *desc, unsigned int type)
{
    ASSERT(test_bit(_IRQ_DISABLED, &desc->status));
    ASSERT(spin_is_locked(&desc->lock));

    /*
     * AIC hardware interrupts are fixed level-high; there is nothing to
     * program.  Warn about specifiers that claim otherwise rather than
     * failing, since the line will still work.
     */
    if ( aic_is_hw_irq(desc) && type != IRQ_TYPE_LEVEL_HIGH &&
         type != IRQ_TYPE_NONE )
        printk_once(XENLOG_WARNING
                    "AIC: IRQ %u: trigger type %#x ignored (lines are level-high)\n",
                    desc->irq, type);
}

static void aic_set_irq_priority(struct irq_desc *desc, unsigned int priority)
{
    /*
     * The AIC has no priority registers: it auto-prioritises by IRQ number
     * (lower = higher priority).  Xen's IPIs do not come through the event
     * register either, so GIC_PRI_IPI preemption does not apply.
     */
}

static int aic_make_hwdom_dt_node(const struct domain *d,
                                  const struct dt_device_node *intc,
                                  void *fdt)
{
    unsigned int naddr = dt_n_addr_cells(intc);
    unsigned int nsize = dt_n_size_cells(intc);
    __be32 *reg, *cell;
    unsigned int i, len;
    int res;

    /*
     * dom0 is not given the AIC.  It gets a GICv3 whose distributor and
     * redistributors Xen emulates, at the synthesised addresses in
     * d->arch.vgic -- there is no hardware GIC layout to inherit -- with
     * interrupts injected through the list registers the cores implement.
     *
     * The device interrupt specifiers need no translation at all, which is why
     * nothing else in dom0's tree is rewritten.  The AIC's 3-cell form is
     * numerically identical to GICv3's: aic_irq_xlate() maps <AIC_IRQ n> to
     * 32 + n exactly as gic_irq_xlate() maps <GIC_SPI n>, and <AIC_FIQ f> to
     * 16 + f exactly as it maps <GIC_PPI f>.  That is not a coincidence --
     * AIC_HWIRQ_BASE is NR_GIC_LOCAL_IRQS and AIC_FIQ_PSEUDO_BASE is the PPI
     * base -- but it is worth stating, because it is what keeps this to one
     * node instead of a rewrite of every device.
     *
     * The caller has already emitted this node's name, its phandle and
     * #interrupt-cells = 3, so every device that referenced the AIC now refers
     * to the GIC with no change.  The AIC's own children (the "affinities"
     * node) and its reg/reg-names are dropped, which is correct: dom0 must not
     * see the real controller, and iomem_deny_access() keeps its MMIO out of
     * reach.
     */
    res = fdt_property_string(fdt, "compatible", "arm,gic-v3");
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#redistributor-regions",
                            d->arch.vgic.nr_regions);
    if ( res )
        return res;

    /* reg is the distributor followed by each redistributor region. */
    len = dt_cells_to_size(naddr + nsize) * (d->arch.vgic.nr_regions + 1);
    reg = xmalloc_bytes(len);
    if ( !reg )
        return -FDT_ERR_XEN(ENOMEM);

    cell = reg;
    dt_child_set_range(&cell, naddr, nsize, d->arch.vgic.dbase,
                       GUEST_GICV3_GICD_SIZE);

    for ( i = 0; i < d->arch.vgic.nr_regions; i++ )
        dt_child_set_range(&cell, naddr, nsize,
                           d->arch.vgic.rdist_regions[i].base,
                           d->arch.vgic.rdist_regions[i].size);

    res = fdt_property(fdt, "reg", reg, len);
    xfree(reg);

    return res;
}

static int aic_iomem_deny_access(struct domain *d)
{
    int rc;
    unsigned long mfn, nr;

    mfn = paddr_to_pfn(aic.base_paddr);
    nr = PFN_UP(aic.base_size);
    rc = iomem_deny_access(d, mfn, mfn + nr - 1);
    if ( rc )
        return rc;

    if ( aic.event != aic.base )
    {
        mfn = paddr_to_pfn(aic.event_paddr);
        nr = PFN_UP(aic.event_size);
        rc = iomem_deny_access(d, mfn, mfn + nr - 1);
    }

    return rc;
}

/*
 * Prove that a fast IPI actually lands on every other CPU.
 *
 * The first thing in boot to need a cross-CPU IPI is apply_alternatives_all(),
 * whose stop_machine_run() pokes each CPU with GIC_SGI_EVENT_CHECK to get it
 * out of wfi and into do_tasklet().  If one is lost, that spins forever with no
 * output at all -- the boot just stops after the last initcall.
 *
 * on_selected_cpus() cannot be used to test this: it waits for the target to
 * respond even with wait=0, so a lost IPI hangs the test the same way.  Send the
 * SGI directly instead and watch the receiver's counter with a deadline, which
 * reports per CPU rather than hanging, and shows at a glance whether a failure
 * follows cluster boundaries (E-cores are cluster 0, P-cores cluster 1).
 */
static int __init aic_ipi_selftest(void)
{
    unsigned int cpu, me = smp_processor_id();
    unsigned int lost = 0;

    if ( !aic_intc_info.nr_lines )
        return 0;

    for_each_online_cpu ( cpu )
    {
        unsigned int before;
        s_time_t deadline;
        register_t mpidr;

        if ( cpu == me )
            continue;

        mpidr = cpu_logical_map(cpu);
        before = per_cpu(aic_ipi_seen, cpu);

        send_SGI_one(cpu, GIC_SGI_EVENT_CHECK);

        deadline = NOW() + MILLISECS(100);
        while ( per_cpu(aic_ipi_seen, cpu) == before && NOW() < deadline )
            cpu_relax();

        if ( per_cpu(aic_ipi_seen, cpu) == before )
            lost++;

        printk("%sAIC: IPI to CPU%u (cluster %u, core %u) %s\n",
               (per_cpu(aic_ipi_seen, cpu) == before) ? XENLOG_ERR : "",
               cpu, (unsigned int)((mpidr >> 8) & 0xff),
               (unsigned int)(mpidr & 0xff),
               (per_cpu(aic_ipi_seen, cpu) == before) ? "LOST" : "ok");
    }

    if ( lost )
        printk(XENLOG_ERR
               "AIC: %u IPI target(s) unreachable; stop_machine_run(), and so "
               "apply_alternatives_all(), will hang\n", lost);

    return 0;
}
__initcall(aic_ipi_selftest);

static const struct intc_hw_operations aic_intc_ops = {
    .info                = &aic_intc_info,
    .init                = aic_init,
    .secondary_init      = aic_secondary_init,
    .disable_interface   = aic_disable_interface,
    .host_irq_type       = &aic_host_irq_type,
    .guest_irq_type      = &aic_guest_irq_type,
    .read_irq            = aic_read_irq,
    .eoi_irq             = aic_eoi_irq,
    .deactivate_irq      = aic_deactivate_irq,
    /*
     * Reading the AIC event register acknowledges *and* masks the event, and
     * there is no physical GIC CPU interface for a list register's HW bit to
     * act on, so Xen has to unmask it once the guest is finished.
     */
    .sw_deactivate_guest_irq = true,
    .set_irq_type        = aic_set_irq_type,
    .set_irq_priority    = aic_set_irq_priority,
    .send_SGI            = aic_send_SGI,
    .handle_fiq          = aic_handle_fiq,
    .make_hwdom_dt_node  = aic_make_hwdom_dt_node,
    .iomem_deny_access   = aic_iomem_deny_access,
};

/*
 * Translate a 3-cell <AIC_IRQ|AIC_FIQ number flags> (or 4-cell, with a
 * leading die id, on apple,aic2 multi-die SoCs) DT interrupt specifier into
 * a Xen linear IRQ (see AIC_HWIRQ_BASE above).
 */
static int aic_irq_xlate(const u32 *intspec, unsigned int intsize,
                         unsigned int *out_hwirq, unsigned int *out_type)
{
    unsigned int die = 0;

    if ( intsize == 4 )
        die = *intspec++;
    else if ( intsize != 3 )
        return -EINVAL;

    if ( die != 0 )
    {
        printk_once(XENLOG_WARNING
                    "AIC: interrupts on die > 0 not supported yet\n");
        return -EINVAL;
    }

    switch ( intspec[0] )
    {
    case AIC_SPEC_IRQ:
        if ( intspec[1] >= aic.nr_irq )
            return -EINVAL;

        /*
         * Xen's linear IRQ space is NR_IRQS wide and a GICv3 reserves INTIDs
         * 1020-1023, so aic_intc_info.nr_lines stops at 1020 and an AIC event
         * beyond that has nowhere to live.  Refuse it here: letting the number
         * escape would index past the end of irq_desc[] in __irq_to_desc().
         *
         * The architected home for these is the GICv3.1 extended SPI range
         * (INTIDs 4096+), which needs CONFIG_GICV3_ESPI, an ESPI case in the
         * translation below, and rewriting of the affected specifiers in dom0's
         * device tree -- they are no longer plain SPIs.  On an M2 this costs
         * the two USB controllers and their DARTs; see plans/asahi/08.
         */
        if ( intspec[1] >= aic.nr_irq ||
             (aic_event_is_espi(intspec[1]) &&
              intspec[1] - AIC_NR_SPI_EVENTS >= aic_nr_espi()) )
        {
            printk_once(XENLOG_WARNING
                        "AIC: event %u is not routable (%u SPI events, %u "
                        "extended)\n", intspec[1], AIC_NR_SPI_EVENTS,
                        aic_nr_espi());
            return -ERANGE;
        }

        *out_hwirq = aic_event_to_irq(intspec[1]);
        break;

    case AIC_SPEC_FIQ:
        if ( intspec[1] >= AIC_NR_FIQ )
            return -EINVAL;
        *out_hwirq = AIC_FIQ_PSEUDO_BASE + intspec[1];
        break;

    default:
        return -EINVAL;
    }

    if ( out_type )
        *out_type = intspec[2] & IRQ_TYPE_SENSE_MASK;

    return 0;
}

/*
 * Derive the per-IRQ register-array bases starting at @start_off, exactly as
 * the Asahi Linux driver does: the arrays follow in order SW_SET, SW_CLR,
 * MASK_SET, MASK_CLR, HW_STATE, each max_irq/32 words, and the per-die stride
 * is the total span from @start_off to the end of the last array.
 */
static void __init aic_derive_layout(unsigned int start_off)
{
    unsigned int off = start_off;
    unsigned int words = 4 * (aic.max_irq >> 5);

    aic.sw_set = off;   off += words;
    aic.sw_clr = off;   off += words;
    aic.mask_set = off; off += words;
    aic.mask_clr = off; off += words;
    off += words;       /* HW_STATE */
    aic.die_stride = off - start_off;
}

static int __init aic_init_v1(struct dt_device_node *node)
{
    paddr_t base, size;

    if ( dt_device_get_paddr(node, 0, &base, &size) )
        return -EINVAL;

    aic.base = ioremap_nocache(base, size);
    if ( !aic.base )
        return -ENOMEM;

    aic.base_paddr = base;
    aic.base_size = size;
    aic.version = 1;
    aic.nr_die = 1;
    aic.nr_irq = aic_read(AIC_INFO) & AIC_INFO_NR_IRQ_MASK;
    aic.max_irq = AIC_MAX_IRQ;
    /* On v1 the event register lives in the main window at AIC_EVENT. */
    aic.event = aic.base;
    aic.event_off = AIC_EVENT;
    /* The per-IRQ arrays follow the TARGET_CPU array. */
    aic_derive_layout(AIC_TARGET_CPU + sizeof(uint32_t) * aic.max_irq);

    return 0;
}

static int __init aic_init_v2(struct dt_device_node *node)
{
    paddr_t base, size, ebase, esize;
    uint32_t info1, info3;

    /* reg[0]: config/main window; reg[1]: per-die event window. */
    if ( dt_device_get_paddr(node, 0, &base, &size) )
        return -EINVAL;

    aic.base = ioremap_nocache(base, size);
    if ( !aic.base )
        return -ENOMEM;

    aic.base_paddr = base;
    aic.base_size = size;
    aic.version = aic_read(AIC2_VERSION) & AIC2_VERSION_VER_MASK;
    if ( aic.version < 2 )
        aic.version = 2;

    info1 = aic_read(AIC2_INFO1);
    info3 = aic_read(AIC2_INFO3);
    aic.nr_irq = info1 & AIC2_INFO1_NR_IRQ_MASK;
    aic.max_irq = info3 & AIC2_INFO3_MAX_IRQ_MASK;
    aic.nr_die = ((info1 >> AIC2_INFO1_LAST_DIE_SHIFT) &
                  AIC2_INFO1_LAST_DIE_MASK) + 1;

    if ( dt_device_get_paddr(node, 1, &ebase, &esize) )
    {
        printk(XENLOG_ERR "AIC: v2 without an event MMIO window (reg[1])\n");
        return -EINVAL;
    }
    aic.event = ioremap_nocache(ebase, esize);
    if ( !aic.event )
        return -ENOMEM;
    aic.event_paddr = ebase;
    aic.event_size = esize;
    /* On v2/v3 the event register is at offset 0 of the second window. */
    aic.event_off = 0;
    /* The per-IRQ arrays follow the IRQ_CFG array. */
    aic_derive_layout(AIC2_IRQ_CFG + sizeof(uint32_t) * aic.max_irq);

    return 0;
}

static int __init aic_dt_preinit(struct dt_device_node *node, const void *data)
{
    bool v2 = dt_device_is_compatible(node, "apple,aic2");
    unsigned int nr_lines;
    int res;

    aic.node = node;
    res = v2 ? aic_init_v2(node) : aic_init_v1(node);
    if ( res )
    {
        printk(XENLOG_ERR "AIC: initialisation failed (%d)\n", res);
        return res;
    }

    printk("AIC: Apple Interrupt Controller v%u, %u IRQs, %u die(s)\n",
           aic.version, aic.nr_irq, aic.nr_die);
    printk("AIC: mask_set=%#x mask_clr=%#x die_stride=%#x\n",
           aic.mask_set, aic.mask_clr, aic.die_stride);

    /*
     * The Xen linear IRQ space keeps the GIC constraints for now: values
     * from 1020 up are treated as special by the dispatch loop.  Lines that
     * do not fit (huge nr_irq, dies > 0) are not routable yet.
     */
    nr_lines = AIC_HWIRQ_BASE + aic.nr_irq;
    if ( nr_lines > 1020 )
    {
        nr_lines = 1020;

        /*
         * Events past the SPI range live in the extended SPI range instead.
         * NR_ESPI_IRQS is the most the architecture allows and also the size of
         * Xen's espi_desc[], so clamp to it; anything beyond stays unroutable
         * and aic_irq_xlate() reports it.
         *
         * Round up to a whole number of 32-interrupt ranks.  The vGIC describes
         * eSPIs in ranks and reconstructs the count by rounding the domain's
         * configured maximum INTID up to a multiple of 32
         * (domain_vgic_init()), so a count that is not itself a multiple of 32
         * comes back larger than what is reported here and the domain is
         * refused with -EINVAL.  t8112 has 1152 events, i.e. 164 past the SPI
         * range, which becomes 192.  Claiming the few extra costs nothing: no
         * event maps to them, because both aic_irq_xlate() and aic_read_irq()
         * range-check against the controller's real event count.
         */
        aic_set_nr_espi(min(ROUNDUP(aic.nr_irq - AIC_NR_SPI_EVENTS, 32),
                            (unsigned int)NR_ESPI_IRQS));

        if ( !IS_ENABLED(CONFIG_GICV3_ESPI) )
            printk(XENLOG_WARNING
                   "AIC: only %u of %u IRQs routable; the rest need "
                   "CONFIG_GICV3_ESPI\n", AIC_NR_SPI_EVENTS, aic.nr_irq);
        else
            printk("AIC: %u IRQs: %u as SPIs, %u as extended SPIs\n",
                   aic.nr_irq, AIC_NR_SPI_EVENTS, aic_nr_espi());
    }
    if ( aic.nr_die > 1 )
        printk(XENLOG_WARNING
               "AIC: %u dies; only die-0 IRQs are routable for now\n",
               aic.nr_die);

    aic_intc_info.nr_lines = nr_lines;
    aic_intc_info.node = node;

    register_intc_ops(&aic_intc_ops);
    dt_irq_xlate = aic_irq_xlate;

    /*
     * The guest-facing half is a GICv3 virtual CPU interface.  Apple SoCs have
     * no GIC distributor, but the cores do implement the GICv3 EL2
     * virtualisation system registers, so Xen's list-register injection engine
     * works unchanged -- see gicv3_register_vcpuif() for why the ID register
     * cannot be used to discover that.
     *
     * The maintenance interrupt arrives as an AIC FIQ rather than a GIC PPI,
     * which is why it gets an FIQ pseudo IRQ of its own.
     */
    gicv3_register_vcpuif(AIC_FIQ_PSEUDO_BASE + AIC_VGIC_MI);

    /*
     * The AIC MMIO must be mapped as Device-nGnRnE on Apple Silicon; the
     * fabric does not tolerate nGnRE for these registers.
     * ioremap_nocache()'s mapping type must be confirmed on real hardware.
     */

    return 0;
}

static const struct dt_device_match aic_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("apple,aic"),
    DT_MATCH_COMPATIBLE("apple,aic2"),
    { /* sentinel */ },
};

DT_DEVICE_START(aic, "Apple AIC", DEVICE_INTERRUPT_CONTROLLER)
    .dt_match = aic_dt_match,
    .init = aic_dt_preinit,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
