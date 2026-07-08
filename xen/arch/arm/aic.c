/*
 * xen/arch/arm/aic.c
 *
 * Apple Interrupt Controller (AIC) driver -- physical layer.
 *
 * Apple Silicon has no ARM GIC; interrupts are managed by the AIC, an MMIO +
 * IMP-DEF-sysreg controller with a completely different model (see
 * plans/asahi/03-interrupt-controller-aic.md).  This file is the physical-side
 * driver.  It currently:
 *   - matches the "apple,aic" (v1) and "apple,aic2" (v2/v3) interrupt
 *     controllers,
 *   - maps their MMIO windows and probes version / IRQ count / die count,
 *   - derives the per-IRQ register layout (mask/sw arrays, die stride) exactly
 *     as the Asahi Linux driver does, and
 *   - provides the leaf primitives: reading+decoding the "event" register
 *     (which atomically acks+masks), and per-IRQ mask/unmask/software-trigger.
 *
 * NOT yet implemented (each needs the gic_hw_operations split of
 * plans/asahi/03 section 6, or real hardware to validate), so the leaf ops are
 * marked __maybe_unused until they are wired up:
 *   - registration as the system interrupt controller (register_gic_ops);
 *   - the FIQ root handler (timers, fast IPIs, PMU, vGIC maintenance);
 *   - fast-IPI send/receive via the IMP-DEF IPI system registers;
 *   - secondary-CPU per-core init and DT interrupt translation.
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
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/softirq.h>
#include <xen/types.h>
#include <xen/device_tree.h>
#include <asm/device.h>
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
    struct dt_device_node *node;
};

static struct aic aic __read_mostly;

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
 * pair, matching the hardware's per-die register banks.  Marked __maybe_unused
 * until register_gic_ops() wires them into Xen's IRQ flow (see file header).
 */
static void __maybe_unused aic_mask_irq(unsigned int die, unsigned int irq)
{
    unsigned int off = die * aic.die_stride;

    aic_write(aic.mask_set + off + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

static void __maybe_unused aic_unmask_irq(unsigned int die, unsigned int irq)
{
    unsigned int off = die * aic.die_stride;

    aic_write(aic.mask_clr + off + AIC_MASK_REG(irq), AIC_MASK_BIT(irq));
}

/* AIC auto-masks on event read; "EOI" simply re-enables the line. */
static void __maybe_unused aic_eoi_irq(unsigned int die, unsigned int irq)
{
    aic_unmask_irq(die, irq);
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
 * Fast IPI: deliver an IPI to another physical CPU via the IMP-DEF IPI request
 * registers.  Same-cluster targets use the LOCAL register, cross-cluster the
 * GLOBAL register.  The IPI arrives on the target as an FIQ.
 */
static void __maybe_unused aic_send_ipi(unsigned int cpu)
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

static void __maybe_unused aic_ack_ipi(void)
{
    WRITE_SYSREG(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);
    isb();
}

/*
 * FIQ root dispatcher.  Unlike a GIC IRQ, an FIQ carries no source id, so we
 * poll every possible source (matching the Asahi driver): the fast IPI, the
 * EL0 physical/virtual architected timers, the core/uncore PMU, and the vGIC
 * maintenance interrupt.  This is the handler the EL2 FIQ vector must call once
 * the exception path is wired (plans/asahi/03 section 7); it is not yet
 * referenced, hence __maybe_unused.
 */
static void __maybe_unused aic_handle_fiq(void)
{
    if ( READ_SYSREG(SYS_IMP_APL_IPI_SR_EL1) & IPI_SR_PENDING )
    {
        aic_ack_ipi();
        /* TODO: demux and dispatch the logical IPI (needs the SW IPI mux). */
    }

    if ( TMR_FIRING(READ_SYSREG(CNTP_CTL_EL0)) )
    {
        /* Mask the source and let the core timer code run via softirq. */
        WRITE_SYSREG(READ_SYSREG(CNTP_CTL_EL0) | TMR_CTL_IMASK, CNTP_CTL_EL0);
        raise_softirq(TIMER_SOFTIRQ);
    }

    if ( TMR_FIRING(READ_SYSREG(CNTV_CTL_EL0)) )
    {
        WRITE_SYSREG(READ_SYSREG(CNTV_CTL_EL0) | TMR_CTL_IMASK, CNTV_CTL_EL0);
        /* TODO: inject the guest virtual timer via the vGIC. */
    }

    /*
     * TODO: core PMU (SYS_IMP_APL_PMCR0_EL1 IMODE==FIQ && IACT), uncore PMU
     * (SYS_IMP_APL_UPMCR0_EL1 / UPMSR), and the vGIC maintenance interrupt
     * (is_hyp && ICH_HCR_EL2.En && ICH_MISR_EL2 != 0).
     */
}

/*
 * Per-CPU init (boot CPU and each secondary), mirroring aic_init_cpu() in the
 * Asahi driver: quiesce every per-CPU FIQ source so nothing fires until a Xen
 * consumer explicitly enables it.
 */
static void __maybe_unused aic_init_cpu(void)
{
    /* Ack any pending fast IPI. */
    WRITE_SYSREG(IPI_SR_PENDING, SYS_IMP_APL_IPI_SR_EL1);

    /* Mask the per-CPU timer FIQs; the timer code re-enables what it uses. */
    WRITE_SYSREG(READ_SYSREG(CNTP_CTL_EL0) | TMR_CTL_IMASK, CNTP_CTL_EL0);
    WRITE_SYSREG(READ_SYSREG(CNTV_CTL_EL0) | TMR_CTL_IMASK, CNTV_CTL_EL0);

    /* Disable guest-timer FIQs (EL2 register) until a guest wants them. */
    WRITE_SYSREG(0, SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2);

    /* Turn off the core PMU FIQ. */
    WRITE_SYSREG((READ_SYSREG(SYS_IMP_APL_PMCR0_EL1) & ~(register_t)PMCR0_IMODE_MASK) |
                 PMCR0_IMODE_OFF, SYS_IMP_APL_PMCR0_EL1);

    isb();
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
    /* On v2/v3 the event register is at offset 0 of the second window. */
    aic.event_off = 0;
    /* The per-IRQ arrays follow the IRQ_CFG array. */
    aic_derive_layout(AIC2_IRQ_CFG + sizeof(uint32_t) * aic.max_irq);

    return 0;
}

static int __init aic_dt_preinit(struct dt_device_node *node, const void *data)
{
    bool v2 = dt_device_is_compatible(node, "apple,aic2");
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
     * The AIC MMIO must be mapped as Device-nGnRnE on Apple Silicon; the fabric
     * does not tolerate nGnRE for these registers.  ioremap_nocache()'s mapping
     * type must be confirmed/overridden here on real hardware.
     *
     * TODO (see plans/asahi/03 and 04), in order:
     *  - split gic_hw_operations and register the AIC physical ops, wiring the
     *    aic_{mask,unmask,eoi}_irq / aic_read_event leaf ops above;
     *  - wire the FIQ root handler (timers, fast IPIs, PMU, vGIC maintenance);
     *  - implement fast-IPI send/receive via the IMP-DEF IPI system registers
     *    plus the >2-IPI software multiplex;
     *  - add AIC DT interrupt translation (AIC_IRQ/AIC_FIQ 3-cell specifiers);
     *  - reuse Xen's vGICv3 for guest injection, backed by the GICv3 CPU
     *    system-register interface Apple cores implement.
     *
     * Until register_gic_ops() is called, the AIC is probed and reported but
     * does NOT yet service interrupts; a real boot still needs the above.
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
