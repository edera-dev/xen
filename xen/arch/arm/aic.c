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
#include <xen/types.h>
#include <xen/device_tree.h>
#include <asm/device.h>
#include <asm/io.h>

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
