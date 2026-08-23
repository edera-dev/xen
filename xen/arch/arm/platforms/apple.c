/*
 * xen/arch/arm/platforms/apple.c
 *
 * Apple Silicon (M1/M2/M3) platform support.
 *
 * This is the platform layer for running Xen natively on Apple Silicon with an
 * Asahi Linux dom0.  It currently:
 *   - claims the "apple,arm-platform" family of machines,
 *   - prints a boot-time diagnostic of the properties the rest of the port
 *     depends on: the translation granule and the EL2/VHE (E2H) mode, and
 *   - implements machine reset via the Apple watchdog.
 *
 * The interrupt controller (AIC), timer-over-FIQ, VHE (E2H=1) execution, SMP
 * bring-up and DART handling are implemented separately; see plans/asahi/.
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
#include <xen/delay.h>
#include <xen/device_tree.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/types.h>
#include <asm/cpufeature.h>
#include <asm/io.h>
#include <asm/platform.h>
#include <asm/processor.h>

/*
 * Apple watchdog (compatible "apple,wdt").  Writing RESET_EN with
 * CUR_TIME >= BITE_TIME resets the whole machine.  Registers/sequence match
 * drivers/watchdog/apple_wdt.c in the Asahi kernel.
 */
#define APPLE_WDT_WD1_CUR_TIME  0x10
#define APPLE_WDT_WD1_BITE_TIME 0x14
#define APPLE_WDT_WD1_CTRL      0x1c
#define APPLE_WDT_CTRL_RESET_EN (1U << 2)

/*
 * ID_AA64MMFR0_EL1.TGran4_2 (stage-2 4KB granule) encoding.  The shift and the
 * stage-1 TGran4 constants live in asm/arm64/sysregs.h; the stage-2
 * "supported/not-supported" values do not, so name them here.
 *   0b0000: identical to the stage-1 TGran4 capability
 *   0b0001: 4KB stage-2 NOT supported
 *   0b0010+: 4KB stage-2 supported
 */
#define TGRAN4_2_DEFAULT        0x0
#define TGRAN4_2_NI             0x1

static void __iomem *apple_wdt_base;

static const char * const apple_dt_compat[] __initconst =
{
    "apple,arm-platform",
    NULL
};

/*
 * Decode ID_AA64MMFR0_EL1 for the two granule facts this port hinges on
 * (see plans/asahi/02-page-size-and-mmu.md).  Reads the register directly so
 * it does not depend on system_cpuinfo having been populated yet.
 */
static void __init apple_report_granule(void)
{
    register_t mmfr0 = READ_SYSREG(ID_AA64MMFR0_EL1);
    unsigned int tgran4 =
        (mmfr0 >> ID_AA64MMFR0_TGRAN4_SHIFT) & 0xf;
    unsigned int tgran4_2 =
        (mmfr0 >> ID_AA64MMFR0_TGRAN4_2_SHIFT) & 0xf;
    bool s1_4k = tgran4 != ID_AA64MMFR0_TGRAN4_NI;
    bool s2_4k;

    switch ( tgran4_2 )
    {
    case TGRAN4_2_DEFAULT: s2_4k = s1_4k; break;
    case TGRAN4_2_NI:      s2_4k = false; break;
    default:               s2_4k = true;  break;
    }

    printk("Apple: page granule support: 4K stage-1 %s, 4K stage-2 %s "
           "(Xen built for %luK pages)\n",
           s1_4k ? "yes" : "NO", s2_4k ? "yes" : "NO",
           1UL << (PAGE_SHIFT - 10));

    /*
     * Fail-fast check from plans/asahi/02 section 8: if Xen is built for the
     * 4KB granule but the CPU cannot use it at stage-2, guests can never run.
     * This turns an otherwise-silent early hang into a clear message.
     */
    if ( PAGE_SHIFT == 12 && !s2_4k )
        printk(XENLOG_ERR
               "Apple: FATAL: Xen is built for 4K pages but this CPU does not "
               "support the 4K stage-2 granule; guest stage-2 will not work\n");
}

/*
 * Report the EL2 execution mode.  Apple cores are VHE-only: HCR_EL2.E2H is
 * forced to 1 (see plans/asahi/06).  Newer cores advertise this via a negative
 * ID_AA64MMFR4_EL1.E2H0; older ("Fruity") cores implement E2H as RAO/WI without
 * advertising it, so we also report the live HCR_EL2.E2H bit.
 */
static void __init apple_report_vhe(void)
{
    register_t hcr = READ_SYSREG(HCR_EL2);
    register_t mmfr4 = READ_SYSREG(ID_AA64MMFR4_EL1);
    /* Signed bitfield extract of E2H0[27:24], mirroring the kernel's sbfx. */
    int e2h0 = (int)(((int64_t)mmfr4
                      << (64 - ID_AA64MMFR4_E2H0_SHIFT - ID_AA64MMFR4_E2H0_WIDTH))
                     >> (64 - ID_AA64MMFR4_E2H0_WIDTH));
    bool e2h_now = !!(hcr & HCR_E2H);
    bool vhe_only_by_id = e2h0 < 0;

    printk("Apple: EL2 mode: %s (HCR_EL2.E2H=%d), MMFR4.E2H0=%d%s\n",
           e2h_now ? "VHE" : "non-VHE", e2h_now, e2h0,
           vhe_only_by_id ? " (advertised VHE-only)" : "");

    /*
     * head.S probes E2H and programs TCR_EL2/SCTLR_EL2 in the matching format,
     * so Xen's own EL2 execution and page tables are correct under forced VHE.
     * What is *not* yet adapted is everything that runs on behalf of a guest:
     * the guest EL1 system registers still use the _EL1 accessors (which alias
     * EL2 state when E2H=1) rather than _EL12, CPTR_EL2 is written in its
     * non-VHE layout, and CNTHCTL_EL2 changes meaning.  See
     * plans/asahi/06-el2-vhe-and-cpu-bringup.md sections 1.2/3-5.
     */
    if ( e2h_now || vhe_only_by_id )
        printk(XENLOG_WARNING
               "Apple: VHE-only CPU; EL2 boot state is VHE-aware, but guest "
               "EL1 context, CPTR_EL2 and the timer are not yet (see "
               "plans/asahi/06-el2-vhe-and-cpu-bringup.md)\n");
}

static int __init apple_init(void)
{
    register_t midr = READ_SYSREG(MIDR_EL1);
    struct dt_device_node *wdt;

    printk("Apple Silicon platform (MIDR=%#lx implementor=%#x partnum=%#x)\n",
           (unsigned long)midr,
           (unsigned int)MIDR_IMPLEMENTOR(midr),
           (unsigned int)MIDR_PARTNUM(midr));

    if ( MIDR_IMPLEMENTOR(midr) != ARM_CPU_IMP_APPLE )
        printk(XENLOG_WARNING
               "Apple: boot CPU implementor is not Apple (%#x); "
               "matched apple,arm-platform anyway\n",
               (unsigned int)MIDR_IMPLEMENTOR(midr));

    apple_report_granule();
    apple_report_vhe();

    /* Map the watchdog now so apple_reset() can use it later. */
    wdt = dt_find_compatible_node(NULL, NULL, "apple,wdt");
    if ( wdt )
    {
        paddr_t base, size;

        if ( !dt_device_get_paddr(wdt, 0, &base, &size) )
        {
            apple_wdt_base = ioremap_nocache(base, size);
            if ( !apple_wdt_base )
                printk(XENLOG_WARNING "Apple: failed to map watchdog\n");
        }
    }
    if ( !apple_wdt_base )
        printk(XENLOG_WARNING
               "Apple: no watchdog found; reset will not be available\n");

    return 0;
}

/*
 * Machine reset via the Apple watchdog: arm it with a zero bite time so the
 * next tick (CUR_TIME >= BITE_TIME) resets the SoC.  Poweroff is left to dom0
 * (it owns the SMC coprocessor); see plans/asahi/07 section 3.
 */
static void apple_reset(void)
{
    if ( !apple_wdt_base )
    {
        printk(XENLOG_ERR "Apple: cannot reset, no watchdog mapped\n");
        return;
    }

    writel(APPLE_WDT_CTRL_RESET_EN, apple_wdt_base + APPLE_WDT_WD1_CTRL);
    writel(0, apple_wdt_base + APPLE_WDT_WD1_BITE_TIME);
    writel(0, apple_wdt_base + APPLE_WDT_WD1_CUR_TIME);
    (void)readl(apple_wdt_base + APPLE_WDT_WD1_CUR_TIME);

    /* The SoC can take ~120-150ms to actually reset; wait and then spin. */
    mdelay(150);
}

PLATFORM_START(apple, "APPLE")
    .compatible  = apple_dt_compat,
    .init        = apple_init,
    .reset       = apple_reset,
    /*
     * Apple RAM is based high (0x8_00000000) and devices sit behind DARTs with
     * an output address size of 36-42 bits; widen the default DMA mask so the
     * allocator hands out reachable addresses (see plans/asahi/05 section 7).
     */
    .dma_bitsize = 42,
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
