/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * xen/arch/arm/platforms/apple-vz.c
 *
 * Apple Virtualization.framework generic platform.
 *
 * This is not Apple hardware in the sense platforms/apple.c means it.  It is
 * the machine macOS's Virtualization.framework synthesises for a guest, running
 * here with nested virtualisation enabled so that the guest is entered at EL2
 * and can itself be a hypervisor.  Everything Apple-specific about the real
 * SoC is gone: there is a GICv3 rather than an AIC, interrupts arrive as IRQs
 * rather than FIQs, PSCI does CPU bring-up rather than a spin table, and there
 * is no IOMMU in front of the (virtio) devices at all.
 *
 * The one thing it shares with the bare-metal port is that Xen must cope with
 * whatever HCR_EL2.E2H does, and it turns out to do the opposite of the SoC:
 * the nested EL2 does not implement VHE (ID_AA64MMFR1_EL1.VH reads 0 and E2H is
 * writable), so head.S's probe takes the plain non-VHE path and Xen runs the
 * way it does on any other GICv3 machine.  That is why this file is a stub and
 * not a second port: see plans/asahi/11-virtualization-framework.md.
 *
 * The platform description exists for two reasons.  It names the machine in the
 * boot log, which is otherwise reported as "Generic System" and gives no hint
 * that Xen is nested; and it is the place to report the handful of facts that
 * are worth having in a log recovered later with `xl dmesg`, because this
 * platform has no serial port for Xen to print to as it boots.
 */

#include <asm/platform.h>
#include <asm/processor.h>
#include <asm/sysregs.h>
#include <xen/console.h>
#include <xen/serial.h>
#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>

static const char * const apple_vz_dt_compat[] __initconst =
{
    "apple,virtualization-generic-platform",
    NULL
};

static int __init apple_vz_init(void)
{
    /*
     * Nested EL2 under Virtualization.framework is a plain non-VHE EL2, unlike
     * the bare-metal Apple cores where HCR_EL2.E2H is RES1.  Say which one we
     * got: it decides the format of TCR_EL2/SCTLR_EL2/CPTR_EL2 and which
     * sysreg encodings reach the guest's EL1 state, so a surprise here is the
     * first thing to suspect if guests misbehave.
     */
    printk("Apple VZ: nested EL2, %s (HCR_EL2.E2H=%d)\n",
           el2_is_vhe() ? "VHE" : "non-VHE", !!el2_is_vhe());

    /*
     * The counter is the host's, undivided and unvirtualised at 24MHz, and the
     * platform declares no memory-mapped counter (GTDT CntControlBase is ~0).
     * Xen only ever uses the system registers, so that is fine, but log the
     * frequency: a nested guest inheriting a surprising CNTFRQ_EL0 would show
     * up as every timeout in Xen being wrong by the same factor.
     */
    printk("Apple VZ: CNTFRQ_EL0 = %lu Hz\n",
           (unsigned long)READ_SYSREG(CNTFRQ_EL0));

    /*
     * The platform's only serial device is a virtio-console on the PCI bus,
     * so give Xen a real console on it.  This runs after vm_init() (so
     * ioremap works) and before console_init_preirq() (so the registration is
     * in place when the console is chosen), which is also what makes
     * conring_flush() replay the whole boot log to it -- everything printed
     * up to this point included.
     *
     * Only when asked.  Writing to a virtio-console port that nothing on the
     * host is draining killed the VMM during bring-up, so this is not
     * something to do to a machine that did not ask for it; and the driver
     * additionally refuses any port it cannot know the state of.  See
     * plans/asahi/11-virtualization-framework.md section 2.
     */
    if ( IS_ENABLED(CONFIG_HAS_VIRTIO_CONSOLE) && console_has("vtcon") )
        virtio_console_init();
    else
        /*
         * Self-documenting, because this log is normally read long after the
         * fact and out of context: there is no UART of any kind here, so
         * without the virtio console everything from this point on exists
         * only in the console ring.
         */
        printk("Apple VZ: no virtio console selected; this log is readable "
               "only from the console ring (`xl dmesg`).  Pass console=vtcon "
               "for a live one.\n");

    return 0;
}

PLATFORM_START(apple_vz, "APPLE VIRTUALIZATION")
    .compatible  = apple_vz_dt_compat,
    .init        = apple_vz_init,
    /*
     * No .reset or .poweroff: the platform is PSCI-compliant (FADT
     * ArmBootArch.PSCI_COMPLIANT, and the device tree's /psci node says so
     * too), and Xen's generic PSCI paths handle both.
     */
PLATFORM_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
