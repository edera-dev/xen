# 07 — Platform layer, Xen console, and low-level drivers

Status: design. The "glue" Xen needs on the Apple platform: a `platform_desc`
registration, an early UART console, reset/poweroff, and the handful of
low-level devices Xen itself must touch (as opposed to the many devices dom0
owns, which are in doc 08).

## 1. The Xen platform stub (`platforms/apple.c`)

Xen has a per-platform hook table, `struct platform_desc`
(`xen/arch/arm/include/asm/platform.h:9-43`), registered by DT compatible via
`PLATFORM_START(_name, _namestr)` and matched in `platform.c`. Add
`xen/arch/arm/platforms/apple.c`:

```c
static const char *const apple_dt_compat[] __initconst = {
    "apple,arm-platform", "apple,t8103", "apple,t6000",
    "apple,t6002", "apple,t8112", "apple,t6020", NULL,
};
PLATFORM_START(apple, "Apple Silicon")
    .compatible   = apple_dt_compat,
    .init         = apple_platform_init,
    .init_time    = apple_init_time,     /* if any platform timer setup needed */
    .reset        = apple_reset,         /* §3 */
    .poweroff     = apple_poweroff,      /* §3 */
    .quirks       = apple_quirks,
    .dma_bitsize  = 42,                  /* DART OAS up to 42 bits; see doc 05 §7 */
    .blacklist_dev = apple_blacklist,    /* devices Xen must not bind (dom0-owned) */
PLATFORM_END
```

Notes and limits:
- On arm64 the `smp_init`/`cpu_up` hooks are **arm32-only**
  (`platform.h:17-21`), so the platform stub **cannot** own SMP bringup — that
  goes through the `enable-method` path (doc 06 §2). Likewise it cannot register
  the interrupt controller (that is the AIC driver / `DEVICE_INTERRUPT_CONTROLLER`
  path, doc 03).
- `arch_get_dma_bitsize()` returns `platform->dma_bitsize`
  (`platform.c:149-152`, default 32). Apple RAM is based at `0x8_00000000` and
  DART OAS is 36–42 bits; set `dma_bitsize` so Xen's allocator and dom0's 1:1
  regions land in device/DART-addressable space (doc 05 §7).
- `init()` is the place for any one-time SoC setup Xen must do that isn't
  covered by the AIC/timer/MMU paths (e.g. mapping the PMGR window Xen needs for
  reset, quirk detection by MIDR/SoC).

## 2. Xen console: `apple,s5l-uart` early_printk + runtime driver

The console is a Samsung-S3C2410-derived UART. From
`arch/arm64/boot/dts/apple/t8103.dtsi:877-881`:
```
serial0: serial@235200000 {
    compatible = "apple,s5l-uart";
    reg = <0x2 0x35200000 0x0 0x1000>;   /* base 0x2_35200000 */
    reg-io-width = <4>;
    interrupt-parent = <&aic>;
};
```
Linux drives it in `drivers/tty/serial/samsung_tty.c` (`TYPE_APPLE_S5L`) and has
an earlycon (`OF_EARLYCON_DECLARE(s5l, "apple,s5l-uart", ...)`). Registers are
S3C2410-style (`S3C2410_UCON`, `UTRSTAT`, `UTXH`, `URXH`), 32-bit accesses, with
Apple-specific TX/RX-threshold interrupt bits (`APPLE_S5L_UCON_*`).

**Two pieces of work:**
1. **early_printk backend** — add `xen/arch/arm/arm64/debug-s5l.inc` (mirroring
   the existing `debug-8250.inc`, `debug-pl011.inc`, `debug-cadence.inc`, …).
   Poll `UTRSTAT` TX-empty, write `UTXH`. Wire it via
   `CONFIG_EARLY_PRINTK`/`EARLY_PRINTK_INC` and the console base in Kconfig.
   This is the **first thing to build** — nothing is debuggable without it, and
   m1n1 leaves the UART initialised so it should print immediately.
2. **Runtime `SERIAL`/vuart driver** — a small `xen/drivers/char/s5l-uart.c`
   registering a `struct uart_driver` + DT `DT_DEVICE_START(..., DEVICE_SERIAL)`
   for RX/TX with AIC IRQ. Straightforward once AIC IRQs work (doc 03).

Console ownership: Xen keeps `serial0` for its own console during bring-up.
Later, either share it or (more typically) give dom0 a **vuart** (Xen has
`vpl011.c` — a virtual PL011) and let Xen keep the physical UART. Decide in doc
08; for early work Xen owns the physical UART and dom0 uses the same or a vuart.

## 3. Reset and poweroff

From `t8103.dtsi:1222-1256`:
- Watchdog `watchdog@23d2b0000`, `compatible = "apple,t8103-wdt","apple,wdt"`
  (Linux: `drivers/watchdog/apple_wdt.c`).
- SMC `apple,t8103-smc` with sub-node `apple,smc-reboot` (reboot/poweroff go
  through the SMC coprocessor) and `apple,smc-rtc`.

Plan:
- **`apple_reset()`** — simplest reliable path is the **watchdog**: map the WDT
  window (small, well-understood MMIO), program a minimal timeout and let it
  fire a full SoC reset. This avoids needing the RTKit/mailbox/SMC stack in Xen.
- **`apple_poweroff()`** — real poweroff needs the **SMC** (an RTKit
  coprocessor: mailbox + shared memory), which Xen should *not* implement.
  Options: (a) stub poweroff → reset for bring-up; (b) route
  `SYSTEM_OFF`/`SYSTEM_RESET` from vPSCI so **dom0** (which owns the SMC driver)
  performs the actual poweroff, and Xen only handles reset via WDT. (b) is the
  clean end-state — power actions that need coprocessors belong to the domain
  that owns the coprocessor.

## 4. Which low-level devices does Xen itself touch?

Keep Xen's device footprint **minimal** — the Xen ARM philosophy is that dom0
owns nearly all hardware. Xen touches only:

| Device | Why Xen needs it | Notes |
|---|---|---|
| AIC (`apple,aic`/`aic2`) | interrupt controller | doc 03 — Xen-owned |
| arch timer (`arm,armv8-timer`) | scheduling tick | doc 04/06 — via FIQ |
| s5l UART (`serial0`) | Xen console | §2 — Xen-owned during bring-up |
| WDT (`apple,wdt`) | reset | §3 — small MMIO map |
| PMGR (`apple,t8103-pmgr`) | *maybe* CPU-start / clock for the above | only if we do Apple CPU-start (doc 06 §2 fallback) or must ungate the UART/WDT clock |
| SPRR/GXF/APRR sysregs | EL2 protection state m1n1 set up | preserve; don't fight it |

Everything else — PCIe, NVMe/ANS2, USB/Type-C, DART/SART, RTKit coprocessors
(SMC, DCP/display, GPU, ISP, SEP, audio), Wi-Fi/BT, PMGR power domains, cpufreq —
is **dom0-owned** (doc 08). Xen assigns their MMIO + IRQs to dom0 and stays out.

## 5. Clocks / power domains (PMGR)

Apple devices are gated by PMGR power domains (`apple,t8103-pmgr`,
`drivers/soc/apple/apple-pmgr-pwrstate.c`). For the few devices Xen touches
(UART, WDT), m1n1 has already powered/clocked them (the console works on entry),
so Xen likely needs **no** PMGR code for its own devices. dom0 owns PMGR for
everything else. Only if the fallback Apple CPU-start (doc 06 §2) is used does
Xen need to poke PMGR CPU-start registers. Keep PMGR out of Xen otherwise.

## 6. Framebuffer

m1n1/iBoot set up a **locked-DART boot framebuffer** (`/chosen/framebuffer`,
`apple,simple-framebuffer`). Options:
- **Give it to dom0** (simplest; dom0's simple-framebuffer/DCP driver uses it).
- **Optional Xen framebuffer console** later (Stabellini listed it) — Xen maps
  the fb and renders text for a graphical Xen console. Nice for headless-less
  debugging but not required if the UART works. Must respect the locked DART
  (doc 05 §4): map, don't reprogram.

## 7. Effort and risk

| Task | Difficulty |
|---|---|
| `platforms/apple.c` stub | TRIVIAL |
| s5l early_printk backend | LOW (first thing built) |
| s5l runtime serial driver | LOW–MODERATE (after AIC IRQs) |
| WDT reset | LOW |
| Poweroff via vPSCI→dom0/SMC | LOW (design), defer real SMC |
| `dma_bitsize`/allocator addressing | LOW |
| Framebuffer console (optional) | MODERATE, deferred |

This entire document is low-risk plumbing. Its only critical-path item is the
**s5l early console**, which must exist before anything in docs 03/04/06 can be
debugged.
