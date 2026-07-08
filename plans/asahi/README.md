# Xen natively on Apple Silicon, with an Asahi Linux dom0 — engineering plan

This directory is a detailed, from-source plan for booting the **Xen
hypervisor natively (type‑1, bare metal) on Apple Silicon (M1/M2)** via
**m1n1 / u‑boot**, with **dom0 being an Asahi Linux install**.

It was written by reading the Xen 4.21 source tree and the Asahi Linux kernel
source in this workspace, cross-checked against the public record (Asahi docs,
m1n1 and Linux/KVM source, LWN, xen-devel). Findings are anchored to concrete
files/line numbers.

## Start here

→ **[`00-overview-and-feasibility.md`](00-overview-and-feasibility.md)** — the
verdict, the architecture, and the honest caveats.

**TL;DR:** It's possible. Nobody has done it. No hard blocker exists. Two
things are genuinely hard — running under Apple's **forced‑VHE EL2** and
building the **AIC/FIQ interrupt stack** — but both have working reference
implementations (KVM‑on‑Asahi and m1n1's `hv`) to copy. Estimate to an Asahi
dom0 shell: ~6–12 months for a focused team. Two common objections ("no 4 KB
pages", "interrupt injection must be software‑only") turned out to be **false**.

## Documents

| # | Document | What it decides / covers |
|---|---|---|
| 00 | [overview-and-feasibility](00-overview-and-feasibility.md) | Verdict, architecture diagram, false alarms, hard problems |
| 01 | [boot-chain](01-boot-chain.md) | iBoot→m1n1→u‑boot→Xen→dom0; Image header; DT/module handoff; EFI; recovery |
| 02 | [page-size-and-mmu](02-page-size-and-mmu.md) | 4 KB vs 16 KB (Path A/B/C); MMU coupling; confirmed 4 KB S2 |
| 03 | [interrupt-controller-aic](03-interrupt-controller-aic.md) | Physical AIC driver, FIQ root, fast‑IPI mux, `gic_hw_ops` split |
| 04 | [virtual-interrupts-and-timer](04-virtual-interrupts-and-timer.md) | vGICv3 reuse vs vAIC; HW LR injection; timer via FIQ |
| 05 | [iommu-dart-and-dma](05-iommu-dart-and-dma.md) | DART/SART, direct‑map dom0, coprocessors, deferred Xen DART driver |
| 06 | [el2-vhe-and-cpu-bringup](06-el2-vhe-and-cpu-bringup.md) | **Forced VHE (E2H=1)**, spin‑table SMP, vPSCI, idle, TSO/ACTLR |
| 07 | [platform-console-and-drivers](07-platform-console-and-drivers.md) | `platforms/apple.c`, s5l UART console, WDT reset, framebuffer |
| 08 | [dom0-asahi-integration](08-dom0-asahi-integration.md) | dom0 DT generation, device‑ownership split, EL1 audit, toolstack |
| 09 | [roadmap-testing-and-risks](09-roadmap-testing-and-risks.md) | Phases P0–P6, milestones, test strategy, risk register, estimate |

## Reading orders

- **Decision-maker / "is this real?"** → 00, then 09 §10–11 (risks + estimate).
- **Kernel/hypervisor engineer starting work** → 00 → 06 (VHE) → 03 → 04 → 02,
  then 01/07 for the console bring-up you'll build first.
- **dom0 / distro integrator** → 08 → 05 → 01.

## The single most important sentences

1. Do **VHE (doc 06 §1) + the s5l console (doc 07 §2) first** — nothing else is
   debuggable until Xen executes at EL2 and prints.
2. Guests see a **virtual GICv3** injected via the **hardware List Registers
   Apple cores actually implement** — reuse Xen's vGICv3 (doc 04).
3. **dom0 owns every Apple device/coprocessor** through native Asahi drivers;
   Xen touches only AIC, timer, UART, watchdog (doc 07/08).

## Status

Implementation has started on the `asahi` branch; these documents are the
design reference for it. Landed so far (compile-verified, QEMU-regression-
tested; Apple hardware still needed to validate):

- `platforms/apple.c`, s5l early-printk + runtime console driver with
  interrupt-driven RX, Kconfig plumbing (doc 07).
- AIC v1/v2/v3 physical driver: probe, event decode, mask/unmask/EOI,
  fast-IPI send/receive with the SW IPI mux, FIQ root dispatcher, per-CPU
  init, 3/4-cell DT translation (doc 03 §3-5, §7-9).
- The `gic_hw_operations` physical/virtual split (doc 03 §6), landed as a
  no-op on GICv2/GICv3, and the AIC registered as the system interrupt
  controller through the physical half; EL2h FIQ vector wired to the
  dispatcher (doc 03 §7).

Not started: forced-VHE EL2 execution (doc 06 — the critical path), vGICv3
reuse for guest injection (doc 04), dom0 integration (doc 08), DART (doc 05).

Line references are against the tree state at the time of writing (Xen
`edera/4.21` lineage; Asahi kernel in the sibling checkout).
