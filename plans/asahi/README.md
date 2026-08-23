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
| 10 | [bringup-runbook](10-bringup-runbook.md) | **How-to**: vdm cable, m1n1 proxy, `apple_defconfig`, the push loop, expected output per milestone |

## Reading orders

- **Decision-maker / "is this real?"** → 00, then 09 §10–11 (risks + estimate).
- **Kernel/hypervisor engineer starting work** → 00 → 06 (VHE) → 03 → 04 → 02,
  then 01/07 for the console bring-up you'll build first.
- **dom0 / distro integrator** → 08 → 05 → 01.
- **Sitting down at the hardware right now** → **10**, then 06.

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

- `arch/arm/configs/apple_defconfig` and the hardware bring-up harness
  (doc 10): m1n1 proxy push loop, machine DTB generation, expected console
  output per milestone.

Not started: vGICv3 reuse for guest injection (doc 04 — now the critical
path, and the exact thing Xen stops on), dom0 module packing (doc 01 §3 A1),
dom0 integration (doc 08), DART (doc 05), and the rest of forced VHE for guest
state (doc 06 §1.2 items 3-5: `_EL12` accessors, `CPTR_EL2`, `CNTHCTL_EL2`).

- Forced-VHE EL2 **boot** state (doc 06 §1.2 item 1): `head.S` probes
  `HCR_EL2.E2H` (attempting to clear it first, so nVHE-capable CPUs keep
  Xen's native path) and programs `TCR_EL2`/`SCTLR_EL2` in the matching
  layout.  Xen lives in the low half of the EL2&0 regime, so no `TTBR1_EL2`
  work was needed -- doc 06 §1.2 item 2 can be dropped.
- **Descriptor `AP[1]` under forced VHE.**  `mfn_to_xen_entry()` set `AP[1]`
  because it is RES1 "as the translation regime applies to only one exception
  level".  With `E2H=1` the regime is EL2&0, which has an EL0, and `AP[1]=1`
  marks the page EL0-accessible -- unusable for privileged execution on Apple
  cores.  Now cleared at runtime in both `mmu/pt.c` and the hard-coded `PT_*`
  values in `arm64/mmu/head.S`.  This was the single blocker between
  `- Turning on paging -` and Xen's banner; see doc 10 §7 M2.

**Confirmed booting on hardware (M2 MacBook Air, t8112-j413).**  Xen enables
paging under forced VHE, reaches C, parses the loader DT, matches the Apple
platform, probes the AIC (v8, 1152 IRQs), initialises the timer over AIC FIQs
(`phys=18 hyp=16 virt=19`, 24 MHz), brings up **all 8 CPUs** through the
spin-table path (P-cores need `hmp-unsafe=true`; their MIDR differs from the
E-cores'), sets up stage 2 (`36-bit IPA/PA, 8-bit VMID, 3 levels`), completes
`smp_call_function` over AIC fast IPIs, runs every initcall and patches
alternatives.

It then stops exactly where the design says it should: `create_dom0` needs a
*virtual* interrupt controller, and only the AIC's physical half exists.
`gic_hw_version()` returns `GIC_INVALID` and domain creation is refused.  That
is doc 04.

Hardware also confirms 4K granule support at **both** stage 1 and stage 2, so
doc 02's Path A stands and no 16K rebuild is needed.  Non-VHE regression
verified throughout under QEMU `virt,virtualization=on`.

Still not adapted for VHE: guest EL1 context switch must move to the `_EL12`
accessors, `CPTR_EL2` is written in its non-VHE layout, and `CNTHCTL_EL2`
changes meaning (doc 06 §1.2 items 3-5).

Line references are against the tree state at the time of writing (Xen
`edera/4.21` lineage; Asahi kernel in the sibling checkout).
