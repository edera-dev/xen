# 09 — Roadmap, testing strategy, and risk register

Status: plan. Sequences the work from the other documents into phases with
explicit, observable milestones, describes how to test on hardware where you
cannot attach a debugger easily, and consolidates the risks.

## 1. Guiding principles

- **Every phase ends in something you can *see*** (a UART line, a tick count, a
  shell prompt). On this hardware, "it silently hung" is the default failure, so
  design each step to print before and after the risky operation.
- **De-risk the two hard things first**: forced-VHE EL2 execution (doc 06 §1)
  and taking interrupts (doc 03/04). Nothing else matters until those work.
- **Reuse the reference implementations**: m1n1 `hv` for Apple EL2/MMU/IMP-DEF,
  KVM for vGICv3-on-Apple and hVHE. Port patterns, don't reinvent.
- **Develop over m1n1 USB proxy** (doc 01 §6) for fast crash/iterate and captured
  early UART; write to the ESP only once dom0 boots.
- **Target M2** (best-understood bare-metal EL2, hardware NV) or **M1**; avoid
  M4 for now (Apple EL2 extensions reportedly disabled in its boot object).

## 2. Phase 0 — Scaffolding and hardware truth (days)

Goal: build, boot to *one* print, and confirm hardware facts.
- Add `platforms/apple.c` (doc 07 §1) and Kconfig; add the SoC compatibles.
- Add the **s5l early_printk** backend (doc 07 §2). Get Xen entered by m1n1 to
  print its banner + `CurrentEL`.
- Add the **fail-fast MMFR check** (doc 02 §8): dump `ID_AA64MMFR0_EL1`,
  `ID_AA64MMFR1_EL1.VHE`, `MIDR`, `CurrentEL`, and confirm 4 KiB stage‑2 +
  forced E2H on the *actual* board.
- **Milestone P0:** Xen prints its banner and the decoded ID registers, then
  (expectedly) hangs at MMU enable. This alone proves boot handoff + console.

## 3. Phase 1 — Run at EL2 under forced VHE (weeks; hardest)

Goal: Xen enables its MMU and reaches C `start_xen()` with a working console,
running with `HCR_EL2.E2H = 1`.
- Implement the hVHE/VHE EL2 setup (doc 06 §1): `TCR_EL2`/`SCTLR_EL2` E2H
  layout, TTBR choice, boot page tables. Prototype the MMU-enable in isolation
  (bare-metal stub / m1n1 proxy) before wiring into Xen.
- Keep 4 KiB granule (doc 02 Path A).
- **Milestone P1:** Xen runs past MMU enable into `start_xen()`, prints heap/
  frametable init and the DT parse, on real hardware. This retires the single
  biggest risk.

## 4. Phase 2 — Interrupts and time (weeks)

Goal: Xen takes AIC IRQs and FIQs, keeps time, and runs SMP.
- AIC physical driver v1+v2 (doc 03): probe, `read_irq`/`eoi`, mask, DT parse.
- Split `gic_hw_operations` physical vs virtual (doc 03 §6) — land as a no-op on
  a GICv3 QEMU model *first* to avoid regressions.
- FIQ root + dispatcher (doc 03 §7): timer, fast-IPI demux, (stub PMU),
  maintenance placeholder.
- Timer via FIQ (doc 04 §6): Xen's own `CNTHP` tick → softirq.
- SMP: release secondaries via m1n1 spin-table (doc 06 §2); per-CPU AIC init.
- **Milestone P2a:** periodic Xen timer tick counted and printed.
- **Milestone P2b:** all cores online (print each secondary's banner);
  inter-CPU IPI (fast-IPI) round-trip works.
- **Milestone P2c:** a device IRQ (UART RX) is taken and handled.

## 5. Phase 3 — First guest via vGICv3 (weeks)

Goal: launch a trivial EL1 guest and inject interrupts into it via hardware LRs.
- vGICv3 decoupled from the physical distributor probe (doc 04 §4): init from
  `ICH_VTR_EL2`, set up the LR pool, force vGIC version = GICv3, force guest
  `ID_AA64PFR0_EL1.GIC = 1`.
- Wire the maintenance interrupt through the FIQ path (doc 04 §4.3).
- SW-driven deactivation + no-maintenance-mask handling (doc 04 §1 caveats).
- vPSCI up to guests (doc 06 §3).
- Use **dom0less** to launch a tiny bare-metal/Linux EL1 guest with a virtual
  timer.
- **Milestone P3:** the guest takes **periodic virtual timer interrupts**
  (injected via `ICH_LR`) and its own vGIC SGIs — this validates the entire
  Design‑1 interrupt-virtualization model on real silicon.

## 6. Phase 4 — Asahi as dom0, to a shell (weeks)

Goal: boot the real linux-asahi kernel as dom0 to a login prompt.
- dom0 DT generation: synthetic GICv3 node, AIC→GIC interrupt translation, PSCI,
  timer PPIs, preserved carveouts + framebuffer (doc 08 §2).
- direct-mapped dom0 with 16 KiB-aligned banks (doc 02 §4.2a).
- Assign DART/SART/coprocessor MMIO+IRQ to dom0; preserve locked DARTs (doc 05).
- dom0 kernel patches to degrade EL2-only drivers gracefully at EL1 (doc 08 §4,
  §8).
- Bring up **ANS2/NVMe (SART) storage** — the root disk — over translated AIC
  IRQs (doc 04 §5); USB for input/console.
- **Milestone P4a:** Asahi dom0 reaches userspace on initramfs (console over
  vuart/serial).
- **Milestone P4b:** dom0 mounts the real NVMe root filesystem and reaches a
  login shell. **This is "Xen natively on Apple Silicon with an Asahi dom0."**

## 7. Phase 5 — Usable system and guests (months)

- Port the toolstack (`xl`/libxl/xenstored), reconciling 16 KiB dom0 userland
  vs 4 KiB grant/ring ABI (doc 08 §7, risk R6).
- Launch **domU** guests (generic arm64 + vGICv3 + virtio) — needs no Apple code.
- ACTLR/TSO per-vCPU context switch (doc 06 §5) for correctness.
- Reset/poweroff polish (WDT + vPSCI→SMC, doc 07 §3).
- **Milestone P5:** create/destroy a Linux domU from dom0 with virtio disk/net
  and a console.

## 8. Phase 6+ — Hardening and passthrough (long tail, optional)

- PCIe MSI: translation shim or switch dom0 to a **vAIC** (Design 2) for native
  MSI (doc 04 §2, doc 08 §5) → Wi-Fi/BT, Thunderbolt.
- Real **Xen DART driver** for domU device passthrough + isolation (doc 05 §6),
  best paired with **16 KiB Xen** (doc 02 Path C).
- Deep cpuidle / cpufreq, PMU virtualization (PMUv3 emulation), GPU.
- Multi-SoC breadth (M1 Pro/Max/Ultra AICv2 multi-die, M2 family).

## 9. Testing strategy

- **Primary signal: UART.** Instrument generously; keep an early-boot ring of
  prints. Capture over the m1n1 USB proxy cable.
- **m1n1 proxy + Python** as an oracle: before writing Xen code for an Apple
  register, poke it live via the proxy to learn its semantics (this is what m1n1
  was built for).
- **Regression-guard the shared refactors on QEMU `virt` (GICv3)**: the
  `gic_hw_operations` split (doc 03 §6) and any generic-arm changes must keep
  stock Xen booting on QEMU/FVP before Apple-specific code is added. This
  protects the upstreamability of the refactors.
- **Bisectable milestones**: each P-milestone is a git-tag-worthy, demonstrable
  state. If a later phase breaks, you can bisect against a known-booting tag.
- **Two-board discipline**: keep one machine on a known-good `boot.bin` for
  recovery; iterate on the other via proxy.
- **Hardware matrix**: primary M2 (or M1) Mac mini (headless-friendly, easy
  UART); validate AICv2 multi-die on an M1 Pro/Max later.

## 10. Consolidated risk register

| # | Risk | Likelihood | Impact | Mitigation | Doc |
|---|---|---|---|---|---|
| R1 | Forced-VHE (E2H=1) port is deep and silently fails | High | High | Prototype MMU-enable in isolation; follow KVM hVHE + m1n1 `hv`; do it first | 06 §1 |
| R2 | AIC driver + FIQ + `gic_hw_ops` split is large | High | High | Direct port of Linux AIC driver; land split as no-op on QEMU first | 03 |
| R3 | vGICv3 `no_hw_deactivation` / maintenance-via-FIQ edge cases | Medium | Medium | Follow KVM's SW-deactivation patches; validate at P3 with vtimer | 04 §1,§4 |
| R4 | Asahi drivers assume EL2/VHE; misbehave at EL1 | Medium | Medium | KVM proves EL1+GICv3 Linux on Apple; audit + guard drivers; defer PMU/cpuidle | 08 §4 |
| R5 | AIC→GIC interrupt-spec translation bugs (Design 1) | Medium | Medium | Mechanical, table-driven; or adopt vAIC (Design 2) to sidestep | 08 §2 |
| R6 | 4 KiB Xen ABI (grant/ring) vs 16 KiB dom0 userland | Medium | Medium | Audit privcmd/gntdev granularity; known-tricky but solved elsewhere; or go 16 KiB Xen (Path C) | 02 §6, 08 §7 |
| R7 | PCIe MSI passthrough hard under Design 1 | High | Low (not boot-critical) | Defer; storage is ANS2 not PCIe; later MSI shim or vAIC | 04 §5, 08 §5 |
| R8 | Coprocessor firmware ABI churn per Darwin release | Medium | Low (dom0-contained) | dom0 owns all coprocessors w/ maintained Asahi drivers; no Xen RTKit | 05 §1, 08 §6 |
| R9 | SoC variety (AICv2 multi-die, per-SoC CPU-start offsets) | Medium | Medium | Start on one SoC (M1/M2 base); parametrise by DT like Linux does | 03 §4, 06 §2 |
| R10 | M4+ changes bare-metal EL2 environment | Low (scoped out) | High | Scope to M1/M2; revisit M3/M4 later | 06, 01 |
| R11 | Direct-mapped dom0 gives it broad DMA (weak isolation) | Certain | Low (dom0 trusted) | Documented limitation; real isolation needs Xen DART driver later | 05 §4,§6 |

## 11. Effort estimate (order of magnitude)

- To **Milestone P4b (Asahi dom0 shell)**: a focused expert or small team,
  ~6–12 months. Dominated by R1 (VHE) and R2 (AIC/FIQ), each multi-week with a
  long debugging tail; dom0 DT + EL1 audit another multi-week.
- To **Milestone P5 (usable, domU guests)**: +3–6 months (toolstack, ABI
  reconciliation, polish).
- Passthrough/isolation/GPU (Phase 6+): open-ended.

This is a **feasible but serious systems project** — greenfield (no prior art),
but with no identified hard blocker and strong reference implementations for
every hard part. See `00-overview-and-feasibility.md` for the verdict.
