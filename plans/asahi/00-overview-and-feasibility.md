# 00 — Xen on Apple Silicon: overview and feasibility verdict

> Goal: run the **Xen hypervisor natively (type‑1, bare metal) on Apple Silicon
> (M1/M2)**, booted via **m1n1 / u‑boot**, with **dom0 being an Asahi Linux
> install**, and (eventually) the ability to run additional guest VMs.

This directory is a from-source engineering plan. It was produced by reading
the Xen 4.21 tree (`/Users/alex/Developer/xen`), the Asahi Linux kernel
(`/Users/alex/Developer/asahi-linux`), and the public record (Asahi docs, m1n1
and Linux/KVM source, LWN, xen-devel). Claims are anchored to specific files and
line numbers throughout; web-sourced facts are cited in doc 01/04/06.

## 1. Verdict

**It is possible. Nobody has done it. There is no hard blocker — but it is a
serious, multi-quarter systems project, not a weekend patch.**

- **Possible**: every Apple-specific obstacle either maps onto an existing Xen
  abstraction, is enabled by an already-present ARM architectural facility, or
  has a working reference implementation (KVM-on-Asahi and m1n1's `hv`) to copy
  from. Two initial "showstoppers" turned out to be false (see §3).
- **Greenfield**: no working port of Xen — or *any* partitioning type‑1
  hypervisor (Jailhouse, seL4, Hafnium, Bao, Xvisor) — to Apple Silicon exists.
  A July‑2024 xen-devel thread of intent produced no code; the Feb‑2026 "macOS
  hypervisor build configuration" patch is only cross-compilation. The closest
  artifact is m1n1's `hv`, a single-guest reverse-engineering tracer, not a
  resource-multiplexing hypervisor.
- **Serious**: two items are genuinely hard (forced‑VHE EL2 execution, and the
  AIC/FIQ interrupt stack), each multi-week with a nasty silent-failure
  debugging profile. Estimate to an Asahi-dom0 shell: **~6–12 months** for a
  focused expert/small team (doc 09 §11).

If someone told you "Xen can't run on Apple Silicon because there's no GIC / no
PSCI / it needs 16 KB pages / interrupt injection needs a GIC," **all four of
those objections are either wrong or already solved** — details below.

## 2. Why it works: the load-bearing facts

1. **Clean EL2 entry.** m1n1 hands its payload control at **EL2, MMU off, DTB in
   `x0`** — precisely Xen's arm64 boot contract (`head.S:84-91`). Xen already
   presents a Linux `Image` header, so m1n1 boots it like a kernel. (doc 01)
2. **dom0 is direct-mapped** (`domain_build.c:297,2261`): guest‑PA == host‑PA.
   This single property lets dom0 drive the Apple DART/SART IOMMUs with real
   addresses, so **no Xen IOMMU driver is needed on day one**. (doc 05)
3. **Hardware virtual-interrupt injection exists.** Although the SoC has no GIC,
   the CPU cores implement the **GICv3 hypervisor List Registers** (`ICH_LR*`,
   `ICH_HCR_EL2`, `ICH_MISR_EL2`, `ICV_*`). Asahi's AIC driver registers
   `gic_kvm_info{ .type = GIC_V3, ... }` and KVM injects guest interrupts through
   these hardware LRs. So **Xen's mature vGICv3 is reusable** — guests see an
   emulated GICv3. (doc 04)
4. **SMP is spin-table**, which **Xen already supports**
   (`arm64/smpboot.c`). m1n1 starts and parks the cores; Xen releases them.
   (doc 06 §2)
5. **PSCI-up, not PSCI-down.** There's no PSCI below EL2, but Xen already
   *provides* vPSCI to guests (`vpsci.c`); dom0 gets normal PSCI while Xen does
   the Apple CPU-start work downward. (doc 06 §3)
6. **4 KB pages work.** M1 `ID_AA64MMFR0_EL1 = 0x000010000f100001` → 4 KB
   supported at **both** stage‑1 and stage‑2 (it is 64 KB that's missing). Xen
   can stay 4 KB while dom0 stays 16 KB — exactly what the Xen ARM maintainer
   suggested. (doc 02)

## 3. The two false alarms (corrected)

- **"Interrupt injection must be pure software (`HCR_EL2.VI/VF`)."** *Wrong.*
  Hardware GICv3 List Registers are present; injection is HW-accelerated, same
  as a real GICv3. (doc 04 §1)
- **"Apple CPUs don't support 4 KB pages."** *Wrong.* The MMU supports 4 KB at
  S1 and S2; 16 KB is forced only at the **DART IOMMU** and firmware ecosystem,
  which constrains **dom0**, not Xen's own granule. (doc 02 §2)

## 4. The two genuinely hard problems

1. **Forced VHE (`HCR_EL2.E2H` is RES1).** Apple M1/M2 have **no non-VHE EL2**.
   Xen/arm is a classic non-VHE hypervisor (`head.S` uses `TTBR0_EL2` only;
   `traps.c:100` never sets E2H; headers assume the non‑E2H `TCR_EL2` layout).
   Xen must gain an **hVHE/VHE mode**: E2H‑format `TCR_EL2`/`SCTLR_EL2`, a
   TTBR/VA-layout decision, and `_EL12` accessors for guest EL1 context. This is
   the biggest architectural change and fails *silently* if wrong (no console
   before the MMU is up). Reference: KVM hVHE + m1n1 `hv`. (doc 06 §1)
2. **The AIC interrupt stack.** A new physical **AIC driver** (v1 + v2/v3
   multi-die), **FIQ** root handling (Apple routes timer, fast‑IPIs, PMU, and
   the vGIC maintenance IRQ through FIQ — Xen currently treats EL2 FIQ as
   fatal), a software **IPI mux** (only 2 HW IPIs), and a refactor to **split
   `gic_hw_operations`** into physical (AIC) vs virtual (GICv3-LR) halves.
   (doc 03, doc 04 §6)

Everything else is bounded plumbing: DT generation for dom0, an s5l UART
console, a platform stub, reset via watchdog, timer-via-FIQ, and the dom0
driver audit.

## 5. Target architecture (one screen)

```
             ┌──────────────────────────────────────────────┐
   EL0/EL1   │  dom0 = Asahi Linux (16 KB pages, direct-map) │  domU (generic
             │  • sees virtual GICv3 (not AIC)               │  arm64 + vGICv3
             │  • PSCI via Xen vPSCI                         │  + virtio)
             │  • owns DART/SART + all RTKit coprocessors,   │
             │    PCIe, NVMe(ANS2), USB, PMGR, SMC, display  │
             └───────────────▲───────────────────────────────┘
                 vGICv3 LR inject │ stage-2 (4 KB)  │ vtimer via FIQ
             ┌───────────────┴───────────────────────────────┐
   EL2 (VHE, │  XEN (4 KB pages, hVHE/E2H=1)                  │
   E2H=1)    │  • AIC physical driver + FIQ dispatch          │
             │  • vGICv3 (reused) backed by HW ICH_LR         │
             │  • spin-table SMP, vPSCI, WFI idle             │
             │  • s5l UART console, WDT reset                 │
             └───────────────▲───────────────────────────────┘
                             │ m1n1: EL2, MMU off, DTB in x0
             ┌───────────────┴───────────────────────────────┐
             │  iBoot → m1n1 s1 (signed) → m1n1 s2 → [u-boot] │
             └────────────────────────────────────────────────┘
```

Key decisions (see the referenced docs for rationale and alternatives):
- **Xen at 4 KB, dom0 at 16 KB** (doc 02, Path A — confirmed viable).
- **Guests see virtual GICv3**, injected via hardware List Registers
  (doc 04, Design 1). A virtual‑AIC (Design 2) is the fallback for native PCIe
  MSI passthrough.
- **dom0 owns all Apple devices/coprocessors** via native Asahi drivers; Xen
  touches only AIC, timer, UART, WDT (doc 07, doc 08).
- **DART untouched by Xen initially**; dom0 drives it identity‑mapped (doc 05).

## 6. What "done" looks like, in stages

- **P1** Xen executes at EL2 under forced VHE and prints from C. *(retires the
  #1 risk)*
- **P2** Xen takes AIC IRQs + FIQs, keeps time, boots all cores.
- **P3** A guest takes hardware‑injected virtual timer interrupts. *(validates
  the interrupt model on real silicon)*
- **P4** **Asahi boots as dom0 to a login shell on the real NVMe root fs.**
  *(this is the headline goal)*
- **P5** Create/destroy Linux domU guests with virtio.
- **P6+** PCIe MSI, a real Xen DART driver + isolation, GPU, power management.

Full milestone/testing/risk detail: `09-roadmap-testing-and-risks.md`.

## 7. Honest caveats

- **Silent-failure debugging.** Until VHE+console work, failures are hangs. Budget
  for it; develop over the m1n1 USB proxy.
- **4 KB-in-the-ABI friction.** Grant tables / I/O rings are 4 KB in Xen's public
  ABI; a 4 KB Xen with a 16 KB dom0 userland needs care in privcmd/gntdev
  granularity (doc 08 §7, risk R6). Solvable, known-tricky.
- **Weak initial isolation.** Direct-mapped, DART-owning dom0 has broad DMA
  reach; strong isolation waits on a Xen DART driver (doc 05 §6, risk R11). Fine
  while dom0 is the only/trusted domain.
- **Apple ABI churn.** ~80 signed-firmware coprocessors change ABI per Darwin
  release; contained because dom0 owns them all (risk R8). Passthrough re-exposes
  it (out of scope initially).
- **SoC scope.** Plan targets M1/M2. M4 changes the bare-metal EL2 environment
  (Apple extensions reportedly disabled) — out of scope until studied (risk R10).

## 8. Document map

| Doc | Topic |
|---|---|
| `00` (this) | Overview, feasibility verdict, architecture |
| `01-boot-chain.md` | iBoot→m1n1→u-boot→Xen→dom0; Image header; DT; EFI; recovery |
| `02-page-size-and-mmu.md` | 4 KB vs 16 KB decision (Path A/B/C); MMU coupling |
| `03-interrupt-controller-aic.md` | Physical AIC driver, FIQ root, IPI mux, ops split |
| `04-virtual-interrupts-and-timer.md` | vGICv3 reuse vs vAIC; LR injection; timer via FIQ |
| `05-iommu-dart-and-dma.md` | DART/SART, direct-map dom0, coprocessors, future driver |
| `06-el2-vhe-and-cpu-bringup.md` | **Forced VHE**, SMP spin-table, vPSCI, idle, CPU quirks |
| `07-platform-console-and-drivers.md` | `platforms/apple.c`, s5l UART, reset, framebuffer |
| `08-dom0-asahi-integration.md` | dom0 DT generation, ownership split, EL1 audit, toolstack |
| `09-roadmap-testing-and-risks.md` | Phases, milestones, test strategy, risk register, estimate |

## 9. One-paragraph pitch

Boot Xen as the m1n1 payload at EL2; teach it to run under Apple's forced‑VHE
EL2 with 4 KB pages; give it a native AIC driver with FIQ handling and reuse its
existing vGICv3 (backed by the GICv3 List Registers Apple cores actually
implement) to inject interrupts into guests; bring up secondaries via the
spin-table Xen already supports and hand guests PSCI via vPSCI; then boot a
stock linux‑asahi kernel as a direct‑mapped, 16 KB dom0 that sees a synthetic
GICv3, owns every Apple device and coprocessor through its existing drivers, and
mounts its real NVMe root filesystem. No step requires inventing new science —
it requires careful systems engineering against two well-understood reference
implementations (KVM‑on‑Asahi and m1n1's `hv`). It has never been done, and
there is no reason it can't be.
