# 06 — EL2 execution environment (forced VHE), SMP bringup, PSCI, idle, CPU quirks

Status: design. This document covers making Xen actually *execute correctly* at
EL2 on Apple Silicon, once the bootloader has handed it control. It contains the
**single hardest architectural item in the port: forced VHE (E2H=1)**. It also
covers SMP secondary bringup (no PSCI), the PSCI-shim-for-guests, CPU idle, and
Apple CPU feature quirks (TSO/ACTLR).

## 1. Forced VHE (`HCR_EL2.E2H == 1`) — the big one

### 1.1 The problem
Apple cores are **VHE-only**: `HCR_EL2.E2H` is forced to 1; non-VHE EL2
(E2H=0) does not functionally exist. This is not a software preference — it is
hardware, and it is confirmed in the kernel's own EL2-setup code
(`arch/arm64/include/asm/el2_setup.h:22-62`), which is the authoritative primary
source. Two mechanisms are distinguished there:

- **Architecturally-compliant CPUs** advertise VHE-onlyness via
  `ID_AA64MMFR4_EL1.E2H0 < 0`; on them `HCR_EL2.E2H` is RES1.
- **"Fruity CPUs" (Apple)** *predate* that architectural field and, per the
  comment, "seem to have `HCR_EL2.E2H` implemented as **RAO/WI**" — Read-As-One,
  **Write-Ignored**. So writing E2H=0 has no effect; it reads back as 1. Because
  Apple doesn't advertise it in the ID register, the kernel **probes it at
  runtime**: set nVHE flags, write `FAR_EL1=1`, overwrite via `FAR_EL2=2`, then
  read `FAR_EL1`; if it now reads `2`, `FAR_EL1`/`FAR_EL2` are the *same*
  register (VHE system-register remapping) ⇒ the CPU is VHE-only.

So "are we sure?" — **yes, for M1/M2**, from three independent angles: this
kernel's RAO/WI comment + runtime probe, Marc Zyngier's KVM commits ("a
workaround for the M1's lack of nVHE mode"), and the hVHE work. It is hardware,
detected empirically, not a boot-time choice.

### 1.1a Does M3/M4 behave differently? (honest answer)
- **M3: present in this tree and handled identically.** The tree ships M3-family
  device trees (`t8122` = M3, `t6030/6031/6032/6034` = M3 Pro/Max/Ultra; P/E
  cores `apple,everest`/`apple,sawtooth`), still using AIC + spin-table + s5l +
  16 KiB DART. Crucially, the E2H logic has **zero per-model special-casing** —
  the generic RAO/WI probe (§1.1) covers every Apple generation. There is no
  M3 MIDR carve-out for E2H, which is exactly what you'd expect if M3 is also
  VHE-only. **Strong inference: M3 is VHE-only too.** (No positive M3
  `HCR_EL2`/`MMFR4` dump is in this tree — `cputype.h` only lists M1/M2 CPU
  parts — so this is inference from the generic handling, not a register dump.)
- **M4: not in this tree, and it has a *separate, larger* concern.** Public
  reports say the M4 raw bare-metal boot object "drops into EL2 but with most
  Apple-specific extensions disabled." If true, that jeopardises the IMP-DEF
  registers the whole AIC/timer plan relies on (fast-IPI `IPI_RR_*_EL1`, the
  guest-timer `VM_TMR_FIQ_ENA_EL2`, PMU) far more than E2H does. **Scope the
  port to M1/M2/M3; treat M4 as a research spike, not a target.**
- **Why this doesn't threaten the plan either way:** VHE-only is the
  *conservative* assumption. If a future chip *did* support nVHE (E2H togglable),
  that can only make a Xen port *easier* (Xen could run in its native non-VHE
  mode). Planning for forced VHE is safe across all generations.

### 1.1b Design consequence: Xen must *probe*, not assume
Do not hardcode "E2H=1" in Xen. Mirror Linux: at EL2 entry, run the FAR-remap
probe (§1.1) — or, on CPUs that advertise it, read `ID_AA64MMFR4_EL1.E2H0` — to
**decide VHE vs non-VHE at runtime**, then configure `TCR_EL2`/`SCTLR_EL2` and
the register accessors accordingly. This makes Xen correct on M1/M2/M3 *and* on
any hypothetical future part that re-enables nVHE, and it costs a few
instructions at boot. It also gives a clean, testable P0 signal ("E2H probe:
VHE-only" printed from the console).

Xen/arm is a classic **non-VHE type-1 hypervisor**. Verified in this tree:
- `xen/arch/arm/arm64/mmu/head.S:287-288,509` set up EL2 paging via
  **`TTBR0_EL2` only** — the non-VHE single-range EL2 regime.
- `xen/arch/arm/include/asm/processor.h:321,330,355` explicitly note that the
  `TCR_EL2.TG1 / IPS / TBI0/1` fields "exist only if `HCR_EL2.E2H==1`" — i.e.
  Xen uses the **non-E2H** `TCR_EL2` layout.
- `check_cpu_mode` (`head.S:316`) checks only "am I in EL2?" — it never inspects
  or attempts to clear E2H.
- `get_default_hcr_flags` (`traps.c:100-105`) sets `HCR_VM|IMO|FMO|AMO|…` but
  **never sets E2H**. On Apple, writing E2H=0 is silently ignored (RES1), so Xen
  ends up running with E2H=1 while every downstream assumption says E2H=0.

**What breaks if unaddressed** (silent, early, hard to debug):
- **`TCR_EL2` / `SCTLR_EL2` field layout changes** under E2H=1 (they take the
  EL1-like VHE format). Xen's boot page-table setup programs the non-VHE layout
  → wrong translation config → early hang.
- **The EL2 translation regime becomes two-range** (`TTBR0_EL2` for low VAs +
  `TTBR1_EL2` for high VAs), like EL1. Xen maps itself at high VAs in a single
  `TTBR0_EL2` regime today; that VA no longer resolves the same way.
- **Register-name redirection**: with E2H=1, `SCTLR_EL1`, `TCR_EL1`,
  `TTBR0/1_EL1`, `CPACR_EL1`, `CNTKCTL_EL1`, etc. accessed *by those names from
  EL2* alias the **EL2** registers, not EL1. Xen's guest context switch
  (`ctxt_switch_to`, save/restore of guest EL1 state) would then corrupt EL2
  state instead of touching the guest's EL1 state.
- **Timer**: `CNTHCTL_EL2` bit meanings change under E2H=1; `CNTKCTL_EL1`
  aliases into EL2.

### 1.2 The solution: teach Xen an hVHE/VHE mode
This is a solved problem — KVM did it. Two framings:
- **hVHE** (KVM's approach for pKVM/nVHE-structured code on E2H-forced HW):
  keep the nVHE code structure but run with E2H=1, using `_EL12`/`_EL02`
  accessors where the code means "the EL1 view."
- **Full VHE adoption**: restructure Xen's EL2 as the VHE EL2&0 regime.

For Xen the pragmatic path is **hVHE-style**: accept E2H=1 and make the minimal
set of changes so the existing type-1 structure works. Concrete work items:

1. **Boot detection & config** (`head.S`): stop assuming E2H=0. Detect
   `ID_AA64MMFR1_EL1.VHE` (`sysregs.h:297` `ID_AA64MMFR1_VHE_SHIFT 8`) and the
   forced-E2H condition; program `TCR_EL2`/`SCTLR_EL2` in the **E2H=1 layout**.
   Set `HCR_EL2.E2H|TGE` appropriately for Xen's own execution (note: `TGE` must
   be **0** while a guest runs so exceptions route correctly; Xen manages TGE).
2. **VA layout / TTBR** (`mmu/head.S`, `layout.h`, `xen.lds.S`): decide whether
   Xen lives in `TTBR0_EL2` (low half) or `TTBR1_EL2` (high half) under E2H.
   The least-disruptive choice keeps Xen's existing high-VA link addresses and
   maps them via `TTBR1_EL2` (VHE high range), mirroring how a VHE host kernel
   runs. This touches the boot page tables and the identity-map bring-up.
3. **Guest EL1 context switch** (`xen/arch/arm/arm64/domain.c`,
   `ctxt_switch_to/from`, `vsysreg.c`): use the **`_EL12` accessors** for guest
   EL1 system registers when running with E2H=1 (`SCTLR_EL12`, `TTBR0_EL12`,
   `TTBR1_EL12`, `TCR_EL12`, `CNTKCTL_EL12`, `SPSR_EL12`, `ELR_EL12`, …). This
   is the bulk of the mechanical work and must be audited register-by-register.
   Note Apple also exposes `PMCR1_EL12` (an EL12 alias) — consistent with the
   VHE model.
4. **Timer** (`time.c`): account for E2H=1 `CNTHCTL_EL2` semantics and the
   `CNTKCTL` aliasing; combine with the FIQ-based delivery from doc 04 §6.
5. **Exception entry** (`entry.S`): EL2h vectors are unchanged in principle, but
   verify `SPSR`/`ELR` handling and the guest-entry/exit `HCR.TGE` toggling.

### 1.3 Effort / risk
**HARD.** This is comparable in effort to the AIC driver and has a nastier
debugging profile (wrong EL2 paging = silent hang before console). Mitigations:
- **Reference implementations exist**: KVM's hVHE series (2022) and arm64 VHE
  support; m1n1's `hv` sets `HCR_EL2 = … | HCR_E2H | HCR_VM` and runs a guest at
  EL1 under E2H=1 — study `src/hv_asm.S` / `src/start.S` / `src/exception.c` for
  the exact Apple EL2 setup and `_EL02` timer remapping.
- **Prototype at EL2 in isolation** before integrating: a tiny bare-metal EL2
  stub (or m1n1 proxy) that enables the MMU under E2H=1 and prints, to validate
  the `TCR_EL2`/`TTBR` layout independently of the rest of Xen.
- This is likely the item to **do first** (with the console), because nothing
  else can be tested until Xen runs stably at EL2.

## 2. SMP secondary CPU bringup (no PSCI)

### 2.1 The situation
There is **no PSCI** on Apple Silicon (no EL3/secure monitor; nothing below
EL2 to service SMC/HVC). The actual core power-on is Apple-MMIO-specific:
- m1n1 **physically starts every core** by poking Apple CPU-start MMIO
  (`CPU_START_OFF_T8103 = 0x54000`; other SoCs differ, e.g. T6031 `0x88000`),
  per-core `RVBAR`, and a debug-unlock register, after the SPRR/GXF chicken-bit
  setup, then **parks them in a spin-table**.
- Mainline/Asahi DTs use `enable-method = "spin-table"` with loader-filled
  `cpu-release-addr` (`t8103.dtsi` etc.).

### 2.2 Xen already has what we need
`xen/arch/arm/arm64/smpboot.c` implements the spin-table method:
`smp_spin_table_init` parses `cpu-release-addr` (`:48`), `smp_spin_table_cpu_up`
writes `__pa(init_secondary)` to the release address and `sev()`s (`:20-42`);
`dt_arch_cpu_init` dispatches on `enable-method` and already handles
`"spin-table"` (`:79-87`). Secondaries land in `init_secondary` (`head.S:268`)
spinning on `smp_up_cpu`.

### 2.3 Plan
- **Primary path — consume m1n1's spin-table.** If m1n1 has already started and
  parked all cores (as it does for Linux), Xen's existing spin-table path
  releases them. **This may work with little or no new bringup code.** The main
  additions are Apple per-CPU init on each secondary once it enters Xen:
  the `aic_init_cpu` equivalent (doc 03 §8), the E2H/EL2 setup (§1) re-applied
  per CPU, and any cluster/coherency register config.
- **Fallback path — do the Apple CPU-start ourselves.** If we boot in a context
  where cores are *not* pre-started (e.g. a future non-m1n1 flow), implement the
  Apple start sequence: RVBAR + debug-unlock + `writel(1<<cpu, cpu_start_mmio)`
  per SoC offset. Precedent: Corellium's `apple,startcpu` enable-method
  (`arch/arm64/kernel/apple_cpustart.c`) does exactly this from the kernel.
  Wire it as a new `enable-method` branch in `dt_arch_cpu_init` + a
  `prepare_cpu` hook (near-copy of `smp_spin_table_cpu_up`) reading the
  `apple,cpu-start`/PMGR registers from DT.
- big.LITTLE: Apple has P and E cores. Xen must handle heterogeneous MPIDR
  topology and the `CCSIDR_EL1` mismatch across P/E cores (KVM fixed a vCPU
  migration bug here in 6.3) — pin or sanitise as needed.

**Difficulty:** LOW–MODERATE if consuming m1n1 spin-table; MODERATE if we
implement Apple CPU-start (per-SoC MMIO offsets + chicken bits, well
documented in m1n1 `src/smp.c`).

## 3. PSCI shim *upward* to dom0/guests

Xen cannot call PSCI *down* (nothing below EL2). But guests (including dom0)
expect PSCI for CPU_ON/OFF/SUSPEND/system reset. **Xen already provides vPSCI**
(`xen/arch/arm/vpsci.c`) and emulates PSCI for guests. So:
- The dom0 DT that Xen generates (doc 08) describes a **PSCI** node
  (`arm,psci-1.0`, `method="hvc"`), *not* spin-table — regardless of how the
  physical bringup works. dom0's generic PSCI CPU bringup then works unchanged.
- Xen's vPSCI `CPU_ON` maps a guest vCPU online → Xen schedules that vCPU on a
  physical core it already started (§2). `SYSTEM_RESET`/`SYSTEM_OFF` map to the
  Apple reset/poweroff sequence (doc 07: PMGR/watchdog based, via the platform
  `reset`/`poweroff` hooks).

This is the "natural layering that is impossible below EL2 but easy to add at
EL2" the research surfaced — and Xen already has it. **Difficulty: LOW** (mostly
DT generation + wiring platform reset/poweroff).

## 4. CPU idle / power management

- No PSCI `CPU_SUSPEND`. Xen's idle loop uses **WFI**, which is fine at EL2 on
  Apple. `vwfi` policy (`get_default_hcr_flags` toggles `HCR_TWI|TWE`) controls
  whether guest WFI traps; default trap-and-schedule is fine.
- **Deep idle / cluster power-down** (the Asahi cpuidle driver pokes Apple
  registers and is explicitly non-upstreamable) is an **optimisation, deferred**.
  Initial Xen runs cores in shallow WFI idle — higher power, correct behaviour.
- CPU frequency scaling (Apple `cpufreq` via PMGR/DVFS MMIO) is likewise
  deferred; run at the boot P-state. Acceptable for bring-up.

## 5. Apple CPU feature quirks Xen must handle

From `arch/arm64/include/asm/apple_cpufeature.h`,
`arch/arm64/kernel/cpufeature_impdef.c`, `arch/arm64/include/asm/cputype.h`:

- **MIDR / implementer**: `ARM_CPU_IMP_APPLE = 0x61`; `MIDR_APPLE_M1_*` /
  `M2_*`. Xen's `processor.c` / cpuerrata must recognise Apple parts (currently
  it only knows ARM/Cavium/etc.) so feature/errata logic doesn't misfire.
- **TSO memory model**: Apple cores toggle x86-like Total Store Ordering via
  `ACTLR_EL1[1]` (`ACTLR_APPLE_TSO`), advertised in `AIDR_EL1[9]`. Used by
  Rosetta/FEX. Xen must **context-switch `ACTLR_EL1` per vCPU** (Asahi enables
  `CONFIG_ARM64_ACTLR_STATE`); otherwise a guest that enables TSO leaks it
  across vCPUs, or loses it. Xen's arm64 context switch must save/restore
  `ACTLR_EL1`. There is also an "ACTLR virtualization" capability
  (`ARM64_HAS_ACTLR_VIRT[_APPLE]`) — a guest attempting `ACTLR` writes may need
  trap/emulate; note the KVM comment that some hypervisors advertise TSO in
  `AIDR` but ignore `ACTLR` writes, so get this right if guest TSO is desired.
- **IMP-DEF sysregs Xen must not fault on / must manage** at EL2: the IPI
  registers (`IPI_RR_*_EL1`, `IPI_SR_EL1`, `IPI_CR_EL1`), the guest-timer FIQ
  enable (`SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2`), PMU (`PMCR0/1_EL1`, `PMCR1_EL12`,
  `UPMCR0/UPMSR`), and the SPRR/GXF/APRR protection registers m1n1 configures.
  Decide per register: pass-through (Xen uses it), trap-and-emulate (guest uses
  it), or leave to dom0. `HCR_TIDCP` (already set in `get_default_hcr_flags`)
  traps guest IMP-DEF sysreg access to EL2 — Xen must handle the Apple ones it
  cares about and inject undef for the rest.
- **PMU**: Apple's PMU is IMP-DEF (not architectural PMUv3) and delivers via
  FIQ (`apple_m1_pmu.h`). dom0 PMU support requires emulating/exposing it;
  **defer** (dom0 boots fine without PMU). Guests would need PMUv3 emulation
  (KVM added this) if PMU is wanted — out of scope initially.

## 6. Summary of work items in this document

| Item | Difficulty | Phase |
|---|---|---|
| Forced-VHE (E2H=1) EL2 execution | **HARD** | 1 (must be first) |
| Consume m1n1 spin-table for SMP | LOW–MODERATE | 2 |
| Apple CPU-start MMIO (fallback) | MODERATE | later/opt |
| PSCI shim upward (vPSCI + DT) | LOW | 3 |
| WFI idle | LOW | 1 |
| Deep idle / cpufreq | deferred | later |
| Apple MIDR recognition | LOW | 1 |
| `ACTLR`/TSO context switch | MODERATE | 4 (guest correctness) |
| IMP-DEF sysreg trap policy | MODERATE | ongoing |
| PMU (dom0/guest) | deferred | later |

The two things that gate *everything* are in this doc and doc 03/04: **run
stably at EL2 under forced VHE**, and **take interrupts (AIC IRQ + FIQ)**. Do
VHE + console first; you cannot debug anything until Xen executes and prints.
