# 03 — Physical interrupt controller: the Apple AIC driver in Xen

Status: design. This document covers the **physical** side of interrupts — the
new AIC driver Xen must implement to handle real hardware interrupts, IPIs
between physical CPUs, the FIQ root, and per-CPU init. The **virtual** side
(what guests see, injection) is `04-virtual-irqs-timer.md`. The two are
deliberately split because Xen today conflates them in one `gic_hw_operations`
struct, and decoupling them is a core part of the work.

Primary reference in Asahi: `drivers/irqchip/irq-apple-aic.c` (1136 lines). Xen
has **no** Apple code today (verified: `grep -riE 'apple|aic|dart' xen/arch/arm`
is empty).

## 1. What AIC is, and why none of Xen's GIC code applies

Apple Silicon has no ARM GIC. AIC ("Apple Interrupt Controller") is an
MMIO + IMP-DEF-sysreg hybrid with a fundamentally different model:

- **896 (v1) / more (v2/v3) level-triggered HW IRQs.** Single mask bit each,
  per-IRQ affinity, hardware auto-prioritisation (lower number = higher prio).
- **A single per-CPU "event" register.** Reading it atomically returns *and
  acks and masks* the highest-priority pending interrupt (`AIC_EVENT` @ 0x2004
  on v1). There is no separate IAR/EOIR/priority-drop/deactivate split like
  GICv3.
- **Two funnels into the CPU**: the **IRQ** vector (ordinary device IRQs, via
  the event register) and the **FIQ** vector (timers, fast IPIs, PMU, and the
  vGIC maintenance interrupt). The FIQ has *no* source register — software must
  poll every possible FIQ source on each FIQ.
- **IPIs** via IMP-DEF system registers ("fast IPI"), delivered as FIQ. Only 2
  hardware IPIs per CPU, so Linux (and Xen) must software-multiplex.
- **v1** (M1, `apple,aic`) vs **v2/v3** (M1 Pro/Max/Ultra, M2, t8110/t8122,
  `apple,aic2`): different register layout, multi-die, no per-IRQ target array
  on v2 (affinity via delay groups / prefer-pcpu).

None of Xen's `gic.c`, `gic-v2.c`, `gic-v3.c`, ITS/LPI, or SGI code is reusable
for the *physical* controller. It all gets replaced by an AIC driver.

## 2. Where the AIC driver plugs into Xen

Good news: interrupt-controller discovery in Xen is already pluggable by DT
compatible string.

- Xen calls `gic_preinit()` → `intc_dt_preinit()` (`xen/arch/arm/gic.c:239`),
  which scans for a node marked `DEVICE_INTERRUPT_CONTROLLER` and dispatches by
  compatible. GIC drivers register with
  `DT_DEVICE_START(gicv3, "GICv3", DEVICE_INTERRUPT_CONTROLLER)`
  (`gic-v3.c`), `.init = gicv3_preinit`.
- **Action:** add `xen/arch/arm/aic.c` registering
  `DT_DEVICE_START(aic, "Apple AIC", DEVICE_INTERRUPT_CONTROLLER)` matching
  compatibles `"apple,aic"` and `"apple,aic2"` (and t8110/t8122 variants). Its
  `.init` probes AIC version and MMIO layout.
- The driver provides a `struct gic_hw_operations`-like vtable via
  `register_gic_ops()` (`gic.c:44`). **But first that struct must be split**
  (§6) so the AIC driver only implements the physical half.

## 3. AIC v1 register model (M1 / `apple,aic`)

From `irq-apple-aic.c:67-105`. All MMIO, "this CPU" view by default:

| Offset | Name | Semantics |
|---|---|---|
| `0x0004` | `AIC_INFO` | `NR_IRQ = bits[15:0]` |
| `0x2000` | `AIC_WHOAMI` | current CPU's AIC index (must == logical CPU id) |
| `0x2004` | `AIC_EVENT` | read → highest-prio pending; **auto-ack + auto-mask**; fields `DIE[31:24] TYPE[23:16] NUM[15:0]`; TYPE 1=IRQ, 4=IPI, 0=SW-FIQ |
| `0x2008` | `AIC_IPI_SEND` | write CPU bitmask to send IPI |
| `0x200c` | `AIC_IPI_ACK` | ack received IPI |
| `0x2024/28` | `AIC_IPI_MASK_SET/CLR` | IPI mask |
| `0x3000` | `AIC_TARGET_CPU` | per-IRQ affinity: one u32/IRQ = CPU bitmask |
| mask regs | `MASK_SET/CLR` | `MASK_REG(x)=4*(x>>5)`, `MASK_BIT(x)=BIT(x&31)` |

IRQ handling (`aic_handle_irq`, `:401-443`):
```c
do {
    event = readl(base + AIC_EVENT);   // non-relaxed read: orders after DMA
    type  = FIELD_GET(AIC_EVENT_TYPE, event);
    irq   = FIELD_GET(AIC_EVENT_NUM,  event);
    if (type == IRQ)  handle(irq);
    else if (type == IPI && irq==1) handle_ipi();
} while (event);   // drain until 0
```
"EOI" = re-unmask (`MASK_CLR`), because the read already acked+masked
(`:391-399`). Xen's `read_irq`/`eoi_irq`/`set_irq_type` map cleanly onto this.

## 4. AIC v2/v3 register model (M1 Pro/Max/Ultra, M2, …)

From `:107-164`, `:1025-1049`. Different and multi-die:

- `AIC2_INFO1` (`0x0004`): `NR_IRQ[15:0]`, `LAST_DIE[27:24]`. `AIC2_INFO3`:
  `MAX_IRQ`, `MAX_DIE`. `AIC2_CONFIG` (`0x0014`): `ENABLE` bit0, `PREFER_PCPU`
  bit28.
- Per-die register blocks (`IRQ_CFG`, `SW_SET`, `SW_CLR`, `MASK_SET`,
  `MASK_CLR`, `HW_STATE`), each `u32 * (MAX_IRQS/32)`, separated by
  `die_stride`. `AIC2_IRQ_CFG` base `0x2000` (v2) / `AIC3_IRQ_CFG` `0x10000`
  (v3). Per-IRQ `IRQ_CFG_TARGET = bits[3:0]` (die/target).
- The **event register lives in a separate `reg` entry** in DT (`of_iomap(node,
  1)`), one 16 KiB page per die, because implemented die count is not
  discoverable. Offsets computed at probe and stored in `struct aic_info`
  (`:246-263`).
- No `AIC_TARGET_CPU` affinity array; `aic2_chip` has no `.irq_set_affinity`
  (`:483-489`).

**Xen action:** model this as `struct aic_info { version; nr_irq; nr_die;
die_stride; event; target_cpu; ... }` filled at probe, exactly as the Linux
driver does. Support v1 and v2 from the start (M1 is v1, most others v2); v3 is
a small delta (different bases).

## 5. IPIs between physical CPUs (fast IPI)

Xen sends IPIs today via GIC SGIs (`smp.c:26-44` → `send_SGI_mask` →
`gic_hw_ops->send_SGI`, with a fixed SGI enum in `gic.h:284`). On Apple this
becomes fast-IPI IMP-DEF sysregs (`:170-192`, `:796-843`):

- **Send** (`aic_ipi_send_fast`): from sender MPIDR compute target
  cluster/CPU; if same cluster write `SYS_IMP_APL_IPI_RR_LOCAL_EL1` else
  `SYS_IMP_APL_IPI_RR_GLOBAL_EL1` (`IPI_RR_CPU[7:0]`, `IPI_RR_CLUSTER[23:16]`,
  `IPI_RR_TYPE[29:28]`), then `isb()`.
- **Receive**: arrives as **FIQ**. `aic_handle_fiq` tests
  `SYS_IMP_APL_IPI_SR_EL1 & PENDING` (`:575`); ack by writing `IPI_SR_PENDING`
  back then `isb()` (`:822`).
- **Legacy v1 fallback** (no fast IPI): MMIO `AIC_IPI_SEND`/`AIC_IPI_ACK`.
- **Only 2 HW IPIs; Xen needs more** (EVENT_CHECK, CALL_FUNCTION, and for the
  vGIC we also need to raise guest interrupts). Linux funnels all IPIs through
  one HW IPI + a 32-entry software vIPI mux (`AIC_NR_SWIPI=32`,
  `ipi_mux_*`). **Xen action:** implement the same SW mux — one physical fast
  IPI, a per-CPU pending bitmap of logical IPIs, demuxed in the FIQ handler.
  Map Xen's `enum gic_sgi` onto logical IPI numbers.

Static keys gate capability: `use_fast_ipi` (A11+), `use_local_fast_ipi`
(M1+) (`:242-244`). Xen sets equivalents at probe from MIDR/feature checks.

## 6. Refactor: split `gic_hw_operations` into physical vs virtual

`xen/arch/arm/include/asm/gic.h:355-426` mixes two concerns. Categorise:

**Physical (AIC implements these):** `init`, `secondary_init`, `read_irq`,
`eoi_irq`, `deactivate_irq`, `set_active_state`, `set_pending_state`,
`set_irq_type`, `set_irq_priority`, `send_SGI`, `read_pending_state`,
`gic_host_irq_type`, `iomem_deny_access`, `make_hwdom_dt_node`.

**Virtual / GIC-HW-assisted (AIC CANNOT implement; belong to the CPU's GICv3
sysreg interface — see doc 04):** `update_lr`, `clear_lr`, `read_lr`,
`write_lr`, `read_vmcr_priority`, `read_apr`, `update_hcr_status`,
`gic_guest_irq_type`, `save_state`/`restore_state`, `info->maintenance_irq`,
`do_LPI`.

**Action:** introduce two structs, e.g. `struct intc_hw_operations` (physical)
and keep the LR/virtual ops in a separate `struct vgic_hw_operations` (or keep
them on the existing gicv3 module, since on Apple the *virtual* interface is
still GICv3 hardware — doc 04). The AIC driver fills only `intc_hw_operations`.
Update call sites: `smp.c` (IPIs), `irq.c` (host IRQ flow), `time.c` (see doc
04), `gic.c` (dispatch). This is mechanical but touches many files; do it as a
prep refactor that leaves GIC platforms working (regression-test on a GICv3
model/board) before adding AIC.

## 7. FIQ: making Xen take fast interrupts

Today Xen treats EL2 FIQ as fatal:
- `xen/arch/arm/arm64/entry.S:628` — `ventry hyp_fiq_invalid` → `BAD_FIQ` →
  `do_bad_mode`. Guest FIQ → `guest_fiq_invalid` (`:633,638`).
- But routing is already enabled: `traps.c:102,171` set `HCR_FMO` (physical FIQ
  → EL2). And a C stub exists: `do_trap_fiq` (`traps.c:2226`) calls
  `gic_interrupt(regs, is_fiq=1)`, which threads the fiq flag to `do_IRQ`.

**Action:**
1. Point `entry.S:628` at a real `hyp_fiq` entry mirroring `hyp_irq` (`:627`):
   save context with FIQ masked, `bl do_trap_fiq`, return via the IRQ epilogue.
2. Implement the AIC FIQ dispatcher (mirror `aic_handle_fiq`, `:557-613`):
   poll, in order, every FIQ source and dispatch:
   - fast IPI: `SYS_IMP_APL_IPI_SR_EL1 & PENDING` → IPI demux (§5).
   - physical/hyp timer: `TIMER_FIRING(CNTP_CTL_EL0)` /
     `TIMER_FIRING(CNTHP_CTL_EL2)` → timer softirq (doc 04). `TIMER_FIRING` =
     `ENABLE && !IT_MASK && IT_STAT`.
   - guest (EL1) timer: `CNTV_CTL_EL0` / EL02 aliases, gated by
     `SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2` → inject guest vtimer (doc 04).
   - core PMU: `SYS_IMP_APL_PMCR0_EL1` IMODE==FIQ && IACT (defer initially).
   - uncore PMU: `SYS_IMP_APL_UPMCR0_EL1`/`UPMSR` (defer).
   - **vGIC maintenance**: `is_hyp && (ICH_HCR_EL2 & En) && ICH_MISR_EL2 != 0`
     → call Xen's maintenance handler (doc 04). This is how Apple delivers what
     a GIC would deliver as a PPI.
3. FIQ masking: most FIQ sources have no HW mask — mask by disabling the source
   and keep a per-CPU software shadow (`aic_fiq_unmasked`, `:349`), exactly as
   Linux does. Only guest timers have real mask bits
   (`SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2`, V/P).

## 8. Per-CPU init (boot + secondary)

Mirror `aic_init_cpu` (`:859-920`) in Xen's `secondary_init`/boot-CPU init:
- Ack/clear pending fast-IPI (`IPI_SR_PENDING`).
- Mask per-CPU timer FIQs (`cntp_ctl`/`cntv_ctl` `IT_MASK`); we will re-enable
  the ones Xen uses.
- Zero the EL2 guest-timer enables (`SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2`) and vGIC
  maintenance (`ICH_HCR_EL2 En`) until a guest needs them.
- Turn off core/uncore PMU FIQ (`PMCR0`/`UPMCR0` IMODE=OFF).
- On v1: assert `AIC_WHOAMI == cpu_id`; keep HW IPIs unmasked (we mask at the
  vIPI level).

## 9. Interrupt numbering / DT parsing

AIC DT uses a 3-cell specifier (`include/dt-bindings/interrupt-controller/apple-aic.h`):
`<AIC_IRQ|AIC_FIQ  number  flags>`. `AIC_IRQ=0`, `AIC_FIQ=1`; FIQ indices name
timers/PMU (`AIC_TMR_HV_PHYS=0`, `HV_VIRT=1`, `GUEST_PHYS=2`, `GUEST_VIRT=3`,
`CPU_PMU_E=4`, `CPU_PMU_P=5`). Xen's `irq.c`/device-tree IRQ translation must
learn this encoding (parallel to the GIC 3-cell parser). The FIQ "IRQs" are
internal to Xen (timer/PMU), not routed to dom0 as AIC FIQs — dom0 sees them as
vGIC PPIs (doc 04).

## 10. Effort and risk

- **New code:** ~1500–2500 LOC for `aic.c` (v1+v2/v3, IPI mux, FIQ dispatch,
  per-CPU init, DT parse), plus the `gic_hw_operations` split refactor across
  ~6 files.
- **Difficulty:** MODERATE-HARD. The register semantics are well-documented in
  the Linux driver (near-direct port). The subtle parts are (a) the FIQ
  poll-all-sources dispatcher, (b) the SW IPI mux, (c) the physical/virtual ops
  split without regressing GIC platforms, (d) v2/v3 multi-die layout.
- **Biggest risk:** the physical/virtual decoupling touching shared code paths.
  Mitigate by landing the refactor first as a no-op on GIC hardware, tested on
  QEMU virt (GICv3), before introducing AIC.
- **Debuggability:** until IRQs work you have only the polled UART early-printk
  (doc 06). Bring up the timer FIQ + one device IRQ (UART RX) first.
