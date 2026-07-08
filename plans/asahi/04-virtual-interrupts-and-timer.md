# 04 — Virtual interrupts and timer (what guests see, and injection)

Status: design. This is the **central design decision** of the whole port:
what interrupt controller does dom0 (and domU) see, and how does Xen inject
virtual interrupts on hardware that has no GIC distributor?

The pivotal hardware fact (verified in Asahi source) reframes the problem in
our favour.

## 1. The pivotal fact: Apple CPUs *do* have the GICv3 virtual CPU interface

Even though the SoC has **no GIC distributor/redistributor** (it has AIC), the
Apple CPU cores implement the **GICv3 CPU system-register interface used for
virtualization**: the list registers and their control/status registers.
Evidence in `drivers/irqchip/irq-apple-aic.c`:

- Registers a GICv3 KVM descriptor (`:922-926`):
  ```c
  static struct gic_kvm_info vgic_info __initdata = {
      .type              = GIC_V3,
      .no_maint_irq_mask = true,
      .no_hw_deactivation = true,
  };
  ```
- Manipulates the EL2 virtualization control/status regs (`:428-441`,
  `:877-878`): `SYS_ICH_HCR_EL2` (`ICH_HCR_EL2_En`), `SYS_ICH_MISR_EL2`.
- Routes the **vGIC maintenance interrupt** through the AIC FIQ path
  (`:423-442`, comment: "vGIC maintenance interrupts end up here too").
- KVM's `vgic-v3.c` reads `ICH_VTR_EL2` for LR/priority-bit counts and sets
  `ICC_SRE_EL1` for the guest — proving the guest-facing `ICC_*`/`ICV_*`
  interface works, backed by `ICH_LR*` list registers.

Consequence: **the hardware can inject virtual interrupts into a guest via the
standard GICv3 list-register mechanism.** This is exactly what makes KVM VMs
work on Asahi. It means Xen's mature **vGICv3** injection engine is reusable,
not dead — contrary to a naive "no GIC ⇒ no injection" reading.

Two Apple-specific caveats from the flags above:
- `no_hw_deactivation`: the CPU interface does not do hardware deactivation of
  physical interrupts (there is no distributor to deactivate at). Xen must run
  the LR path in the "EOImode/no-HW-deactivate" configuration and perform
  physical EOI via AIC (doc 03), not via a GIC.
- `no_maint_irq_mask`: the maintenance interrupt is an AIC FIQ, not a
  maskable GIC PPI; wire it via the FIQ dispatcher (doc 03 §7).

## 2. Two designs for the guest-visible controller

Injection *backend* (how Xen makes an IRQ pending in the guest) and the
guest-visible *model* (what the guest's driver talks to) are separable:

| | Guest sees | Guest driver | Injection backend | Xen reuse | Fights Apple device model? |
|---|---|---|---|---|---|
| **Design 1** | virtual **GICv3** | `irq-gic-v3` | HW list registers (`ICH_LR`) | **high** (existing vGICv3) | yes for PCIe-MSI |
| **Design 2** | virtual **AIC** | `irq-apple-aic` | software via `HCR_EL2.VI/VF` | low (new vAIC) | no |

### Design 1 — present a virtual GICv3 (KVM's model)
- dom0/domU DT describes a GICv3; the guest uses the standard GICv3 driver at
  EL1; `ICC_*` accesses are HW-virtualized to `ICV_*` and backed by `ICH_LR`.
- Xen reuses `vgic-v3.c` / the new vGIC in `xen/arch/arm/vgic/` and
  `gic-vgic.c`'s `gic_raise_guest_irq` → `update_lr` almost unchanged (those
  `ICH_LR*` sysregs exist on Apple).
- Physical device IRQ → arrives at Xen via AIC → Xen maps physical AIC hwirq to
  a guest virtual SPI → writes an LR. Xen already has host-irq→guest-virq
  routing (`route_irq_to_guest`).
- **Cost:** the dom0 DT must be rewritten so every device's `interrupts`
  property uses GICv3 SPI/PPI encoding instead of AIC encoding (doc 07), and a
  synthetic GICv3 node is emitted (Xen normally *copies* the host GIC node;
  here it must *synthesize* one — `gicv3_make_hwdom_dt_node`, see doc 07).
- **Friction:** Apple PCIe (`pcie-apple.c`) delivers MSIs as **AIC IRQs**; a
  GICv3-thinking dom0 driver can't program them. Not boot-critical (see §5).

### Design 2 — present a virtual AIC
- dom0 DT keeps the AIC node; dom0 uses its native `irq-apple-aic` driver at
  EL1 (the driver already has an EL1 path, `aic:722-736,1092`). All device
  `interrupts` properties pass through unchanged. PCIe-MSI works natively.
- Xen must **emulate**: the AIC MMIO (event register semantics, mask/target
  arrays, IPI regs) via the MMIO trap framework, and trap+emulate the fast-IPI
  IMP-DEF sysregs (`IPI_RR_*_EL1`, `IPI_SR_EL1`). Guest IRQ line asserted by
  toggling **`HCR_EL2.VI`** (IRQ) / **`.VF`** (FIQ) — both defined in Xen
  (`processor.h:274-275`) but currently unused. This is the "single-line
  software injection" model; every guest ack/EOI traps to Xen.
- **Cost:** a from-scratch virtual interrupt controller (the "major surgery"
  the Xen survey flagged) and a per-IRQ trap on injection/ack (slower). But it
  makes dom0 behave like bare-metal Asahi and sidesteps all DT interrupt
  translation and MSI friction.

## 3. Recommendation: phase it

- **Phase 1–3 (boot dom0, console, timer, IPIs, platform IRQs): Design 1.**
  Fastest path to a booting dom0, maximal reuse of Xen's vGICv3, proven on this
  exact silicon by KVM. Enough for UART, the ANS2/NVMe mailbox IRQ (a normal
  level IRQ → SPI), SMC, PMGR, etc.
- **Phase 5+ (full native device passthrough incl. PCIe/Thunderbolt/Wi-Fi
  MSIs): evaluate Design 2 (vAIC).** If MSI translation for Design 1 proves
  too invasive to dom0's `pcie-apple` driver, a vAIC lets dom0 use every native
  Apple driver unmodified. Keep the injection backend pluggable so the vAIC can
  still use `HCR.VI/VF` while vGICv3 keeps LRs.

This is honest about the trade: Design 1 gets you booting fast; Design 2 is the
cleaner long-term end-state for full passthrough. They are not mutually
exclusive across domains — but a single domain must pick one (an
`interrupt-parent` is singular).

## 4. Xen changes for Design 1 (the recommended first path)

1. **vGIC is currently mandatory and version-gated** —
   `xen/arch/arm/domain.c:742-765` `switch(gic_version){ GIC_V2|GIC_V3; default
   BUG() }`, and dom0 uses `XEN_DOMCTL_CONFIG_GIC_NATIVE`
   (`domain_build.c:2242`). On Apple there is no "native" GIC. **Action:** make
   the Apple platform report vGIC = GICv3 (the CPU interface *is* GICv3), so
   `gic_version` resolves to `GIC_V3` and the existing vGICv3 path runs.
2. **Decouple vGICv3 init from the physical distributor probe.** Today
   `gicv3_preinit`/`gicv3_init` probe distributor + redistributor MMIO *and*
   set up the virtual interface. On Apple there is no distributor MMIO.
   **Action:** factor a "virtual CPU interface init" that only reads
   `ICH_VTR_EL2` (LR count, priority/ID bits), sets up the LR pool
   (`gic-vgic.c:101-124` `lr_mask`, `gic_get_nr_lrs`), and does *not* touch
   distributor/redistributor. The AIC driver (doc 03) provides the physical
   side; this provides the virtual side.
3. **Maintenance interrupt.** `gic.c:389` `init_maintenance_interrupt` does
   `request_irq(info->maintenance_irq, ...)`. On Apple there is no PPI —
   instead the FIQ dispatcher (doc 03 §7) detects `ICH_MISR_EL2 != 0` and calls
   the maintenance handler directly. **Action:** replace the `request_irq` with
   an FIQ-driven call; keep `gic_hcr_status`/LR underflow handling intact.
4. **Injection path unchanged in spirit.** `vgic_inject_irq`
   (`vgic/vgic.c:381`) → `gic_raise_guest_irq` (`gic-vgic.c:126`) →
   `gic_set_lr` → `update_lr` (writes `ICH_LR<n>_EL2`). These sysregs exist on
   Apple, so this works once (1)–(3) are done.
5. **Run EOImode without HW deactivation** (`no_hw_deactivation`): physical
   deactivation/EOI happens in the AIC driver; the LR "HW bit" linkage to a
   physical INTID must be handled so Xen deactivates via AIC, not via a
   non-existent GIC. Audit `gic-vgic.c` `gic_update_one_lr` for the HW-IRQ
   deactivation assumption and route it to `intc_hw_ops->deactivate_irq`.

## 5. Storage without PCIe — why Design 1 reaches the root disk

A crucial de-risking fact: the **internal SSD is not behind PCIe**. It is the
**ANS2** NVMe *coprocessor* reached via a mailbox + RTKit + SART
(`drivers/nvme/host/apple.c`, doc 05/07). Its interrupts are **ordinary AIC
IRQs** (the mailbox IRQ), which translate cleanly to a vGICv3 **SPI**. So under
Design 1 dom0 can mount its real root filesystem without any MSI support. PCIe
(Wi-Fi/BT, Thunderbolt) needs MSIs and is deferred to the Design-2/MSI work.
This is what makes a *useful* dom0 reachable in the early phases.

## 6. Timer

Xen's timer logic is reusable; only the **delivery plumbing** changes, because
Apple wires the architected timer to **FIQ**, not a GIC PPI.

Today:
- Xen self-tick uses `CNTHP_*_EL2` (`time.c:223-256`).
- Delivery assumes GIC PPIs via `request_irq(timer_irq[TIMER_HYP_PPI],
  htimer_interrupt)` and `[TIMER_VIRT_PPI]` (`time.c:307-320`), IRQ numbers from
  the arch-timer DT `interrupts` (`time.c:176-191`). Guest vtimer:
  `vtimer_interrupt` (`time.c:258-278`) → `vgic_inject_irq`.

On Apple (`irq-apple-aic.c:552-613`, `t8103.dtsi:368-375` — the `arm,armv8-timer`
node points `interrupt-parent = &aic` with `AIC_FIQ` timer indices):

1. **Stop routing the timer through `request_irq`/`do_IRQ`.** Instead the FIQ
   dispatcher (doc 03 §7) demuxes by reading control registers:
   - `TIMER_FIRING(CNTHP_CTL_EL2)` → Xen hypervisor tick →
     `raise_softirq(TIMER_SOFTIRQ)` (reuse `htimer_interrupt` body).
   - `TIMER_FIRING(CNTP_CTL_EL0)` / `CNTV_CTL_EL0` per policy.
2. **Guest (EL1) vtimer:** enable/mask via the Apple EL2 register
   `SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2` (`:187-189`, V=bit0 virt, P=bit1 phys). On
   the guest-timer FIQ, inject the vtimer as a **vGICv3 PPI 27** through the
   existing `vgic_inject_irq` path (reuse `vtimer_interrupt` body). There is no
   architectural CNTHCTL trap equivalent — this Apple register *is* the
   guest-timer control.
3. **`CNTVOFF_EL2`/`CNTFRQ`** must be programmed per the boot protocol
   (m1n1 sets `CNTFRQ`; Xen manages `CNTVOFF` per vCPU as it already does).
4. Drop `check_timer_irq_cfg` (`time.c:322`) trigger-type assumptions — the
   FIQ has no configurable GIC trigger.

Net: `time.c` keeps its scheduling/softirq logic; the ~40 lines of
`init_timer_interrupt`/`request_irq`/`do_IRQ` glue are replaced by FIQ-dispatch
hooks and the Apple guest-timer enable register.

## 7. IPIs to guests / guest SGIs

Under Design 1, guest-to-guest IPIs are GICv3 **SGIs**: the guest writes
`ICC_SGI1R_EL1`, which the CPU virtualizes; Xen's vGICv3 handles SGI delivery
via LRs exactly as on stock hardware. No Apple-specific work. (Physical
inter-CPU IPIs inside Xen use AIC fast-IPI — doc 03 §5. The two are
independent.)

## 8. Effort and risk

- **Design 1:** MODERATE. Mostly *decoupling* existing vGICv3 from the physical
  distributor + rewiring the maintenance IRQ and timer to FIQ. Small new code;
  the risk is in the `no_hw_deactivation` EOI/deactivate audit and the DT
  interrupt translation (doc 07).
- **Design 2 (vAIC):** HARD. A new emulated controller + `HCR.VI/VF` injection
  + IMP-DEF sysreg trap/emulate. Only undertaken if MSI passthrough demands it.
- **Key validation:** the very first guest-injection test is the dom0 vtimer
  tick (Phase 3). If the guest takes periodic vtimer interrupts via LR
  injection, the whole Design-1 model is proven on real silicon.
