# 08 — dom0 (Asahi Linux) integration

Status: design. How Asahi Linux actually runs as dom0: the device tree Xen
must generate for it, the device-ownership split, the coprocessor question, the
kernel-config implications, and the toolstack. Assumes Design 1 (dom0 sees a
virtual GICv3) from doc 04 unless noted.

## 1. dom0 model recap

Xen/arm dom0 is **direct-mapped** (guest PA == host PA;
`domain_build.c:297,2261`). This is load-bearing for Apple:
- DART/SART programming by dom0 uses real machine addresses (doc 05 §2).
- dom0 memory is physically contiguous enough to satisfy 16 KiB alignment for
  Asahi's 16 KiB stage-1 (doc 02 §4.2a).
dom0 is **trusted** (as on all Xen/arm). Isolation of untrusted device users is
a later, driver-domain concern (doc 05 §6).

Boot dom0 via the normal Xen/arm flow: `multiboot,kernel`(=Asahi `Image`),
`multiboot,ramdisk`, `multiboot,device-tree` in the FDT `/chosen` (doc 01).
Alternatively **dom0less** (`xen/arch/arm/dom0less-build.c`) to launch dom0 (and
even domUs) straight from the boot FDT with no toolstack — attractive for a
first bring-up because it removes xenstore/xl from the critical path (§7).

## 2. The device tree Xen generates for dom0 — the real integration work

Xen does not pass the host DT to dom0 verbatim; it **builds a dom0 DT** from the
host DT, substituting the virtualized bits. On stock ARM it copies the GIC node;
on Apple that step must be **rewritten**. Concretely, Xen must produce a dom0 DT
that:

1. **Describes a GICv3, not an AIC** (Design 1). Xen currently synthesizes the
   dom0 interrupt-controller node from the host GIC
   (`domain_build.c:1424-1428` → `gic_make_hwdom_dt_node` →
   `gicv3_make_hwdom_dt_node`, `gic-v3.c:1432`). On Apple there is no host GIC
   node to base it on, so Xen must **emit a synthetic GICv3 node** with:
   - `compatible = "arm,gic-v3"`, `#interrupt-cells = <3>`,
     `interrupt-controller`;
   - distributor + redistributor `reg` windows placed in dom0 IPA space that
     Xen's vGICv3 emulates (these are *virtual* MMIO regions, not real MMIO).
   - This mirrors what Xen already does for domU (`make_intc_domU`-style vGICv3
     node generation) — reuse that path for dom0.
2. **Rewrites every device's `interrupts` property from AIC → GICv3 encoding.**
   Host nodes use the AIC 3-cell form `<AIC_IRQ|AIC_FIQ num flags>`; dom0 needs
   the GIC 3-cell form `<GIC_SPI|GIC_PPI num flags>`. Xen must:
   - maintain a **physical-AIC-hwirq → virtual-GIC-SPI map** (e.g. vSPI = f(aic
     hwirq)); route each passed-through IRQ with `route_irq_to_guest(d, virq,
     ...)` (Xen already has host-irq→guest-virq routing);
   - walk the dom0 DT and translate each `interrupts`/`interrupts-extended`
     cell of every device assigned to dom0.
   This is the **largest chunk of dom0 integration** and is mechanical but
   fiddly (level/edge flags, multi-interrupt devices, the ANS2/NVMe mailbox
   IRQ, SMC, DART fault IRQs, PMGR, USB, PCIe INTx).
   *Alternative:* Design 2 (vAIC, doc 04 §2) avoids all of this by keeping the
   AIC node and native encodings — the trade being a full vAIC implementation.
3. **Replaces spin-table with PSCI.** Rewrite `/cpus/cpu@N` to
   `enable-method = "psci"` and add an `arm,psci-1.0` node (`method = "hvc"`),
   backed by Xen's vPSCI (doc 06 §3). dom0 then uses generic PSCI CPU bringup.
4. **Presents timers as GICv3 PPIs.** The dom0 `arm,armv8-timer` node points at
   the (virtual) GIC with standard PPIs (e.g. virt timer PPI 27), not at AIC
   FIQ lines. Xen injects the vtimer via vGICv3 (doc 04 §6).
5. **Preserves `/reserved-memory` carveouts** for coprocessor firmware, and the
   `/chosen` framebuffer, RNG seed, and the ESP PARTUUID so dom0 userspace (and
   its bootloader chain, if any) still work.
6. **Keeps all dom0-owned device nodes** (DART, SART, RTKit coprocessors, PCIe,
   NVMe, USB, PMGR, SMC, etc.) with their MMIO `reg` mapped 1:1 to dom0 and
   their (translated) interrupts.

**Implication:** the dom0 kernel must be built with `CONFIG_ARM_GIC_V3=y` (it
is, in any standard arm64 config) and must be willing to run at **EL1** using a
GICv3 instead of AIC. See §4.

## 3. Device-ownership split

| Component | Owner | Mechanism |
|---|---|---|
| AIC (physical) | **Xen** | doc 03 |
| Arch timer | **Xen** (+ vtimer to dom0) | doc 04/06 |
| s5l UART (console) | **Xen** (dom0 gets vuart or shared) | doc 07 |
| WDT (reset) | **Xen** | doc 07 |
| Everything else | **dom0** | MMIO+IRQ assigned, native Asahi drivers |
| DART / SART | **dom0** (identity) | doc 05 |
| RTKit coprocessors (NVMe/ANS2, SMC, DCP, GPU, ISP, SEP, audio) | **dom0** | native drivers via mailbox+DART |
| PCIe / USB / Type-C | **dom0** | native drivers (MSI caveat §5) |
| PMGR power/clock, cpufreq | **dom0** | native drivers |

This is the standard Xen/arm "dom0 drives the hardware" model and it is what
makes the port tractable: the ~80 signed-firmware coprocessors with Apple's
per-Darwin-release ABI churn stay entirely inside dom0's existing, maintained
Asahi drivers. Xen never speaks RTKit.

## 4. Will Asahi run at EL1 with a GICv3 (no AIC)?

This is the key dom0 risk for Design 1. Evidence it is feasible:
- **KVM guests on Asahi already do exactly this**: a Linux VM runs at EL1 with a
  KVM-emulated **GICv3** (not AIC) and boots fine. So a Linux kernel at EL1 with
  GICv3 on Apple silicon is a proven configuration.
- The Asahi AIC driver even has an explicit **EL1 path**
  (`irq-apple-aic.c:722-736,1092` "Kernel running in EL1, mapping interrupts"),
  though in Design 1 dom0 won't probe AIC at all.

Risks to validate:
- **Drivers that assume `is_kernel_in_hyp_mode()` (EL2/VHE).** The AIC and
  timer paths do, but dom0 uses neither under Design 1. Audit other Asahi
  drivers for EL2 assumptions (mostly cpuidle/PMU, which we defer). At EL1, any
  IMP-DEF EL2 sysreg access traps to Xen (`HCR_TIDCP`) — Xen injects undef or
  emulates (doc 06 §5). Expect a few drivers to need `depends on !XEN` / graceful
  degradation.
- **PMU/cpufreq/deep-idle** won't work initially (need EL2 IMP-DEF or emulation)
  — acceptable; dom0 boots and runs without them.

If Design 1's driver friction proves too high, fall back to Design 2 (vAIC,
dom0 uses native AIC driver at EL1) — doc 04 §2.

## 5. The PCIe MSI question (Wi-Fi / Thunderbolt)

Apple PCIe (`pcie-apple.c`) delivers MSIs as **AIC IRQs**. Under Design 1, a
GICv3-thinking dom0 can't program those without translation, so **PCIe MSI
passthrough is deferred**. Impact:
- **Not boot-critical**: the internal SSD is **ANS2** (mailbox/RTKit/SART, plain
  AIC IRQ → vGIC SPI), *not* PCIe — so dom0 mounts its real root fs without MSI
  (doc 04 §5). Ethernet-over-USB and the SPI keyboard/trackpad likewise avoid
  PCIe MSI.
- **Deferred to a later phase**: Wi-Fi/BT (PCIe) and Thunderbolt need MSI. The
  fix is either an MSI-translation shim (map Apple PCIe MSI doorbell → vGIC
  SPIs/LPIs) or Design 2 (vAIC) where dom0's `pcie-apple` programs "AIC" MSIs
  that Xen's vAIC maps to real AIC IRQs. Design 2 is the cleaner MSI story.

## 6. Coprocessor / firmware caveats

- **Locked DARTs** (DCP/display framebuffer) are pre-programmed by iBoot; Xen
  must not reset them and dom0 adopts them (doc 05 §4).
- **Reserved-memory carveouts** back coprocessor firmware; Xen must preserve
  them out of both its heap and dom0's allocator, mapped 1:1 to dom0.
- **SMC** owns reboot/poweroff/RTC/sensors; leave to dom0 and route vPSCI
  `SYSTEM_OFF` to it (doc 07 §3).
- **ABI churn**: Apple changes coprocessor ABIs per Darwin release; because dom0
  owns all of it with the maintained Asahi drivers, Xen is insulated. Only
  passthrough to *non-dom0* domains would re-expose this (out of scope).

## 7. Toolstack and running guests

- **dom0 userspace**: build the Xen tools (`xl`, libxenlight, xenstored) for
  arm64 in the Asahi userland. These are page-size sensitive in places (grant
  tables, ring buffers use 4 KiB in the ABI — doc 02 §6 / doc 09 risk): with a
  4 KiB Xen and 16 KiB dom0 userland, audit `xengnttab`/`xenforeignmemory`
  mmap granularity (Linux privcmd/gntdev must reconcile 16 KiB VMA granularity
  with 4 KiB grant refs). This is a real, known-tricky integration point.
- **Fastest first light: dom0less** (`dom0less-build.c`). Launch dom0 (and a
  test domU) directly from the boot FDT — no xenstore, no `xl`. Ideal for
  proving the hypervisor before the toolstack is ported.
- **domU guests**: generic arm64 Linux with vGICv3 + virtio (Xen PV or virtio-
  mmio). These need **none** of the Apple-specific device code — they see a
  clean virtual platform. This is a strong reason to prefer Design 1's GICv3
  for domUs even if dom0 later uses a vAIC.

## 8. Kernel config / patch surface for the Asahi dom0

- Ensure `CONFIG_ARM_GIC_V3=y`, `CONFIG_XEN=y`, `CONFIG_XEN_*` front/back
  drivers, virtio, PV console.
- Keep `CONFIG_ARM64_16K_PAGES=y` (mandatory, doc 02).
- Expect a small out-of-tree patch set: guard EL2-only Apple drivers so they
  degrade gracefully at EL1 under Xen; possibly a Xen-platform quirk to skip
  cpuidle/PMU. Aim to upstream these as "runs as Xen dom0" conditionals.
- The dom0 kernel is otherwise the stock linux-asahi tree.

## 9. Effort and risk

| Task | Difficulty |
|---|---|
| dom0 DT: synthetic GICv3 node | LOW–MODERATE (reuse domU vGICv3 gen) |
| dom0 DT: AIC→GIC interrupt translation | MODERATE (mechanical, fiddly) |
| dom0 DT: PSCI + timer + carveouts | LOW |
| Asahi boots at EL1 w/ GICv3 (Design 1) | MODERATE (driver audit; proven by KVM) |
| dom0 storage (ANS2/SART) reachable | LOW–MODERATE |
| Toolstack on 16 KiB userland vs 4 KiB ABI | MODERATE (grant/ring granularity) |
| PCIe MSI passthrough | HARD, deferred |
| dom0less first-light path | LOW |

The dom0 integration is dominated by **DT generation/translation** and the
**EL1-with-GICv3 driver audit**. Neither is deep research — both are bounded
engineering with KVM as an existence proof that Linux-at-EL1-with-GICv3 works on
this silicon.
