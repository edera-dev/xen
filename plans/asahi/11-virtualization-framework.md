# 11 — Xen nested inside Virtualization.framework

Status: **code written, never booted.** Everything below marked "(measured)"
was read out of the running VM described in §1; everything marked
"(untested)" is a change made on the strength of those measurements and not
yet observed to work.

This is a *second target*, not a variation of the bare-metal port. The
machine macOS's Virtualization.framework synthesises for a guest has none of
the hardware that made §03–§07 hard: it has a GICv3, not an AIC; PSCI, not a
spin table; no IOMMU at all; and a nested EL2 that is not VHE-only. So Xen's
stock arm64 paths apply, and what this document is mostly about is the two
things the platform *doesn't* have — a device tree and a serial port.

```
  macOS (Apple Silicon, real EL2)
    └─ Virtualization.framework VM, nested virt enabled  →  guest enters at EL2
         └─ GRUB (arm64-efi)  →  xen.efi + Linux + initramfs, DTB from `devicetree`
              └─ Xen  (virtual EL2, non-VHE)
                   └─ dom0: this Fedora 44 install, root on virtio-blk
```

---

## 1. The machine (measured)

Read from a Fedora 44 aarch64 guest under UTM on an M3 Max, nested
virtualisation on, 6 vCPUs, 8 GiB. `DMI: Apple Inc. Apple Virtualization
Generic Platform, BIOS 2164.0.0.0.0`; firmware is EDK II (`efi: EFI v2.7 by
EDK II`), so the boot path is UEFI, not `m1n1`.

| Fact | Value | Source |
|---|---|---|
| MIDR | `0x610f0000` — implementer Apple, part **0** | `dmesg` |
| Entered at | **EL2** (`CPU: All CPU(s) started at EL2`) | `dmesg` |
| VHE | **absent.** KVM reports `Hyp nVHE mode initialized successfully`, which arm64 `init_kernel_el` only reaches when `ID_AA64MMFR1_EL1.VH == 0` | `dmesg` |
| Page granule | 4 KB works (`getconf PAGESIZE` = 4096) | guest |
| Firmware tables | RSDP/XSDT/**FACP/DSDT/GTDT/APIC/MCFG** only. No SPCR, no PPTT, no IORT | `/sys/firmware/acpi/tables` |
| Device tree | **none.** `/sys/firmware/fdt` is the 866-byte tree the EFI stub builds for `/chosen`; it describes no hardware | `dtc` |
| GICv3 GICD | `0x1000_0000`, 64 KB, 988 SPIs, 0 eSPIs, `GICD_CTLR.DS=1` | MADT / `dmesg` |
| GICv3 GICR | `0x1001_0000`, len `0xc_0000` (6 × `0x2_0000`) | MADT |
| GIC ITS | **none** | MADT |
| MSI | one **GICv2m** frame at `0x1fff_0000`, SPIs 128–255 | MADT / `dmesg` |
| vGIC maintenance | PPI 25 | MADT |
| Timer | NS-EL1 PPI 30, virt PPI 27, **NS-EL2 PPI 26**, secure: *absent* (GSIV 0); level, active-high; 24 MHz | GTDT |
| Memory-mapped counter | none (`CntControlBase = ~0`) | GTDT |
| PSCI | v1.1, **SMC** conduit (`FADT ArmBootArch` = 1: compliant, `USE_HVC` clear) | FADT / `dmesg` |
| PCI ECAM | `0x4000_0000`, 256 MB, buses 0–255 | MCFG |
| PCI windows | `0x5000_0000–0x6ffd_ffff` (32-bit), `0x2_8000_0000–0x6_7fff_ffff` (64-bit) | `/proc/iomem` |
| DRAM | `0x7000_0000–0x2_6fff_ffff` contiguous | `/proc/iomem` |
| IOMMU | none | `/sys/class/iommu` empty |
| UART | **none.** The only non-PCI device in the DSDT is a PL061 GPIO at `0x2006_0000` (SPI 37) used as the power button GED | DSDT |
| Devices | all virtio-pci: net, blk, fs, gpu, snd, rng, balloon, console; plus 2 Apple xHCI | `lspci` |

Two of these deserve emphasis because they invert assumptions from the
bare-metal port:

**The nested EL2 is a plain non-VHE EL2.** On the real cores `HCR_EL2.E2H` is
RES1 and §06 had to teach Xen the VHE register formats. Here `E2H` is
writable and reads back 0, so `cpu_init`'s probe in `arm64/head.S` takes the
*first* branch and Xen runs exactly as it does on any other GICv3 machine —
non-VHE `TCR_EL2`/`SCTLR_EL2`, `_EL1` sysreg names reaching the guest,
`ARM64_HAS_VHE` unset so `entry.S`'s alternatives stay on the plain path.
Everything §06 added is runtime-conditional on `el2_is_vhe()`, so none of it
fires. This is why there is no second port here, only a platform stub.

**PSCI is SMC-based on a machine with no EL3.** `GICD_CTLR.DS=1` says there
is no secure world, so the SMC cannot be going to EL3 firmware. It must be
trapped by the *real* EL2 — macOS — which sets `HCR_EL2.TSC` for the whole
nested guest, and that traps SMC from virtual EL2 just as it does from EL1.
So Xen, at virtual EL2, can use PSCI for CPU bring-up. (Inferred, not
measured: what was measured is only that Linux at EL1 brought up 6 CPUs
through it.)

---

## 2. There is no console, and one attempt at one killed the VM

This is the biggest practical problem and it is worth being blunt about.

There is no UART. Not a PL011 (the DSDT has no `ARMH0011`), not an 8250,
nothing. Virtualization.framework's only serial device is
`VZVirtioConsoleDeviceSerialPortConfiguration`, i.e. **virtio-console over
PCI**, which is what `0000:00:0b.0` (`1af4:1043`) is. Xen has no virtio
driver, so with no changes Xen boots with no console at all.

The obvious fix — write one — was investigated and is **not recommended**,
because of what happened when the existing plumbing was tested:

```
$ echo "XEN-VZ-PROBE hello from dom0-to-be" > /dev/vport7p0
```

**killed the VMM instantly.** Not a guest panic: the whole VM died,
`journalctl -b -1` ends mid-audit-record at exactly the timestamp of that
`sudo` (15:43:42.975), and `last -x` records that boot alone ending in `crash`
with no shutdown record, unlike the boots either side of it. Nothing
guest-side survived — pstore, `/var/crash` and the kernel ring are all empty
for that boot — which is itself consistent with the host process dying rather
than the guest.

The port in question is `vport7p0`, name `com.redhat.spice.0`, a **non-console**
multiport port created by UTM's serial device. Two measurements narrow what
happened:

- The `sudo` session lived 5.6 ms and the surrounding `timeout 3` never fired,
  so the `write()` did not block. `virtio_console` blocks whenever
  `!host_connected`, so the backend *had* asserted `PORT_OPEN`: the port was
  attached in the virtio sense, whatever was or was not draining it.
- The **control queue works** — `virtio7-control-i` has taken interrupts and
  the port was enumerated and named — while `virtio7-output` has never taken
  one. So the crashing write was the first traffic that queue ever carried,
  and a generic ring-format or guest-physical-address bug in the backend is
  ruled out: the control queue uses the same machinery and is fine. Whatever
  breaks is specific to the port data path.

The guest side did nothing unusual whatsoever: 35 bytes in a `kmalloc`'d
buffer, a one-element scatterlist, `virtqueue_add_outbuf` on vq 1 (port 0
transmit), a 16-bit MMIO kick. `VIRTIO_F_ACCESS_PLATFORM` is clear and there
is no IOMMU, so the descriptor carried a raw guest-physical address, as it
does for every other device here.

The full forensic write-up, including which macOS crash report would settle
"faults with nothing draining it" versus "faults on port data at all", is in
`~/vm-crash.txt`; the host-side evidence lives in
`~/Library/Logs/DiagnosticReports/` and UTM's debug log, neither reachable
from inside the guest.

The conclusion for Xen is that a virtio-console driver would have as its very
first act the operation that is known to be able to kill the VM, with no way
to tell beforehand whether it is safe. That is a bad trade for a debug
console. It is not ruled out forever — if the host end is known to be
attached (UTM's serial set to a built-in terminal, window open) it may be
perfectly fine — but it must never be the default, and confirming which of
the two failure modes it is needs the macOS-side crash log, not anything
visible from in here.

### What to use instead

1. **Xen's EFI-stage output goes to the screen.** `xen.efi` prints through
   `SystemTable->ConOut` until `ExitBootServices`, and EDK II's console is on
   the virtio-gpu that UTM displays. That covers image load, the DTB, the
   module list and the memory map — i.e. most of the ways a first boot goes
   wrong. Expect:

   ```
   Using modules provided by bootloader in FDT
   Device tree describes: Apple Virtualization Generic Platform, 6 CPUs, 8192 MiB
   ```

   Read the second line carefully. `gen-vz-dtb.py` stamps the vCPU count and
   memory size into the `model` string precisely so that a device tree left
   over from a differently-configured VM announces itself here rather than
   becoming a hang later. If instead you get a warning that the tree describes
   no CPUs, GRUB's `devicetree` line did not run.
2. **`xl dmesg` recovers the whole ring afterwards.** Xen keeps its log in
   `conring` regardless of whether any physical console exists, so once dom0
   is up, every message from `start_xen` onwards is retrievable. This is why
   `apple_vz_defconfig` turns on `DEBUG_INITCALL_TRACE`: log space is the only
   diagnostic channel, so it may as well be used.

   Two boot parameters matter a great deal here and are easy to miss:

   - **`conring_size=512`.** The ring Xen boots with is a static 16 KiB
     buffer, and `console_init_postirq()` only replaces it partway through
     `start_xen`. With `loglvl=all` and an initcall trace, the front of the
     log — the part that describes a boot problem — is quite capable of
     being overwritten before then. Xen now prints `Dropped N bytes of the
     boot log` when that happens, so at least the loss is visible, but on
     this platform it is better to just make the ring big enough.
   - **`console_to_ring`.** This sends *guest* console output, dom0 included,
     into Xen's ring as well. That is what makes dom0's own boot log
     recoverable: with `console=hvc0` in the dom0 command line and this set,
     everything dom0 printed before `virtio_gpu` came up is sitting in
     `xl dmesg` afterwards. Without it, dom0's early boot is simply gone.
3. **Give dom0 `console=tty0`** so that dom0's own boot is visible on the UTM
   display via virtio-gpu's DRM fbcon (`console=hvc0` alone goes into Xen's
   ring and nowhere else). But do not expect it early: there is no EFI
   framebuffer to fall back on (the boot console is `dummycon` and
   `/sys/class/graphics` has no `fb0` until DRM is up), and Fedora builds
   `CONFIG_DRM_VIRTIO_GPU=m`, so nothing appears until that module loads. Put
   it in the initramfs (`dracut --add-drivers virtio_gpu`) if you want output
   before the root filesystem is mounted.

So the dark window is `ExitBootServices` → `virtio_gpu` probing, which covers
all of Xen's boot *and* early dom0. If Xen dies in there the symptom is a hung
or reset VM and no text at all, which is why §7 is a bisection list rather
than a debugging procedure.

Note that `xl dmesg` means the arm64 tools have to be built and installed in
dom0: the log comes back through a sysctl hypercall and there is no other
reader. It does not need `xenstored` running, though, so a dom0 that only
reached a dracut shell can still produce the log if `xl` is in the initramfs.

### Why the panic message cannot be saved

The obvious escape — have `panic()` write the console ring into an EFI
variable, then reboot into plain Linux and read it out of `efivarfs` — does
not work today, and it is worth recording why so nobody re-derives it.
`arch/arm/efi/boot.c` does call `SetVirtualAddressMap()` and keeps `efi_rs`,
so the runtime services *pointer* survives; but `common/efi/runtime.c` guards
the whole call path with `#ifndef CONFIG_ARM /* TODO - disabled until
implemented on ARM */`, and `efi_rs_enter()`/`efi_rs_leave()` have no arm64
implementation at all. Making runtime calls work on arm64 is its own piece of
work, not something to bolt onto a panic path.

Until then `noreboot` (§6) is the whole of the story: the VM powering off
means Xen panicked, the VM sitting there idle means Xen hung. One bit, but a
real one.

---

## 3. Xen needs a device tree, and this platform has none

Xen's arm64 ACPI support is not a path this port has any confidence in, and
this firmware would make it worse: there is no SPCR (so no console
description), no PPTT and no IORT. Xen boots perfectly well from a device
tree, and GRUB can supply one, so the approach is to **translate the firmware
tables into a DTB once, outside Xen, and hand it to GRUB.**

`plans/asahi/vz/gen-vz-dtb.py` does the translation. Run it as root in the VM
*outside* Xen — the only place the tables are readable — and re-run it after
any change to the VM's vCPU count, memory size or device set, because Xen
believes the CPU nodes and the PCI windows.

```
sudo plans/asahi/vz/gen-vz-dtb.py > vz.dts
dtc -I dts -O dtb -o vz.dtb vz.dts
```

`plans/asahi/vz/vz.dts` is the output for the machine in §1, checked in as a
reference. What it describes, and why each part is the way it is:

- **`/psci`, `method = "smc"`** — from the FADT, per §1.
- **`/cpus`** — one node per enabled MADT GICC, `reg` = MPIDR,
  `enable-method = "psci"`.
- **`/timer`** — uses `interrupt-names` (`"phys"`, `"virt"`, `"hyp-phys"`)
  rather than the positional form, because the GTDT declares no secure
  physical timer and position 0 has no way to say "absent". Xen reads
  `interrupt-names` when present (`init_dt_xen_time`), and the branch already
  treats `sec-phys` as optional.
- **`arm,gic-v3`** with `ranges` and `#address-cells`/`#size-cells`, because
  it has a child node.
- **`arm,gic-v2m-frame`** as that child, with `arm,msi-base-spi`/
  `arm,msi-num-spis` stated explicitly. It has to be a child of the GIC node:
  Linux's `gicv2m_of_init` only ever looks there.
- **`pci-host-ecam-generic`** with both MMIO windows identity-mapped in
  `ranges`, `dma-coherent`, `msi-parent = <&v2m>`, and deliberately **no**
  `interrupt-map` — see §4.
- **`/memory`** for the whole DRAM range. Advisory only: booted through EFI,
  Xen takes the real map from `GetMemoryMap`. It is emitted so the tree is
  not wrong for anything that does read it.

---

## 4. MSIs are the only interrupts that work, so Xen has to route them

The DSDT's `_PRT` has 32 entries, one per slot, and every one of them
describes **pin 0 (INTA)**. Every device's PCI Interrupt Pin register reads
**2 (INTB)**. So `acpi_pci_irq_lookup` finds nothing, `lspci` says `pin B
disabled` for every device, and all of them use MSI-X. There is no legacy
routing to describe and the generated DT omits `interrupt-map` accordingly
(Xen's `dt_for_each_irq_map` treats a missing map as "nothing to do" and
returns 0, so this is safe).

That leaves the GICv2m frame as dom0's only route to an interrupt, and
nothing in Xen handled it, for a structural reason: a v2m frame is a *child of
the interrupt controller node*, and `handle_node()` replaces that node
wholesale with Xen's own vGIC and does not recurse. dom0 would have got a DT
with no MSI controller, and its virtio-blk would have had no way to signal
completion.

`xen/arch/arm/gic-v2m.c` (new, `CONFIG_GICV2M`) does the three things needed
(untested):

- **maps the frame's page** into the hardware domain. dom0 on arm is
  direct-mapped, so the guest address is the host address and the doorbell
  write needs no translation — which also means it works with no IOMMU.
- **routes the whole SPI block** (128–255 here) to dom0 up front. It cannot
  be done lazily: which SPI a device ends up on is chosen by dom0's own MSI
  allocator long after Xen has finished building it, and nothing tells Xen.
  An SPI routed but unused costs one `irqaction` and one quiet distributor
  line. The trigger type is left alone deliberately —
  `irq_type_set_by_domain()` is true for the hardware domain, so it is
  configured when dom0 writes `GICD_ICFGR`, which is also the first moment
  anything knows the SPI is now an edge-triggered MSI.
- **re-emits the frame** inside dom0's vGIC node, *keeping the host phandle*,
  because the PCI host bridge node is copied to dom0 with its `msi-parent`
  intact and that is a reference to this node.

The call sites are one line each: `gicv2m_hwdom_setup()` from `handle_node()`
where the interrupt controller is recognised, and `gicv2m_hwdom_dt_nodes()`
from `gicv3_make_hwdom_dt_node()` after the ITS nodes. The `ranges` property
that child nodes need may only be emitted once and the ITS path emits it too,
so `gicv2m_hwdom_dt_nodes()` looks for an ITS among the GIC's children to
decide whether it owns that property. On a machine with an ITS none of this
is wanted anyway — Xen drives the ITS itself — so `CONFIG_GICV2M` defaults
off and is selected only by `APPLE_VZ`.

---

## 5. What was changed

| Change | Why |
|---|---|
| `arch/arm/platforms/apple-vz.c`, `CONFIG_APPLE_VZ` | Names the machine in the log and reports E2H/CNTFRQ, which are the two facts worth having in a ring recovered later. Nothing else: the platform needs no quirks. |
| `arch/arm/gic-v2m.c`, `CONFIG_GICV2M` | §4. |
| `arch/arm/gic-v3.c`, `arch/arm/domain_build.c` | The two call sites for the above. |
| `arch/arm/configs/apple_vz_defconfig` | GICv3 + GICv2m, `EARLY_PRINTK` **off** (nothing to print to), initcall trace on. |
| `plans/asahi/vz/gen-vz-dtb.py`, `vz.dts` | §3. |

Note what is *not* here. No AIC, no dockchannel, no s5l, no forced-VHE work,
no DART: `CONFIG_APPLE` is off in this build, which also means
`local_irq_disable()` goes back to masking I only (`DAIF_IRQ_BITS`, which is
compile-time), as it should on a machine that delivers no FIQs.

`xen.efi` on arm64 is a symlink to `xen`, and that is correct — the arm64
image carries a PE header in `head.S`, and it verifies as
`machine=0xaa64, subsystem=0x0a` (EFI application), which is what GRUB's
`LoadImage` needs.

---

## 6. The GRUB recipe (untested)

GRUB's arm64 `xen_boot` starts `xen.efi` with `LoadImage`/`StartImage` and
installs the FDT as an EFI configuration table; Xen's
`efi_arch_use_config_file()` sees an FDT containing `multiboot,module` nodes
and skips `xen.cfg` in favour of it. So the DTB must come from GRUB's
`devicetree` command — GRUB will otherwise hand Xen an empty tree.

### First, the dom0 kernel — the stock one will not work

Two independent problems, both measured on this VM, and both the same traps
§10 records for Fedora Asahi:

- **`# CONFIG_XEN is not set`** in `/boot/config-7.1.13-200.fc44.aarch64`.
  Fedora's aarch64 kernel has no Xen guest support at all — no hypercall
  page, no xenbus, no `CONFIG_XEN_DOM0` — so it can be used to exercise Xen's
  module-loading path but it cannot be a dom0. A self-built kernel is
  required: `CONFIG_XEN=y`, `CONFIG_XEN_DOM0=y`, the `XEN_*` front and back
  ends, and `CONFIG_ARM_GIC_V3=y`/`CONFIG_ARM_GIC_V2M=y` (both already `y`
  here) plus `CONFIG_PCI_HOST_GENERIC=y` (also already `y`) so it can drive
  the DT-described ECAM bridge.
- **`CONFIG_EFI_ZBOOT=y`**, so `/boot/vmlinuz-*` is a PE wrapper with the real
  Image compressed inside (verified: `MZ` header). Xen's loader understands a
  raw `Image`, a `zImage` or a `uImage` and nothing else, so the zboot wrapper
  has to be unwrapped — the same `unzboot.py` step as §10 — or the kernel
  built with `CONFIG_EFI_ZBOOT=n` in the first place, which is simpler when
  you are building it anyway.

The initramfs needs `virtio_pci`, `virtio_blk` and `btrfs` (all built in
here), and `virtio_gpu` if you want early console output per §2. Rebuild it
`--no-hostonly`: the one on disk was generated for a machine booting from
ACPI without Xen, which is not the machine it will see.

### Then the GRUB commands

Copy `xen.efi`, the dom0 Image, the initramfs and `vz.dtb` to `/boot`, then at
the GRUB command line (`c`) or in a `menuentry`:

```
insmod xen_boot
devicetree /vz.dtb
xen_hypervisor /xen.efi dom0_mem=2G dom0_max_vcpus=2 console=none console_to_ring conring_size=512 loglvl=all guest_loglvl=all noreboot
xen_module /Image-xen-dom0 console=hvc0 console=tty0 root=UUID=e85e08dd-7a99-4c3c-a467-4eda069b5859 ro rootflags=subvol=root selinux=0
xen_module --nounzip /initramfs-xen-dom0.img
boot
```

Notes on the command lines:

- `console=none` is honest about there being no serial port; `xl dmesg` still
  works. Do **not** put `console=dtuart` there — there is no UART to find.
- `console_to_ring conring_size=512` per §2. These are the difference between
  having a log and not.
- `noreboot` because the default is not what you want here. `panic()` calls
  `machine_restart(5000)` unless told otherwise, and on a machine whose only
  log is the console ring, rebooting on panic destroys the one copy of the
  panic message *and* loops: GRUB re-selects the same entry and Xen panics
  again. With `noreboot` the VM halts via PSCI `SYSTEM_OFF` instead, so it
  powers off once and stays off — which is also a clear signal that Xen
  panicked rather than hung.
- dom0 gets **both** consoles: `console=hvc0` so its output reaches Xen's
  ring (with `console_to_ring` above), and `console=tty0` so it is also on
  screen once `virtio_gpu` is loaded. Linux uses the last `console=` as
  `/dev/console` for the getty, which is what you want on the display.
- The root UUID above is this VM's btrfs root (`rootflags=subvol=root`); it is
  on `vda`, i.e. behind the virtio-blk at `0000:00:05.0`, which is exactly the
  device that needs §4 to work.
- `dom0_max_vcpus=2` to start with: the host GICR region holds exactly 6
  redistributors, so 6 dom0 vCPUs fit exactly, but fewer is fewer things to go
  wrong on a first boot.

---

## 7. If it does not boot, look here first

In rough order of likelihood, and all of it untested:

1. **Xen complains about the dom0 module, or dom0 never starts.** The zboot
   wrapper and the missing `CONFIG_XEN`, per §6. These are the two most
   likely first failures and neither is Xen's fault, so rule them out before
   suspecting anything in §5.
2. **Nothing on screen after GRUB.** Xen died before or during
   `ExitBootServices`. The EFI-stage messages should have appeared; if
   `xen.efi` printed nothing at all, GRUB's `LoadImage` rejected the image or
   the FDT was not installed.
3. **Screen goes blank and stays blank.** Xen got past EFI and hung with no
   console. The dark window of §2. Bisect by removing things: fewer dom0
   vCPUs, `dom0_max_vcpus=1`, then no PCI at all in the DTB (drop the `pcie`
   node) to separate "Xen cannot boot" from "dom0 cannot use its devices".
4. **PSCI.** If secondaries never come up, the assumption in §1 that macOS
   traps SMC from virtual EL2 is wrong. Symptom: Xen boots on one CPU and
   `setup_virt_paging`'s `smp_call_function` never returns.
5. **The EL2 physical timer.** Xen needs `CNTHP_EL2` and PPI 26 delivered.
   The GTDT declares it (§1) but nothing in the guest exercises it, since
   Linux at EL1 uses PPI 30 and nVHE KVM does not use the hyp timer for the
   host. This is the least-corroborated hardware assumption in the whole
   plan.
6. **dom0 has no disk.** MSIs (§4). Check with `xl dmesg` for the
   `GICv2m: dom0: frame 0x1fff0000, SPIs 128-255` line, then in dom0 for
   `GICv2m: range[mem 0x1fff0000-0x1fff0fff], SPI[128:255]` and for
   `virtio1-req.0` appearing in `/proc/interrupts`.
7. **dom0 oopses in `virtio_gpu`.** Then §2's plan for seeing anything is
   gone; fall back to `console=hvc0` plus `xl dmesg` from an SSH session over
   virtio-net.
