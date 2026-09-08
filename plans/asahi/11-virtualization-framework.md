# 11 — Xen nested inside Virtualization.framework

Status: **Xen boots; dom0 boots to its first interrupt and stops there.** Everything below
marked "(measured)" was read out of the running VM described in §1;
everything marked "(untested)" is a change made on the strength of those
measurements and not yet observed to work. What the two boots so far did
prove, and what they did not, is §7.

This is a *second target*, not a variation of the bare-metal port. The
machine macOS's Virtualization.framework synthesises for a guest has none of
the hardware that made §03–§07 hard: it has a GICv3, not an AIC; PSCI, not a
spin table; no IOMMU at all; and a nested EL2 that is not VHE-only. So Xen's
stock arm64 paths apply, and what this document is mostly about is the two
things the platform *doesn't* have: a device tree, and any serial port Xen
already knew how to drive.

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
| Serial | virtio-console over PCI, and only that. A configured UTM serial port appears as a second such device which does *not* offer MULTIPORT — see §2 | `lspci`, sysfs |
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

## 2. The console: a virtio-console, and the one that killed the VM

Start with what the platform does not have. There is no UART. Not a PL011
(the DSDT has no `ARMH0011`), not an 8250, nothing — the only non-PCI device
in the whole DSDT is a PL061 GPIO serving as the power button.
Virtualization.framework's only serial device is
`VZVirtioConsoleDeviceSerialPortConfiguration`, i.e. **virtio-console over
PCI**. So either Xen drives virtio-console or Xen has no console.

It does now: `xen/drivers/char/virtio-console.c`, selected with
`console=vtcon`. That matters more than a debug convenience, because
`console_init_preirq()` ends in `conring_flush()`, and with
`CONFIG_EARLY_PRINTK` off that flush includes `CONSOLE_SERIAL` — so the
moment the console comes up, Xen replays *its entire log from the first
message*. There is no dark window.

### Why this needs care: the port that killed the VMM

Before the UTM configuration had a serial port, testing the virtio-console
device that was there anyway did this:

```
$ echo "XEN-VZ-PROBE hello from dom0-to-be" > /dev/vport7p0
```

and **killed the VMM instantly.** Not a guest panic: the whole VM died,
`journalctl -b -1` ends mid-audit-record at exactly the timestamp of that
`sudo` (15:43:42.975), and `last -x` records that boot alone ending in
`crash` with no shutdown record, unlike the boots either side of it. Nothing
guest-side survived — pstore, `/var/crash` and the kernel ring are all empty
for that boot — which is itself consistent with the host process dying rather
than the guest.

Two measurements narrow it:

- The `sudo` session lived 5.6 ms and the surrounding `timeout 3` never fired,
  so the `write()` did not block. `virtio_console` blocks whenever
  `!host_connected`, so the backend *had* asserted `PORT_OPEN`: the port was
  attached in the virtio sense, whatever was or was not draining it.
- The **control queue works** — `virtio7-control-i` has taken interrupts and
  the port was enumerated and named `com.redhat.spice.0` — while
  `virtio7-output` had never taken one. So the crashing write was the first
  traffic that queue ever carried, and a generic ring-format or
  guest-physical-address bug in the backend is ruled out: the control queue
  uses the same machinery and is fine. Whatever breaks is specific to the
  port data path.

The guest side did nothing unusual: 35 bytes in a `kmalloc`'d buffer, a
one-element scatterlist, `virtqueue_add_outbuf` on vq 1, a 16-bit MMIO kick.
The full forensic write-up is in `~/vm-crash.txt`; only a macOS crash report
can distinguish "faults with nothing draining it" from "faults on port data
at all", and those live in `~/Library/Logs/DiagnosticReports/` and UTM's
debug log, neither reachable from inside the guest.

### What the driver does about it

Adding a serial port in UTM adds a **second** virtio-console PCI device, and
the two are measurably different:

| Device | MULTIPORT offered | What it is |
|---|---|---|
| `00:05.0` | **no** (feature bit 1 clear) | the serial port UTM shows; Linux puts `hvc0` and a getty on it |
| `00:0c.0` | yes | the `com.redhat.spice.0` port that crashed the VMM |

That difference is the whole safety rule. A device without
`VIRTIO_CONSOLE_F_MULTIPORT` has exactly one port, port 0, which the
specification says is the console and is *always open* — there is no
attachment state to get wrong. A device with MULTIPORT requires opening the
port through the control queue, and until that handshake completes a driver
has no idea whether anything is attached, which is precisely the condition
that killed the VM.

So the driver **refuses any device offering MULTIPORT**, says so in the log,
and takes the first one that does not. On this machine that picks `00:05.0`
and skips `00:0c.0`. It applies the rule to an explicitly selected device
too (`vtcon=<bus>:<dev>.<fn>` names one): the reason is not "we guessed
wrong", it is "we cannot know the port is safe to write to".

Beyond that the driver is deliberately dull. It negotiates nothing but
`VIRTIO_F_VERSION_1`, so split rings with no event index and no indirect
descriptors — a device offering those must work without them. It is polled;
the device's only interrupt is an MSI-X, and wiring an MSI up for a debug
console is not worth it when a 10 ms receive timer is imperceptible for
typing. And it uses one descriptor per character, which is what a PL011
effectively does anyway (one MMIO store per byte) and which cannot lose a
partial line the way a buffer flushed on newline can; Xen's serial layer
already knows how to wait, since `tx_ready()` reports free descriptors and it
spins on zero.

It also only touches the device when asked. `console=vtcon` has to be on the
command line before the platform code calls `virtio_console_init()` at all —
given the above, bringing up a virtio-console is not something to do to a
machine that did not ask for it.

### dom0 must not drive the same device

This is the one new sharp edge, and it has two halves.

Xen owns the device it picks. If dom0's `virtio_console` also binds to it,
two drivers reset and re-queue the same virtqueues. Fedora builds
`CONFIG_VIRTIO_CONSOLE=y`, so a blacklist will not help — but a custom dom0
kernel is mandatory here anyway (§6), so build it with
`CONFIG_VIRTIO_CONSOLE=n`, or `=m` and `module_blacklist=virtio_console`.

The second half is a name collision that would be very confusing to debug:
both `virtio_console` and Xen's PV console (`CONFIG_HVC_XEN`) register
`hvc0`, and whichever probes first wins. With `virtio_console` gone, dom0's
`hvc0` is Xen's PV console — which Xen multiplexes onto the same physical
port. So dom0 loses nothing by giving up the device: `console=hvc0` in dom0
comes out of the same serial terminal as Xen's own output, which is the
ordinary Xen arrangement.

### What is still worth having anyway

1. **Xen's EFI-stage output goes to the screen** regardless, through
   `SystemTable->ConOut` until `ExitBootServices`. Expect:

   ```
   Using modules provided by bootloader in FDT
   Device tree describes: Apple Virtualization Generic Platform, 6 CPUs, 8192 MiB
   ```

   Read the second line carefully. `gen-vz-dtb.py` stamps the vCPU count and
   memory size into the `model` string precisely so that a device tree left
   over from a differently-configured VM announces itself here rather than
   becoming a hang later. If instead you get a warning that the tree
   describes no CPUs, GRUB's `devicetree` line did not run.

2. **`conring_size=512`.** The ring Xen boots with is a static 16 KiB buffer
   and `console_init_postirq()` only replaces it partway through `start_xen`.
   Xen now prints `Dropped N bytes of the boot log` when the front is
   overwritten, but with `loglvl=all` and an initcall trace it is better to
   make the ring big enough — especially since `conring_flush()` can only
   replay what is still in it.

3. **`console_to_ring`**, which sends guest console output, dom0 included,
   into Xen's ring as well, so `xl dmesg` shows dom0's boot too.

4. **`xl debug-keys` reaches every keyhandler** through
   `XEN_SYSCTL_debug_keys`, so `xl debug-keys i && xl dmesg` gets §03's
   interrupt binding dump, `q` the domain list, and so on. Useful even with a
   console, since it does not need input to reach Xen.

### The dead ends, so nobody re-derives them

**EFI framebuffer:** ruled out on evidence. Fedora's kernel is built with
`CONFIG_FB_EFI=y` and `CONFIG_SYSFB_SIMPLEFB=y`, yet this VM's boot console is
`dummycon` and no `efifb` or `simple-framebuffer` ever appears — so the arm64
EFI stub found no GOP framebuffer to hand over, and there is none for Xen to
write to either. That matches how EDK II drives virtio-gpu: GOP `Blt` sends
the display a `RESOURCE_FLUSH` command, so writes to a linear buffer would not
reach the screen even if one were exposed.

**Panic log to an EFI variable:** closed. `arch/arm/efi/boot.c` does call
`SetVirtualAddressMap()` and keeps `efi_rs`, so the runtime services pointer
survives; but `common/efi/runtime.c` guards the whole call path with
`#ifndef CONFIG_ARM /* TODO - disabled until implemented on ARM */`, and
`efi_rs_enter()`/`efi_rs_leave()` have no arm64 implementation. That is its
own piece of work, not a panic-path addition. It also matters much less now
that a panic message can just come out of the serial port as it is printed.

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
| `drivers/char/virtio-console.c`, `CONFIG_HAS_VIRTIO_CONSOLE` | §2. The only serial port the platform has. `console=vtcon`, `vtcon=<bus>:<dev>.<fn>`. |
| `drivers/char/serial.c`, `include/xen/serial.h` | `console=vtcon` parsing, on the otherwise unused `SERHND_DBGP` slot. |
| `arch/arm/gic-v3.c`, `arch/arm/domain_build.c` | The two call sites for the above. |
| `arch/arm/configs/apple_vz_defconfig` | GICv3 + GICv2m + the virtio console, `CONFIG_DOM0_MEM`, initcall trace on. `EARLY_PRINTK` stays **off**: it writes to a fixed MMIO address from assembly, which a PCI device found at runtime can never be — and with it off, `conring_flush()` replays everything to the virtio console instead. |
| `plans/asahi/vz/gen-vz-dtb.py`, `vz.dts` | §3. |
| `common/device-tree/kernel.c` | Report what a rejected boot module actually is, rather than only `rc = -22`. |
| `plans/asahi/vz/install-vz.sh` | §6. Installs Xen and the DTB, writes the GRUB entries, and fixes the four things that make a first boot fail silently. |

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
  Image zstd-compressed inside. Xen's loader understands a raw `Image`, a
  `zImage` or a `uImage and nothing else, so the wrapper has to be unwrapped —
  the same `unzboot.py` step as §10 — or the kernel built with
  `CONFIG_EFI_ZBOOT=n`, which is simpler when you are building it anyway.

  **An `MZ` header is not how you tell.** An arm64 `Image` starts with `MZ`
  too, deliberately: it is simultaneously a raw Image and a valid PE/COFF EFI
  application, which is what the EFI stub is. The discriminator is the arm64
  Image magic at **offset 56**, which is what
  `kernel_zimage64_probe()` checks:

  ```
  /boot/vmlinuz-xen-dom0             first2=4d5a off56=41524d64   <- raw Image
  /boot/vmlinuz-7.1.13-200.fc44      first2=4d5a off56=00000000   <- zboot PE
  ```

  Getting this wrong cost a boot: see below.

- **`CONFIG_VIRTIO_CONSOLE=n`** (or `=m` plus
  `module_blacklist=virtio_console`). Xen owns the virtio-console device it
  picked, and this is also what leaves `hvc0` to Xen's PV console rather than
  to a second driver on the same hardware. See §2.

The initramfs needs `virtio_pci`, `virtio_blk` and `btrfs` (all built in
here). Rebuild it `--no-hostonly`: the one on disk was generated for a machine
booting from ACPI without Xen, which is not the machine it will see.

### Then install it

`plans/asahi/vz/install-vz.sh` does the whole thing and is idempotent, so it is
what to re-run after every Xen rebuild:

```
sudo ./plans/asahi/vz/install-vz.sh
```

It installs `xen/xen` as `/boot/xen/xen.efi` with `vz.dtb` beside it, writes
two menu entries to `/boot/grub2/custom.cfg`, and unsets `menu_auto_hide`.
Four things it does are not obvious, and each is a boot that silently does not
work if it is missing:

- **GRUB needs `xen_boot.mod` on disk.** Fedora's `grubaa64.efi` is a
  monolithic image, `xen_boot` is *not* in it (`devicetree` is), and there is
  no `/boot/grub2/arm64-efi` directory at all — so `insmod xen_boot` has
  nowhere to look. The script populates it from `grub2-efi-aa64-modules`,
  which is version-matched to the installed core.
- **Xen goes in `/boot/xen/`, not `/boot`.** `/etc/grub.d/20_linux_xen` globs
  `/boot/xen*` and would generate its own entries, which cannot work here: it
  emits no `devicetree` line, and it would pair Xen with the stock zboot
  kernel. A directory fails its `test -f` check, so it is skipped — verified
  by `grub2-mkconfig` emitting nothing at all between its BEGIN and END
  markers.
- **The entries live in `custom.cfg`,** which `41_custom` sources at boot. So
  editing Xen's command line — the thing actually being iterated on — does not
  need `grub2-mkconfig`.
- **`menu_auto_hide=1` in `grubenv`** hides the menu entirely once
  `boot_success=1`. `GRUB_TIMEOUT_STYLE=menu` and `GRUB_TIMEOUT=10` in
  `/etc/default/grub` make the intent explicit as well.

`GRUB_DEFAULT` stays `saved`, i.e. the ordinary Fedora kernel, deliberately: a
Xen entry has to be chosen by hand, so a Xen boot that hangs never becomes what
this machine boots by default.

The second entry is `console=none` — the fallback that separates "Xen cannot
boot" from "the console cannot", given §2. Its log is still recoverable with
`xl dmesg`.

The dom0 kernel and initramfs are referenced through fixed names, so the entry
never needs editing when the kernel changes. Point these at the real files once
the kernel is built:

```
sudo ln -sf vmlinuz-<version> /boot/vmlinuz-xen-dom0
sudo ln -sf initramfs-<version>.img /boot/initramfs-xen-dom0.img
```

The script warns if either is missing, and warns if the kernel is a PE image —
which is how a `CONFIG_EFI_ZBOOT` kernel presents itself, and which Xen's
loader cannot unwrap.

### The GRUB commands themselves

For reference, and for typing at the GRUB prompt (`c`) when bisecting:

```
insmod xen_boot
search --no-floppy --fs-uuid --set=root <the /boot filesystem UUID>
devicetree /xen/vz.dtb
xen_hypervisor /xen/xen.efi dom0_mem=2G dom0_max_vcpus=2 console=vtcon console_to_ring conring_size=512 loglvl=all guest_loglvl=all noreboot
xen_module /vmlinuz-xen-dom0 root=UUID=e85e08dd-7a99-4c3c-a467-4eda069b5859 ro rootflags=subvol=/root selinux=0 console=tty0 console=hvc0
xen_module --nounzip /initramfs-xen-dom0.img
boot
```

Note there is no argument between the image path and the command line: GRUB
passes `argv[1..]` as the command line and Xen's `cmdline_parse()` does not
skip a leading token, so an extra one there becomes an unknown parameter.

Notes on the command lines:

- `console=vtcon` selects the virtio-console (§2). Do **not** put
  `console=dtuart` there — there is no UART to find, and `dt_uart_init()` will
  just say "No dtuart path configured". `console=none` also still works, if you
  would rather Xen did not touch the device at all; the log is then `xl dmesg`
  only.
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
- `dom0_mem` is belt and braces: `apple_vz_defconfig` sets `CONFIG_DOM0_MEM`
  to `2G` so that omitting it cannot silently land on Xen's 512M default,
  whose `warning_add()` would not be readable until dom0 was already up.

---

## 7. If it does not boot, look here first

### What the boots so far actually did

**Boot 1** got as far as `construct_dom0()` and failed with `rc = -22`,
because the dom0 kernel was still a zstd stream. That is item 1 below, and it
is fixed.

**Boot 2** (`git:a67d8630b7-dirty`) went much further, and everything in
§1–§6 that it exercised worked:

- the virtio console carried the whole log, including the pre-`init_preirq()`
  part replayed out of the ring (§2);
- the generated device tree was accepted whole — `Platform: APPLE
  VIRTUALIZATION`, `Apple VZ: nested EL2, non-VHE (HCR_EL2.E2H=0)` and
  `CNTFRQ_EL0 = 24000000 Hz` confirm §1's two central measurements from
  Xen's own side (§3);
- **PSCI works from virtual EL2**, which was an inference in §1 and is now
  measured: `Brought up 6 CPUs`. Item 7 below is ruled out;
- `Generic Timer IRQ: phys=30 hyp=26 virt=27` — the `interrupt-names` in the
  generated timer node are read the way `init_dt_xen_time()` expects;
- `GICv2m: d0: frame 0x0000001fff0000, SPIs 128-255` (§4), and dom0 was built
  1:1 at `0x70000000` with its kernel, initrd and DTB loaded.

Then dom0 ran. Two `Unhandled SMC/HVC` lines, `0x84000050` and `0x8600ff01`,
are `smccc_probe_trng()` and `kvm_init_hyp_services()` off
`arm_smccc_version_init()`, i.e. PSCI probing inside `setup_arch()`; the
`vGICD`/`vGICR` writes after them are Linux's `gic_dist_config()` and
`gic_cpu_config()` inside `init_IRQ()`. So dom0 executes real code at EL1 and
its MMIO traps reach Xen.

**And then nothing at all** — not a crash Xen can see, either: no domain
crash dump, no further traps. The reason for the silence is structural: dom0
has no console until `console_init()`, because `hvc_xen` is a
`console_initcall`, and `start_kernel()` reaches that only after
`init_IRQ()`, `time_init()` and the first `local_irq_enable()`. Every
`printk` before it goes into a buffer nothing has been attached to yet.

**Boot 3** added `earlycon=xenboot` and dom0 became legible. It works, and it
is now on the command line `install-vz.sh` writes:
`xenboot_earlycon_write()` is `dom0_write_console()`, an outright
`HYPERVISOR_console_io` hypercall, so it prints from the first `printk` in
`setup_arch()` with no device and no mapping. It needs only
`CONFIG_HVC_XEN=y` and `CONFIG_SERIAL_EARLYCON=y` — note that the *other* Xen
console in `hvc_xen.c`, `xenboot_console`, is behind `CONFIG_EARLY_PRINTK`,
which arm64 does not have; the `EARLYCON_DECLARE` is not. `keep_bootcon`
keeps it alive once `hvc0` takes over, and `nokaslr` makes the PCs in Xen's
`0` dump resolvable straight against the dom0 kernel's `System.map`.

What boot 3 then showed, interleaved with the same Xen messages:

```
[    0.000000] GICv3: CPU0: found redistributor 0 region 0:0x0000000010010000
[    0.000000] GICv2m: DT overriding V2M MSI_TYPER (base:128, num:128)
[    0.000000] GICv2m: range[mem 0x1fff0000-0x1fff0fff], SPI[128:255]
[    0.000000] arch_timer: cp15 timer running at 24.00MHz (virt).
[    0.000000] clocksource: arch_sys_counter: mask: 0xffffffffffffff ...
[    0.000000] sched_clock: 56 bits at 24MHz, resolution 41ns, wraps every ...
```

and then stopped. That is a much smaller box than boot 2's, and three more
things are now measured rather than assumed:

- **The vGIC's system-register interface works.** dom0 is past
  `gic_cpu_sys_reg_init()` — `ICC_SRE_EL1`, `ICC_PMR_EL1`, `ICC_CTLR_EL1`,
  `ICC_IGRPEN1_EL1` — with no "unable to set SRE (disabled at EL2)". That was
  the second suspect after boot 2 and it is dead.
- **§4's v2m frame is mapped and readable in dom0.** `gicv2m_init_one()`
  reads `V2M_MSI_IIDR` at `0x1fff_0fcc` unconditionally on the DT path, and
  the read neither faulted nor stopped dom0. (The "DT overriding MSI_TYPER"
  line says nothing about the register: Linux prints it whenever the DT
  carries `arm,msi-base-spi`, agreement or not.) Item 9's Xen half and dom0
  half are both confirmed as far as they can be before a device uses one.
- **The virtual timer is set up correctly**: `(virt)` means
  `arch_timer_uses_ppi == ARCH_TIMER_VIRT_PPI`, i.e. dom0 took PPI 27 out of
  the generated timer node at the right index, and 24 MHz matches §1.

### Where it stops: the first interrupt

`sched_clock: 56 bits at 24MHz` is the last line of `arch_counter_register()`,
i.e. the end of `time_init()` (`init/main.c:978`). The next `printk` a normal
arm64 boot produces is `Console: colour dummy device 80x25` from `con_init()`
inside `console_init()` (`init/main.c:1002`). Between the two there is
`perf_event_init()`, `profile_init()`, `call_function_init()`,
`kmem_cache_init_late()` — and **`local_irq_enable()` at
`init/main.c:993`**, which is the first moment dom0 takes an interrupt at EL1
at all.

A virtual timer interrupt is already waiting for it. `arch_timer_register()`
ends with `cpuhp_setup_state(CPUHP_AP_ARM_ARCH_TIMER_STARTING, ...)` —
commented "Register and immediately configure the timer on the boot CPU" — so
`arch_timer_starting_cpu()` has already enabled PPI 27 and
`clockevents_config_and_register()` has already armed the periodic tick, all
of it *before* the banner and `sched_clock` lines that we can see. dom0 then
enables interrupts and never prints again.

So this is no longer about how anything is configured. Interrupt *delivery*
to dom0 is the thing that does not work, and the vtimer is what exercises it
first:

1. dom0 is spinning in its own handler — a vIRQ it acknowledges and Xen
   re-injects, or a line it cannot deactivate. Xen sees no MMIO for any of
   this: with SRE the whole `IAR`/`EOIR` cycle is system registers and the
   deactivate lands in the LR, so a storm is completely invisible in Xen's
   log, which is consistent with what we have.
2. the storm is on Xen's side of the LR — the nested GIC's **maintenance
   interrupt**, PPI 25 (`interrupts = <1 9 4>` in the generated tree,
   `init_maintenance_interrupt()`, whose handler is deliberately a no-op).
   Note *when* that first becomes possible: at the first LR write, which is
   this timer interrupt. If it asserts and Xen cannot clear it, Xen never
   returns to dom0, and Xen prints nothing either.
3. dom0 is not running at all, and nothing is left to wake it.

Xen's keyhandlers separate the three without a rebuild. `CTRL-a` three times
takes the console back from dom0, then:

- **`0`** (`dump_hwdom_registers()`) — dom0's PC for every vCPU. In
  `arch_timer_handler_virt`, `gic_handle_irq` or `el1_interrupt` is case 1.
- **`d`** — Xen's own registers on every pCPU. In `maintenance_interrupt` or
  `do_IRQ` is case 2.
- **`q`** — vCPU state; d0v0 blocked rather than runnable is case 3.
- **`i`** — the interrupt bindings, for an SPI from the v2m block sitting
  routed and active.

Resolve dom0's PC against its `System.map` directly: `nokaslr` is on the
command line, and arm64 does not randomise without a seed in `/chosen`
anyway, which Xen's generated dom0 tree does not provide.

### Two things in those logs that are *not* the bug

- **`vGICD: unhandled word write ... to ICACTIVERn`**, 31 times, then the same
  on the redistributor. Upstream Xen's `vgic-v3.c` has never implemented
  `ICACTIVER` writes, and this is `gic_dist_config()` deactivating every SPI
  and `gic_cpu_config()` every SGI/PPI at a moment when nothing is active, so
  dropping them changes nothing. It is noise on every Xen/arm dom0 boot.
- **`Maximum number of vGIC IRQs exceeded`**. `GICD_TYPER` reports 1020 lines
  and `VGIC_MAX_IRQS` is 992, so dom0's vGIC stops at 992 — and dom0's own
  writes stopping at `ICACTIVER120` (IRQ 991) is it agreeing. Everything this
  machine has is below that: 988 SPIs per the MADT (§1) and the v2m block at
  128–255 (§4).

One assumption is still unproven rather than ruled out: item 8, the EL2
physical timer. Nothing in these logs needs PPI 26 — Xen's boot reads the
counter rather than waiting on the interrupt, and dom0's tick comes from the
*virtual* timer PPI 27 trapped into `vtimer_interrupt()`, not from a Xen soft
timer. A dead hyp timer would not explain the silence and would not have
shown up yet; it would, however, be a second reason interrupt delivery is the
area to look at.

### The list

In rough order of likelihood:

1. **`Could not set up d0 guest OS (rc = -22)`**, right after `Loading
   ramdisk from boot module @ ...`. This is the first thing that actually
   happened, and the message names nothing useful. It is
   `kernel_image_probe()` returning `-EINVAL` from `kernel_probe()`, i.e. the
   dom0 kernel is not an image Xen recognises.

   The cause here was a **zstd stream**: `kernel_decompress()` in
   `common/device-tree/kernel.c` says `/* only gzip is supported */`, so a
   zstd payload falls straight through to a probe of still-compressed data.
   That is not an oversight — `common/Makefile` builds every non-gzip
   decompressor `$(CONFIG_X86)`-only, so on arm64 they do not exist. Fix it
   outside Xen:

   ```
   zstd -dc vmlinuz.zst > /boot/vmlinuz-xen-dom0    # the "unsupported format"
                                                    # complaint is the 4-byte
                                                    # size Linux appends; the
                                                    # output is complete
   ```

   Then check `off56` is `41524d64` as above. `install-vz.sh` now does that
   check and names the format it found, and Xen now says what the module
   actually is instead of only `rc = -22`.
2. **Xen complains about the dom0 module, or dom0 never starts.** The zboot
   wrapper and the missing `CONFIG_XEN`, per §6. Neither is Xen's fault, so
   rule them out before suspecting anything in §5.
3. **Nothing on screen after GRUB.** Xen died before or during
   `ExitBootServices`. The EFI-stage messages should have appeared; if
   `xen.efi` printed nothing at all, GRUB's `LoadImage` rejected the image or
   the FDT was not installed.
4. **Nothing on the serial terminal, but the EFI lines appeared.** Either the
   console never came up or Xen died before it did. Those are
   distinguishable: with `console=vtcon` the driver logs
   `vtcon: virtio-console at 05:00.0 ...` from `platform_init()` and
   `vtcon: console on virtio-console ...` from `init_preirq()`, and the whole
   ring is replayed the moment the second one succeeds — so if the terminal
   shows nothing at all, bring-up failed and the reason is in the ring for
   `xl dmesg` later. Check that the UTM serial device exists and its terminal
   is open, and look for `vtcon: skipping ...: offers MULTIPORT` naming the
   only candidate, which means the port Xen would need is one it will not
   write to (§2).
5. **Serial output stops partway through Xen's boot.** Suspect the device
   rather than Xen: everything Xen prints goes through one descriptor per
   character with a notification each, and a backend that stops consuming
   will make `tx_ready()` return zero forever and Xen will spin in
   `__serial_putc()`. `console=none` plus `xl dmesg` separates "Xen hung"
   from "the console hung".
6. **Screen and serial both blank after EFI.** Xen got past EFI and hung
   before the console. Bisect by removing things: fewer dom0 vCPUs,
   `dom0_max_vcpus=1`, then no PCI at all in the DTB (drop the `pcie` node) —
   which also removes the console, so pair it with `console=none`, and use it
   to separate "Xen cannot boot" from "dom0 cannot use its devices".
7. **PSCI.** *Ruled out by boot 2: `Brought up 6 CPUs`.* If secondaries ever
   do stop coming up, the assumption in §1 that macOS traps SMC from virtual
   EL2 is wrong. Symptom: Xen boots on one CPU and `setup_virt_paging`'s
   `smp_call_function` never returns.
8. **The EL2 physical timer.** Xen needs `CNTHP_EL2` and PPI 26 delivered.
   The GTDT declares it (§1) but nothing in the guest exercises it, since
   Linux at EL1 uses PPI 30 and nVHE KVM does not use the hyp timer for the
   host. This is the least-corroborated hardware assumption in the whole
   plan.
9. **dom0 has no disk.** MSIs (§4). Check with `xl dmesg` for the
   `GICv2m: dom0: frame 0x1fff0000, SPIs 128-255` line, then in dom0 for
   `GICv2m: range[mem 0x1fff0000-0x1fff0fff], SPI[128:255]` and for
   `virtio1-req.0` appearing in `/proc/interrupts`.
10. **dom0's `hvc0` is the wrong thing.** If `virtio_console` is still built
   into the dom0 kernel it will race Xen's PV console for the `hvc0` name and
   fight Xen for the device. §2, and §6's kernel prerequisites.
