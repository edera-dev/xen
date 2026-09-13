# 11 — Xen nested inside Virtualization.framework

Status: **Xen boots; dom0 boots to its first interrupt and stops there,
reproducibly.** Everything below
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
| `arch/arm/time.c`, `arch/arm/setup.c` | A 10 ms self-test that proves the hypervisor timer's interrupt arrives, run while there is still a console to report it on. §7. |
| `common/keyhandler.c` | `auto_debug_keys=<keys>[,<seconds>[,<repeats>]]`, which runs debug keys off a timer rather than off console input, and bounds the two waits inside `d` and `0` so that one unresponsive CPU or vCPU cannot cost the whole dump. §7. |
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
xen_hypervisor /xen/xen.efi dom0_mem=2G dom0_max_vcpus=2 dom0_vcpus_pin console=vtcon console_to_ring conring_size=512 loglvl=all guest_loglvl=all noreboot auto_debug_keys=0pq,10,3
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
- `auto_debug_keys=0pq,10,3` runs the `0`, `p` and `q` keyhandlers every ten
  seconds, three times over, without anything being typed. Why it cannot be
  typed instead is the first part of §7; why these three keys in this order,
  and why `p` needs `CONFIG_PERF_COUNTERS=y`, is "What boot 7 changes".
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
`kfence_init()` at `init/main.c:984`, `perf_event_init()`, `profile_init()`,
`call_function_init()`, `kmem_cache_init_late()` — and **`local_irq_enable()`
at `init/main.c:993`**, which is the first moment dom0 takes an interrupt at
EL1 at all.

(Boot 6 found it in `kfence_init()`, four lines into that window and nine
lines before the `local_irq_enable()`, so most of what follows in this section
was aimed at the wrong thing. It is kept because the things it ruled out are
still ruled out.)

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

**Boot 4** (`git:3a34bca481`) is boot 3 again on the committed tree, and stops
at the same line. So the stop is deterministic, not a race. Its log is the
first complete capture, and three things in the parts boot 3's excerpt had
elided are worth having:

- **Physical interrupts do reach Xen at virtual EL2, on every pCPU.**
  `setup_virt_paging()` ends in `smp_call_function(setup_virt_paging_one,
  NULL, 1)` — an SGI to the other five CPUs, and `wait = 1`, so it does not
  return until all five have run the function and cleared themselves from the
  mask. The log continues straight into `do_initcalls()`, so it returned.
  That kills the broadest version of "the nested GIC delivers nothing": the
  CPU interface, the redistributors and the EL2 exception path all work. What
  is *not* proven by it is the PPIs, which is a different source with the same
  destination, and the case where the interrupt arrives while dom0 rather than
  Xen is running, which is where the nested `HCR_EL2.IMO` has to be honoured
  by macOS.
- **Both timer PPIs are level-triggered, as intended.** `check_timer_irq_cfg()`
  warns when a timer IRQ ends up edge-triggered, and no such warning appears
  for any of the three.
- **`CPU0: Guest atomics will try 1 times before pausing the domain`.** That
  loop counts iterations of an `ldxr`/`stxr` pair plus a `NOW()` in one
  microsecond, so one iteration means a `NOW()` costs about that much on its
  own — which is what a `CNTPCT_EL0` read trapped to the outer hypervisor
  would cost, and not what a native read costs. It is a performance fact, not
  a bug, but it is the first direct sign of how much of the counter is
  emulated.

### The debug plan above needs the thing it is debugging

`CTRL-a` three times only works if Xen is reading console input, and the
virtio-console has no interrupt: `vtcon_rx_poll()` runs off a Xen timer, and
every Xen timer runs off the hypervisor timer's PPI 26. So if PPI 26 is one of
the things that does not arrive — item 8, the least-corroborated assumption in
the plan — then nothing typed ever reaches Xen and *every* keyhandler is out
of reach, silently, in exactly the situation that wants them. The same is true
of `xl dmesg`, which needs a dom0 that is running.

Two changes make the next boot answer this on its own:

- **`check_timer_interrupt_delivery()`**, from `start_xen()` right after
  `local_irq_enable()`. It arms a 10 ms Xen timer and polls softirqs by hand
  until it fires or a second of counter time goes by, then prints either
  `Hypervisor timer IRQ26 works` or a loud failure naming the consequences.
  Nothing else in Xen's boot waits on that interrupt — the boot path reads the
  counter rather than waiting on the timer — which is precisely why a machine
  that never delivers it boots to the very end looking healthy.
- **`auto_debug_keys=<keys>[,<seconds>[,<repeats>]]`**, which runs the same
  keyhandlers off a timer instead of off input. `install-vz.sh` now puts
  `auto_debug_keys=0pq,10,3` on the hypervisor command line, so the hardware
  domain's registers, the performance counters and the domain list are dumped
  three times at two-second intervals with nothing typed. It runs them from a
  tasklet, not from the timer callback, because the handlers that pause a vCPU
  must not run from a timer that interrupted that same vCPU — a tasklet runs
  on the idle vCPU, which is where a real keypress ends up too.

Three dumps rather than one is the point of `repeats`: a dom0 spinning in its
own handler and a dom0 that has stopped dead are indistinguishable in a single
dump and obvious in three. Read the next boot like this:

| What the log shows | What it means |
|---|---|
| `Hypervisor timer IRQ26 never fired` | Item 8. PPI 26 is not delivered, Xen has no timers, and PPI 27 is almost certainly no better — which alone explains dom0 stopping at its first tick. The dumps below will not appear either. |
| Timer works, dom0's PC moves between dumps and sits in `gic_handle_irq`/`el1_interrupt`/`arch_timer_handler_virt` | Case 1: dom0 is in an interrupt storm Xen cannot see, because with SRE the whole IAR/EOIR cycle is system registers. |
| Timer works, `d` shows a pCPU in `maintenance_interrupt` or `do_IRQ` | Case 2: the storm is on Xen's side of the LR. |
| Timer works, dom0's PC is identical in all three dumps and `q` shows d0v0 blocked | Case 3: dom0 is not running and nothing is left to wake it — look at what it is blocked on. |
| Timer works, dom0's PC is identical in all three dumps and `q` shows d0v0 runnable | dom0 is spinning at EL1 with interrupts enabled and no interrupt ever arriving: delivery *into* the guest, i.e. the LRs, rather than delivery to Xen. |

### Boot 5: the hyp timer is fine, and the debugging was on the wrong CPU

Boot 5 (`git:80f4d93dbb`) is the first boot with both of those changes in it.
It stops at the same `sched_clock:` line as boots 3 and 4, and it settles one
thing outright:

**`Hypervisor timer IRQ26 works` — item 8 is dead.** That line is worth
believing precisely. The self-test's wait only runs softirqs that are already
pending, and `TIMER_SOFTIRQ` is raised by exactly two things: `set_timer()`
when the new timer becomes the earliest on the CPU, which happened once, at
arm time, with the deadline 10 ms in the future; and `htimer_interrupt()`,
the PPI 26 handler. So the run that found the timer expired can only have
followed the interrupt. PPI 26 is delivered, at virtual EL2, on the boot CPU,
while Xen is running. The least-corroborated hardware assumption in the plan
is now a measured fact.

**And then nothing.** No `*** auto_debug_keys ***`, no dumps, and `CTRL-a`
three times gets no response. The `Debug keys '0dq' will run 3 times, every
10s from now` line is the last anyone hears of them.

That is not a measurement. It is the same mistake the previous section was
written to avoid, made one level down: everything doing the looking was on the
CPU being looked at.

- `auto_debug_keys_init()` is an initcall, so `smp_processor_id()` there is
  the boot CPU, and that is where its timer was queued.
- `vtcon_init_postirq()` calls `init_timer(&v->rx_timer, vtcon_rx_poll, port,
  0)` — CPU 0, hard-coded, because when it runs no other CPU is online yet.
  That poll is the only thing that ever reads console input.
- dom0's first vCPU is placed on the boot CPU too.

So the timer fires and the tasklet is scheduled, but a tasklet runs from
`do_softirq()`, and softirqs on a CPU run only when that CPU passes through
the return-to-guest path or the idle loop. The whole of the boot-5 evidence is
therefore one fact: **after dom0 starts, Xen does not get back onto CPU0.**
Every one of case 1, case 2 and case 3 still produces exactly that, so the
table above is not yet usable. It does, however, add a fourth candidate that
has nothing to do with interrupts at all.

### The console can wedge the machine by itself

`vtcon` puts one character in one descriptor, has 64 of them, and the serial
layer's synchronous path is:

```
while ( !(n = port->driver->tx_ready(port)) )
    cpu_relax();
```

with `port->tx_lock` held and interrupts off. For a UART that is right: a FIFO
drains on its own, so the wait is a few character times and always ends. A
virtio ring does not drain on its own. It drains because something on the host
is consuming it, and if that stops there is nothing this side can do to
restart it — Xen spins there forever.

Follow what that looks like from outside. dom0's `earlycon=xenboot` is
`HYPERVISOR_console_io`, so every dom0 `printk` is a hypercall that ends in
that loop: dom0 stops mid-`printk` and never returns to EL1. The CPU it stops
on is CPU0, which is where the input poll and the auto-keys timer were queued,
so neither ever runs again. No dumps, no `CTRL-a`, no more output from anyone.
Every symptom of boot 5, with nothing wrong with interrupt delivery at all.

The last line of the log being a complete one (`sched_clock: ... wraps every
4398046511097ns`, newline and all) argues against it a little — a stall would
more likely strand a line in the middle — but only a little: the ring drained
that write and could have stopped before the next one, which is the moment
`local_irq_enable()` makes the interesting thing possible too. It is a
hypothesis to eliminate, not to believe.

### What boot 6 changes

Three changes, all of them removing a dependency on the CPU under suspicion:

- **`vtcon_tx_ready()` gives up.** Once the ring has been full for 200 ms it
  returns an error rather than zero, which makes the serial layer discard the
  character instead of waiting for it, and `vtcon_rx_poll()` prints `vtcon:
  device stopped draining the transmit ring; N characters dropped` once the
  device is consuming again — from the poll, because `tx_ready()` runs inside
  `printk()` with the port lock held and is the one place in the driver that
  cannot report anything. A console that loses output is a nuisance; a console
  that stops the hypervisor is a bug, and it is one this driver has had since
  it was written.
- **The console's input poll moves off the boot CPU**, to
  `cpumask_last(&cpu_online_map)`, by an initcall that `migrate_timer()`s it
  once the other CPUs are up. This is what makes `CTRL-a` survive a wedged
  CPU0, which is the whole point of having it.
- **`auto_debug_keys` queues its timer there too**, and `dom0_vcpus_pin` is
  now on the command line so that dom0's two pinned vCPUs reach CPU1 and no
  further, leaving CPU5 genuinely idle.

One more, in `dump_registers()`: the per-CPU wait for a state dump is bounded
at a second, and prints `CPU%u did not answer the state dump request` instead
of spinning. The request is an IPI, so a CPU that does not answer it is not
taking interrupts at all — which is the single most decisive line boot 6 can
produce, and the old code would have hung the dumping CPU forever rather than
print it.

The keys are now `dq0`: `d` first because it is the one that names CPU0's
state, `0` last because it schedules a tasklet on the hardware domain vCPU's
own pCPU and so is the one dump that a wedged CPU0 will swallow.

| What the log shows | What it means |
|---|---|
| `vtcon: device stopped draining the transmit ring` | The console stalled. Interrupt delivery was never the problem; look at the host end of the virtio-console. |
| Dumps appear, `d` puts CPU0 in `__serial_putc`/`vtcon_tx_ready` | The same, caught in the act. |
| Dumps appear, `CPU0 did not answer the state dump request` | CPU0 takes no interrupts at all while dom0 runs. That is physical IRQ delivery to virtual EL2 during guest execution — the nested `HCR_EL2.IMO`, flagged in §4 and never yet exercised, since boot's PPI 26 arrived while *Xen* was running. |
| Dumps appear, CPU0 in `gic_interrupt`/`do_IRQ`/`maintenance_interrupt` | Case 2. The storm is on Xen's side of the LR, and `gic_interrupt()`'s read-IAR-until-spurious loop never exits, which is why no softirq ever runs. |
| Dumps appear, CPU0 in the guest and its PC moves between dumps | Case 1: dom0 is storming at EL1 where Xen cannot see it. |
| Dumps appear, CPU0 in the guest with the same PC three times, `q` says d0v0 runnable | Injection rather than delivery: the LRs. |
| Dumps appear, `q` says d0v0 blocked | Case 3. Look at what it is blocked on. |
| Still nothing at all | The fault is not specific to CPU0: either no Xen timer fires anywhere, or output is dead for every CPU. `console=none` and the ring then become the next move. |

What the hyp timer's self-test does *not* reach is the case that matters now.
It ran from `start_xen()`, on a CPU with no guest on it, so it proves PPI 26
arrives while Xen is the thing executing. Whether a physical interrupt reaches
virtual EL2 while the CPU is executing a guest at EL1 is a different question
with a different answer — it is the one that depends on macOS honouring the
nested `HCR_EL2.IMO` — and boot 5 says nothing about it either way. Boot 6 is
built to.

### Boot 6: dom0 is alive, at EL1, in `kfence_init()`

Boot 6 (`git:508803b5f6`) is the first boot that produced dumps, and they
answer the question the last three sections were built around. Both of the
candidates the table was pointed at are dead:

- **`CPU0` answered the state dump request.** `*** Dumping CPU0 guest state
  (d0v0): ***` is printed by CPU0 itself, from the IPI handler, while dom0
  was running on it. No `CPU0 did not answer the state dump request` line
  appears for any CPU. So a physical interrupt does reach virtual EL2 while
  the CPU is executing a guest at EL1: macOS honours the nested
  `HCR_EL2.IMO`. **Item 11 is ruled out**, and with it the whole of "Xen
  never gets back onto CPU0".
- **The console is draining.** No `vtcon: device stopped draining the
  transmit ring`, and ~250 lines of dump came out after dom0 stopped
  printing. **Item 12 is ruled out** for the window up to the first dump.
- `q` says d0v0 is `[has=T]`, `pause_flags=0`, on CPU0, with `Inflight
  irq=27` — the virtual timer, injected and waiting. d0v1 is `pause_flags=2`,
  i.e. still `VPF_down`, which is right: dom0 has not reached `smp_init()`.
  **Case 3 is ruled out.** CPU1–CPU4 are in `idle_loop`, so nothing else is
  stuck either.

So dom0 is running, at EL1, with `CPSR.I` set — before the
`local_irq_enable()` that all of §"Where it stops" was about. `nokaslr` makes
the rest exact. Resolved against the dom0 kernel's `System.map`, CPU0's guest
stack is:

```
__primary_switched
  start_kernel+0x304            init/main.c:984
    kfence_init
      kfence_init_pool
        __get_random_u32_below
          get_random_u32
            _get_random_bytes
              crng_make_state
                extract_entropy
                  arch_get_random_longs
                    this_cpu_has_cap
                      has_cpuid_feature
                        read_scoped_sysreg
                          __read_sysreg_by_encoding   <- PC
```

`ESR_EL2 = 0x6230026d` is `EC=0x18`, a trapped `MRS`: `Op0=3 Op1=0 CRn=0
CRm=6 Op2=0`, which is `ID_AA64ISAR0_EL1`, into `Rt=19`. And `X19` in the
dump is `0221100110212120` — byte for byte the `ISA Features` line Xen prints
for itself at boot, i.e. the sanitised value Xen's `TID3` emulation returned.
Disassembling the PC settles the rest:

```
ffff80008005a38c:  mrs  x19, id_aa64isar0_el1
ffff80008005a390:  b    ...                      <- PC
```

**The PC is the instruction after the trapping `MRS`, and the value is
already in the register.** Xen took the trap, emulated it, advanced the PC by
four and returned. Nothing is wedged, nothing is looping on a trap Xen
mishandles: dom0 is executing forwards. It is just doing it extremely slowly.

### Why that stack is a trap amplifier

`kfence_init_pool()` ends with a Fisher–Yates shuffle of its freelist —
`for (i = CONFIG_KFENCE_NUM_OBJECTS; i > 0; i--) rand =
get_random_u32_below(i);`, and this kernel has `CONFIG_KFENCE_NUM_OBJECTS=255`.
At that point in boot the CRNG is not ready, so `get_random_u32()` takes its
`if (!crng_ready())` path straight into `_get_random_bytes()`, and
`crng_make_state()` with `crng_init == CRNG_EMPTY` calls `extract_entropy()`
*every time* rather than once. `extract_entropy()` then runs a four-iteration
loop that asks the architecture for entropy twice per iteration —
`arch_get_random_seed_longs()` and `arch_get_random_longs()`.

Both go through `__cpu_has_rng()`, and before `system_capabilities_finalized()`
— which happens in `setup_system_features()` off `smp_cpus_done()`, far later
— that is `this_cpu_has_cap(ARM64_HAS_RNG)`, which reads `ID_AA64ISAR0_EL1`
for real rather than consulting the cap bitmap. Xen does not expose `RNDR`
(the top nibble of the sanitised value above is `0`), so both calls fail and
the loop falls back to `random_get_entropy()` — after paying for the reads.

That is **eight trapped `MRS` per `get_random_u32_below()`, 255 times over:
about two thousand exits to EL2 in one loop**, in a kernel that has produced
no output since `sched_clock`. On real hardware it is imperceptible. Here it
is the first stretch of dom0's boot long enough to be mistaken for a hang,
and there is no reason to think it is the only one — dom0 has no timestamps
yet (`[    0.000000]` on every line, `sched_clock_init()` is at
`init/main.c:1030`), so nothing in the log says how long the *rest* of dom0's
boot took either.

None of this is a bug in Xen. `HCR_EL2.TID3` has to be set — feature
sanitisation is what it is for, and KVM sets it too — and `HCR_EL2 =
0x807c663f` in the dump is otherwise as sparse as it gets: `TVM`, `TTLB`,
`TPU` and `TRVM` are all clear. The cost is the nested exit itself.

### What boot 6 could not measure, and why

There is exactly **one** dump. The log ends mid-way through the first run of
the key sequence, on the line `*** Dumping Dom0 vcpu#0 state: ***` — the
first `printk` in `vcpu_show_execution_state()`, whose next statement is
`vcpu_pause(v)`.

`vcpu_pause()` is `vcpu_pause_nosync()` plus a spin until the vCPU is off its
pCPU, and the comment next to it in `arch/arm/traps.c` says `/* acceptably
dangerous */`. It is not acceptable here, for a reason that has nothing to do
with how long CPU0 takes to answer: the spin runs in a **tasklet**, and a
tasklet that never returns takes out `do_softirq()` on the CPU running it.
That CPU was CPU5 — deliberately, per the previous section — and on CPU5 sit
the auto-keys repeat timer, the virtio-console's `rx` poll (so `CTRL-a`), and
the timer that would have printed `device stopped draining the transmit
ring`. One unbounded wait inside one keyhandler silenced every diagnostic the
last two sections added, including the repeats.

And the repeats were the measurement. One sample of a PC cannot distinguish
"stuck" from "slow"; the disassembly above happens to, but only by luck.

The premise that put `0` last was also wrong. `dump_hwdom_registers()` only
defers to a tasklet under `alt_key_handling`, which is off unless `A` is
pressed, so `0` never ran on "the hardware domain vCPU's own pCPU" at all —
it ran on CPU5 like the others and blocked there.

### What boot 7 changes

- **`dump_hwdom_vcpu()`** — `0`'s per-vCPU wait is bounded at a second, like
  `d`'s, using `vcpu_pause_nosync()` and an explicit deadline before handing
  the already-stopped vCPU to `vcpu_show_execution_state()`. A vCPU that will
  not stop now prints `*** d0v0 did not stop running on CPU0 ***` and the
  sequence continues. The `v == current` case is dumped directly, as before.
- **`auto_debug_keys` passes `need_context = true`**, as the keypress tasklet
  always did. Without it `d` prints nothing at all for the CPU it runs on:
  outside an interrupt `get_irq_regs()` is `NULL`, and the
  `guest_cpu_user_regs()` fallback is by construction a guest frame — on an
  idle vCPU, so `dump_execstate()` skips both of its two cases and returns.
  That is why boot 6's dump has CPU0 through CPU4 in it and no CPU5.
- **The keys become `dpq`**, and the build gets
  `CONFIG_PERF_COUNTERS=y`. `d` first because CPU0's guest PC is the
  measurement; `p` second because **the difference between two samples of
  `trap: sysreg access` is the number** — it converts "is dom0 moving?" into
  a trap rate, and a trap rate divided into the ~2000 traps that one kfence
  shuffle costs says how long dom0 needs to get out of it. `0` is dropped:
  d0v0 is on CPU0 and `d` already dumps it live and in more detail, d0v1 is
  down, and `0` is what hung boot 6. Five runs rather than three, so the log
  covers fifty seconds.

`CONFIG_PERF_COUNTERS` is a `.config` setting and `.config` is not tracked;
`./scripts/config --enable PERF_COUNTERS` before `update-xen`.

| What the log shows | What it means |
|---|---|
| `trap: sysreg access` climbing by thousands between samples | dom0 is executing, and the nested exit cost is the whole problem. Measure it, then look at what dom0 can be made to stop doing — `kfence.sample_interval=0` on dom0's command line removes this particular loop outright. |
| `trap: sysreg access` flat, guest PC identical | dom0 really has stopped, and it stopped somewhere `extract_entropy()` cannot: the loops on that stack are all bounded. |
| Guest PC moves but the trap counters barely do | The cost is not the traps. Look at the counter reads (`random_get_entropy()` is `CNTVCT_EL0`) and at `flush_tlb_kernel_range()` from `kfence_protect()`. |
| dom0 prints again, anywhere | It was only ever slow. The next question is how slow, and `p` answers that too. |

### Boot 7: fifteen million virtual timer interrupts

Boot 7 (`git:253d0589b6`) ran all its dumps — CPU5 included, the `need_context`
fix works — and the performance counters end the guessing in one line:

```
(XEN) Virtual timer interrupts   TOTAL[15475868]  CPU00[15475882]
(XEN) #PPIs                      TOTAL[15479567]  CPU00[15475520]  CPU05[4063]
(XEN) Maintenance interrupts     TOTAL[      0]
(XEN) Hypervisor timer interrupts TOTAL[   4140]  CPU00[     77]  CPU05[4063]
(XEN) 'q' pressed -> dumping domain info (now = 50555588666)
```

**15,475,882 virtual timer interrupts on CPU0 in fifty seconds — about
310,000 a second.** Every PPI CPU0 took was that one. Nothing else on the
machine is busy: CPU5's 4,063 hypervisor timer interrupts are the console's
input poll at its normal 81 Hz, and CPU1–CPU4 are idle. Xen's own timers are
fine; CPU0 is drowning in a single interrupt.

That is the missing factor of a hundred from the last section's arithmetic,
and it is item 13's answer with the emphasis in a different place. Nested
exits are not the problem. **A physical interrupt that never stops asserting
is**, and dom0 gets whatever slivers of CPU0 are left between one handler
returning and the next one entering — about three microseconds apart.

It also names the *right* one of the original three cases. This is case 2,
the storm on Xen's side of the LR — but not the maintenance interrupt, which
the counters say has never fired once. It is the virtual timer's own PPI 27.

### Why PPI 27 never stops

The sequence is supposed to be self-limiting. `vtimer_interrupt()` in
`arch/arm/time.c` is Xen's handler for the guest's virtual timer:

```c
current->arch.virt_timer.ctl = READ_SYSREG_EL0(CNTV_CTL);
WRITE_SYSREG_EL0(current->arch.virt_timer.ctl | CNTx_CTL_MASK, CNTV_CTL);
vgic_inject_irq(current->domain, current, current->arch.virt_timer.irq, true);
```

PPI 27 is level-triggered — `check_timer_irq_cfg()` confirms it on every
boot, and boot 4 already recorded that it does not warn. The level is the
timer's output, `ISTATUS && ENABLE && !IMASK`. Setting `IMASK` is what
deasserts it, and it stays deasserted until the guest takes the interrupt
Xen just queued and re-arms the timer with a write Xen does not trap. On
every other machine this fires once per guest tick.

Here it fires until the counter overflows the page. dom0 cannot break the
loop: it is still before `local_irq_enable()`, `CPSR.I` is set in every dump,
and `q` says `Inflight irq=27` from the *first* injection, unchanged fifty
seconds later. So the `IMASK` write is not deasserting the line.

Two things can produce that, and they need different fixes:

- **The write does not take.** Xen is at virtual EL2 with `HCR_EL2.E2H=0`, so
  `WRITE_SYSREG_EL0(..., CNTV_CTL)` is a write to `CNTV_CTL_EL0` — the right
  register for non-VHE, and the same one the AIC driver reaches as
  `CNTV_CTL_EL02` when Xen runs bare-metal in VHE mode. Under FEAT_NV2 it is
  also a register macOS may be shadowing.
- **The write takes and the line does not care.** macOS is emulating Xen's
  GIC, and if its PPI 27 input is driven from something other than a live
  re-evaluation of `CNTV_CTL_EL0`, no write Xen makes will quiet it.

### What boot 8 changes

One change, in `vtimer_interrupt()`, which both measures and stops it.

Detecting the re-entry costs nothing and needs no new state. `IMASK` on this
timer is set by Xen and by nobody else — a guest silencing its timer clears
`ENABLE`, and a guest that has serviced the interrupt re-arms with `IMASK`
clear — so **finding `IMASK` already set on the way into the handler means
the line asserted while masked**. Masking again just returns straight back
here, so the handler takes the timer's other lever and clears `ENABLE`
instead, reads the register back, and says once what it found:

```
CPU0: d0v0's virtual timer fired again with IMASK already set
  CNTV_CTL <before> -> <after>, CNTVCT ..., CNTV_CVAL ..., CNTVOFF ...
  timer disabled instead; the guest re-arms it from its own handler
```

or, if `ENABLE` is ignored too, `ENABLE did not clear either: this timer
cannot be stopped from EL2`. Nothing is taken from the guest either way: the
interrupt it is owed is already queued in its vGIC, and its handler re-arms
the timer with an untrapped write to `CNTV_CTL_EL0`.

A new counter, `Virtual timer interrupts while masked`, sits next to
`Virtual timer interrupts` in the `p` dump, so the two numbers together say
whether the storm was stopped or only counted.

| What the log shows | What it means |
|---|---|
| `timer disabled instead`, and `while masked` stays near zero | Fixed. `ENABLE` is honoured where `IMASK` is not, dom0 gets CPU0 back, and the next question is simply how far it boots. |
| `timer disabled instead`, but `while masked` still in the millions | `ENABLE` is honoured and the line still asserts, so PPI 27 is not driven by this timer at all. The lever left is the GIC: mask the PPI while the guest's vIRQ is inflight and re-enable it when the guest retires it. |
| `ENABLE did not clear either` | Neither bit reaches the hardware. Xen cannot use the hardware virtual timer for guests on this platform, and the answer is to emulate the guest's vtimer in software off Xen's own `CNTHP_EL2`, which already works (boot 5). |
| No such line at all, `while masked` zero, and dom0 still crawls | The storm is not a re-entry — each interrupt is a genuinely new timer expiry. Then look at `CNTVOFF_EL2`: `init_timer_interrupt()` writes 0 to it, and if macOS applies an L1 write to it directly rather than composing it, the guest's `CNTV_CVAL` is permanently in the past. |

One gap in boot 7's evidence worth naming: only the last of the five `dpq`
runs was captured, so there is no second sample of the counters and no rate
*over time* — just the fifty-second average. Three runs rather than five from
here, so the whole log fits in one paste.

### Boot 8: the timer is not the lever

Boot 8 (`git:bd978701d3`) put the detector in and it fired on essentially
every interrupt:

```
(XEN) Virtual timer interrupts              TOTAL[9372994]  CPU00[9373008]
(XEN) Virtual timer interrupts while masked TOTAL[9373192]  CPU00[9373206]
                                                    now = 30339115875
```

Two numbers, two conclusions.

**The rate has not changed.** 9,373,008 in 30.3 seconds is 309,000 a second,
against boot 7's 310,000. Clearing `ENABLE` did nothing at all.

**Every interrupt found `IMASK` already set.** The two counters are equal to
within the few thousand the `p` dump itself races past while printing, so
from the second interrupt onwards the handler has never once seen a timer
that was not already masked. That is worth stating precisely: the bit Xen
writes to `CNTV_CTL_EL0` *persists* — Xen reads its own `IMASK` back nine
million times in a row. **The register is writable and holds its value. The
interrupt line does not care.**

dom0 is where it always is: PC `__read_sysreg_by_encoding`, `X19` holding the
sanitised `ID_AA64ISAR0_EL1`, the stack running back through
`__get_random_u32_below` to `kfence_init_pool` — at shuffle iteration 253 of
255 after thirty seconds, against 254 after ten in boot 6. `trap: sysreg
access` reached 176,093, within ten of boot 7's total at fifty seconds. The
sliver of CPU0 dom0 gets is small and varies a lot between boots; nothing
else about it has moved.

### Three ways for a register to hold a value and mean nothing

The report line `vtimer_interrupt()` prints names them, and it prints
`CNTVCT`, `CNTV_CVAL` and `CNTVOFF` because those separate the third from the
first two:

1. **The write lands and the line is driven from elsewhere.** macOS emulates
   Xen's GIC; if its PPI 27 input is not a live re-evaluation of
   `CNTV_CTL_EL0`, no write Xen makes will quiet it.
2. **The write lands in a copy the guest does not use.** Xen is at virtual
   EL2 with `HCR_EL2.E2H=0`, so it reaches the guest's timer as
   `CNTV_CTL_EL0` — the same physical EL1 virtual timer the guest uses. Under
   nested virtualisation that sharing is macOS's to arrange, and if it keeps
   a separate copy for the L1 then Xen has been masking its own timer for
   nine million interrupts while the guest's ran free. **`CNTV_CVAL` is the
   tell**: Xen never programs it and the guest always does, so a plausible
   deadline near `CNTVCT` means Xen is looking at the guest's copy and a zero
   means it is not.
3. **`ENABLE` is not sticking either.** Boot 8 cannot rule this out from its
   counters, because it only counted the entries, not what they contained.

Boot 9 settles 3 from the counters alone — a new `Virtual timer interrupts
while masked+off` counts the entries that found `ENABLE` set again after the
previous entry cleared it — and settles 2 from the report line, which now
repeats rather than being said once at the top of a log.

### What boot 9 changes: stop listening to the line

Nothing Xen can write to the timer stops it, so `vtimer_interrupt()` stops
listening instead. On the stuck path it now **disables PPI 27 at the GIC for
this pCPU** and arms a one-millisecond Xen timer to turn it back on.

It is safe for the same reason the early return is: the guest is owed exactly
one virtual timer interrupt and already has it queued in its vGIC, so there
is nothing to deliver while the PPI is off. What it costs is latency — a
timer interrupt that becomes deliverable while the PPI is masked waits up to
a millisecond — and that is beneath anything a guest's boot can distinguish
from jitter.

What it buys is the whole machine. The wasted interrupt rate goes from
309,000 a second to 1,000, CPU0 goes from spending all of its time in
`vtimer_interrupt()` to spending a fraction of a percent, and dom0 gets a CPU
for the first time since it started. It also degrades correctly if case 1 is
what is happening and the line never deasserts: the steady state is then one
wasted interrupt per millisecond forever, and the guest still gets each real
tick the first time it is deliverable, because the handler only injects when
`IMASK` is clear — which only the guest ever makes it.

| What the log shows | What it means |
|---|---|
| dom0 prints again and boots on | Fixed, at the cost of 1,000 interrupts a second. The next question is what dom0 does next, and `while masked` says how much the workaround is still absorbing. |
| `while masked+off` climbing with `while masked` | Case 2 or 3: the `ENABLE` write is not reaching the register the line is derived from. Check `CNTV_CVAL` in the report — if it is zero, Xen has been masking its own timer, and the guest's virtual timer needs to be emulated in software off `CNTHP_EL2`. |
| `while masked+off` stays at zero | Case 1: both bits land, and PPI 27 is simply not this timer's output. Nothing Xen writes will ever quiet it, and the millisecond poll is the permanent shape of the fix rather than a workaround. |
| `Virtual timer PPI disabled at the GIC` near zero, storm gone | The line does follow `ENABLE` after all and boot 8's reading was wrong. |
| Storm unchanged at 309,000/s | The PPI is not being disabled — the redistributor write is going the same way as the timer write, and the only lever left is not to route the guest's timer through the hardware at all. |

### Boot 9: dom0 boots, and the report line arrives

Boot 9 (`git:bd978701d3-dirty`) is the first boot where dom0 gets a CPU. It
goes from `sched_clock` — where boots 3 through 8 all stopped — through
`kfence: initialized`, `Console: colour dummy device`, `printk: legacy
console [tty0] enabled`, `[hvc0] enabled`, `Calibrating delay loop`, the LSM
stack, `xen:grant_table: Grant tables using version 1 layout`, `xen:events:
Using FIFO-based ABI`, `smp: Brought up 1 node, 2 CPUs`, `devtmpfs:
initialized`, `clocksource: Switched to clocksource arch_sys_counter`, and on
to `pnp: PnP ACPI: disabled`. It has timestamps of its own for the first
time, so from here dom0's own clock can be compared against Xen's.

And the report line, at last:

```
(XEN) CPU0: d0v0's virtual timer fired again with IMASK already set (#1)
(XEN)   CNTV_CTL 0000000000000007 -> 0000000000000006, CNTVCT 0000000001dba72a,
        CNTV_CVAL 0000000001db95bc, CNTVOFF 0000000009745572
```

`CNTV_CVAL` is `0x01db95bc` against a `CNTVCT` of `0x01dba72a`: a deadline
4,462 ticks — 186 microseconds — behind the counter, exactly where a tick
that has just expired should be. Reports #2 through #4 show the same shape at
three later counter values. **Xen is reading the guest's copy of the timer.**
Reading 2 is dead, and with it the worry that Xen has spent four boots
masking a timer nobody was using.

`0x7 -> 0x6` says the rest: both bits are writable, both read back, `ENABLE`
clears when told to. Xen's view of this timer is entirely normal.

What the line follows is neither of them. The counters:

```
(XEN) Virtual timer interrupts                 TOTAL[224]  CPU00[180]  CPU01[44]
(XEN) Virtual timer interrupts while masked    TOTAL[112]  CPU00[ 90]  CPU01[22]
(XEN) Virtual timer interrupts while masked+off TOTAL[112]  CPU00[ 90]  CPU01[22]
(XEN) Virtual timer PPI disabled at the GIC    TOTAL[112]  CPU00[ 90]  CPU01[22]
```

224 interrupts, of which 112 were re-entries: **exactly one spurious
assertion per real expiry**. That is not a storm, it is a latch. PPI 27 is
made pending at the moment the timer expires, and masking the source
afterwards does not retract it — which is the behaviour the comment already
at the top of `vtimer_interrupt()` warns about for an edge-triggered timer
interrupt, on a line `check_timer_irq_cfg()` reports as level-triggered.

Boots 7 and 8 were the same fact seen through a guest that could not run: the
deadline stayed in the past, so the assertion was continuous rather than
one-per-tick, and no amount of masking cleared it.

### But `#PPIs` is ten million

```
(XEN) #PPIs   TOTAL[10798559]  CPU00[5379793]  CPU01[5417166]  CPU05[1633]
```

Against 224 virtual timer interrupts and 223 hypervisor timer interrupts on
CPU0 and CPU1 together. **Ten point eight million interrupts reached
`do_IRQ()` and no handler ran for any of them.** In a `debug=y` build there
is exactly one path in `do_IRQ()` that discards an interrupt silently:

```c
if ( test_bit(_IRQ_DISABLED, &desc->status) )
    goto out;
```

— and `_IRQ_DISABLED` on PPI 27 is precisely what `gicv3_irq_disable()` sets
when boot 9's workaround quiesces it. CPU5 is the control: it runs no guest,
so it never disables PPI 27, and its `#PPIs` equals its hypervisor timer
count to the interrupt.

So the redistributor's enable bit looks no more effective than `IMASK` or
`ENABLE` were. The workaround did not stop the interrupts; it made them
cheap. That bought a factor of a hundred and the whole of dom0's boot so far,
but CPU0 and CPU1 are still taking a quarter of a million interrupts a second
each, dom0 advanced 0.13 seconds of its own clock in twenty of Xen's, and
`Virtual timer PPI disabled at the GIC` reaching only 112 says the
millisecond re-enable timer is itself being starved — CPU0 took 180
hypervisor timer interrupts in twenty seconds.

### A bug boot 9 introduced

`virt_timer_save()` arms the software fallback timer — the one that injects a
guest's virtual timer interrupt while its vCPU is descheduled — only for a
vCPU whose timer is enabled and unmasked:

```c
if ( (v->arch.virt_timer.ctl & CNTx_CTL_ENABLE) &&
     !(v->arch.virt_timer.ctl & CNTx_CTL_MASK) )
    set_timer(&v->arch.virt_timer.timer, ...);
```

Clearing `ENABLE` in the handler leaves exactly the state that condition
rejects, so a vCPU descheduled between a stuck interrupt and the guest
re-arming had no timer at all. Both vCPUs in boot 9's last dump are not
running, with `Inflight irq=27 lr=255` — queued and never placed in a list
register. Clearing `ENABLE` was not merely useless, which boot 8 established;
it was harmful.

### What boot 10 changes

- **Stop clearing `ENABLE`.** It does not quiet the line and it breaks the
  fallback timer above.
- **Push the deadline out instead.** The timer's output is `ISTATUS && ENABLE
  && !IMASK`. Two of those three are measured not to matter, which leaves
  `ISTATUS`, and the only way to clear `ISTATUS` from EL2 is to move the
  deadline the guest set. `vtimer_interrupt()` now writes `CNTV_CVAL_EL0 =
  0x7fffffffffffffff` — twenty-four thousand years out at 24 MHz — and reads
  `CNTV_CTL` back to say whether `ISTATUS` went with it.

  Nothing is lost by moving it: the interrupt the deadline earned is already
  queued in the guest's vGIC, and the guest re-arms `CNTV_CVAL` itself in its
  handler, which un-pushes it. The one place that would be misled is
  `virt_timer_save()`, which saves the deadline to arm the fallback timer
  from — so it now recognises the pushed value and keeps what the guest asked
  for. The sentinel is the state; there is nothing else to track.
- **Attribute the ten million.** `IRQs taken while disabled at the GIC`
  counts the silent path in `do_IRQ()`. On real hardware it is a narrow race
  on the way into `disable_irq()` and should read single digits.

| What the log shows | What it means |
|---|---|
| `ISTATUS cleared ...`, `#PPIs` collapses to a few thousand | Fixed, properly. The line is the timer's output after all, and `ISTATUS` is the only input this platform honours. |
| `ISTATUS cleared ...` but `#PPIs` still in the millions, `IRQs taken while disabled` with them | The line is not this timer's output. Nothing in the timer will ever quiet it, and the redistributor is not honouring the mask either, so the next lever is the CPU interface: leave the interrupt active after the priority drop, which is the one thing a GIC cannot re-signal. |
| `ISTATUS survived ...` | The register is a write-only shadow as far as the comparison is concerned. Same conclusion, one step sooner. |
| `IRQs taken while disabled` in single digits, `#PPIs` still millions | The ten million are not the disabled PPI 27 and this section's arithmetic is wrong. Find which PPI by adding per-INTID counting. |

### Boot 10: the storm is over, and the console gets moved out from under Xen

Boot 10 is the first boot where dom0 runs at speed. Its own clock and the
things on it look like an ordinary arm64 boot: `kfence` at 0.008, both
consoles at 0.010, `smp: Brought up 1 node, 2 CPUs` at 0.073, `devtmpfs` at
0.090, the network stack at 0.146, a 275 MB initramfs unpacked between 0.155
and 0.503, then `io scheduler bfq registered` and PCI enumeration out to
0.556. Every boot before this one stopped at `sched_clock`.

**Two stuck virtual timer interrupts in the entire boot**, against boot 9's
112 in twenty seconds with ten million dropped interrupts behind them. The
report prints the first four and there are only two, so that is the whole
count. Pushing the deadline out is the lever.

What it is not is an explanation. The report says so:

```
(XEN) CPU0: d0v0's virtual timer fired again with IMASK already set (#1)
(XEN)   CNTV_CTL 0000000000000007 -> 0000000000000007, CNTVCT 0000000002056b0f,
        CNTV_CVAL 7fffffffffffffff, CNTVOFF 0000000012ead2b7
```

`CNTV_CVAL` reads back as the pushed value, so the write landed. `CNTVCT` is
`0x02056b0f`, twenty-four thousand years short of it. And `CNTV_CTL` still
reads `0x7` — `ISTATUS` set, immediately after an `isb`, with the deadline in
the far future. **The register Xen reads and the comparison the interrupt
line is derived from are not the same thing.** The write reaches the one that
matters; the read does not come from it. That also retires the puzzle of
boots 7 and 8: `IMASK` and `ENABLE` "persisting" across nine million
interrupts was the same stale read, not proof that the writes had taken.

So the shape of this platform's virtual timer is: writes work, reads of
`CNTV_CTL` do not reflect them, and the interrupt line follows the
comparator and nothing else. Xen's handler now works entirely by writing.

### Where boot 10 stops: dom0 moves Xen's console

The last two lines of the log are:

```
[    0.555589] pci 0000:00:01.0: BAR 0 [mem 0x280000000-0x28000ffff 64bit]: assigned
[    0.556070] pci 0000:00:05.0: BAR 0 [mem 0x280010000-0x28001ffff 64bit]: assigned
```

`00:05.0` is Xen's console — `vtcon: virtio-console at 00:05.0, BAR0
0x00000280060000` from the top of the same log. dom0 has just decided to move
BAR0 from `0x280060000` to `0x280010000`, and the next thing
`pci_assign_resource()` does is write that address into the device's
configuration space. Xen's mapping still points at `0x280060000`, where there
is now nothing. The log ends on the line before the write.

This is §2's "dom0 must not drive the same device", one layer lower than §2
expected: not a driver binding to the console, but the PCI core moving it
before any driver is involved. Linux's generic host driver (`pci-host-generic`,
the DT path) assigns BARs rather than claiming what the VMM already
programmed, so every device in the machine gets a new address — `00:01.0`
moved to where `00:0c.0` used to be, and `00:05.0` to where `00:0b.0` was.

`linux,pci-probe-only` in `/chosen` is the property that exists for exactly
this case: with it set, `pci_host_probe()` claims the existing resources and
assigns nothing. Xen builds dom0's device tree, so boot 11 adds it — and only
when `vtcon_in_use()`, i.e. only when Xen actually owns a PCI function that
must not move.

### Boot 11: the same ending, because the property went to the wrong builder

Boot 11 stops on the same two lines, and says so before it gets there:
`Loading d0 DTB to 0x0000000078000000-0x000000007800085c`, byte for byte the
size boot 10's was. A new property would have made it bigger. Linux agrees —
`of_pci_check_probe_only()` prints `PCI: PROBE_ONLY enabled` when it finds
one, and nothing of the sort is in the log.

`make_chosen_node()` is not the function that builds a normal dom0's
`/chosen`. It serves the ACPI path and dom0less; a dom0 whose device tree is
copied from the host gets its `/chosen` patched by `write_properties()` in
`arch/arm/domain_build.c`, which is where `bootargs` and the initrd
placeholders are written. Boot 12 says it in both places, through one helper,
so neither can drift from the other.

Everything else in boot 11 repeats boot 10 exactly, including two stuck
virtual timer interrupts and no third.

### Boot 12: the BARs stay put, and the device is reset anyway

`linux,pci-probe-only` worked. The tree grew — `Loading d0 DTB to
0x0000000078000000-0x0000000078000881` against boot 11's `0x7800085c` — no
`: assigned` line appears for any function, `00:05.0` keeps `BAR 0 [mem
0x280060000-0x28006ffff 64bit]`, and dom0 goes past enumeration into
`pci_bus 0000:00: resource 4`, the USB quirks, and the start of driver
binding. Item 15 is fixed.

The log then ends four lines later:

```
[    0.572030] pci 0000:00:0e.0: enabling device (0010 -> 0012)
[    0.574621] virtio-pci 0000:00:01.0: of_irq_parse_pci: failed with rc=-22
```

The `-22` is not the problem: the generated tree gives the host bridge a
`msi-parent` and no `interrupt-map`, because §4's whole point is that MSIs are
the only interrupts this machine can deliver, so there is no legacy INTx to
parse and Linux says so and carries on. What matters is which device is next.
`virtio-pci` binds to every `1af4:` function in BDF order, and the one after
`00:01.0` is `00:05.0` — Xen's console.

`virtio_pci_probe()` does not need a console driver to take the device away.
`vp_modern_probe()` resets it: status register to zero, queues gone, before
`virtio_console` or anything else is consulted. There is no line for
`00:05.0` in the log because the reset happens during its probe, and the
probe's own messages had nowhere left to go.

That the console rather than dom0 is what stopped is not an inference from
the last line alone. The `auto_debug_keys` timer fires ten seconds in, on
CPU5, which has no guest on it and nothing to do with PCI. `*** auto_debug_keys
***` is not in the log. Xen is running; the console is not.

### What boot 13 changes: dom0 never sees the device at all

Stopping dom0 moving the BARs was necessary and is not sufficient, and
neither would hiding the BARs be. The device has to be invisible.

dom0 is created with `XEN_DOMCTL_CDF_trap_unmapped_accesses`, and
`arch/arm/io.c` answers an unmapped access from such a domain with
`unmapped_handler`: reads return all ones, writes are dropped. That is
exactly what an empty PCI slot looks like. So `construct_hwdom()` now unmaps
the one 4 KiB page of ECAM that describes the console's function and denies
dom0 permission to map it again. Linux reads `ffff` for the vendor ID, skips
the slot, and never enumerates, claims, or resets it.

It costs dom0 one device it was never able to use anyway — Xen is holding it
— and it costs nothing at all on a machine whose console is a UART, where
`vtcon_config_space()` returns zero.

### Boot 13: the right page, and exactly the wrong default

The page was right. Xen unmapped `0x40028000` — `0x40000000 + (5 << 15)`, the
ECAM function for `00:05.0` — and the console lived through the whole scan
for the first time. dom0 did not.

```
(XEN) arch/arm/traps.c:1999:d0v0 HSR=0x00000093800007 pc=0xffff800080b903f8
      gva=0xffff800090028000 gpa=0x00000040028000
[    0.551988] Unable to handle kernel ttbr address size fault at ...
[    0.559341] pc : pci_generic_config_read+0x40/0xd0
...
[    0.575217] Kernel panic - not syncing: Attempted to kill init!
```

The fault is the first configuration read of the bus scan,
`pci_bus_read_dev_vendor_id()` on a slot Xen had just made disappear, with
interrupts off in `kernel_init`. `HSR=0x93800007` decodes as a data abort from
a lower EL with `ISV=1`, a four-byte read into `x0`, DFSC `0x07` — a
translation fault, cleanly decoded, exactly the kind Xen is equipped to
emulate. It injected it into dom0 instead.

Because `XEN_DOMCTL_CDF_trap_unmapped_accesses` means the opposite of what the
previous section assumed. In `try_handle_mmio()`:

```c
else if ( rc == IO_UNHANDLED && !trap_unmapped )
    handler = &unmapped_handler;    /* reads all ones, writes dropped */
else
    return rc;                      /* -> inject_dabt_exception() */
```

The flag asks for unmapped accesses to be *trapped* — reported to the guest as
a fault. Reading all ones is the behaviour of a domain **without** it, and
`create_dom0()` sets it.

So do not inherit a default that means the opposite: say what the page does.
Boot 14 registers a handler over it, using the same `unmapped_ops` that
`arch/arm/io.c` already has, through a new `register_unmapped_mmio_handler()`.
An empty slot then reads as an empty slot whatever the domain's default is.

(The handler functions have to live in `io.c` rather than beside the caller:
`domain_build.c` is linked as `.init.o`, so everything in it must be
`__init`, and these run for as long as dom0 does.)

| What the log shows | What it means |
|---|---|
| No `00:05.0` in dom0's enumeration, boot continues | Fixed. The next question is whether the root filesystem appears, which is item 9 and the `PHYSDEVOP` returns below. |
| `00:05.0` still enumerated | The page being handled is not the one dom0 reads. Check `vtcon: configuration space at ... hidden` against dom0's ECAM base and the bus/device/function in `vtcon:`'s own banner. |
| Another abort at `0x40028000` | The handler is not being found: `find_mmio_handler()` before the p2m, so check the range and that dom0 has a spare slot of its `MAX_IO_HANDLER`. |
| Silence again with no `auto_debug_keys` | Something else on that probe path reaches the device — the BAR, most likely, which would mean hiding the MMIO too. |

### Two things in boot 10 that are not the bug, and one that is next

- **`kvm [1]: HYP mode not available`.** dom0 is at EL1 under Xen. Correct.
- **`ARM FF-A: FFA_VERSION returned not supported`** after `Unhandled SMC/HVC:
  0x84000063`. Linux probing for a firmware framework that is not there.
- **`PHYSDEVOP cmd=25: not implemented`, `cmd=15: not implemented`**, once per
  PCI function, each followed by `Failed to add - passthrough or MSI/MSI-X
  might fail!`. `arch/arm/physdev.c` returns `-ENOSYS` for everything, so
  `xen_add_device()` cannot register any of dom0's PCI devices with Xen. This
  is item 9 arriving on schedule: the root filesystem is on `00:06.0` or
  `00:07.0` (`[1af4:1042]`, virtio-blk) and it needs MSI-X through the v2m
  frame. It is the next thing after the console.

### Boot 14: the slot is empty, and it was never the slot

`vtcon: configuration space at 0x00000040028000 hidden from Dom0`, and dom0's
scan steps from `00:01.0` straight to `00:06.0`. No fault, no panic, the
whole bus enumerated, resources claimed, USB quirks run. The device Xen is
using is invisible and the empty-slot handler does what it says.

And the log ends on the same line as boot 12's:

```
[    0.586342] virtio-pci 0000:00:01.0: of_irq_parse_pci: failed with rc=-22
```

So the previous section's reasoning was wrong. It argued that the next device
after `00:01.0` was `00:05.0` and that `vp_modern_probe()` reset it; `00:05.0`
is now not there at all and the boot stops in the same place. Whatever ends
it is inside `00:01.0`'s own probe — the virtio-net device — and `00:06.0`,
which would print its own `of_irq_parse_pci` line, is never reached.

Hiding the console was still worth doing: it is the difference between a
device Xen holds and a device any dom0 driver may reset, and boot 13's panic
proved dom0 does reach for it. It is simply not what stops boot 14.

### What boot 15 changes: make the dumps land where the failure is

The honest state is that the two candidates — Xen's console stopping, and
dom0 stopping — are still not separated, and the thing that would separate
them is `auto_debug_keys`, which fires ten seconds in. dom0's clock reads
0.586 s when the log ends; Xen's wall clock at that moment is unknown and
certainly much less than ten seconds. The dumps may simply not have happened
yet.

So stop guessing and move them: `auto_debug_keys=0pq,10,3` dumps at two, four,
six, eight and ten seconds. A dump that appears says Xen is alive and names
what dom0's CPUs are doing; no dump at all, with the log ending mid-boot,
says the console is gone.

| What the log shows | What it means |
|---|---|
| Dumps appear, dom0's PC in `virtio_pci_probe` or below it | dom0 is stuck in that probe. The guest PC names where, against the same `System.map`. |
| Dumps appear, dom0 idle and runnable | dom0 is fine and the output is not getting out: the console's transmit path, and `vtcon: device stopped draining the transmit ring` is the line to look for. |
| No dumps, log ends mid-boot | Xen's console died during `00:01.0`'s probe. What that device and Xen's share is the v2m frame at `0x1fff0000` and the ECAM window; neither should be fatal, so instrument whichever is touched first. |
| Dumps appear and dom0 is running normally | The capture was just short. Read on. |

### Boot 15: Xen is fine, and dom0 is blocked on nothing

Moving the dumps to two seconds was the whole point and it worked on the
first try. `*** auto_debug_keys: 'dpq', 5 runs left ***` appears immediately
after dom0's last line, and everything after it is healthy: CPU5 in its
tasklet, CPU0 through CPU4 in `idle_loop`, the console carrying two thousand
lines of dump without a stumble.

**So the console is not what stops. dom0 is**, and every boot from 12 onward
was the same thing seen through an instrument pointed ten seconds too late.

What `q` says about dom0:

```
(XEN)     VCPU0: CPU0 [has=F] ... upcall_mask=01
(XEN)     pause_count=0 pause_flags=1
(XEN)     VCPU1: CPU1 [has=F] ... upcall_mask=01
(XEN)     pause_count=0 pause_flags=1
```

`pause_flags=1` is `VPF_blocked`. Both vCPUs are blocked, and neither has an
`Inflight` or a `Pending` line — no virtual interrupt is queued for either of
them. Nothing is going to wake them.

And `p` says what they are not waiting for:

- **`#SPIs TOTAL[0]`.** Not one SPI has ever been delivered, so no MSI has
  ever arrived — but nor was one ever asked for.
- **`vgicd: write TOTAL[1352]`**, which is the same 1352 as boot 4, all of it
  `gic_dist_config()` inside `init_IRQ()`. dom0 has not touched the
  distributor since. It never enabled an MSI SPI, so it never reached
  `request_irq()`, so it never finished `vp_find_vqs()`.
- **`Virtual timer interrupts TOTAL[4]`** and `vtimer: virt expired,
  injected TOTAL[3]`, in the second and a half since dom0 went quiet. It is
  not sleeping with a timeout — a `msleep()` loop would be a thousand of
  these. It is blocked with nothing armed at all.

Three other things worth having from the same dump. The virtual timer fix is
holding: two stuck interrupts in the whole boot and `IRQs taken while disabled
at the GIC TOTAL[0]`, which also retires boot 9's ten million unaccounted PPIs
— they were the storm, and the storm is gone. `trap: sysreg access` is
192,876 at two seconds against boot 9's 176,093 at twenty, so dom0 is running
at speed right up to the moment it stops. And the hole Xen punched in dom0's
configuration space is visible in its own rangeset: `I/O Memory { 1fff0,
40000-40027, 40029-6ffdf, 280000-67ffff }`.

### What boot 16 changes: ask the vCPU, not the pCPU

The one thing the dump does not have is dom0's program counter, and that is
not an accident. `d` dumps what is on each pCPU, and what is on each pCPU is
the idle vCPU, because dom0's are blocked — so the `*** Dumping CPU0 guest
state ***` block that every earlier boot had is simply absent.

`0` is the handler for exactly that: it pauses the hardware domain's vCPUs and
dumps them wherever they are. It was dropped after boot 6 because it hung, and
it has been bounded since boot 7, and a blocked vCPU stops instantly, so the
bound will not even be reached. The keys become `0pq` — `d` is redundant now
that `0` covers the running case too, and dropping it halves the log.

With dom0's PC and stack against the same `System.map`, "blocked inside
`virtio_pci_probe()` waiting for X" stops being an inference.

| What the log shows | What it means |
|---|---|
| d0v0 in `virtnet_probe` or `virtnet_send_command` | Waiting on the control virtqueue, i.e. the device is not answering a kick. That is DMA or the notify BAR, not interrupts. |
| d0v0 in `wait_for_completion` under `really_probe` | Deferred or asynchronous probe waiting on another thread; find that thread in d0v1's dump. |
| d0v0 in `msix_capability_init` or below | MSI-X setup itself, and the v2m frame is next. |
| d0v0 somewhere unrelated to PCI | The `of_irq_parse_pci` line was a coincidence and the boot stops for its own reasons. |

### Boot 16: dom0 is not stuck, it is idle

`0` gave what `d` could not, and it is the same on both vCPUs and identical in
all three dumps ten seconds apart:

```
PC: ffff8000816282b4    cpu_do_idle+0x14 -- the instruction after `wfi`
LR: ffff8000816282f8    arch_cpu_idle+0x10
ELR_EL1: ffff800080184668  cpuidle_idle_call, immediately after cpuidle_enter
```

Xen traps the `wfi`, blocks the vCPU and advances the PC past it, so a saved
PC of `cpu_do_idle+0x14` is precisely a vCPU parked in the idle loop. **Both
of dom0's CPUs are running the idle task.** Not spinning, not stuck in a
probe: idle.

The counters agree and are frozen solid. `trap: wfi` is 298 at two seconds,
298 at four, 298 at six. `trap: sysreg access` is 192,898 at all three.
`sched: context switches` is 596 at all three. dom0 has not executed an
instruction in four seconds. Meanwhile CPU5's hypervisor timer count climbs
179 → 347 → 514, which is the console poll at its usual rate: Xen is fine and
the clock is running.

So the thing that stopped the boot is a *task* blocked inside an initcall
while every other task idles, and the reason there is no timer armed is that
an idle `NO_HZ` kernel whose next timer is a long way off does exactly this.

That also disposes of the guesses in the last three sections. dom0 is not
spinning in `vp_reset()`'s `msleep()` loop — that would arm a timer every
millisecond and the virtual timer count would not be stuck at four. It is
blocked with no timeout at all.

One limitation worth recording: `0`'s stack traces say `Failed to convert
stack to physical address`. `show_guest_stack()` translates the guest's stack
pointer through the translation regime installed on the CPU doing the dump,
and that CPU is CPU5 running its idle vCPU, not dom0. The stack of an idle
task would have said `cpu_do_idle <- arch_cpu_idle <- do_idle` and nothing
more anyway, so nothing was lost here — but a non-current vCPU's stack needs
`guest_walk_tables()` rather than the current regime, and that is worth
fixing before it matters.

### What boot 17 changes: ask dom0, because Xen cannot see a task

Xen can say which vCPUs are idle. It cannot say which of dom0's hundred kernel
threads is blocked, or on what. Linux can, and already has the machinery:
`khungtaskd` prints the stack of any task that has been in `TASK_UNINTERRUPTIBLE`
for longer than its timeout. The default is 120 seconds, which is longer than
anyone watches a console, so boot 17 puts
`sysctl.kernel.hung_task_timeout_secs=20` on dom0's command line, and moves the
dumps back out to ten seconds so the third lands after it has spoken.

| What the log shows | What it means |
|---|---|
| `INFO: task ...:N blocked for more than 20 seconds` with a stack | The answer, by name. Resolve it and fix what it waits on. |
| Nothing from khungtaskd, dom0 still idle | The blocked task is interruptible, which `khungtaskd` does not report. `sysctl.kernel.softlockup_panic` will not help either; the next lever is `initcall_debug` plus sysrq over `hvc0`. |
| dom0 wakes up and carries on after twenty seconds | It was waiting on a timeout all along, and the timeout is long. Read what it says next. |

### Boot 17: the wrong question, and the right answer anyway

The experiment was void before it ran. `CONFIG_DETECT_HUNG_TASK is not set` in
this dom0 kernel, so there is no `khungtaskd` and
`sysctl.kernel.hung_task_timeout_secs` had nothing to configure. Checking the
config costs one `grep` and would have saved a boot.

The boot answered a better question anyway, and the answer is a bug in Xen.
Comparing the `p` dumps at twenty seconds and at thirty:

```
Hypervisor timer interrupts  CPU00[ 124]  CPU01[   4]  CPU05[1673]   (20s)
Hypervisor timer interrupts  CPU00[ 124]  CPU01[   4]  CPU05[2502]   (30s)
```

**Xen's own timer has not fired on CPU0 or CPU1 in twenty-eight seconds**,
while CPU5 — the pCPU with no guest on it — takes 829 more. A pCPU takes a
hypervisor timer interrupt only when Xen has a timer queued on it, so Xen has
*nothing queued* for either of the pCPUs carrying dom0. In particular it has no
software fallback virtual timer, and that is the only thing that can wake a
blocked vCPU when its deadline arrives. dom0 is asleep with no way to wake,
and what it is waiting for stops mattering.

### Why nothing was armed

`virt_timer_save()` armed the fallback like this:

```c
if ( (v->arch.virt_timer.ctl & CNTx_CTL_ENABLE) &&
     !(v->arch.virt_timer.ctl & CNTx_CTL_MASK) )
    set_timer(&v->arch.virt_timer.timer, ...);
```

`IMASK` in that register is **Xen's, not the guest's**. `vtimer_interrupt()`
sets it to quiesce a line whose interrupt has already been injected, and the
only thing that clears it is the guest re-arming its timer. So a vCPU that
blocks after an interrupt and before the guest re-arms looks, to that test,
like a vCPU whose timer the guest does not want — and loses its fallback.

On ordinary hardware the guest re-arms within microseconds and the window never
matters. Here it is not a window at all: boot 10 measured that `CNTV_CTL_EL0`
does not read back live on this platform, so once Xen has set `IMASK` the read
may keep saying `IMASK`, indefinitely.

Boot 18 arms on `ENABLE` alone. A spurious virtual timer interrupt costs the
guest one interrupt it dismisses; a missing one costs it the boot. Two counters
say which branch is taken, so if `ENABLE` reads stale as well the next log says
so rather than leaving it to be inferred.

| What the log shows | What it means |
|---|---|
| dom0 boots on | Fixed, and the last four sections were chasing a symptom of this. |
| `software fallback armed` climbing, dom0 still asleep | The fallback is armed and the interrupt still is not reaching dom0: look at `virt_timer_expired()` and the injection, not the arming. |
| `software fallback not armed` climbing | `ENABLE` reads stale too, and Xen cannot learn the guest's timer state from this register at all. Then the guest's virtual timer has to be tracked from the values Xen itself writes. |
| Hypervisor timer counts on CPU0/CPU1 still frozen | Nothing is being queued for them at all, which is a different fault from this one. |

### Boot 18: the fallback works, and uncovers the next storm

The fix took, exactly:

```
Virtual timer software fallback armed      TOTAL[313]  CPU00[114]  CPU01[199]
Virtual timer software fallback not armed  TOTAL[  0]
vtimer: virt expired, injected             66 -> 75 -> 87   (10s, 20s, 30s)
```

`not armed` is zero, so `ENABLE` reads true every time and the register is not
stale in that bit. The fallback is armed and it fires: dom0's virtual timer is
being delivered to a blocked vCPU for the first time. And dom0 is executing
again — `trap: wfi` 300 → 309 → 321, `sched: context switches` 584 → 602 →
626, all of it on CPU1, where d0v1 now runs.

d0v0 does not. `q` says `pause_flags=0` — runnable, not blocked — with
`Inflight irq=27 lr=255` and `Inflight irq=1 lr=255`: two interrupts queued
for it and neither placed in a list register, because the vCPU never runs.
And:

```
#PPIs  CPU00[2943098]  (10s)   CPU00[6277837]  (20s)   CPU00[9609700]  (30s)
Hypervisor timer interrupts  CPU00[116]   Virtual timer interrupts  CPU00[38]
IRQs taken while disabled at the GIC  TOTAL[0]
```

**CPU0 is taking 330,000 PPIs a second that reach no handler and no counter.**
Not the disabled path, which is zero. In `do_IRQ()` every other route either
runs a handler or prints. The only silent exits left are the two early returns
at the tops of the timer handlers, and `htimer_interrupt()`'s is ruled out by
CPU5 taking its 2,449 quite happily.

So it is `vtimer_interrupt()`'s:

```c
if ( unlikely(is_idle_vcpu(current)) )
    return;
```

Which is correct upstream and wrong here. `virt_timer_save()` clears `ENABLE`
when a vCPU is switched out, and on ordinary hardware that drops the line, so
an interrupt arriving with the idle vCPU in front is a leftover worth
ignoring. On this platform the line follows the comparator and nothing else,
so the guest's expired deadline holds it up, the handler returns without
quieting anything, and it comes straight back. CPU0 never reaches its
scheduler — `sched: runs through scheduler` is frozen at 387 — which is
exactly why the vCPU it should be running is runnable and not running.

This is the same fault as boots 7 through 10, in the one place that was still
returning early instead of dealing with it. Boot 19 pushes the deadline out
there too. Nothing is lost: the guest's real deadline is already saved in
`v->arch.virt_timer.cval`, and `virt_timer_restore()` writes it back before
the guest runs again. A counter now sits above the return, so the next log
will not have to infer this from a subtraction.

| What the log shows | What it means |
|---|---|
| dom0 boots on, `no guest on the pCPU` small | Fixed. Both halves of the timer are finally quiet. |
| `no guest on the pCPU` in the millions | The push does not quiet the line when no guest is on the pCPU, though it does when one is. Then the PPI has to be masked at the GIC for as long as the pCPU is idle, and re-enabled in `virt_timer_restore()`. |
| CPU0's PPI count still climbing with every counter flat | Something else on that pCPU, and every early return in an interrupt handler on this platform now needs the same audit. |

### Boot 19: the counter says the deadline is not the lever either

```
Virtual timer interrupts with no guest on the pCPU  TOTAL[10410919]
                                     CPU00[5191921]  CPU01[5219038]   (20s)
```

Counted now rather than subtracted, and the answer is no: pushing the deadline
out does not quiet the line when no guest is on the pCPU. Both pCPUs are in it
this time — 5.2 million each in twenty seconds — and everything about dom0 is
frozen at the ten-second mark: `trap: wfi` 152, `sysreg access` 192,756,
`context switches` 298, all identical at twenty. Both vCPUs are `pause_flags=0`,
runnable, with `Inflight irq=27 lr=255`: an interrupt each, queued, and neither
pCPU ever reaching a scheduler to run the vCPU that would take it.

So the rule this platform has been teaching since boot 7 is now complete.
**Nothing Xen writes to the virtual timer quiets its interrupt line.** Not
`IMASK` (boot 8), not `ENABLE` (boot 8), and not `CNTV_CVAL` when the pCPU is
idle (this one). Boot 10's apparent success with `CNTV_CVAL` was the guest
re-arming its own timer a moment later, not the write.

The same dump names the lever that does work, and it has been in every log
since boot 14:

```
Virtual timer PPI disabled at the GIC    TOTAL[22]
IRQs taken while disabled at the GIC     TOTAL[0]
```

Twenty-two windows in which the PPI was masked at the redistributor, and not
one interrupt got through any of them. **The GIC mask is honoured.** It is the
only thing on this machine that is.

### What boot 20 changes: mask it and leave it masked

`vtimer_interrupt()`'s no-guest path masks PPI 27 at the redistributor and
stops there — no push, no millisecond timer. `virt_timer_restore()` unmasks it,
on the pCPU the guest is about to run on, because that is exactly when the
interrupt becomes wanted again. The mask is a per-CPU flag so the three callers
that reach for it cannot fight.

Nothing is lost by holding the mask: Xen does not use the virtual timer for
itself, so between one guest leaving a pCPU and the next arriving there is
nobody the interrupt could be for.

| What the log shows | What it means |
|---|---|
| `no guest on the pCPU` a few dozen, `PPI re-enabled for a guest` tracking it | Fixed. One interrupt per idle transition, which is what it should always have been. |
| `no guest on the pCPU` still in the millions | The redistributor mask is not honoured after all, and the 22-for-0 above was luck. Then nothing on this machine can gate PPI 27 and the guest's virtual timer has to be emulated in software off `CNTHP_EL2`. |
| dom0 boots on | Read what it says next; item 9 and the `PHYSDEVOP` returns are still waiting. |

### Boot 20: dom0 runs, and one bug is left in the timer

Boot 20 reaches a login prompt. `Fedora Linux 44 (Workstation Edition)`,
`Kernel 6.18.50-xen-dom0 on aarch64 (hvc0)`, cockpit on 9090, a network
address. The machine boots Xen and Xen boots Fedora, which is where this
document started.

Masking PPI 27 while no guest is on the pCPU was the last of the storms. What
is left is narrower: guest timers that sometimes do not fire. `ssh` fails at
random, programs that sleep wake late or not at all, and the console carries
this:

```
(XEN) CPU1: d0v1's virtual timer fired again with IMASK already set (#4096)
(XEN)   CNTV_CTL 0000000000000007 -> 0000000000000007, CNTVCT 000000001d31bf67,
        CNTV_CVAL 7fffffffffffffff, CNTVOFF 0000000018e232c7
```

`CNTV_CVAL 7fffffffffffffff` is the tell, and it is Xen's own doing. The stuck
path was written when the deadline looked like the lever:

```c
current->arch.virt_timer.cval = READ_SYSREG64_EL0(CNTV_CVAL);
WRITE_SYSREG64_EL0(VTIMER_CVAL_PUSHED, CNTV_CVAL);
```

Save the guest's deadline, push the sentinel in. But **that read does not
return what the guest programmed** — it returns Xen's own previous write. So
what gets saved into `v->arch.virt_timer.cval` is the sentinel, and
`virt_timer_restore()` then writes the sentinel into the guest's timer. A vCPU
whose next deadline is twenty-four thousand years out gets no tick until
something else makes it re-arm. Every one of those 4,096 stuck interrupts
destroyed a deadline.

Boot 19 already established that the push achieves nothing. It was not merely
useless; it was the last bug.

### What boot 21 changes

- **The stuck path writes nothing.** Count it, say it rarely, mask the PPI,
  return. The sentinel and the machinery in `virt_timer_save()` that worked
  around it are gone with it.
- **The mask window drops from a millisecond to fifty microseconds.** It is a
  floor under every guest timer — a deadline falling inside it is not
  delivered until it ends — and a millisecond floor is exactly what
  "unreliable timers" feels like from inside a guest arming an hrtimer fifty
  microseconds out. Being wrong in this direction costs one more spurious
  interrupt, which the counters show and which is bounded by how long the
  guest takes to service the one it already has.

If fifty microseconds still swallows short timers, the poll is the wrong shape
and the right one is to unmask the moment the guest retires the interrupt —
`gic_update_one_lr()` sees exactly that — rather than guessing at how long it
will take.

### Boot 21: the deadline is real, the loop is Xen's

Boot 21 runs a shell, and then floods:

```
CPU1: d0v1's virtual timer asserted again while masked (#7708672)
  CNTV_CTL 0000000000000007, CNTVCT 000000006033ae8b,
  CNTV_CVAL 0000000031561166, CNTVOFF 0000000008034a62
```

`CNTV_CVAL` is no longer the sentinel — the last fix worked, and this is a real
deadline the guest programmed. It is also **the same value in every report**,
and `CNTVCT` has passed it by 0x2e32441d ticks: **the deadline is thirty-two
seconds in the past and the guest is not re-arming it.**

The rate is in the log too. Reports are one in 4096, and between two of them
`CNTVCT` advances 425,401 ticks — 17.7 ms, so **4.3 microseconds per
interrupt**. The fifty-microsecond mask is not holding for fifty microseconds;
something is unmasking it almost immediately.

That something is `virt_timer_save()`, and it is the change from boot 18:

```c
if ( v->arch.virt_timer.ctl & CNTx_CTL_ENABLE )
    set_timer(&v->arch.virt_timer.timer, base + ticks_to_ns(cval));
```

A deadline already in the past makes `set_timer()` fire the instant it is
armed. So: the vCPU blocks, `virt_timer_save()` arms a timer for a moment
thirty-two seconds gone, it expires immediately, `virt_timer_expired()` injects
and kicks, the vCPU switches back in, `virt_timer_restore()` unmasks the PPI,
the line — still asserted — fires, and round again. The guest never gets long
enough to reach its own interrupt handler and re-arm, which is why the deadline
never moves.

Boot 18's change was right about `IMASK` and wrong about *when* the fallback is
needed. The fallback exists to wake a vCPU for a deadline that has not yet been
delivered. A deadline in the past has been delivered: the interrupt is already
queued in the guest's vGIC.

### What boot 22 changes

- **`virt_timer_save()` arms only for a deadline still to come.** One already
  passed is already queued and needs no timer. That kills the loop.
- **`gic_update_one_lr()` unmasks the PPI when the guest retires the timer
  interrupt.** This is the signal the fifty-microsecond poll was guessing at:
  the guest has finished with the interrupt, so it has re-armed, so the line is
  wanted again. The poll stays as a backstop, but the prompt path is now the
  real one, and there is no longer a floor under short guest timers.
- **The report is said once.** One spurious assertion per guest tick is the
  expected shape here, so the rate belongs in the counters. Two lines every
  4096 interrupts through a console that costs a virtio descriptor per
  character is a storm's worth of output spent describing a storm.

| What the log shows | What it means |
|---|---|
| dom0 usable, `software fallback deadline already passed` climbing quietly | Fixed. The counter is the loop that used to be, now declined. |
| `asserted again while masked` once, counters quiet | Fixed properly: one spurious assertion per tick and no thrash. |
| dom0 still stalling, `PPI re-enabled for a guest` far below `PPI disabled at the GIC` | The guest is not retiring the interrupt, so the unmask hook never runs and the backstop poll is carrying it. Look at why the vIRQ is not reaching the guest. |

### Boot 22: dom0 is the development machine, and sleeps still stall

Boot 22 is the first that can be worked on from inside. dom0 runs Fedora to a
shell, the root filesystem is live on virtio-blk, and `/proc/interrupts` shows
`virtio1-req.0` at 49,604 through `GICv2m-PCI-MSIX` — **item 9 is closed by
demonstration**: MSIs reach dom0, the v2m frame works, the disk works. The
`PHYSDEVOP ... not implemented` and `of_irq_parse_pci: failed with rc=-22`
lines are still there and still cosmetic; nothing else in `dmesg -l err,warn`
belongs to Xen.

Measured from inside, timers are mostly right and occasionally very wrong:

```
200 x 5ms sleeps:  p50 5.6ms  p90 6.4ms  p99 435ms  max 660ms
2000 x 2ms sleeps: 23 stalls over 20ms, worst 6.5 seconds
```

And the decisive control: **a fifteen-second busy loop has no gap over 20 ms at
all.** The vCPU is scheduled continuously. Nothing is stealing its time. The
stalls happen only when it sleeps, so what is late is the interrupt that should
wake it.

### The hole the masking leaves

`vtimer_interrupt()` masks PPI 27 after every tick, because nothing written to
this timer quiets the line. The mask is lifted by the retire hook or the
fifty-microsecond backstop. In that window the hardware timer cannot deliver
anything — which is fine, unless the guest uses the window:

1. Guest arms a deadline a few microseconds out and blocks.
2. The deadline passes while the PPI is masked, so no interrupt fires and
   nothing is injected.
3. `virt_timer_save()` looks at the deadline, sees it in the past, and declines
   to arm the fallback — on the reasoning from boot 21 that a passed deadline
   has already been delivered.
4. It has not. The vCPU sleeps with nothing left to wake it, until some
   unrelated interrupt happens along.

Boot 21's reasoning was right for the case it was written for and wrong as a
blanket rule. "Already delivered" is not the same as "already passed", and Xen
has an exact marker for the difference: `IMASK`, which `vtimer_interrupt()`
sets on injection and only the guest clears, by re-arming.

So `virt_timer_save()` now distinguishes three cases rather than two — still to
come, arm for it; passed and unmasked, fire at once; passed and masked, decline
— each with a counter. The declining case is boot 21's loop and stays declined.

### Boot 23: timers work

Same measurements, same machine, from inside dom0:

| | boot 22 | boot 23 |
|---|---|---|
| 200 x 5ms sleeps, p99 | 435 ms | 6.9 ms |
| 200 x 5ms sleeps, max | 660 ms | 7.2 ms |
| 2000 x 2ms sleeps, stalls > 20 ms | 23 | 1 |
| worst stall | 6,576 ms | 26.7 ms |
| wall clock for that run | 24.9 s | 5.0 s |

The run taking five seconds instead of twenty-five is the clearest line of the
lot: the stalls *were* the extra twenty seconds. A thirty-second soak at 1 ms
with the other vCPU pinned busy gives 24,964 sleeps and **no stall over 20 ms
at all**, and `dmesg` has nothing from Xen beyond the two cosmetic PCI lines.

So the virtual timer is finished. What it took, in the end, was three separate
facts about this platform, none of which are true anywhere else:

- The interrupt line follows neither `IMASK` nor `ENABLE` nor anything Xen
  writes to `CNTV_CVAL`; only masking the PPI at the redistributor stops it.
- Because Xen must therefore mask the PPI after every tick, a guest arming a
  deadline inside that window gets no hardware interrupt at all, and the
  software fallback is the only thing that can deliver it.
- `IMASK` is still useful, not as a mask but as Xen's own record of what it has
  already injected, which is what tells the fallback whether a passed deadline
  is owed to the guest or already paid.

### Boot 23, overnight: dom0's second vCPU stops

Left running, dom0 wedged one CPU after about eleven minutes:

```
rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
rcu:     1-...0: (20 ticks this GP) idle=ead4/1/0x4000000000000000 softirq=10230/10231
rcu:     (detected by 0, t=600017 jiffies, g=12621, q=1453 ncpus=2)
Sending NMI from CPU 0 to CPUs 1:
```

Read carefully, that says four things. **CPU0 is entirely healthy** — it
detects, it counts `fqs` up to 142,503, it keeps printing. **CPU1 has taken
twenty timer ticks in six hundred seconds**, which is not a slow tick, it is no
tick. **CPU1 does not answer the backtrace IPI**: the "Sending NMI" line is
never followed by a trace. And **RCU believes CPU1 is not idle**
(`dynticks_nesting` is 1), which is what a vCPU looks like if it stopped being
run while in kernel code — the state was true when it was last updated and has
not been updated since.

Those four together are the signature of a vCPU that Xen is not running, not of
a guest spinning. Which of the two reasons it could be is exactly what the log
cannot say:

- **pCPU1 is in an interrupt storm**, so vCPU1 is runnable and starved. Every
  earlier storm looked precisely like this from dom0's side.
- **vCPU1 is blocked and nothing ever wakes it** — the virtual timer PPI masked
  with no unmask, and the software fallback declined.

### Why the console did not say which

Because of a change in the previous section. The stuck report was cut from
"first four, then every 4096" down to "once", on the grounds that one spurious
assertion per tick is the expected shape and the rate belongs in the counters.
That is true, and it is also how a storm eleven minutes into an overnight run
became invisible: the counters are only readable through `xl`, and `xl` does
not exist on this machine.

Trimming output is right; trimming it to a single line is not. A *count* is not
news here, but a *rate* is — four thousand assertions in under a second is not
a tick rate. So `vtimer_note()` now says the first one, then at most one line a
second for as long as the rate stays pathological, and nothing in between, on
both the stuck path and the no-guest path. The clock read it needs is taken
once per 4096 interrupts, not per interrupt.

That makes the next occurrence self-describing:

| What the log shows | What it means |
|---|---|
| `virtual timer asserted ... (#N)` repeating once a second on CPU1 | A storm. vCPU1 is runnable and starved, and the masking has a hole in it. |
| Nothing from Xen, dom0 stalling the same way | No storm. vCPU1 is blocked and nothing wakes it: the fault is in the wake path, not the mask. |

### What is left

- **The Xen tools are not built.** `/dev/xen` has only `xenbus`; there is no
  `xl`, so dom0 cannot read `xl dmesg`, press a debug key, or start a guest.
  Everything in this document was diagnosed by rebooting and reading a serial
  log, which is no longer the cheapest way to work now that dom0 runs.
- **`PHYSDEVOP cmd=25`/`cmd=15: not implemented`**, once per PCI function, and
  the `of_irq_parse_pci: failed with rc=-22` that follows. Both cosmetic: MSI-X
  works regardless, which is what item 9 was about.
- **`show_guest_stack()` cannot walk a non-current vCPU's stack**, because it
  translates through the regime installed on the dumping CPU. It wants
  `guest_walk_tables()`. Nothing has needed it yet.

### The list

In rough order of likelihood — though after boot 12 the timer is settled and
the one that matters is 9:

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
8. **The EL2 physical timer.** *Ruled out by boot 5: `Hypervisor timer IRQ26
   works`.* Xen needs `CNTHP_EL2` and PPI 26 delivered, and nothing in the
   guest exercises it — Linux at EL1 uses PPI 30 and nVHE KVM does not use the
   hyp timer for the host — so the one workload Apple's nested virtualisation
   obviously has to support never programs the register Xen depends on. It
   works anyway. What that line covers is delivery to a CPU that is running
   Xen; delivery to a CPU that is running a guest is item 11.
9. **dom0 has no disk.** *Closed by boot 22: the root filesystem is on
   virtio-blk and `/proc/interrupts` shows `virtio1-req.0` taking MSI-X
   through the v2m frame.* MSIs (§4). Check with `xl dmesg` for the
   `GICv2m: dom0: frame 0x1fff0000, SPIs 128-255` line, then in dom0 for
   `GICv2m: range[mem 0x1fff0000-0x1fff0fff], SPI[128:255]` and for
   `virtio1-req.0` appearing in `/proc/interrupts`.
10. **dom0's `hvc0` is the wrong thing.** If `virtio_console` is still built
   into the dom0 kernel it will race Xen's PV console for the `hvc0` name and
   fight Xen for the device. §2, and §6's kernel prerequisites.
11. **No physical interrupt reaches virtual EL2 while a guest is running.**
   *Ruled out by boot 6: CPU0 answered the state dump IPI from inside dom0.*
   Xen runs guests with `HCR_EL2.IMO` set, so every physical IRQ is supposed
   to be taken at EL2 rather than by the guest. Under nested virtualisation
   that is macOS's job to honour, on a path nothing else needs: KVM's guests
   are at EL1 under an EL2 that is *not* itself a guest. Everything boot 5
   proved about interrupts was proved on a CPU that was running Xen at the
   time; boot 6 proved the other half.
12. **The console's transmit ring stops draining.** One character per
   descriptor, 64 descriptors, and until boot 6 an unbounded spin in
   `__serial_putc()` when they are all in flight. Any CPU that printed while
   the host was not consuming would stop there for good, holding the port
   lock, with dom0's `earlycon` hypercall inside it. Item 5 is the same
   failure seen from further away. Boot 6 announces it instead: `vtcon: device
   stopped draining the transmit ring`, and did not: the ring carried ~250
   lines of dump after dom0 went quiet. *Ruled out for the window up to the
   first dump*; the driver's `tx_ready()` bound stays regardless, because an
   unbounded spin there is a bug whether or not it has fired yet.
13. **Nested exits are slow enough to look like a hang.** *Subsumed by 14:
   real, but a hundred times too small.* dom0 is executing at EL1 and making
   forward progress, in a `kfence_init()` loop that costs about two thousand
   trapped `ID_AA64ISAR0_EL1` reads. Boot 7 counted 176,103 sysreg traps in
   fifty seconds, which is a genuine tax and nowhere near enough to explain
   what dom0 is not getting done. `kfence.sample_interval=0` on dom0's
   command line still removes this particular loop, if it is ever worth
   removing.
14. **PPI 27 asserts continuously and CPU0 does nothing else.** 15,475,882
   virtual timer interrupts in fifty seconds in boot 7, 9,373,008 in thirty
   in boot 8 — the same 310,000 a second — all on the pCPU running dom0, with
   `Maintenance interrupts` at zero and every other pCPU idle. Xen masks the
   guest's virtual timer in `vtimer_interrupt()`, the write sticks, and the
   line does not follow; clearing `ENABLE` as well changed nothing. This is
   *Fixed in boot 10 by pushing the deadline out.* Two stuck interrupts in a
   whole boot, and dom0 runs at speed. The line follows the comparator and
   nothing else, and `CNTV_CTL` reads back stale — which is why `IMASK` and
   `ENABLE` appeared to persist across nine million interrupts without
   helping.
15. **dom0 takes Xen's console.** *Two halves, both now addressed.* Linux's
   DT PCI host driver assigns BARs rather than claiming them, so `00:05.0`
   got a new BAR0 and Xen's mapping stopped pointing at the device;
   `linux,pci-probe-only` in the tree Xen builds for dom0 fixed that in boot
   12. Then `virtio_pci_probe()` reset the device where it stood. Boot 13
   unmapped its configuration space, which was the right page and the wrong
   default — dom0 was trapped rather than told the slot was empty — and boot
   14 puts an explicit empty-slot handler over it.
