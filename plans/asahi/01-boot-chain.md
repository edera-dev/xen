# 01 — Boot chain: getting Xen launched on Apple Silicon

Status: design. How Xen becomes the thing that runs at EL2, and how it then
launches Asahi Linux as dom0. This is the *least* risky part of the port —
Apple's own bootloader ecosystem hands us an almost-ideal entry point.

## 1. The Apple Silicon boot chain (confirmed)

```
SecureROM (mask ROM)
  → LLB / iBoot1        (NOR flash; APFS-aware; reads LocalPolicy)
  → iBoot2              (inside macOS partition; the last Apple-signed stage)
  → m1n1 stage 1        (Asahi; signed w/ machine key, immutable "shim")
  → m1n1 stage 2        (<ESP>/m1n1/boot.bin on writable FAT32 ESP)
  → [DTB] + U-Boot      (u-boot = m1n1 stage-2's default payload)
  → GRUB (EFI)          (BOOTAA64.EFI)
  → Linux (Asahi)
```

Key properties we exploit:
- **iBoot2** is the last stage Apple's security policy signs; Asahi installs
  **m1n1 stage 1** as an Apple "fuOS" custom kernelcache
  (`kmutil configure-boot -c m1n1-stage1.bin --raw --entry-point 2048
  --lowest-virtual-address 0`). Stage 1 is immutable and just chainloads
  `<ESP>/m1n1/boot.bin`.
- **m1n1 stage 2** is literally `cat m1n1.bin <DTBs> <gzipped u-boot> >
  boot.bin`. It initialises hardware, **selects and patches the DTB** (fills
  memory size, framebuffer base/format, RNG seed, `cpu-release-addr`
  spin-table info, and the `asahi,efi-system-partition` PARTUUID into
  `/chosen`), then boots its payload.
- The whole chain runs and hands off **at EL2, MMU off** (deliberately, so
  guest Linux can use KVM). There is **no EL3** on M1/M2.

## 2. The handoff contract m1n1 gives its payload (confirmed)

m1n1 boots a **standard arm64 Linux `Image` + DTB** ("a trivial subset of the
XNU boot protocol"):
- Entry at image offset **0x800, MMU off, caches off**.
- In `kboot_boot()` it sets `next_stage.args[0] = dt` and calls
  `entry(dt, 0, 0, 0, 0)` → **the standard arm64 protocol: DTB physical address
  in `x0`, x1–x3 = 0**.
- Payload is entered at **EL2** (m1n1 does *not* drop to EL1 — plain indirect
  call, payload inherits EL2). MMU/caches off. `CNTFRQ` programmed.

This is **exactly** what Xen's arm64 entry expects
(`xen/arch/arm/arm64/head.S:84-91`: "MMU off, D-cache off, x0 = physical FDT";
`:235` saves `x21 := x0`; `check_cpu_mode` requires EL2). Xen already presents a
Linux `Image` header (`head.S:93-115`, magic `ARM\x64`, page-size flag derived
from `PAGE_SHIFT`). So **m1n1 can boot Xen as if it were a Linux kernel, with no
changes to m1n1's protocol.**

⚠️ Caveat that dominates the CPU work (see doc 06): the payload inherits
**`HCR_EL2.E2H = 1` (VHE)**, which is RES1 on M1/M2. Xen's arm64 EL2 code
assumes E2H=0. The boot handoff is trivial; making Xen *execute* correctly at
EL2 under forced VHE is the hard part, covered in doc 06.

## 3. Two integration options for where Xen sits

### Option A (recommended for bring-up): Xen as the m1n1 stage-2 payload
Replace u-boot with Xen in the concatenated payload:
```
cat m1n1.bin <DTBs> <xen.gz> > boot.bin          # conceptually
```
But Xen alone is not enough — Xen needs its **boot modules** (dom0 kernel,
dom0 ramdisk, dom0 DTB) described in the FDT via `/chosen` sub-nodes
(`multiboot,kernel` / `xen,linux-zimage`, `multiboot,ramdisk`,
`multiboot,device-tree`; see `xen/common/device-tree/bootfdt.c:10-20`). m1n1's
concatenation model boots a single Image+DTB, so we need one of:
- **A1 — a small FDT + module-packing shim:** produce a combined blob where the
  FDT already contains `multiboot,*` nodes whose `reg` point at the
  Image/initrd/dom0.dtb that we also load into RAM. This is how Xen is booted
  from u-boot elsewhere; adapt it to m1n1's single-blob handoff (e.g. an
  Image-wrapped "bootwrapper" that stages the modules and jumps to Xen with the
  augmented FDT in x0). Lowest-dependency path; good for the earliest
  "does Xen print anything" milestone.
- **A2 — patch m1n1 stage 2** to understand a small manifest (kernel + N
  modules + FDT) and place them in RAM + emit `multiboot,*` nodes. Cleaner
  long-term; requires building a custom m1n1.

### Option B (recommended end-state): keep u-boot/GRUB, boot Xen via EFI/DT
Asahi's u-boot provides **UEFI boot services + an EFI boot manager** and
**passes the FDT to its EFI payload automatically**; it can load "any arm64 EFI
binary," and it already forwards a (lightly modified) DT. Two sub-options:
- **B1 — Xen EFI stub:** build Xen with `CONFIG_ARM_EFI`
  (`xen/arch/arm/Kconfig:110`, entry `efi_xen_start` `head.S:503`), and have
  u-boot/GRUB load `xen.efi` plus a Xen config that names the dom0 kernel,
  ramdisk and DTB (the standard `xen.efi` + `xen.cfg` mechanism). This gives a
  familiar, updatable install flow (files on the ESP), matching how Asahi users
  already boot.
- **B2 — GRUB multiboot2:** GRUB loads Xen and modules via multiboot2, the way
  x86 Xen is usually booted. arm64 Xen's DT/module discovery is FDT-based, so
  B1 (EFI + config) is the more natural arm64 fit.

**Plan:** start with **A1** (fewest moving parts to first console output), then
move to **B1** for a maintainable, ESP-file-based install that Asahi users can
manage like any other kernel. Both are additive; A1 is a debugging aid, B1 is
the product.

## 4. What Xen must consume from the m1n1/Asahi DTB

m1n1 (and, in Option B, u-boot) hand over an FDT derived from Apple's ADT with
loader-filled dynamic properties. Xen must read and preserve:
- `/memory` (size filled by loader; base at `0x8_00000000`).
- `/reserved-memory` — **coprocessor firmware carveouts** (filled by loader).
  Xen must keep these out of its heap and out of the dom0 allocator, and keep
  their mappings intact (doc 05 §4, doc 08).
- `/cpus/cpu@N` with `enable-method = "spin-table"` and loader-filled
  `cpu-release-addr` (doc 06 §SMP).
- `/chosen`: `stdout-path` (the `apple,s5l-uart` console — doc 07),
  `framebuffer` (locked-DART boot framebuffer, doc 05/07), `kaslr-seed`,
  `asahi,efi-system-partition`.
- The AIC node (`apple,aic`/`aic2`) and the `arm,armv8-timer` node whose
  interrupts point at `&aic` FIQ lines (doc 03/04).

Xen then **rewrites** a derived DTB for dom0 (doc 08): synthesizing a GICv3
node, translating device interrupts AIC→GIC (Design 1), inserting a PSCI node
(Xen's vPSCI, doc 06), the `multiboot`-free normal dom0 view, and re-pointing
`stdout-path` at dom0's console.

## 5. Console during bring-up

Before Xen can do anything useful it must print. The physical UART is
`apple,s5l-uart` (doc 07). Add an `early_printk` backend
(`xen/arch/arm/arm64/debug-s5l.inc`, mirroring the existing `debug-*.inc`) so
`PRINT_ID`/early boot messages work with the MMU off. m1n1 leaves the UART
initialised, so early prints should work immediately — this is the primary
debugging tool for the whole port (doc 09). A framebuffer console is a
nice-to-have later (Stabellini explicitly listed "UART + framebuffer for the
Xen console" as a needed piece).

## 6. Recovery / bricking safety

The Asahi model is friendly to experimentation:
- **m1n1 stage 1 is immutable** and machine-key-signed; a broken stage-2 /
  payload does **not** brick the machine — you recover by re-imaging the ESP
  from macOS recovery (or via the m1n1 USB proxy). Apple's "1TR"
  (one-true-recoveryOS) is always available.
- During development, **m1n1's USB proxy mode** lets a host push the payload
  (Xen + modules) over USB/UART without touching the ESP — ideal for fast
  iterate-and-crash cycles and for capturing early UART over the same cable.
- Recommend developing against the **m1n1 proxy + USB** flow first, and only
  writing `boot.bin` to the ESP once Xen reliably reaches dom0.

## 7. Effort and risk

| Task | Difficulty |
|---|---|
| Xen accepts m1n1 EL2/MMU-off/x0=FDT handoff | TRIVIAL (already matches) |
| s5l early_printk backend | LOW |
| A1 module-packing shim → first Xen console | LOW–MODERATE |
| B1 `xen.efi` + config install flow | MODERATE |
| Consuming/preserving loader DT (carveouts, spin-table, fb) | MODERATE |
| **Executing correctly under forced E2H=1** | **HARD (doc 06)** |

The boot *handoff* is essentially free. The risk in this area is entirely
downstream: once entered, Xen must survive forced VHE (doc 06) and produce
console output. Target **M2** (best-understood bare-metal EL2, hardware nested
virt) or M1; avoid M4 (Apple EL2 extensions reportedly disabled in its boot
object).
