# 10 — Bring-up runbook: booting Xen on an M2 via m1n1

Status: **operational**. This is the how-to, not a design doc: the physical
cabling, the m1n1 install, the build config, the push loop, and what each
milestone's console output should look like. Everything below marked
"(verified)" was checked against the actual sources/binaries in this workspace.

The target for this runbook is an **M2 MacBook Air 13" (`t8112-j413`)** driven
from an **arm64 Fedora VM on an Apple Silicon macOS host**, with the target
attached to the host by a USB-C **vdm** cable.

---

## 1. Topology

```
  ┌───────────────────────────┐          ┌────────────────────────────┐
  │ macOS host (Apple Si)     │          │ TARGET: M2 MacBook Air     │
  │                           │          │         (t8112-j413)       │
  │  macvdmtool ─ USB-C PD ───┼──────────┼─→ debug UART, DFU port     │
  │   /dev/cu.kis-100000-ch-0 │  vdm     │   debugusb: USB channel    │
  │   or /dev/cu.debug-console│  cable   │   serial:   1 500 000 baud │
  │           │               │          │   m1n1 stage 1 → stage 2   │
  │   serial-bridge-host.py   │          │        (proxy mode)        │
  │           │  (pyserial)   │          └────────────────────────────┘
  │           │               │
  │  ┌────────┴────────────┐  │
  │  │ arm64 Fedora VM     │  │   192.168.64.2 → host 192.168.64.1
  │  │  ~/src/xen          │  │   (verified: Virtualization.framework
  │  │  ~/src/m1n1         │  │    shared network)
  │  │  ~/src/linux-asahi  │  │
  │  │  ~/src/asahi-bringup│  │
  │  └─────────────────────┘  │
  └───────────────────────────┘
```

The vdm UART is the *only* channel that works from the first instruction, so
it carries both m1n1's proxy protocol and Xen's `early_printk` output. m1n1's
USB gadget (`/dev/cu.usbmodemP_01`) is faster for big uploads but only exists
after m1n1 has brought USB up, and Xen's early printk goes straight to the
SoC UART regardless — so use the UART for everything during bring-up.

---

## 2. One-time host setup (macOS)

1. **macvdmtool** — switches the target's USB-C port into a debug mode:
   ```sh
   git clone https://github.com/AsahiLinux/macvdmtool && cd macvdmtool && make
   sudo ./macvdmtool reboot debugusb   # preferred; see below
   ls -l /dev/cu.kis-*                 # -> /dev/cu.kis-100000-ch-0
   ```

   **Cable in the DFU port on both ends**, or nothing works:
   - MacBook Air / 13" MacBook Pro: the **rear** port (hinge side)
   - 14"/16" MacBook Pro: the port **next to MagSafe**
   - Mac mini: the port nearest the power plug

   There are two debug modes, and they are *not* equally robust:

   | | `serial` | `debugusb` |
   |---|---|---|
   | Host device | `/dev/cu.debug-console` @1500000 | `/dev/cu.kis-100000-ch-0` |
   | Local-end mux needed | **yes** (`DVEn` to the local Ace2) | no — VDM to the target only |
   | Cable | USB 3 SuperSpeed or Thunderbolt (needs SBU) | USB 2.0 is fine |
   | Speed | 1.5 Mbaud (~3 s per push) | USB — much faster |
   | Baud handling | non-standard rate, painful on macOS | irrelevant |

   **Prefer `debugusb`.** `serial` mode has an extra failure mode with no
   counterpart in `debugusb`: after the target-side VDM succeeds, `DoSerial()`
   (`main.cpp:235`) issues a `DVEn` host-interface command to the *local*
   machine's Ace2 to mux its own SBU pins to the UART, and that command is
   rejected on some host/macOS/cable combinations —

   ```
   Putting target into serial mode... OK
   Putting local end into serial mode... Failed.
   ```

   Everything before that line travels over CC and works regardless, which is
   why the failure looks so late. `DoDebugUSB()` sends only the VDM and issues
   no local command, so it cannot fail this way. m1n1 supports both
   (`M1N1DEVICE=/dev/cu.kis-100000-ch-0`).

   If you do want `serial` working, in order of likelihood: use a genuine USB 3
   / Thunderbolt cable (charge-only cables lack SBU and are the classic
   culprit); confirm both ends are in the DFU port; retry `sudo ./macvdmtool
   serial` while the target is already in serial mode; check macOS ≥ 14
   (`AppleSerialShim` blocked the console device on 12/13). `macvdmtool`
   discards the Ace2's error nibble, so apply
   `asahi-bringup/macvdmtool-dven-diagnostics.patch` to see whether the IOKit
   call failed (driver/entitlement problem) or the chip rejected the command
   (state/port/cable problem).

   `sudo ./macvdmtool reboot debugusb` reboots the target and re-arms the debug
   mode — this is the one command you run every iteration.

   **The two modes may not deliver the same hardware to the host, and this
   decides which early-printk backend Xen needs.** m1n1 writes its console to
   *both* the s5l UART and the dockchannel FIFO (`src/startup.c:194-200`, "Use
   Dockchannel as a secondary UART for now"), and while the proxy is running,
   m1n1's console output is tunneled inside the proxy protocol as `REQ_EVENT`
   packets (`src/uartproxy.c:59,303`) rather than as raw UART bytes. So
   **seeing m1n1's log proves nothing about which UART the host is reading** —
   only after `kboot_boot()` does `linux.py` call `iface.ttymode()` and switch
   to raw passthrough. Xen writes exactly one UART, so it has to be the right
   one.

   The symptom of getting this wrong is total silence from Xen after a
   perfectly healthy m1n1 handoff (`Vectoring to next stage...` and nothing
   more), which looks identical to Xen crashing on its first instruction.

   Resolve it with one command against a running m1n1:

   ```sh
   M1N1DEVICE=$HOME/m1n1-tty:1500000 ~/src/asahi-bringup/probe-console.py
   ```

   It prints `p.iodev_whoami()` — the iodev the proxy is actually on — plus the
   ADT addresses of both candidates, and tells you which backend to select:

   | `iodev_whoami()` | Xen backend | Base address |
   |---|---|---|
   | `IODEV.UART` | `debug-s5l.inc` | `0x235200000` |
   | `IODEV.DOCKCHANNEL_UART` | `debug-dockchannel.inc` | ADT `dockchannel-uart` reg[0] **+ 0x4000** |

   Switch with `set-console.sh`, which applies the `0x4000` data-window offset
   for you so the ADT value can be pasted verbatim:

   ```sh
   ~/src/asahi-bringup/set-console.sh dockchannel 0x<reg0>   # debugusb
   ~/src/asahi-bringup/set-console.sh s5l                    # serial
   ```

   **Record the reg[0] value here once probed** — it is a property of the SoC,
   not of a session, and it is otherwise held *only* in `xen/.config`:

   | machine | ADT `dockchannel-uart` reg[0] | data window (`+ 0x4000`) |
   |---|---|---|
   | t8112-j413 (M2 Air 13") | `0x23d128000` | `0x23d12c000` |

   A single `make distclean` -- or any detour through `arm64_defconfig` for a
   QEMU run -- regenerates `.config` from `apple_defconfig`, which selects the
   **s5l** backend. Xen then boots correctly and writes every byte into a port
   nobody is reading, which is indistinguishable from Xen dying before its
   first print. `set-console.sh` now records the choice in
   `asahi-bringup/out/console.conf` and `mkpayload.sh` re-applies it on every
   build, so the route survives; the table above is the backstop for when the
   whole working directory is gone.

   ### Why the dockchannel needs its own backend

   It is not a UART at all: no baud rate, no line control, just a byte FIFO
   with a free-space count (`DATA_TX8`, `DATA_TX_FREE`). `debug-dockchannel.inc`
   mirrors m1n1's `src/dockchannel_uart.c`, cross-checked against the Asahi
   kernel's `drivers/soc/apple/dockchannel.c`.

   One trap worth recording: m1n1 folds the data window into its constants
   (`0x4004`/`0x4014` off the controller base), and Xen **cannot** copy that,
   because `0x4014` exceeds the 16380-byte range of the 32-bit scaled
   immediate, and neither caller of `early_uart_transmit` has a spare register
   to fold the addition into — `asm_puts` clobbers only x0-x1, and `asm_putn`
   already uses x1 (hex table), x2 (char) and x3 (counter). So Xen takes the
   data window as its base and uses `0x4`/`0x14`, matching how the kernel
   models it as a separate `data` reg resource.

   There is also **no `dockchannel-uart` node in any Apple device tree** — it
   exists only in the ADT — so the address cannot be discovered from the FDT
   and has to be compiled in, exactly like the s5l base.

   Whichever route is in use, neither driver reprograms the line: the early
   backend deliberately does not select `CONFIG_EARLY_UART_INIT` (so the
   `early_uart_init` call at `head.S:446` is compiled out) and
   `s5l_uart_init_preirq()` is intentionally empty. Whatever iBoot/m1n1 set is
   what the port controller expects on the other side.

---

## 3. One-time target setup (M2 MacBook Air)

1. Run the **Asahi installer** and pick *"UEFI environment only (m1n1 +
   U-Boot + ESP)"* — that is enough for hypervisor work; a full Asahi rootfs
   is only needed later for dom0 (doc 08).
   ```sh
   curl https://alx.sh | sh
   ```
   This installs the machine-key-signed **m1n1 stage 1** as a "fuOS" custom
   kernelcache via `kmutil configure-boot`. Stage 1 is immutable and cannot be
   bricked by anything we do (doc 01 §6); worst case you re-image the ESP from
   1TR.

2. **Make every boot land in the m1n1 proxy** by replacing the stage-2 payload
   with a bare m1n1 (no payload appended ⇒ it waits on the UART/USB):
   ```sh
   # in the VM
   scp ~/src/m1n1/build/m1n1.bin <target>:/tmp/          # or via USB stick
   # on the target, with the ESP mounted (asahi installer mounts it):
   sudo cp /tmp/m1n1.bin <ESP>/m1n1/boot.bin
   ```
   Keep the original `boot.bin` (m1n1 + DTBs + u-boot) around — you'll want it
   back for the `xen.efi` install flow (doc 01 §3 Option B1).

3. Set the m1n1/Asahi volume as the **startup disk** so `macvdmtool reboot`
   comes straight back to the proxy without touching the boot picker.

---

## 4. VM-side prerequisites (all verified present)

| Thing | Where | State |
|---|---|---|
| Xen tree | `~/src/xen` (branch `asahi`) | builds clean, `xen` = 1.2 MB |
| m1n1 | `~/src/m1n1` | **builds** (`build/m1n1.bin`, 1.1 MB) |
| Asahi dts sources | `~/src/linux-asahi` (sparse: dts + dt-bindings + scripts/dtc) | 26 MB |
| Patched `dtc` | `~/src/asahi-bringup/dtc-asahi` | built from `scripts/dtc` |
| `t8112-j413.dtb` | `~/src/asahi-bringup/` | 71 897 bytes |
| Bring-up scripts | `~/src/asahi-bringup/*.sh` | staging + push verified |
| `pyserial`, `construct`, `libfdt`, `dtc`, `bison`, `flex` | dnf | installed |
| `rustup target aarch64-unknown-none-softfloat` | needed by m1n1's Rust GPU lib | installed |

Notes:
- Fedora's stock `dtc` **cannot** compile the Asahi tree — the AGX nodes use
  float literals (`apple,avg-power-ki-only = <9.375>`) that only the kernel's
  in-tree `dtc` accepts. `mkdtc.sh` builds that one; `mkdtb.sh` uses it.
- m1n1's build needs the bare-metal Rust target even for a plain
  `make` — its GPU support is a Rust static lib.

### The Xen config

`xen/arch/arm/configs/apple_defconfig` (new) is the bring-up config:

```
CONFIG_APPLE=y                              # platforms/apple.c, selects GICV3
CONFIG_APPLE_AIC=y                          # physical AIC v1/v2/v3 driver
CONFIG_HAS_S5L_UART=y                       # runtime console driver
CONFIG_DEBUG=y                              # EARLY_PRINTK is behind DEBUG||EXPERT
CONFIG_EARLY_UART_CHOICE_S5L=y
CONFIG_EARLY_UART_BASE_ADDRESS=0x235200000  # serial@235200000 on t8103 and t8112
```

`make -C xen apple_defconfig` applies it. **`CONFIG_DEBUG=y` is not optional**:
`EARLY_PRINTK` sits inside `if DEBUG || EXPERT` in `xen/Kconfig.debug:16`, and
without early printk you get a black screen with no way to tell how far you got.

The UART base is not discovered — early printk is a compile-time constant, and
`0x235200000` is correct for both M1 (t8103) and M2 (t8112) (verified against
`serial@235200000` in the generated DTB).

---

## 5. The handoff contract (verified against m1n1's source)

| Requirement | m1n1 | Xen | |
|---|---|---|---|
| Payload format | Linux `Image` | `ARM\x64` magic at file offset 0x38 | ✅ |
| Entry | `next_stage.entry(dt,0,0,0,0)`, `src/kboot.c:2908` | `head.S` offset 0/4 → `real_start` | ✅ |
| `x0` | DTB physical address | `x21 := x0`, `head.S:235` | ✅ |
| Exception level | EL2 (plain indirect call — payload inherits) | `check_cpu_mode` requires EL2 | ✅ |
| MMU/caches | off | required off | ✅ |
| Page-size flag | ignored | header flags `0x0a` ⇒ 4 KB, PHYS_BASE | ✅ |
| Command line | `-b` → `/chosen/bootargs` | read via `bootinfo-fdt.c:537` fallback | ✅ |
| `stdout-path` | `"serial0"` in the DTB | `uart-init.c:55` uses it when `dtuart=` is empty | ✅ |
| `enable-method` | `"spin-table"` + `cpu-release-addr` | `arm64/smpboot.c:86` handles spin-table | ✅ |
| AIC compatible | `"apple,t8112-aic","apple,aic2"` | `aic_dt_match` has `apple,aic2` | ✅ |

`m1n1/proxyclient/tools/linux.py` takes `<payload> <dtb> [initramfs]`. The DTB
is **mandatory and must match the machine** — `kboot_prepare_dt()` does
per-SoC fixups keyed off the root compatible (`src/kboot.c:1976-2032`) and
fills in memory size, framebuffer, RNG seed and `cpu-release-addr`. The
payload must be `.gz`/`.xz` unless you pass `--compression none`; we gzip
(422 KB, ~3 s at 1.5 Mbaud, decompressed on-target by `p.gzdec`).

---

## 6. The iteration loop

```sh
# terminal 1, on the macOS host — the bridge (leave running)
./serial-bridge-host.py

# terminal 2, in the VM — the bridge's local end (leave running)
~/src/asahi-bringup/bridge-vm.sh          # creates ~/m1n1-tty

# terminal 3, in the VM — the actual loop
cd ~/src/asahi-bringup
./mkpayload.sh                            # build Xen + stage out/
ssh host 'sudo ./macvdmtool reboot serial' # target reboots into m1n1 proxy
./push-xen.sh                             # upload + boot + tty passthrough
```

`push-xen.sh` passes:

```
console=dtuart dtuart=serial0 sync_console loglvl=all guest_loglvl=all
```

`sync_console` matters — without it a crash eats the last lines of the log.

After `p.kboot_boot()`, `linux.py` calls `iface.ttymode()`, so Xen's output
appears in the same terminal. To capture it, `M1N1DEVICE` output can be teed;
otherwise run `screen /dev/cu.debug-console 1500000` on the host once the push
has finished handing off.

Crash triage: `out/xen-syms` is staged next to the payload, so
`aarch64-linux-gnu-addr2line -e out/xen-syms <PC>` (or `gdb -ex 'info line
*0x...'`) resolves any address Xen prints.

---

## 7. Milestones and their expected output

### M0 — the loop works (no Xen involved)

```sh
M1N1DEVICE=~/m1n1-tty:1500000 python3 ~/src/m1n1/proxyclient/tools/shell.py
```
You should land in a Python REPL with `p`, `u`, `iface` bound. Try
`p.iodev_whoami()` and `u.adt["chosen"]`. If this doesn't work, nothing else
will — debug the cable/bridge here, not with Xen in the picture.

### M1 — first light: Xen executes and prints ← **reached, 2026-08-22**

Push Xen. Expect exactly:

```
- UART enabled -
- Boot CPU booting -
- Current EL 0000000000000008 -
- Initialize CPU -
- Turning on paging -
```

and then **silence**. Getting those five lines is the M1 pass criterion: it
proves the cable, the proxy, the Image handoff, EL2 entry and the early-printk
backend all work. Confirmed on an M2 MacBook Air (t8112-j413) over the
dockchannel console, with `- Current EL 0000000000000008 -` verifying EL2 entry.

The silence after `- Turning on paging -` was the forced-VHE blocker, now fixed
(see M2); a tree with that fix prints `- Forced VHE (HCR_EL2.E2H is RES1) -`
between `- Initialize CPU -` and `- Turning on paging -`, which is also the
quickest confirmation that the probe fired.

**Why it stops there.** `cpu_init` (`arm64/head.S:380-391`) programs `TCR_EL2`
in the **non-VHE** layout, then `enable_mmu` (`arm64/mmu/head.S:296`) sets
`SCTLR_EL2.M`. On Apple cores `HCR_EL2.E2H` is **RES1**, so `TCR_EL2` has the
*`TCR_EL1`* layout instead:

| Xen writes | non-VHE meaning | what E2H=1 actually reads it as |
|---|---|---|
| `PARange` in bits `[18:16]` | `PS` (output address size) | `T1SZ[21:16]` — garbage |
| bit 23 (`TCR_RES1`) | RES1 | `EPD1=1` — harmless |
| bit 31 (`TCR_RES1`) | RES1 | `TG1=0b10` — harmless |
| *nothing* in `[34:32]` | — | **`IPS = 0` ⇒ 32-bit output addresses** |

Apple RAM starts at `0x8_00000000` (verified: `memory@800000000` in the DTB),
so with a 32-bit output size the very first table walk — the `TTBR0_EL2` base
itself — takes an address-size fault, and the core dies at the instruction
after `msr SCTLR_EL2`. There is no way to print from there.

If you see fewer lines than the five above, that's a different bug:

| Last line seen | Meaning |
|---|---|
| nothing at all, after a clean `Vectoring to next stage...` | **wrong console route** — run `probe-console.py` (§2); in `debugusb` mode the host may be reading the dockchannel, not the s5l UART |
| nothing at all, no m1n1 handoff message | dead cable, or the push never completed |
| `- UART enabled -` only | Xen faulted before `real_start`'s first print — check the load address |
| `- Current EL 0000000000000004 -` then a bootloader complaint | entered at EL1: m1n1's payload path dropped EL (should not happen) |
| `- Turning on paging -` then reboot rather than hang | WDT bit; harmless, same cause |

### M2 — reach C code — **reached, 2026-08-22**

Reached and then passed: on hardware Xen now initialises the timer over AIC
FIQs (`phys=18 hyp=16 virt=19`, 24 MHz), XSM, the credit2 scheduler, brings up
the other three E-cores through the spin-table path, and sets up stage 2
(`36-bit IPA with 36-bit PA and 8-bit VMID, 3 levels`) before reaching dom0
construction.

Xen now boots to `create_dom0` on hardware and panics on the missing dom0
module, which is the correct finish for this milestone.  Two fixes were needed
beyond the register layout, and the second one cost nine hardware iterations,
so it is worth stating plainly what it was and what misled the search.

**The blocker was descriptor `AP[1]`.**  `mmu/pt.c` set it with the comment
"for EL2 stage-1 page table, up (aka AP[1]) is RES1 as the translation regime
applies to only one exception level", and `arm64/mmu/head.S` hard-coded the
same bit into `PT_MEM_L3` and friends (`0xf7f`).  Under `E2H=1` the regime is
EL2&0, which *does* have an EL0, so `AP[1]=1` marks the page EL0-accessible --
and such a page cannot be used for privileged execution on Apple cores.  The
instruction fetch immediately after `SCTLR_EL2.M` is set therefore does not
fault, it simply cannot proceed: the core wedges with **no exception at all**,
which is why a fault catcher on `VBAR_EL2` stayed silent.

Both sites now mask it at runtime (`el2_is_vhe()` in `pt.c`, an `x22` mask in
`create_page_tables`), because `AP[1]` genuinely is RES1 when `E2H=0` and
clearing it unconditionally would be wrong on every other platform.

What made this hard, recorded so the next person does not repeat it:

- **A silent wedge with no exception looks like every other failure.**  A
  correct-looking software page-table walk plus a dead MMU is the signature of
  a *permission* problem, not a translation one.  Suspect the bits that change
  meaning between regimes before suspecting the table contents.
- **Bisect from the configuration that works, not the one that fails.**  The
  breakthrough came from enabling the MMU on the *bootloader's* tables and TCR
  (still in RAM, since m1n1 runs with the MMU on at EL2 with E2H=1) and then
  mutating that towards Xen's one field at a time.  Every field left at the
  working value is then a control.
- **Watch for confounds in the probe harness itself.**  Several probes ran as
  *second* MMU enables while the only passing one was a first; running the
  identical baseline twice (`-A1-`/`-A2-`) proved re-enabling was fine and the
  results were valid, but that had to be checked rather than assumed.
- **Read the probe's own attribute bits.**  The probe that finally worked used
  `AttrIndx=0`, which in *Xen's* MAIR is Device memory -- an accident that
  briefly suggested a cache problem.  Adding the Xen-isms back one bit at a
  time (`-ATTR-` passed, `-AP-` did not) is what isolated `AP[1]`.

Eliminated with hardware evidence along the way, none of which was the cause:
the VHE register layout, table contents on both the runtime and identity
chains, cache/coherency/shareability, memory attributes and `MAIR`, `IPS`
(36-bit works, despite m1n1 hardcoding 42-bit), `EPD1`, `TG1`, the TTBR1 walk
attributes, `nG`, the number of walk levels, and the page granule -- hardware
reports **and demonstrates** 4K support at both stage 1 and stage 2.

### Forced-VHE boot state (doc 06 §1.2 item 1)

`cpu_init` (`arm64/head.S`) now probes `HCR_EL2.E2H` and programs the matching
register layout:

1. It first *tries to clear* E2H. Where the bit is writable this keeps Xen on
   its native, well-tested non-VHE path; where it is RES1 (Apple Silicon) or
   RAO/WI (older Apple "Fruity" cores) the write is ignored and it reads back
   as 1. Probing beats assuming in both directions, and it must happen before
   `TCR_EL2`/`SCTLR_EL2` are written since E2H selects their format. Safe
   there because the MMU is still off.
2. Under E2H=1, `TCR_EL2` is programmed in the `TCR_EL1` format:
   `IPS[34:32]` from `ID_AA64MMFR0_EL1.PARange` (**this** is the bit whose
   absence was fatal), `EPD1=1`, `TG1`/`T1SZ` given architected values, and no
   RES1 bits.
3. `SCTLR_EL2` gets an `SCTLR_EL1`-format RES1 set (`SCTLR_EL2_VHE_SET`):
   bit 20 (TSCXT) becomes RES1, while 4/5/16/18 stop being RES1.

Doc 06 §1.2 item 2 (`TTBR1_EL2` for high VAs) turned out to be **unnecessary**:
this tree links Xen at `0x0a00_0020_0000`, a low VA inside the `TTBR0_EL2`
range, so the TTBR1 half is simply disabled with `EPD1`.

Two implementation traps worth remembering:

- `PRINT_ID` clobbers x0, x1 **and x3** (it stashes `lr` in x3), so nothing can
  be held in a low register across a print. The PARange computation is a local
  `parange_clamped` macro instantiated inside each arm rather than a value
  computed once before the branch.
- Verify the literal pool, not just that it builds. The four constants should be
  `0x80803510` (non-VHE TCR), `0x80903510` (VHE TCR), `0x30c51838`
  (`SCTLR_EL2_SET`), `0x30d01808` (`SCTLR_EL2_VHE_SET`); the first and third
  must be *unchanged* from before the patch, which is the no-regression check.

Regression-tested on the non-VHE path under QEMU
(`-machine virt,virtualization=on,gic-version=3 -cpu max -smp 2`): full boot
through GIC, SMP and the scheduler to the expected `Missing kernel boot module?`
panic, with no `- Forced VHE -` line, confirming the probe took the nVHE branch.

### The console moves at `console_init_preirq()`

On ARM the default console is `dtuart`, so `console_init_preirq()` resolves
`/chosen/stdout-path` to the **s5l** UART, registers it, and clears
`serial_steal_fn` (`console.c:1106`) -- moving every later `printk` onto the
SBU pins, which are invisible in debugusb mode.  The boot looks like it dies
one line after `Looking for dtuart at "serial0"`, and then the machine reboots
about five seconds later: that reboot is Xen's *own* panic path on the missing
dom0 module, going through `apple_reset()`'s watchdog.  Nothing is wrong.

Until Xen has a dockchannel runtime console driver, pass
`dtuart=/nonexistent`: `dt_uart_init()` then bails out without registering a
handle (`uart-init.c:86-90`), so `early_puts` keeps the dockchannel for the
whole boot.  `push-xen.py` does this by default.

### Xen's command line must be `xen,xen-bootargs`

`boot_fdt_cmdline()` (`common/device-tree/bootinfo-fdt.c:529`) reads
`/chosen/xen,xen-bootargs` first, and falls back to plain `/chosen/bootargs`
**only** when `xen,dom0-bootargs` is present or a dom0 kernel module carries a
command line.  With no dom0 module yet, neither holds, so a plain `bootargs` --
which is what m1n1's `linux.py -b` sets -- is silently ignored and Xen reports
`Command line: <NULL>`.

The tell is exactly that line in the log, plus any argument appearing to have
no effect.  `push-xen.py` sets `xen,xen-bootargs` through
`p.kboot_set_chosen()`, which takes an arbitrary property name; `push-xen.sh`
now delegates to it rather than to `linux.py`, which can only set `bootargs`.

### FIQ must be unmasked, and must track IRQ

The boot hung inside `setup_virt_paging()`, which ends with
`smp_call_function(setup_virt_paging_one, NULL, 1)` -- the **first use of IPIs
in the whole boot**.  `CONFIG_DEBUG_INITCALL_TRACE` printing nothing at all is
what localised it: the hang was before `do_initcalls()`, not inside it.

Cause: `head.S` masks all of DAIF at entry, `local_irq_enable()` is
`msr daifclr, #2` (I only), and **nothing in Xen has ever called
`local_fiq_enable()`** -- reasonably, since on a GIC platform FIQ belongs to
the Secure world.  Apple's AIC has no Secure world and delivers Xen's own
interrupts, timers and fast IPIs alike, as FIQs.  So nothing was ever
delivered, and the secondaries could not answer the IPI.

Unmasking F independently would be worse than leaving it masked: AIC handlers
would then run inside `local_irq_disable()` sections, defeating the protection
those sections exist for.  So `local_irq_{disable,enable}()` now act on I and F
together when `CONFIG_APPLE_AIC` is set (`arm64/system.h`), which is what arm64
Linux does for the same reason.  Note that gate is effectively on for any
`ALL64_PLAT` build, and that is the intended reading: such a binary may run on
a FIQ-delivering controller.  It is benign on a GIC, where an FIQ either goes
to EL3 or falls through `do_trap_fiq()` into the normal acknowledge loop.

The dispatch side needed nothing -- `hyp_fiq` (`arm64/entry.S:382`) and
`intc_hw_ops->handle_fiq` were already in place from doc 03 §7, and `hyp_fiq`
correctly masks both I and F so FIQs do not nest.

### Things hardware surfaced past the banner

- **`sec-phys` is not optional in Xen, but is in the binding.**
  `init_dt_xen_time()` panicked on the missing secure physical timer PPI.
  Apple has no EL3, so its timer node lists only phys/virt/hyp-phys/hyp-virt.
  Fixed in `time.c`, with `domain_build.c` and `vtimer.c` substituting
  `GUEST_TIMER_PHYS_S_PPI` (29, the architectural INTID) so dom0's positional
  `interrupts` array stays well-formed and the vGIC reservation matches it.
- **big.LITTLE stops half the machine.**  The P-cores report MIDR
  `0x611f0330` against the E-cores' `0x611f0320`, and `smpboot.c:339` stops
  any CPU whose MIDR differs from the boot CPU.  Boot with `hmp-unsafe=true`
  to keep them (it sets `TAINT_CPU_OUT_OF_SPEC`, since Xen assumes uniform
  errata and features).  Note the boot CPU is an *E*-core.
- **`Maximum number of vGIC IRQs exceeded`** is a warning, not a failure:
  `VGIC_MAX_IRQS` is 992 and the AIC reports 1152 lines.  It pairs with the
  driver's own `only 988 of 1152 IRQs routable` note and needs fixing before
  dom0 owns real devices.
- **`I/O virtualisation disabled`** is expected -- no DART driver yet (doc 05).
- `Processor: "Unknown"` is cosmetic: Xen's MIDR table has no Apple part names.

**Still not adapted for VHE** — none of it needed to reach `start_xen`, all of
it needed before a guest runs (doc 06 §1.2 items 3-5):

4. Guest EL1 state: every `*_EL1` access Xen makes *on behalf of a guest*
   (`ctxt_switch_to/from`, `vsysreg.c`, and the `FAR_EL1`/`ESR_EL1` writes in
   `traps.c:483-589` that inject faults) must become `*_EL12`, or Xen corrupts
   its own EL2 state instead of the guest's.
5. `CPTR_EL2` is written by `init_traps()` (`setup.c:314`, before
   `platform_init`) in its non-VHE layout; under E2H=1 it takes the
   `CPACR_EL1` format with inverted polarity. Not fatal for reaching the
   banner — Xen is built `-mgeneral-regs-only` and executes no FP/SIMD itself —
   but wrong for guests.
6. Timer: `CNTHCTL_EL2` changes layout under E2H=1, and `CNTP_*_EL0` at EL2
   with `TGE=0` hits the physical timer (already noted in `aic.c:557`).

Pass criterion — you should then see `- Paging turned on -`, `- Ready -`, and
Xen's banner, followed by:

```
Apple Silicon platform (MIDR=... implementor=0x61 partnum=0x32)
Apple: stage-1 4K granule: yes, stage-2 4K granule: yes (Xen built for 4K pages)
Apple: EL2 mode: VHE (HCR_EL2.E2H=1), MMFR4.E2H0=...
Apple: VHE-only CPU; ...
```

then the AIC probe, then a **panic for the missing dom0 kernel module** —
which is the correct, expected end of M2. `start_xen` order is `setup_mm` →
`init_IRQ` → `platform_init` → `console_init_preirq` → `gic_init` →
`create_dom0` (`arch/arm/setup.c:347-475`), so a clean run exercises the AIC
and the runtime s5l console before it gets to dom0.

### M2.5 — the end of the implemented path

With FIQ unmasked, Xen completes `smp_call_function`, runs all initcalls,
patches alternatives, and enters `create_dom0`, where
`arch_sanitise_domain_config()` asks for the native GIC version.  Only the
AIC's *physical* half is registered, `gic_hw_ops` is NULL, and
`gic_hw_version()` returns `GIC_INVALID`.

That path used to hit `ASSERT_UNREACHABLE()` and produce a full crash dump for
what is really an unimplemented feature; it now returns `-EOPNOTSUPP` with a
plain message.  The next milestone is therefore doc 04 (vGICv3 for guest
injection), not doc 01's module packing -- dom0 cannot be created at all until
a guest can be given an interrupt controller, so module packing would only move
the same failure later.

### M3 — dom0 modules — **tooling done**

`push-xen.py --dom0 <Image> [--initrd <file>] [--dom0-args "..."]` loads the
modules into RAM and adds the `/chosen/module@N` nodes Xen looks for.  m1n1
cannot do this itself: `kboot_set_chosen()` only sets *properties* on `/chosen`,
never sub-nodes, so the tree is rewritten with `python3-libfdt` before handover.

Two details that matter:

- `reg` is decoded with **`/chosen`'s own** `#address-cells`/`#size-cells`,
  which Apple's tree sets to 2/2 where the device tree default would be 2/1.
  The tool reads them rather than assuming.
- Nodes are inserted in reverse, because `fdt_add_subnode()` prepends and Xen's
  `kind_guess` in `process_multiboot_node()` treats the first unknown module as
  the kernel.  Explicit compatibles make that moot, but the order is also what
  a human reading the tree expects.

Verified against the real `t8112-j413.dtb` by exercising the shipped
`add_modules()` and decompiling the result.

Module uploads are compressed on the host and decompressed on the target
(`--compress`, default `auto` = xz unless the file already looks compressed).
An unwrapped Asahi kernel Image goes from 79MB to 14.7MB, which is a 5.4x
saving on the slowest part of the loop.  Files that are already compressed --
an initramfs is zstd -- are detected and sent as-is.

**Do not "improve" the xz settings.**  m1n1 decodes with minilzlib, not
liblzma, and it requires a single-stream *single-block* file, CRC32 (or no)
check, LZMA2 with no BCJ filter, and `lc=3 lp=0 pb=2` -- the only property byte
it accepts (`k_LzSupportedProperties`, `lzmadec.c:117`).  liblzma splits a
stream into multiple blocks only when threading, so `xz -T0` produces a file
minilzlib rejects.  Preset 6 is used rather than 9 because it is within 1% on a
kernel Image while claiming an 8MB dictionary instead of 64MB.

Fedora Asahi's `vmlinuz` is not directly loadable: it is a CONFIG_EFI_ZBOOT
image, a PE32+ EFI application with the real Image zstd-compressed inside, and
Xen's loader understands only a raw Image, a zImage, or a uImage (decompressing
only the last).  `unzboot.py` unwraps it.  Note also that the distribution
kernel is built with `# CONFIG_XEN is not set`, so it can be used to exercise
the boot path but cannot function as a dom0.

### M4 — dom0's device tree (plans/asahi/08)

This is the next substantial piece, and it is where dom0's device tree stops
being m1n1's and becomes Xen's.  `aic_make_hwdom_dt_node()` currently returns
`-ENODEV`, which is the wall a `--dom0` boot now hits.

dom0 holds a **vGICv3** but every node in the tree it inherits says
`interrupt-parent = <&aic>` with AIC 3-cell specifiers, so it is not enough to
emit a GIC node: every device interrupt has to be re-parented and rewritten.

The translation is mechanical, because `AIC_HWIRQ_BASE == NR_GIC_LOCAL_IRQS ==
32`:

| AIC specifier | Xen linear IRQ | GIC specifier |
|---|---|---|
| `<AIC_IRQ n flags>` | `32 + n` | `<GIC_SPI n IRQ_TYPE_LEVEL_HIGH>` |
| `<AIC_FIQ f flags>` | `16 + f` | `<GIC_PPI (16 + f - 16) ...>` |

so an AIC event number *is* its SPI number, and the FIQ sources land in the PPI
range where the timer already expects them (`phys=18 hyp=16 virt=19` on
hardware).

Pieces needed:

1. Emit a synthetic GICv3 node from `d->arch.vgic.dbase` and the rdist regions.
   `make_gicv3_domU_node()` in `dom0less-build.c` already does exactly this for
   domUs; it is `static` and takes a `kernel_info` for its phandle, so it wants
   refactoring into something `aic_make_hwdom_dt_node()` can share.
2. Point `interrupt-parent` at that node's phandle everywhere.
3. Rewrite each `interrupts` property per the table above.
4. Drop the AIC node itself, and keep `iomem_deny_access()` denying its MMIO so
   dom0 cannot reach the real controller.

### M3 (original notes) — dom0 modules

Xen needs `/chosen` `multiboot,kernel` / `multiboot,ramdisk` /
`multiboot,device-tree` sub-nodes whose `reg` point at where the modules were
loaded (`common/device-tree/bootfdt.c`). `linux.py` cannot emit those, so this
needs doc 01's **A1** shim: a variant of `push-xen.sh` that `u.memalign()`s
each module, `iface.writemem()`s it, and rewrites the DTB in Python
(`python3-libfdt` is installed for exactly this) before `kboot_prepare_dt`.
Then move to **B1** (`xen.efi` + `xen.cfg` on the ESP, u-boot `bootefi`) for a
flow Asahi users can actually install — note `linux.py` already has `-u` and
`-E` for the u-boot/EFI path.

---

## 8. Recovery

Nothing here can brick the machine. Stage 1 is signed and immutable and only
chainloads `<ESP>/m1n1/boot.bin`; a payload that hangs is fixed by
`macvdmtool reboot` and re-pushing, and a broken `boot.bin` is fixed by
mounting the ESP from macOS or 1TR. Keep a copy of the installer's original
`boot.bin`.

## dom0 userspace

As of 2026-08-23 dom0 Linux boots to completion on the M2 Air: all 8 CPUs, arch
timer on the virtual counter at 24 MHz, `hvc0` console, device probing, and the
simple framebuffer. The first boot panicked only with `VFS: Unable to mount root
fs`, because no initramfs had been supplied -- not a hypervisor problem.

Fedora's stock initramfs cannot be reused. It targets
`7.1.6-400.asahi.fc44.aarch64+16k`, while the Xen-enabled tree in
`~/src/asahi-linux` builds `7.1.6+`, so none of its modules load. `nvme-apple`,
`apple-sart` and `apple-dart` are all modules -- and the DART *is* the IOMMU that
NVMe needs for DMA -- so they have to be in the initramfs; there is no root to
load them from.

```sh
~/src/asahi-bringup/mkinitramfs.sh      # stages modules, runs dracut
```

The `realpath: /lib/modules/7.1.6+` and `ldconfig ... uid=0` warnings from dracut
are expected: it is building for a kernel this VM is not running.

The real kernel command line is in the BLS entry copied from the target,
`boot/5409f4eeaf2142ed8915ea0eda6dd506-7.1.6-400.asahi.fc44.aarch64+16k.conf`:

```
root=UUID=89cb3d63-91a4-4916-a6c4-de361910eb92 ro rootflags=subvol=root
rd.luks.uuid=81535f8c-fb81-45a0-b32d-a27c578fd08e
```

**The root is LUKS.** That is easy to miss and fatal: without dracut's `crypt`
module and `dm-crypt` (a module, as is `CRYPTO_ESSIV`) there is nothing to unlock
and no `root=` value can work. dracut prompts for the passphrase on `hvc0`.

`--force-drivers` rather than `--add-drivers` for the storage stack, so the
image also carries `rd.driver.pre=` and loads it before the pre-mount hooks
instead of waiting for udev to match. A dracut that bails early -- a bad or
missing `root=`, for instance -- never reaches those hooks, which is why the
first attempt left no `/dev/nvme0n1` and needed a manual `modprobe`. The DART
and SART are listed first so the suppliers are present before `nvme-apple`
probes, avoiding a deferred-probe round trip.

```sh
./push-xen.py --dom0 ~/src/asahi-linux/arch/arm64/boot/Image \
    --initrd out/initramfs-dom0.img --seconds 300 \
    --dom0-args "console=hvc0 earlycon=xenboot rd.shell \
                 root=UUID=89cb3d63-91a4-4916-a6c4-de361910eb92 ro \
                 rootflags=subvol=root \
                 rd.luks.uuid=81535f8c-fb81-45a0-b32d-a27c578fd08e"
```

`rhgb quiet` from the BLS entry are dropped on purpose; `rd.shell` is added so a
failure lands in a shell rather than a panic.

### dom0 memory

`PLEASE SPECIFY dom0_mem PARAMETER - USING 512M FOR NOW` is not a detection
failure. Xen sees the whole machine; from the boot log its main bank is

```
(XEN) RAM: 0000000801fbc000 - 0000000dd1bdbfff      ~23.2 GiB
```

plus the small reserved-memory banks above it. Apple Silicon puts RAM at
`0x800000000`, so *no* memory is below the 32-bit line and
`allocate_memory_11()` reports `No bank has been allocated below 32-bit` -- which
is harmless for a 64-bit dom0 (it only panics for a 32-bit one). dom0 was simply
being given Xen's ARM default of 512M, which is why its single bank landed at
`0xd80000000-0xd9fffffff`.

`push-xen.py --dom0-mem` supplies it (default `16G`), leaving room for guests;
`--dom0-mem 0` restores Xen's default. Two things to know about the parameter:

- ARM's `parse_dom0_mem()` (`arch/arm/domain_build.c`) takes a **plain size**.
  The x86 `min:`/`max:` syntax is not accepted.
- It sets `d->max_pages`, so it is a hard ceiling -- dom0 cannot balloon past it.

There is no bank-count limit to worry about: `NR_MEM_BANKS` is 256 and the 1:1
allocator fills banks with descending power-of-2 orders down to 4MB, so a large
request is satisfied out of the contiguous main bank. `CONFIG_DOM0_MEM` can bake
a default into the build instead, if passing it every boot becomes tiresome.

### The pmgr messages

The `apple-pmgr-pwrstate ... sync_state() pending due to <device>` flood is not a
fault. Every one of those lines is timestamped at ~10.2 s, which is
`deferred_probe_timeout` expiring: the driver core is reporting which consumers
have not probed yet, and a minimal initramfs guarantees that most of them never
will, because their modules are not in it. A power-domain provider simply cannot
run `sync_state()` -- which is what would turn *off* unused domains -- until its
consumers have probed, so the effect of these messages is that nothing gets
powered down. That is the safe direction.

`always-on domain msg is not on at boot` is a different line and a real one, but
it is a sanity check rather than a failure. The DT node is
`power-controller@78` in the pmgr at `0x23d280000`, `label = "msg"`, with
`apple,always-on`; `apple_pmgr_pwrstate_probe()` warns when such a domain reads
back inactive and then sets `GENPD_FLAG_ALWAYS_ON` so genpd keeps it on. It is
also not on the NVMe path.

The message that *would* implicate Xen is a pmgr **write** failing --
`apple-pmgr-pwrstate ... timeout` or a failure to set a power state -- since that
would mean dom0's MMIO mapping of the pmgr is not writable or is mapped with the
wrong memory type. Watch for that specifically; the benign warning above is not
evidence of it.

### Diagnostics that are expected, and why

None of these indicate a fault:

| Message | Explanation |
|---|---|
| `Unhandled SMC/HVC: 0x84000050` | a PSCI function Xen does not implement; Linux probes and moves on |
| `Unhandled SMC/HVC: 0x8600ff01` | SMCCC vendor-hypervisor UID query -- Linux asking "are you KVM?". Xen is not, and says so |
| `Unhandled SMC/HVC: 0x84000063` | `FFA_VERSION`; the log's own `ARM FF-A: ... not supported` is the handled result |
| `vGICD: unhandled word write ... to ICACTIVER*` | Xen's vGIC does not emulate `ICACTIVER` writes. Linux clears active state at init; pre-existing upstream gap, not Apple-specific |
| `vGICD: RAZ on reserved register offset 0x00000c` | `GICD_TYPER2`, GICv3.1 only. RAZ is the correct answer |
| `kvm [1]: HYP mode not available` | correct: EL2 belongs to Xen |
| `cacheinfo: Unable to detect cache hierarchy` | Xen's generated dom0 device tree carries no cache nodes |

`GICv3: 960 SPIs implemented` is worth noting: the synthesised GICv3 exposes 960
SPIs against the AIC's 1152 lines, which is the `VGIC_MAX_IRQS` / ESPI gap
recorded in doc 04. Nothing dom0 needs today falls in the missing range.

Also note that the outstanding `CNTHCTL_EL2` bug (doc 06 §1.2 item 4) did **not**
bite here: Linux under Xen uses the *virtual* counter (`arch_timer: cp15 timer
running at 24.00MHz (virt)`), which those bits do not gate. A guest reading the
*physical* counter from EL1 would still trap, so the bug is latent rather than
fixed.
