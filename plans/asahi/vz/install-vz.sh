#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Install Xen and its device tree into /boot and give GRUB an entry for them,
# on an Apple Virtualization.framework guest.  Re-run after every Xen rebuild;
# it is idempotent.
#
# There are four things here that are not obvious, and each of them is a boot
# that silently does not work if it is missing:
#
#  - GRUB needs xen_boot.mod on disk.  Fedora's grubaa64.efi is a monolithic
#    image and xen_boot is not in it (`devicetree` is), and there is no
#    /boot/grub2/arm64-efi at all, so `insmod xen_boot` has nowhere to look.
#
#  - Xen goes in /boot/xen/ rather than /boot.  /etc/grub.d/20_linux_xen globs
#    /boot/xen* and would generate its own entries -- which cannot work here,
#    because it emits no `devicetree` line and this platform has no device tree
#    of its own.  A directory fails its `test -f` check, so it is skipped.
#
#  - The entry lives in /boot/grub2/custom.cfg, which 41_custom sources at boot.
#    That means editing Xen's command line does not need grub2-mkconfig, which
#    matters when the command line is the thing being iterated on.
#
#  - The menu has to be visible.  Fedora sets menu_auto_hide=1 in grubenv, and
#    with boot_success=1 that hides it entirely.
#
# The dom0 kernel and initramfs are referenced through fixed names so that this
# entry never has to be edited when the kernel changes:
#
#     /boot/vmlinuz-xen-dom0        (a raw arm64 Image, NOT a zboot PE)
#     /boot/initramfs-xen-dom0.img
#
# Point those at the real files, by symlink or copy, once the dom0 kernel is
# built.  See plans/asahi/11-virtualization-framework.md section 6 for what
# that kernel has to have in it.

set -eu

XEN_SRC=${XEN_SRC:-$(cd "$(dirname "$0")/../../.." && pwd)/xen/xen}
DTB_SRC=${DTB_SRC:-$(dirname "$0")/vz.dtb}

BOOTDIR=/boot/xen
GRUBDIR=/boot/grub2
CUSTOM=$GRUBDIR/custom.cfg
MODDIR=$GRUBDIR/arm64-efi

DOM0_KERNEL=/vmlinuz-xen-dom0
DOM0_INITRD=/initramfs-xen-dom0.img

die() { echo "install-vz: $*" >&2; exit 1; }
note() { echo "install-vz: $*"; }
warn() { echo "install-vz: WARNING: $*" >&2; }

[ "$(id -u)" = 0 ] || die "must run as root"
[ -f "$XEN_SRC" ] || die "no Xen image at $XEN_SRC (build it, or set XEN_SRC=)"
[ -f "$DTB_SRC" ] || die "no device tree at $DTB_SRC (run gen-vz-dtb.py)"

# Xen's arm64 image carries a PE header in head.S, and that is what GRUB's
# LoadImage() needs.  A raw Image here would be accepted by nothing and would
# fail at the point where there is least to see.
read -r magic < <(od -An -tx2 -N2 "$XEN_SRC" | tr -d ' \n'; echo)
[ "$magic" = "5a4d" ] || die "$XEN_SRC is not a PE image (magic $magic, expected 5a4d/MZ)"

# ---------------------------------------------------------------- GRUB modules
if [ ! -f "$MODDIR/xen_boot.mod" ]; then
    [ -d /usr/lib/grub/arm64-efi ] || \
        die "install grub2-efi-aa64-modules: no /usr/lib/grub/arm64-efi"
    note "installing GRUB modules into $MODDIR (for insmod xen_boot)"
    mkdir -p "$MODDIR"
    cp -a /usr/lib/grub/arm64-efi/. "$MODDIR/"
fi

# ------------------------------------------------------------------ Xen + DTB
mkdir -p "$BOOTDIR"
install -m 0644 "$XEN_SRC" "$BOOTDIR/xen.efi"
install -m 0644 "$DTB_SRC" "$BOOTDIR/vz.dtb"
note "installed $BOOTDIR/xen.efi ($(stat -c%s "$BOOTDIR/xen.efi") bytes) and vz.dtb"

# --------------------------------------------------------------- the dom0 pair
#
# Check the thing Xen actually checks.  kernel_zimage64_probe() looks for the
# arm64 Image magic "ARM\x64" at offset 56 and returns -EINVAL otherwise, which
# surfaces as "Could not set up d0 guest OS (rc = -22)" -- a message that says
# nothing about the kernel being at fault.
#
# Note what is NOT a usable test: an arm64 Image starts with "MZ" because it is
# deliberately also a valid PE/COFF EFI application (that is the EFI stub), so
# a PE header says nothing.  A CONFIG_EFI_ZBOOT vmlinuz.efi starts with "MZ"
# too and has zeroes at offset 56.
for f in "$DOM0_KERNEL" "$DOM0_INITRD"; do
    [ -e "/boot$f" ] || warn "/boot$f does not exist yet; the entry will not boot until it does"
done
if [ -e "/boot$DOM0_KERNEL" ]; then
    k=/boot$DOM0_KERNEL
    off56=$(od -An -tx1 -j56 -N4 "$k" | tr -d ' \n')
    head4=$(od -An -tx1 -N4 "$k" | tr -d ' \n')

    if [ "$off56" != "41524d64" ]; then
        warn "$k is not a raw arm64 Image: no ARM\\x64 magic at offset 56"
        case $head4 in
        28b52ffd)
            warn "  it is a zstd stream -- decompress it:"
            warn "    zstd -dc $k > /boot/Image-dom0   # ignore the trailing-bytes"
            warn "                                     # complaint: that is the"
            warn "                                     # 4-byte size Linux appends"
            ;;
        1f8b*)
            warn "  it is gzip-compressed; Xen can decompress gzip, so if this"
            warn "  still fails the size trailer is probably missing"
            ;;
        fd377a58)
            warn "  it is xz-compressed -- decompress it with: xz -dc" ;;
        4d5a*)
            warn "  it is a PE image with no Image magic, i.e. a CONFIG_EFI_ZBOOT"
            warn "  vmlinuz.efi.  Xen's loader cannot unwrap that; build the"
            warn "  kernel with CONFIG_EFI_ZBOOT=n, or use arch/arm64/boot/Image."
            ;;
        *)  warn "  head is $head4; expected a raw Image or a supported"
            warn "  compressed stream" ;;
        esac
        warn "Xen will refuse this with rc = -22."
    fi
fi

# ------------------------------------------------------------------- the entry
BOOT_UUID=$(findmnt -no UUID /boot) || die "cannot determine /boot UUID"
ROOT_SPEC=$(findmnt -no UUID /) || die "cannot determine / UUID"

# btrfs needs the subvolume, and it is not guessable: this root is subvol=/root.
ROOT_FLAGS=
subvol=$(findmnt -no OPTIONS / | tr ',' '\n' | grep -m1 '^subvol=' || true)
[ -n "$subvol" ] && ROOT_FLAGS=" rootflags=$subvol"

note "writing $CUSTOM"

# Two entries.  The second exists because of the history in
# plans/asahi/11-virtualization-framework.md section 2: writing to a
# virtio-console port killed the VMM once, and while the driver refuses the
# port that did it, "boot Xen without touching the console device at all" is
# the fallback that separates "Xen cannot boot" from "the console cannot".
# Its log is still recoverable from the ring with `xl dmesg`.
emit_entry() {
	local title=$1 console=$2

	cat <<EOF

menuentry '$title' --class xen {
	insmod part_gpt
	insmod ext2
	insmod xen_boot
	search --no-floppy --fs-uuid --set=root $BOOT_UUID

	# The platform is described only by ACPI, so Xen is given a device tree
	# translated from the firmware tables by plans/asahi/vz/gen-vz-dtb.py.
	# Without this GRUB hands Xen an empty tree and it hangs with no CPUs.
	devicetree /xen/vz.dtb

	# console_to_ring puts dom0's output in Xen's ring too, and noreboot
	# stops a panic from rebooting into this same entry and destroying the
	# only copy of the panic message.
	#
	# auto_debug_keys runs the 'd', 'p' and 'q' keyhandlers by itself, two
	# seconds apart, five times over.  Two rather than ten because dom0 now
	# gets far enough that the interesting failures happen in the first few
	# seconds, and a first dump at ten seconds can land after the capture
	# has already stopped -- which is exactly what made boot 14 ambiguous.  Typing them would need console
	# input, and console input is polled off a Xen timer -- so on a machine
	# where Xen cannot get back onto the CPU the hardware domain is on,
	# which is what boot 5 showed, nothing typed ever arrives.  That timer
	# and the console's input poll now both run on the highest-numbered
	# CPU for the same reason, and dom0_vcpus_pin is what keeps a dom0 vCPU
	# off it: pinned 1:1, two vCPUs reach CPU1 and no further.
	#
	# 'd' comes first because CPU0's guest PC is the measurement, and 'p'
	# second because the difference between two samples of "trap: sysreg
	# access" is what says whether that PC is stuck or merely slow.  '0' is
	# gone: boot 6 showed it dumps the same vCPU 'd' already caught live,
	# and it was what hung that boot.  It needs CONFIG_PERF_COUNTERS=y.
	xen_hypervisor /xen/xen.efi dom0_mem=2G dom0_max_vcpus=2 \\
		dom0_vcpus_pin \\
		$console console_to_ring conring_size=512 \\
		loglvl=all guest_loglvl=all noreboot \\
		auto_debug_keys=dpq,2,5

	# hvc0 last, so it is dom0's /dev/console: that is Xen's console, which
	# comes out of the same serial terminal as Xen's own output.
	#
	# earlycon=xenboot is the difference between a silent dom0 and a
	# debuggable one.  hvc0 is a console_initcall, so it only registers in
	# console_init(), which start_kernel() reaches *after* init_IRQ(),
	# time_init() and the first local_irq_enable() -- a dom0 that dies in
	# that window prints absolutely nothing.  The earlycon goes through
	# HYPERVISOR_console_io from the first printk in setup_arch() instead.
	# keep_bootcon keeps it alive once hvc0 takes over, so the end of the
	# log can never be lost; the price is that everything from that point
	# appears twice.  nokaslr makes the PCs in Xen's guest-state dumps
	# resolvable straight against the dom0 kernel's System.map.
	xen_module $DOM0_KERNEL \\
		root=UUID=$ROOT_SPEC ro$ROOT_FLAGS selinux=0 \\
		console=tty0 console=hvc0 \\
		earlycon=xenboot keep_bootcon nokaslr

	xen_module --nounzip $DOM0_INITRD
}
EOF
}

cat > "$CUSTOM" <<EOF
# Written by plans/asahi/vz/install-vz.sh -- re-run it rather than hand-editing,
# or hand-edit freely: 41_custom sources this file at boot, so changes here take
# effect without grub2-mkconfig.
EOF

# console=vtcon is the virtio-console, the only serial port this platform has.
emit_entry 'Xen (Virtualization.framework) with Linux dom0' \
	'console=vtcon' >> "$CUSTOM"
emit_entry 'Xen (Virtualization.framework), no console -- xl dmesg only' \
	'console=none' >> "$CUSTOM"

grub2-script-check "$CUSTOM" || die "$CUSTOM is not valid GRUB script"

# ------------------------------------------------------------ show the menu
if grub2-editenv "$GRUBDIR/grubenv" list | grep -q '^menu_auto_hide='; then
    note "unsetting menu_auto_hide so the menu is shown"
    grub2-editenv "$GRUBDIR/grubenv" unset menu_auto_hide
fi
grub2-editenv "$GRUBDIR/grubenv" unset menu_show_once 2>/dev/null || true

note "done.  Select 'Xen (Virtualization.framework)' from the GRUB menu."
