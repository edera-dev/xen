#!/usr/bin/env bash
# Boots Xen and a busybox dom0 on an emulated arm64 machine that describes
# itself only through UEFI and ACPI, as Graviton does, and checks the serial
# console for a clean boot.
#
#   run-arm64.sh --xen xen.efi --kernel Image --busybox busybox --out DIR
#                [--machine NAME] [--case NAME]
#
# --kernel is the dom0 kernel, compressed or not, and --busybox a static
# aarch64 busybox. --machine names a file in machines/, the platform to
# imitate, by default graviton4. --case names a file in cases/, such as
# dom0-mem-default/floor: a Xen option and the outcome it must have. The
# console log is DIR/serial.log.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FIRMWARE=${FIRMWARE:-/usr/share/AAVMF}
TIMEOUT=${TIMEOUT:-300}

usage() {
    sed -n 's/^#   //p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

xen='' kernel='' busybox='' out=''
machine=graviton4 case=''
while [ $# -gt 0 ]; do
    case $1 in
    --xen) xen=$2 ;;
    --kernel) kernel=$2 ;;
    --busybox) busybox=$2 ;;
    --out) out=$2 ;;
    --machine) machine=$2 ;;
    --case) case=$2 ;;
    *) usage ;;
    esac
    shift 2
done
[ -n "$xen" ] && [ -n "$kernel" ] && [ -n "$busybox" ] && [ -n "$out" ] ||
    usage

# Every machine has the same few cores and the same memory: QEMU emulates
# each core, and the platform model, not the size of a host, is what is
# tested.
cpus=4
memory_mib=2048

# A machine file sets its CPU model and sockets. A case file may change the
# memory and the Xen command line, which is the one the installer gives arm64
# hosts, with a dom0_mem that fits these machines.
cpu='' sockets=1
xen_options='console=dtuart acpi=force dom0_mem=1G smp=on dom0_vcpus_pin=on spec-ctrl=ssbd=runtime pci-passthrough=on loglvl=all guest_loglvl=all sync_console'
# Each is an extended regular expression that some console line must match.
expect=()
# A case may also define check(), which reads the console log named by its
# argument and prints one line for each thing wrong with it.

# shellcheck source=/dev/null
. "$HERE/machines/$machine.sh"
if [ -n "$case" ]; then
    # shellcheck source=/dev/null
    . "$HERE/cases/$case.sh"
fi
cores=$((cpus / sockets))
expect+=(
    "^\(XEN\) Brought up $cpus CPUs"
    "smp: Brought up [0-9]+ nodes?, $cpus CPUs"
)

rm -rf "$out"
mkdir -p "$out/esp/EFI/BOOT" "$out/initramfs"
out=$(cd "$out" && pwd)

(
    cd "$out/initramfs"
    mkdir -p bin sbin usr/bin usr/sbin dev proc sys
    install -m 0755 "$busybox" bin/busybox
    install -m 0755 "$HERE/init" init
    find . | cpio --quiet -o -H newc -R 0:0 | gzip -9 >"$out/esp/EFI/BOOT/initrd"
)

# Booted from the removable media path, xen.efi reads its configuration from
# BOOTAA64.cfg beside it.
install -m 0644 "$xen" "$out/esp/EFI/BOOT/BOOTAA64.EFI"
install -m 0644 "$kernel" "$out/esp/EFI/BOOT/Image"
cat >"$out/esp/EFI/BOOT/BOOTAA64.cfg" <<EOF
[global]
default=xen

[xen]
options=$xen_options
kernel=Image console=hvc0 earlycon=xenboot panic=-1
ramdisk=initrd
EOF

cp "$FIRMWARE/AAVMF_VARS.fd" "$out/vars.fd"

# Each socket is a NUMA node with an equal share of the memory, which QEMU
# describes to the firmware in an SRAT.
numa=()
if [ "$sockets" -gt 1 ]; then
    for ((s = 0; s < sockets; s++)); do
        numa+=(
            -object "memory-backend-ram,id=mem$s,size=$((memory_mib / sockets))M"
            -numa "node,nodeid=$s,cpus=$((s * cores))-$((s * cores + cores - 1)),memdev=mem$s"
        )
    done
fi

# virtualization=on gives Xen EL2. When QEMU supplies ACPI tables, the
# firmware gives the operating system no device tree, so Xen finds the machine
# through ACPI alone. With an SMMUv3 between the PCI root complex and the ITS,
# Xen rewrites the IORT it gives dom0, as it does on Graviton hardware. A dom0
# panic reboots, which -no-reboot turns into an exit.
echo "Booting $machine${case:+, case $case}"
status=0
timeout "$TIMEOUT" qemu-system-aarch64 \
    -machine virt,virtualization=on,gic-version=3,its=on,iommu=smmuv3 \
    -cpu "$cpu" -smp "$cpus,sockets=$sockets,cores=$cores,threads=1" \
    -m "${memory_mib}M" "${numa[@]}" \
    -nodefaults -display none -serial stdio -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$FIRMWARE/AAVMF_CODE.fd" \
    -drive if=pflash,format=raw,file="$out/vars.fd" \
    -drive if=virtio,format=raw,readonly=on,file="fat:$out/esp" \
    </dev/null 2>&1 | sed -u 's/\r$//' | tee "$out/serial.log" || status=$?

# Lines that mean Xen or dom0 went wrong, whatever else the boot did. The Xen
# ones are those edera-dev/xen-qa looks for.
faults=(
    'Panic on CPU [0-9]+:'
    "Assertion '.*' failed at"
    'Xen BUG at'
    'Xen WARN at'
    'UBSAN: Undefined behaviour in'
    'Hardware Dom0 crashed'
    'Kernel panic - not syncing'
    'Internal error: Oops'
    'Unable to handle kernel'
    'WARNING: CPU: [0-9]+ PID: [0-9]+'
    '\bBUG: '
    'xenqa: fail '
)

failed=0
fail() {
    echo "FAIL: $*"
    failed=1
}

if [ "$status" -eq 124 ]; then
    fail "the boot did not end within $TIMEOUT seconds"
elif [ "$status" -ne 0 ]; then
    fail "qemu exited with status $status"
fi
for pattern in "${faults[@]}"; do
    while read -r line; do
        fail "$line"
    done < <(grep -E -- "$pattern" "$out/serial.log")
done
for pattern in "${expect[@]}"; do
    grep -q -E -- "$pattern" "$out/serial.log" ||
        fail "no line matches: $pattern"
done
if declare -F check >/dev/null; then
    while read -r line; do
        fail "$line"
    done < <(check "$out/serial.log")
fi
grep -q 'xenqa: pass boot.dom0_runs_init' "$out/serial.log" ||
    fail "dom0 did not run init"
# Only init powers dom0 off, after it has reported.
grep -q 'Hardware Dom0 halted' "$out/serial.log" ||
    fail "dom0 did not power off"

if [ "$failed" -eq 0 ]; then
    echo PASS
fi
exit "$failed"
