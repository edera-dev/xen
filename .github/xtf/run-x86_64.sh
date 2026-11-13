#!/usr/bin/env bash
# Boots Xen on an emulated x86 machine with one XTF test as dom0, and checks
# the verdict the test prints on the serial console.
#
#   run-x86_64.sh --xen xen --variant hvm64|pv64 --test NAME --out DIR
#
# --xen is the uncompressed hypervisor. --test names a directory in tests/
# here, or a test XTF already has. An hvm64 test runs as a PVH dom0. QEMU
# emulates the CPU, SVM and nested paging included, so that dom0 has HAP on a
# host without KVM. The console log is DIR/serial.log.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TIMEOUT=${TIMEOUT:-300}
XTF_URI=${XTF_URI:-https://xenbits.xen.org/git-http/xtf.git}
# Pinned so that a test does not change when XTF does.
XTF_COMMIT=${XTF_COMMIT:-453490df6f65fb503a39b1bddf0093441eece9ae}

usage() {
    sed -n 's/^#   //p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

xen='' variant='' test='' out=''
while [ $# -gt 0 ]; do
    case $1 in
    --xen) xen=$2 ;;
    --variant) variant=$2 ;;
    --test) test=$2 ;;
    --out) out=$2 ;;
    *) usage ;;
    esac
    shift 2
done
[ -n "$xen" ] && [ -n "$test" ] && [ -n "$out" ] || usage

xen_options='loglvl=all guest_loglvl=all console=com1'
case $variant in
hvm64) xen_options="$xen_options dom0-iommu=none dom0=pvh" ;;
pv64) ;;
*) usage ;;
esac

rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)

git clone -q "$XTF_URI" "$out/xtf"
git -C "$out/xtf" checkout -q --detach "$XTF_COMMIT"
if [ -d "$HERE/tests/$test" ]; then
    cp -r "$HERE/tests/$test" "$out/xtf/tests/"
fi
make -C "$out/xtf" -j"$(nproc)" TESTS="tests/$test" >"$out/build.log" 2>&1 || {
    tail -n 40 "$out/build.log" >&2
    exit 1
}

# Xen halts when the test shuts dom0 down, and QEMU then runs on, so stop it
# at the verdict.
timeout "$TIMEOUT" qemu-system-x86_64 \
    -accel tcg -cpu max -m 2048 -smp 2 \
    -no-reboot -nographic -monitor none -serial stdio \
    -kernel "$xen" \
    -initrd "$out/xtf/tests/$test/test-$variant-$test" \
    -append "$xen_options" \
    </dev/null >"$out/serial.raw" 2>&1 &
qemu=$!
while kill -0 "$qemu" 2>/dev/null &&
    ! grep -q -a '^Test result:' "$out/serial.raw"; do
    sleep 1
done
kill "$qemu" 2>/dev/null || true
wait "$qemu" 2>/dev/null || true
sed 's/\r$//' "$out/serial.raw" | tee "$out/serial.log"

if [ "$variant" = hvm64 ] &&
    ! grep -q 'Hardware Assisted Paging (HAP) detected' "$out/serial.log"; then
    echo "FAIL: Xen found no HAP, so the test did not run as a HAP guest" >&2
    exit 1
fi
if ! grep -q '^Test result: SUCCESS' "$out/serial.log"; then
    echo "FAIL: $(grep '^Test result:' "$out/serial.log" || echo 'no verdict')" >&2
    exit 1
fi
echo PASS
