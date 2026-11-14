#!/usr/bin/env bash
# Builds the QEMU that boot cases with a PCI console need: a QEMU release with
# the patches beside this script, and only the devices that the boots use.
#
#   build.sh DIR
#
# The emulator is DIR/qemu-system-aarch64; run-arm64.sh runs it when QEMU names
# it. The build needs a C compiler, ninja, pkg-config, Python 3 with venv,
# setuptools and wheel, glib, libfdt, flex and bison, and network access to
# download.qemu.org only.
#
# The patches are `git format-patch --zero-commit --no-signature --no-thread
# --no-numbered` of commits on QEMU's tag v$VERSION. To change one, apply them
# with git am to a clone at that tag, change the commit, and export them
# again. The first is an upstream fix that no release has yet: without it, two
# CPUs that contend for a Xen spinlock can both sleep in WFE and hang the boot.
# Drop it when VERSION moves to a release that has it.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VERSION=11.1.3
SHA256=5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22

if [ $# -ne 1 ]; then
    sed -n 's/^#   //p' "${BASH_SOURCE[0]}" >&2
    exit 2
fi
mkdir -p "$1"
out=$(cd "$1" && pwd)

curl -fsSL --retry 5 -o "$out/qemu.tar.xz" \
    "https://download.qemu.org/qemu-$VERSION.tar.xz"
echo "$SHA256  $out/qemu.tar.xz" | sha256sum --check --quiet -

rm -rf "$out/src" "$out/build"
mkdir -p "$out/src" "$out/build"
tar -xJf "$out/qemu.tar.xz" -C "$out/src" --strip-components=1
# No fuzz: after a new VERSION, a hunk that no longer applies where it was
# written must fail, not land on lines that merely look alike.
for patch in "$HERE"/*.patch; do
    patch -d "$out/src" -p1 --fuzz=0 --quiet <"$patch"
done

# xen-boot, a device list that one of the patches adds, keeps the build to
# the virt machine and the devices the cases add to it. The firmware boots Xen
# from a vvfat drive. No debug information, which only lengthens the build.
# No downloads: configure then takes its Python packages from the wheels in
# the tarball and from the system, not from PyPI, where nothing pins them.
cd "$out/build"
"$out/src/configure" --target-list=aarch64-softmmu \
    --without-default-features --without-default-devices \
    --with-devices-aarch64=xen-boot --enable-fdt=system --enable-vvfat \
    --disable-debug-info --disable-download
ninja qemu-system-aarch64
cp qemu-system-aarch64 "$out/"
