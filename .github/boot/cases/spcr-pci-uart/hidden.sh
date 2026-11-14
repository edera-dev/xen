# The SPCR names a PCI UART behind a PCI Express root port as Xen's console,
# with its registers in a memory BAR and Graviton's IDs, and the host bridge
# asks the OS to keep the firmware's PCI layout, as on Graviton. Xen hides the
# UART from dom0 and makes the port read-only. dom0 still finds the port, as
# its reads return the port's own registers. The lines that say dom0 ran init
# and halted come through the UART, so the case passes only if Xen's console
# outlives dom0's PCI scan.
machine_options+=,x-pci-preserve-config=on
devices+=(-device 'pcie-root-port,id=uart-port,bus=pcie.0,addr=2,chassis=1')
# shellcheck disable=SC2034 # run-arm64.sh reads it
console_uart=pci-serial,bus=uart-port,x-memory-bar=on,x-vendor-id=0x1d0f,x-device-id=0x8250

expect+=(
    '^\(XEN\) SPCR: port 0000:00:02\.0 above console 0000:01:00\.0 is read-only to d0$'
    '^\(XEN\) SPCR: console 0000:01:00\.0 hidden from d0$'
    '^\[ *[0-9.]+\] pci 0000:00:02\.0: \[1b36:000c\] type 01 '
)

# dom0 finds neither the UART nor a hotplug slot in the port above it. QEMU's
# slot reports the UART present and powered, so a pciehp that took the port
# would leave it on, and the console would survive: only this check shows
# that the port hides its hotplug capability.
check() {
    grep -E 'pci 0000:01:00\.0|pcieport 0000:00:02\.0: pciehp' "$1"
}
