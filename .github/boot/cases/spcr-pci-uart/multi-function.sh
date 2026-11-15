# The SPCR's console is function 0 of a multi-function device. Xen keeps it
# visible to dom0, since hiding it would hide the other functions too, and
# leaves the port above it alone. dom0 then finds the UART, and pciehp takes
# the port: the lines that hidden.sh checks for do appear when Xen does not
# hide the UART.
machine_options+=,x-pci-preserve-config=on
devices+=(-device 'pcie-root-port,id=uart-port,bus=pcie.0,addr=2,chassis=1')
# shellcheck disable=SC2034 # run-arm64.sh reads it
console_uart=pci-serial,bus=uart-port,multifunction=on,x-memory-bar=on,x-vendor-id=0x1d0f,x-device-id=0x8250

expect+=(
    '^\(XEN\) SPCR: console 0000:01:00\.0 stays visible to the hardware domain: it is one of several functions of its device'
    '^\[ *[0-9.]+\] pci 0000:01:00\.0: \[1d0f:8250\] type 00 '
    '^\[ *[0-9.]+\] pcieport 0000:00:02\.0: pciehp: '
)

# Xen neither hides the UART nor locks the port.
check() {
    grep -E '^\(XEN\) SPCR: (port .* is read-only to d0|console .* hidden from d0)$' "$1"
}
