# The SPCR's console sits on the root bus, with no port and no slot above it.
# Xen hides it from dom0, and has no port to make read-only.
machine_options+=,x-pci-preserve-config=on
# shellcheck disable=SC2034 # run-arm64.sh reads it
console_uart=pci-serial,bus=pcie.0,addr=2,x-memory-bar=on,x-vendor-id=0x1d0f,x-device-id=0x8250

expect+=(
    '^\(XEN\) SPCR: console 0000:00:02\.0 hidden from d0$'
)

# dom0 does not find the UART, and Xen locks no port.
check() {
    grep -E 'pci 0000:00:02\.0|^\(XEN\) SPCR: port ' "$1"
}
