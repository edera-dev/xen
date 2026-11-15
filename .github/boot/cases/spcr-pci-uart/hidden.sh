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
    '^xenqa: pass spcr\.port_read_only'
    '^xenqa: pass spcr\.console_page'
    '^\(XEN\) DOM0: spcr vuart$'
)

# dom0 finds neither the UART nor a hotplug slot in the port above it. QEMU's
# slot reports the UART present and powered, so a pciehp that took the port
# would leave it on, and the console would survive: only this check shows
# that the port hides its hotplug capability.
#
# The tools that dom0() runs report their errors on the console. One that
# failed leaves the probe reading or writing some other register than it says.
check() {
    grep -E 'pci 0000:01:00\.0|pcieport 0000:00:02\.0: pciehp' "$1"
    grep -E '^(od|dd|dmesg|sed|devmem|sh): ' "$1"
}

# dom0 tries to turn off the port's decoding and to power off its slot. Either
# write, let through, would cut Xen's console off: QEMU then stops routing the
# UART's registers. Both registers must read back unchanged.
#
# Then dom0 reads the UART's own registers. Xen gives dom0 its vuart on the
# first, the data register, and empties the rest of the page, so the line
# status register reads as all ones, as from a missing UART. A line that dom0
# writes to the data register reaches Xen's console through the vuart.
dom0() {
    config=/sys/bus/pci/devices/0000:00:02.0/config

    # Slot Control is in the PCI Express capability. od pads the numbers it
    # prints with spaces, and refuses them as offsets: arithmetic expansion
    # strips the padding.
    cap=$(od -An -tu1 -j 52 -N 1 "$config")
    while [ "$cap" -ne 0 ] &&
        [ "$(od -An -tu1 -j $((cap)) -N 1 "$config")" -ne 16 ]; do
        cap=$(od -An -tu1 -j $((cap + 1)) -N 1 "$config")
    done
    if [ "$cap" -eq 0 ]; then
        echo "xenqa: fail spcr.port_read_only: no PCI Express capability"
        return
    fi
    slot_control=$((cap + 24))

    command=$(od -An -tu2 -j 4 -N 2 "$config")
    slot=$(od -An -tu2 -j "$slot_control" -N 2 "$config")

    # Each a 16-bit write, low byte first.
    value=$((command & ~7))
    printf '%b' "$(printf '\\0%03o\\0%03o' $((value & 255)) $((value >> 8)))" |
        dd of="$config" bs=2 seek=2 conv=notrunc 2>/dev/null
    value=$((slot | 1024))
    printf '%b' "$(printf '\\0%03o\\0%03o' $((value & 255)) $((value >> 8)))" |
        dd of="$config" bs=2 seek=$((slot_control / 2)) conv=notrunc 2>/dev/null

    command_now=$(od -An -tu2 -j 4 -N 2 "$config")
    slot_now=$(od -An -tu2 -j "$slot_control" -N 2 "$config")
    printf 'spcr: port command %#x, after the write %#x; ' \
        $((command)) $((command_now))
    printf 'slot control %#x, after the write %#x\n' $((slot)) $((slot_now))
    if [ "$command_now" -eq "$command" ] && [ "$slot_now" -eq "$slot" ]; then
        echo "xenqa: pass spcr.port_read_only"
    else
        echo "xenqa: fail spcr.port_read_only"
    fi

    uart=$(dmesg | sed -n 's/.*ACPI: SPCR: console: uart,mmio,\(0x[0-9a-f]*\),.*/\1/p')
    data=$(devmem "$uart" 8)
    status=$(devmem $((uart + 5)) 8)
    echo "spcr: console data register $data, line status register $status"
    if [ "$data" = 0x00 ] && [ "$status" = 0xFF ]; then
        echo "xenqa: pass spcr.console_page"
    else
        echo "xenqa: fail spcr.console_page"
    fi
    # "spcr vuart" and a newline.
    for c in 115 112 99 114 32 118 117 97 114 116 10; do
        devmem "$uart" 8 "$c"
    done
}
