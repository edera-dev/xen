#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Emit a device tree for the machine this script is running on, for Xen.

Apple's Virtualization.framework platform is described only by ACPI: there is
an MADT, a GTDT, an MCFG and a tiny DSDT, and no device tree anywhere (the
866-byte FDT in /sys/firmware/fdt is the one the EFI stub builds to carry
/chosen, and describes no hardware).  Xen's arm64 ACPI support is not a path
this port has any confidence in, and Xen boots happily from a device tree, so
translate one from the other.

Run this as root inside the VM *outside* Xen -- that is the only place the
firmware tables can be read -- and pass the result to GRUB with `devicetree`.
Re-run it whenever the VM's CPU count, memory size or device set changes: the
CPU nodes and the PCI windows are read from this machine, and Xen believes
them.

Usage: sudo ./gen-vz-dtb.py > vz.dts && dtc -I dts -O dtb -o vz.dtb vz.dts
"""

import re
import struct
import sys

ACPI = "/sys/firmware/acpi/tables/"


def table(sig):
    with open(ACPI + sig, "rb") as f:
        return f.read()


def check(cond, msg):
    if not cond:
        sys.exit("gen-vz-dtb: " + msg)


def parse_madt():
    """CPUs (as MPIDRs), the GICD/GICR windows and any GICv2m MSI frames."""
    b = table("APIC")
    length = struct.unpack_from("<I", b, 4)[0]
    cpus, gicd, gicr, frames, maint = [], None, [], [], None
    off = 44
    while off < length:
        typ, l = struct.unpack_from("<BB", b, off)
        if typ == 0x0B:  # GICC
            (_, _, uid, flags, _, _, _, _, _, _,
             vgic_maint, _, mpidr) = struct.unpack_from("<HIIIIIQQQQIQQ", b, off + 2)
            if flags & 1:  # enabled
                cpus.append((uid, mpidr))
                maint = vgic_maint
        elif typ == 0x0C:  # GICD
            _, _, base, _, version = struct.unpack_from("<HIQII", b, off + 2)
            check(version == 3, "expected a GICv3, MADT says version %d" % version)
            gicd = base
        elif typ == 0x0D:  # GIC MSI frame
            _, _, base, flags, count, spi_base = struct.unpack_from("<HIQIHH", b, off + 2)
            # Flags bit 0 clear means the SPI count/base in the table are not
            # to be trusted and V2M_MSI_TYPER is authoritative.  Xen reads the
            # register in that case too, so just emit what the table says and
            # let it be overridden.
            frames.append((base, spi_base, count))
        elif typ == 0x0E:  # GICR
            _, base, size = struct.unpack_from("<HQI", b, off + 2)
            gicr.append((base, size))
        elif typ == 0x0F:  # ITS
            sys.exit("gen-vz-dtb: this machine has a GIC ITS; the v2m path in "
                     "gic-v2m.c is not what you want, and none of this was tested")
        off += l
    check(cpus, "no enabled CPU in the MADT")
    check(gicd is not None, "no GIC distributor in the MADT")
    check(len(gicr) == 1, "expected exactly one redistributor region, got %d" % len(gicr))
    return cpus, gicd, gicr, frames, maint


def parse_gtdt():
    """The four generic-timer PPIs, as GIC INTIDs."""
    b = table("GTDT")
    (_, _, sec_el1, sec_f, ns_el1, ns_f, virt, virt_f,
     el2, el2_f) = struct.unpack_from("<QIIIIIIIII", b, 36)
    # GTDT flags: bit 0 is 1 for edge-triggered, bit 1 is 1 for active-low.
    def flags(f):
        return ("edge" if f & 1 else "level", "low" if f & 2 else "high")
    check(el2 != 0,
          "the GTDT declares no non-secure EL2 timer interrupt; Xen has no "
          "other timer to use")
    return {
        "sec_phys": sec_el1, "ns_phys": ns_el1, "virt": virt, "hyp": el2,
        "flags": flags(ns_f),
    }


def parse_mcfg():
    b = table("MCFG")
    length = struct.unpack_from("<I", b, 4)[0]
    regions = []
    off = 44
    while off + 16 <= length:
        base, seg, sbus, ebus, _ = struct.unpack_from("<QHBBI", b, off)
        regions.append((base, seg, sbus, ebus))
        off += 16
    check(len(regions) == 1, "expected one ECAM region, got %d" % len(regions))
    return regions[0]


def psci_uses_hvc():
    b = table("FACP")
    arm_boot = struct.unpack_from("<H", b, 129)[0]
    check(arm_boot & 1, "the FADT does not claim to be PSCI compliant")
    return bool(arm_boot & 2)


def iomem():
    rows = []
    with open("/proc/iomem") as f:
        for line in f:
            m = re.match(r"^(\S+)-(\S+) : (.*)$", line.rstrip())
            if m:
                rows.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3)))
    check(rows and rows[0][1] != 0,
          "/proc/iomem is redacted -- run this as root")
    return rows


def ram_banks(rows):
    """Merge the top-level System RAM and firmware-reserved runs into DRAM.

    Firmware-reserved pages are holes in "System RAM" but they are still DRAM,
    and the boundaries between them move with every firmware version.  Xen
    booted through EFI takes the real map from GetMemoryMap and ignores this
    node; it is emitted so that the tree also describes the machine correctly
    for anything that does read it.
    """
    banks = []
    for start, end, name in rows:
        if name not in ("System RAM", "reserved"):
            continue
        if banks and start == banks[-1][1] + 1:
            banks[-1][1] = end
        else:
            banks.append([start, end])
    # A leading "reserved" run below DRAM would be firmware, not memory.
    return [b for b in banks if b[1] - b[0] >= (1 << 20)]


def pci_windows(rows):
    """The host bridge's MMIO apertures, as (flags, addr, size)."""
    wins = []
    for start, end, name in rows:
        if name != "PCI Bus 0000:00":
            continue
        # ss = 10b for 32-bit memory space, 11b for 64-bit.
        flags = 0x03000000 if end > 0xFFFFFFFF else 0x02000000
        wins.append((flags, start, end - start + 1))
    check(wins, "found no PCI host bridge aperture in /proc/iomem")
    return wins


def cells64(v):
    return "0x%x 0x%x" % (v >> 32, v & 0xFFFFFFFF)


def main():
    cpus, gicd, gicr, frames, maint = parse_madt()
    timer = parse_gtdt()
    ecam_base, _, sbus, ebus = parse_mcfg()
    rows = iomem()
    banks = ram_banks(rows)
    wins = pci_windows(rows)
    method = "hvc" if psci_uses_hvc() else "smc"

    # DT interrupt specifiers count PPIs from INTID 16.
    def ppi(intid):
        check(16 <= intid < 32, "INTID %d is not a PPI" % intid)
        return intid - 16
    trig = {"level": 4, "edge": 1}[timer["flags"][0]]
    if timer["flags"][1] == "low":
        trig <<= 1

    o = []
    w = o.append
    w("/dts-v1/;")
    w("")
    w("/*")
    w(" * Apple Virtualization.framework generic platform, for Xen.")
    w(" *")
    w(" * Generated by plans/asahi/vz/gen-vz-dtb.py from this machine's ACPI")
    w(" * tables.  Do not hand-edit: re-generate after changing the VM's CPU")
    w(" * count, memory size or device set.")
    w(" */")
    w("")
    w("/ {")
    w('\tcompatible = "apple,virtualization-generic-platform";')
    w('\tmodel = "Apple Virtualization Generic Platform";')
    w("\t#address-cells = <2>;")
    w("\t#size-cells = <2>;")
    w("\tinterrupt-parent = <&gic>;")
    w("")
    w("\tchosen { };")
    w("")
    w("\t/*")
    w("\t * PSCI is how Xen starts the secondary CPUs.  The conduit is SMC even")
    w("\t * though there is no EL3: the outer hypervisor traps SMC from the")
    w("\t * whole nested guest, virtual EL2 included, and emulates it.")
    w("\t */")
    w("\tpsci {")
    w('\t\tcompatible = "arm,psci-1.0", "arm,psci-0.2";')
    w('\t\tmethod = "%s";' % method)
    w("\t};")
    w("")
    w("\tcpus {")
    w("\t\t#address-cells = <1>;")
    w("\t\t#size-cells = <0>;")
    w("")
    for uid, mpidr in cpus:
        check(mpidr <= 0xFFFFFFFF, "MPIDR 0x%x needs two address cells" % mpidr)
        w("\t\tcpu@%x {" % mpidr)
        w('\t\t\tdevice_type = "cpu";')
        w('\t\t\tcompatible = "arm,armv8";')
        w("\t\t\treg = <0x%x>;" % mpidr)
        w('\t\t\tenable-method = "psci";')
        w("\t\t};")
        w("")
    w("\t};")
    w("")
    # Name the interrupts rather than relying on position.  There is no secure
    # physical timer here (the GTDT's secure EL1 GSIV is 0) and no secure world
    # for one to belong to, and the positional form of the binding has no way to
    # say "absent" for entry 0.  Both Xen and Linux read interrupt-names when it
    # is present, so name them and simply omit the ones that do not exist.
    named = [("phys", timer["ns_phys"]), ("virt", timer["virt"]),
             ("hyp-phys", timer["hyp"])]
    if timer["sec_phys"]:
        named.insert(0, ("sec-phys", timer["sec_phys"]))
    w("\t/*")
    w("\t * Xen runs on the non-secure EL2 physical timer, \"hyp-phys\".")
    w("\t */")
    w("\ttimer {")
    w('\t\tcompatible = "arm,armv8-timer";')
    w("\t\tinterrupt-names = %s;" % ", ".join('"%s"' % n for n, _ in named))
    w("\t\tinterrupts = %s;" %
      (",\n\t\t              ".join("<1 %d 0x%x>" % (ppi(i), trig)
                                     for _, i in named)))
    w("\t};")
    w("")
    for start, end in banks:
        w("\tmemory@%x {" % start)
        w('\t\tdevice_type = "memory";')
        w("\t\treg = <%s %s>;" % (cells64(start), cells64(end - start + 1)))
        w("\t};")
        w("")
    w("\tgic: interrupt-controller@%x {" % gicd)
    w('\t\tcompatible = "arm,gic-v3";')
    w("\t\t#interrupt-cells = <3>;")
    w("\t\t#address-cells = <2>;")
    w("\t\t#size-cells = <2>;")
    w("\t\tranges;")
    w("\t\tinterrupt-controller;")
    w("\t\treg = <%s %s>,\t/* GICD */" % (cells64(gicd), cells64(0x10000)))
    for i, (base, size) in enumerate(gicr):
        w("\t\t      <%s %s>;\t/* GICR */" % (cells64(base), cells64(size)))
    w("\t\t#redistributor-regions = <%d>;" % len(gicr))
    if maint:
        w("\t\tinterrupts = <1 %d 4>;" % ppi(maint))
    w("")
    for base, spi_base, count in frames:
        w("\t\t/*")
        w("\t\t * The only MSI controller here.  It matters more than it looks:")
        w("\t\t * the PCI _PRT routes INTA for every slot while every device")
        w("\t\t * reports INTB, so MSIs are the only interrupts that work.")
        w("\t\t */")
        w("\t\tv2m: v2m@%x {" % base)
        w('\t\t\tcompatible = "arm,gic-v2m-frame";')
        w("\t\t\tmsi-controller;")
        w("\t\t\treg = <%s %s>;" % (cells64(base), cells64(0x1000)))
        w("\t\t\tarm,msi-base-spi = <%d>;" % spi_base)
        w("\t\t\tarm,msi-num-spis = <%d>;" % count)
        w("\t\t};")
    w("\t};")
    w("")
    w("\tpcie@%x {" % ecam_base)
    w('\t\tcompatible = "pci-host-ecam-generic";')
    w('\t\tdevice_type = "pci";')
    w("\t\t#address-cells = <3>;")
    w("\t\t#size-cells = <2>;")
    w("\t\tbus-range = <0x%x 0x%x>;" % (sbus, ebus))
    w("\t\treg = <%s %s>;" % (cells64(ecam_base), cells64((ebus - sbus + 1) << 20)))
    w("\t\tdma-coherent;")
    if frames:
        w("\t\tmsi-parent = <&v2m>;")
    w("\t\t/*")
    w("\t\t * No interrupt-map and no #interrupt-cells: the firmware's _PRT")
    w("\t\t * describes INTA for each slot, but every device's Interrupt Pin")
    w("\t\t * register says INTB, so there is no legacy routing that would")
    w("\t\t * ever fire and nothing to describe.  Both Xen and Linux treat an")
    w("\t\t * absent interrupt-map as \"no legacy interrupts\" and go straight")
    w("\t\t * to MSI, which is the only thing that works here anyway.")
    w("\t\t */")
    parts = []
    for flags, addr, size in wins:
        parts.append("<0x%08x %s  %s  %s>" % (flags, cells64(addr),
                                              cells64(addr), cells64(size)))
    w("\t\tranges = " + (",\n\t\t          ".join(parts)) + ";")
    w("\t};")
    w("};")
    print("\n".join(o))


if __name__ == "__main__":
    main()
