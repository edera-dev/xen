/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * The host bridge part of QEMU's Arm virt DSDT, in the order that
 * hw/pci-host/gpex-acpi.c builds it: the PCI interrupt link devices ahead of
 * the bridge, and in the bridge a _PRT VarPackage and a _CBA Method before
 * _CRS, then _OSC, _DSM and the RES0 Device after it.
 *
 * Two differences from QEMU:
 *   - iasl makes a Package into a VarPackage, as QEMU does for _PRT, only
 *     when it is declared longer than 255 elements, so _PRT is declared
 *     0x100 long and gives one slot's four entries, not QEMU's 128;
 *   - COM0's _CRS has a DWordMemory where QEMU has a Memory32Fixed, so that
 *     taking the windows of a device that is not a host bridge would show.
 */
DefinitionBlock ("", "DSDT", 2, "XEN", "VIRT", 1)
{
    Scope (\_SB)
    {
        Device (COM0)
        {
            Name (_HID, "ARMH0011")
            Name (_UID, Zero)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceConsumer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x00000000, 0x09000000, 0x09000FFF, 0x00000000, 0x00001000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x21 }
            })
        }

        Device (L000)
        {
            Name (_HID, "PNP0C0F")
            Name (_UID, Zero)
            Name (_PRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x23 }
            })
            Name (_CRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x23 }
            })
            Method (_SRS, 1, NotSerialized)
            {
            }
        }

        Device (L001)
        {
            Name (_HID, "PNP0C0F")
            Name (_UID, One)
            Name (_PRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x24 }
            })
            Name (_CRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x24 }
            })
            Method (_SRS, 1, NotSerialized)
            {
            }
        }

        Device (L002)
        {
            Name (_HID, "PNP0C0F")
            Name (_UID, 0x02)
            Name (_PRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x25 }
            })
            Name (_CRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x25 }
            })
            Method (_SRS, 1, NotSerialized)
            {
            }
        }

        Device (L003)
        {
            Name (_HID, "PNP0C0F")
            Name (_UID, 0x03)
            Name (_PRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x26 }
            })
            Name (_CRS, ResourceTemplate ()
            {
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 0x26 }
            })
            Method (_SRS, 1, NotSerialized)
            {
            }
        }

        Device (PCI0)
        {
            Name (_HID, "PNP0A08")
            Name (_CID, "PNP0A03")
            Name (_SEG, Zero)
            Name (_BBN, Zero)
            Name (_UID, Zero)
            Name (_STR, Unicode ("PCIe 0 Device"))
            Name (_CCA, One)
            Name (_PRT, Package (0x100)
            {
                Package () { 0xFFFF, Zero, L000, Zero },
                Package () { 0xFFFF, One, L001, Zero },
                Package () { 0xFFFF, 0x02, L002, Zero },
                Package () { 0xFFFF, 0x03, L003, Zero },
            })

            Method (_CBA, 0, NotSerialized)
            {
                Return (0x4010000000)
            }

            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000, 0x0000, 0x00FF, 0x0000, 0x0100)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x00000000, 0x10000000, 0x3EFEFFFF, 0x00000000, 0x2EFF0000)
                DWordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    EntireRange,
                    0x00000000, 0x00000000, 0x0000FFFF, 0x3EFF0000, 0x00010000)
                QWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x8000000000, 0xFFFFFFFFFF, 0x0, 0x8000000000)
            })

            Name (SUPP, Zero)
            Name (CTRL, Zero)
            Method (_OSC, 4, NotSerialized)
            {
                CreateDWordField (Arg3, Zero, CDW1)
                CDW1 |= 0x04
                Return (Arg3)
            }

            Method (_DSM, 4, NotSerialized)
            {
                Return (Buffer (One) { 0x00 })
            }

            Device (RES0)
            {
                Name (_HID, "PNP0C02")
                Name (_CRS, ResourceTemplate ()
                {
                    QWordMemory (ResourceConsumer, PosDecode, MinFixed,
                        MaxFixed, NonCacheable, ReadWrite,
                        0x0, 0x4010000000, 0x401FFFFFFF, 0x0, 0x10000000)
                })
            }
        }
    }
}
