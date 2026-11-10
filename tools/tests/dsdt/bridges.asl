/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * One host bridge per segment, each described in a different way, and each
 * with a window of its own.
 */
DefinitionBlock ("", "DSDT", 2, "XEN", "BRIDGES", 1)
{
    Scope (\_SB)
    {
        /* _SEG of One, ahead of segment 0's bridge. */
        Device (PCI1)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, One)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x60000000, 0x6FFFFFFF, 0x0, 0x10000000)
            })
        }

        /* No _SEG, so segment 0. */
        Device (PCI0)
        {
            Name (_HID, "PNP0A08")
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x10000000, 0x1FFFFFFF, 0x0, 0x10000000)
            })
        }

        /* _SEG in a BytePrefix integer. */
        Device (PCI2)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, 2)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x20000000, 0x2FFFFFFF, 0x0, 0x10000000)
            })
        }

        /* Known as a host bridge by its _CID alone. */
        Device (PCI3)
        {
            Name (_HID, "TEST0001")
            Name (_CID, "PNP0A03")
            Name (_SEG, 3)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x30000000, 0x3FFFFFFF, 0x0, 0x10000000)
            })
        }

        /* A _CRS that only a Method computes, which is never run. */
        Device (PCI4)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, 4)
            Method (_CRS, 0, Serialized)
            {
                Return (ResourceTemplate ()
                {
                    DWordMemory (ResourceProducer, PosDecode, MinFixed,
                        MaxFixed, NonCacheable, ReadWrite,
                        0x0, 0x40000000, 0x4FFFFFFF, 0x0, 0x10000000)
                })
            }
        }

        /* _HID as a compressed EisaId. */
        Device (PCI5)
        {
            Name (_HID, EisaId ("PNP0A08"))
            Name (_SEG, 5)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x50000000, 0x5FFFFFFF, 0x0, 0x10000000)
            })
        }

        /* Known as a host bridge by an EisaId _CID alone. */
        Device (PCI6)
        {
            Name (_HID, "TEST0002")
            Name (_CID, EisaId ("PNP0A03"))
            Name (_SEG, 6)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x70000000, 0x7FFFFFFF, 0x0, 0x10000000)
            })
        }

        /* _SEG in a WordPrefix integer. */
        Device (PCIW)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, 0x100)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0x80000000, 0x8FFFFFFF, 0x0, 0x10000000)
            })
        }
    }
}
