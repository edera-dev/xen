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

        /* _SEG from a Method, which is never run, ahead of segment 0's bridge. */
        Device (PCIM)
        {
            Name (_HID, "PNP0A08")
            Method (_SEG, 0, NotSerialized)
            {
                Return (7)
            }
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0xA0000000, 0xAFFFFFFF, 0x0, 0x10000000)
            })
        }

        /*
         * _SEG after a term the walk stops at (OperationRegion), ahead of
         * segment 0's bridge.
         */
        Device (PCIR)
        {
            Name (_HID, "PNP0A08")
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0xB0000000, 0xBFFFFFFF, 0x0, 0x10000000)
            })
            OperationRegion (OPR0, SystemMemory, 0x1000, 0x10)
            Name (_SEG, 9)
        }

        /*
         * _SEG values too large for a segment, ahead of segment 0's bridge:
         * iasl stores the first in a DWord and the second in a QWord, the
         * widths no other bridge here has.
         */
        Device (PCID)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, 0x10000)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0xD0000000, 0xDFFFFFFF, 0x0, 0x10000000)
            })
        }

        Device (PCIQ)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, 0x100000000)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0xE0000000, 0xEFFFFFFF, 0x0, 0x10000000)
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

        /*
         * _SEG read before a term the walk stops at (OperationRegion), so the
         * segment is still known.
         */
        Device (PCIS)
        {
            Name (_HID, "PNP0A08")
            Name (_SEG, 8)
            Name (_CRS, ResourceTemplate ()
            {
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x0, 0xC0000000, 0xCFFFFFFF, 0x0, 0x10000000)
            })
            OperationRegion (OPR1, SystemMemory, 0x1000, 0x10)
        }
    }
}
