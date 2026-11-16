/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for PCI_SBDF().  Each case builds an SBDF in the three forms the
 * macro takes, from values read at run time, and checks the result and the
 * fields pci_sbdf_t decodes.  The test is built to trap on a shift whose
 * result does not fit its type, so a segment that shifts into the sign bit of
 * an int fails it.
 */

#include "harness.h"

static const struct {
    uint16_t seg;
    uint8_t bus, devfn;
} cases[] = {
    { 0,      0x00, 0x00 },
    { 0x7fff, 0xff, 0xff },
    { 0x8000, 0x00, 0x08 },
    { 0xe83f, 0x12, 0x34 },
    { 0xffff, 0xff, 0xff },
};

static const char *test_name;

static bool check(const char *form, pci_sbdf_t sbdf, uint32_t want)
{
    if ( sbdf.sbdf == want && sbdf.seg == (uint16_t)(want >> 16) &&
         sbdf.bus == (uint8_t)(want >> 8) && sbdf.devfn == (uint8_t)want )
        return true;

    printf("%s: %s gave %#x (segment %#x, bus %#x, devfn %#x), want %#x\n",
           test_name, form, sbdf.sbdf, sbdf.seg, sbdf.bus, sbdf.devfn, want);
    return false;
}

static bool sbdf_of(uint16_t s, uint8_t b, uint8_t df)
{
    /* Read at run time, so that the compiler cannot fold the shifts. */
    volatile uint16_t vseg = s;
    volatile uint8_t vbus = b, vdevfn = df;
    uint16_t seg = vseg;
    uint8_t bus = vbus, devfn = vdevfn;
    uint32_t want = ((uint32_t)s << 16) | (b << 8) | df;

    return check("PCI_SBDF(seg, bdf)",
                 PCI_SBDF(seg, (bus << 8) | devfn), want) &
           check("PCI_SBDF(seg, bus, devfn)",
                 PCI_SBDF(seg, bus, devfn), want) &
           check("PCI_SBDF(seg, bus, slot, func)",
                 PCI_SBDF(seg, bus, devfn >> 3, devfn & 7), want);
}

int main(void)
{
    unsigned int i, failed = 0;
    char name[64];

    for ( i = 0; i < ARRAY_SIZE(cases); i++ )
    {
        snprintf(name, sizeof(name), "segment %#x, bus %#x, devfn %#x",
                 cases[i].seg, cases[i].bus, cases[i].devfn);

        /* Named first, so that a trap shows which case it was. */
        test_name = name;
        printf("%s\n", test_name);
        fflush(stdout);

        if ( !sbdf_of(cases[i].seg, cases[i].bus, cases[i].devfn) )
            failed++;
    }

    printf("%s\n", failed ? "FAIL" : "PASS");

    return failed != 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
