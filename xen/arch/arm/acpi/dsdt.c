/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Extract the PCI host bridge memory windows from the DSDT.
 *
 * The windows a host bridge decodes live in its _CRS, and MCFG describes only
 * config space, so without them Xen cannot tell whether a BAR lies inside a
 * region the bridge actually claims.  pci_check_bar() needs that, and gets it
 * from the device tree's "ranges" on a device tree system.
 *
 * _CRS is AML, and Xen has no interpreter: it carries only the table subset of
 * ACPICA, deliberately, since executing firmware bytecode in the hypervisor is
 * an attack surface x86 has always left to the hardware domain.  However, a
 * host bridge's _CRS is normally not a Method computing something at runtime
 * but a Name holding a fixed ResourceTemplate buffer.  That needs the AML to be
 * walked, not executed, which is all this does.
 *
 * Only the constructs required to find "Device { Name(_HID, ...) ...
 * Name(_CRS, Buffer) }" are understood.  Anything else stops the walk of the
 * term list it appears in, so an unexpected encoding costs the windows for that
 * bridge and nothing else: the caller then behaves exactly as it did before
 * this existed, rather than acting on a misparse.
 */

#include <xen/acpi.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/rangeset.h>

#include <asm/acpi-dsdt.h>

/* AML opcodes, only those handled here. */
#define AML_ZERO_OP             0x00
#define AML_ONE_OP              0x01
#define AML_NAME_OP             0x08
#define AML_BYTE_PREFIX         0x0a
#define AML_WORD_PREFIX         0x0b
#define AML_DWORD_PREFIX        0x0c
#define AML_STRING_PREFIX       0x0d
#define AML_QWORD_PREFIX        0x0e
#define AML_SCOPE_OP            0x10
#define AML_BUFFER_OP           0x11
#define AML_PACKAGE_OP          0x12
#define AML_VAR_PACKAGE_OP      0x13
#define AML_METHOD_OP           0x14
#define AML_DUAL_NAME_PREFIX    0x2e
#define AML_MULTI_NAME_PREFIX   0x2f
#define AML_ROOT_CHAR           0x5c
#define AML_PARENT_CHAR         0x5e
#define AML_EXT_OP_PREFIX       0x5b
#define AML_EXT_FIELD_OP        0x81
#define AML_EXT_DEVICE_OP       0x82
#define AML_EXT_PROCESSOR_OP    0x83
#define AML_EXT_POWER_RES_OP    0x84
#define AML_EXT_THERMAL_ZONE_OP 0x85
#define AML_EXT_INDEX_FIELD_OP  0x86
#define AML_EXT_BANK_FIELD_OP   0x87

/* Large resource descriptor types used by a host bridge's _CRS. */
#define ACPI_RESOURCE_END_TAG           0x79
#define ACPI_RESOURCE_WORD_ADDRESS      0x88
#define ACPI_RESOURCE_DWORD_ADDRESS     0x87
#define ACPI_RESOURCE_QWORD_ADDRESS     0x8a
#define ACPI_RESOURCE_TYPE_MEMORY       0

struct aml_span {
    const uint8_t *p;
    const uint8_t *end;
};

/*
 * A PkgLength is one to four bytes: the top two bits of the first give the
 * number of extra bytes, and when there are none the low six bits are the
 * length.  The length counts the PkgLength encoding itself.
 */
static bool __init aml_pkglength(struct aml_span *s, uint32_t *len)
{
    const uint8_t *p = s->p;
    unsigned int extra;
    uint32_t v;

    if ( p >= s->end )
        return false;

    extra = p[0] >> 6;
    if ( p + 1 + extra > s->end )
        return false;

    if ( !extra )
        v = p[0] & 0x3f;
    else
    {
        unsigned int i;

        v = p[0] & 0x0f;
        for ( i = 0; i < extra; i++ )
            v |= (uint32_t)p[1 + i] << (4 + i * 8);
    }

    if ( v < 1 + extra )
        return false;

    s->p = p + 1 + extra;
    *len = v;

    return true;
}

/*
 * Step over a NameString, returning its final NameSeg so the caller can tell
 * _HID from _CRS without caring about the scoping in front of it.
 */
static bool __init aml_namestring(struct aml_span *s, const uint8_t **last_seg)
{
    unsigned int segs = 1;

    while ( s->p < s->end &&
            (*s->p == AML_ROOT_CHAR || *s->p == AML_PARENT_CHAR) )
        s->p++;

    if ( s->p >= s->end )
        return false;

    switch ( *s->p )
    {
    case AML_ZERO_OP:               /* NullName */
        s->p++;
        *last_seg = NULL;
        return true;

    case AML_DUAL_NAME_PREFIX:
        segs = 2;
        s->p++;
        break;

    case AML_MULTI_NAME_PREFIX:
        s->p++;
        if ( s->p >= s->end )
            return false;
        segs = *s->p++;
        if ( !segs )
            return false;
        break;

    default:
        break;
    }

    if ( s->p + (uint64_t)segs * 4 > s->end )
        return false;

    *last_seg = s->p + (segs - 1) * 4;
    s->p += segs * 4;

    return true;
}

/* Step over a fixed-width or buffer/package data object following a Name. */
static bool __init aml_skip_data(struct aml_span *s)
{
    uint32_t len;
    const uint8_t *start;

    if ( s->p >= s->end )
        return false;

    switch ( *s->p )
    {
    case AML_ZERO_OP:
    case AML_ONE_OP:
        s->p += 1;
        return true;

    case AML_BYTE_PREFIX:  s->p += 2; break;
    case AML_WORD_PREFIX:  s->p += 3; break;
    case AML_DWORD_PREFIX: s->p += 5; break;
    case AML_QWORD_PREFIX: s->p += 9; break;

    case AML_STRING_PREFIX:
        s->p++;
        while ( s->p < s->end && *s->p )
            s->p++;
        s->p++;                     /* the NUL */
        break;

    case AML_BUFFER_OP:
    case AML_PACKAGE_OP:
    case AML_VAR_PACKAGE_OP:
        s->p++;
        start = s->p;
        if ( !aml_pkglength(s, &len) )
            return false;
        s->p = start + len;
        break;

    default:
        return false;               /* something we do not model */
    }

    return s->p <= s->end;
}

/*
 * Step over one term that is not a Name: a Method, a nested Device, or another
 * construct introduced by a PkgLength.  Returns false for anything else, which
 * stops the caller rather than letting it resynchronise on misread bytes.
 */
static bool __init aml_skip_term(struct aml_span *s)
{
    const uint8_t *start;
    uint32_t len;

    if ( s->p >= s->end )
        return false;

    if ( *s->p == AML_METHOD_OP || *s->p == AML_SCOPE_OP )
        s->p++;
    else if ( *s->p == AML_EXT_OP_PREFIX && s->p + 1 < s->end )
    {
        switch ( s->p[1] )
        {
        case AML_EXT_DEVICE_OP:
        case AML_EXT_PROCESSOR_OP:
        case AML_EXT_POWER_RES_OP:
        case AML_EXT_THERMAL_ZONE_OP:
        case AML_EXT_FIELD_OP:
        case AML_EXT_INDEX_FIELD_OP:
        case AML_EXT_BANK_FIELD_OP:
            s->p += 2;
            break;

        default:
            return false;
        }
    }
    else
        return false;

    start = s->p;
    if ( !aml_pkglength(s, &len) || start + len > s->end )
        return false;

    s->p = start + len;

    return true;
}

/* Decode the resource descriptors of a _CRS buffer into @windows. */
static int __init crs_add_windows(const uint8_t *p, const uint8_t *end,
                                  struct rangeset *windows)
{
    int added = 0;

    while ( p < end )
    {
        unsigned int len;
        uint64_t min, max;
        const uint8_t *b;

        if ( *p == ACPI_RESOURCE_END_TAG )
            break;

        if ( !(*p & 0x80) )         /* small descriptor */
        {
            p += 1 + (*p & 0x07);
            continue;
        }

        if ( p + 3 > end )
            return -EINVAL;

        len = p[1] | ((unsigned int)p[2] << 8);
        b = p + 3;
        if ( b + len > end )
            return -EINVAL;

        /*
         * Address space descriptors share a layout: resource type, two flag
         * bytes, then granularity, min, max, translation offset and length at
         * the descriptor's width.  Only memory is of interest here.
         */
        if ( len >= 3 && b[0] == ACPI_RESOURCE_TYPE_MEMORY )
        {
            switch ( *p )
            {
            case ACPI_RESOURCE_WORD_ADDRESS:
                if ( len < 13 )
                    return -EINVAL;
                min = b[5] | ((uint64_t)b[6] << 8);
                max = b[7] | ((uint64_t)b[8] << 8);
                break;

            case ACPI_RESOURCE_DWORD_ADDRESS:
                if ( len < 23 )
                    return -EINVAL;
                min = b[7] | ((uint64_t)b[8] << 8) | ((uint64_t)b[9] << 16) |
                      ((uint64_t)b[10] << 24);
                max = b[11] | ((uint64_t)b[12] << 8) | ((uint64_t)b[13] << 16) |
                      ((uint64_t)b[14] << 24);
                break;

            case ACPI_RESOURCE_QWORD_ADDRESS:
            {
                unsigned int i;

                if ( len < 43 )
                    return -EINVAL;
                for ( min = 0, i = 0; i < 8; i++ )
                    min |= (uint64_t)b[11 + i] << (i * 8);
                for ( max = 0, i = 0; i < 8; i++ )
                    max |= (uint64_t)b[19 + i] << (i * 8);
                break;
            }

            default:
                min = max = 0;
                break;
            }

            if ( max >= min && max )
            {
                if ( rangeset_add_range(windows, min, max) )
                    return -ENOMEM;
                added++;
            }
        }

        p = b + len;
    }

    return added;
}

struct crs_search {
    uint16_t segment;
    struct rangeset *windows;
    bool found;
};

/*
 * Scan one Device's term list for the three Names that matter, and if it is
 * the host bridge being looked for, decode its windows.
 */
static int __init scan_device(struct aml_span body, struct crs_search *search)
{
    const uint8_t *crs = NULL, *crs_end = NULL;
    bool is_host_bridge = false;
    uint16_t segment = 0;

    while ( body.p < body.end )
    {
        const uint8_t *seg;
        struct aml_span data;
        uint32_t len;

        if ( *body.p != AML_NAME_OP )
        {
            /*
             * A host bridge carries Methods and a Device per slot between its
             * _HID and its _CRS, so these have to be stepped over rather than
             * treated as the end of the device.
             */
            if ( !aml_skip_term(&body) )
                break;
            continue;
        }

        body.p++;
        if ( !aml_namestring(&body, &seg) || !seg )
            return -EINVAL;

        data = body;

        if ( !memcmp(seg, "_HID", 4) || !memcmp(seg, "_CID", 4) )
        {
            /* Either a string, or a compressed EisaId in a DWord. */
            if ( data.p < data.end && *data.p == AML_STRING_PREFIX &&
                 (!memcmp(data.p + 1, "PNP0A08", 8) ||
                  !memcmp(data.p + 1, "PNP0A03", 8)) )
                is_host_bridge = true;
            else if ( data.p + 5 <= data.end && *data.p == AML_DWORD_PREFIX &&
                      data.p[1] == 0xd0 && data.p[2] == 0x41 &&
                      data.p[3] == 0x0a &&
                      (data.p[4] == 0x08 || data.p[4] == 0x03) )
                is_host_bridge = true;
        }
        else if ( !memcmp(seg, "_SEG", 4) && data.p < data.end )
        {
            if ( *data.p == AML_ZERO_OP )
                segment = 0;
            else if ( *data.p == AML_BYTE_PREFIX && data.p + 2 <= data.end )
                segment = data.p[1];
            else if ( *data.p == AML_WORD_PREFIX && data.p + 3 <= data.end )
                segment = data.p[1] | ((uint16_t)data.p[2] << 8);
        }
        else if ( !memcmp(seg, "_CRS", 4) && data.p < data.end &&
                  *data.p == AML_BUFFER_OP )
        {
            struct aml_span buf = data;

            buf.p++;
            if ( !aml_pkglength(&buf, &len) )
                return -EINVAL;

            crs_end = data.p + 1 + len;
            /* Step over the buffer size, an integer, to reach the data. */
            if ( !aml_skip_data(&buf) )
                return -EINVAL;
            crs = buf.p;

            if ( crs_end > data.end )
                return -EINVAL;
        }

        if ( !aml_skip_data(&body) )
            return -EINVAL;
    }

    if ( !is_host_bridge || !crs || segment != search->segment )
        return 0;

    if ( crs_add_windows(crs, crs_end, search->windows) > 0 )
        search->found = true;

    return 0;
}

/* Walk a term list, recursing into Scope and Device. */
static int __init scan_terms(struct aml_span s, struct crs_search *search,
                             unsigned int depth)
{
    if ( depth > 8 )
        return 0;

    while ( s.p < s.end && !search->found )
    {
        const uint8_t *start;
        struct aml_span inner;
        const uint8_t *seg;
        uint32_t len;
        bool device = false;

        if ( *s.p == AML_EXT_OP_PREFIX && s.p + 1 < s.end &&
             s.p[1] == AML_EXT_DEVICE_OP )
        {
            s.p += 2;
            device = true;
        }
        else if ( *s.p == AML_SCOPE_OP )
            s.p++;
        else if ( *s.p == AML_NAME_OP )
        {
            s.p++;
            if ( !aml_namestring(&s, &seg) || !aml_skip_data(&s) )
                return -EINVAL;
            continue;
        }
        else if ( *s.p == AML_METHOD_OP )
        {
            s.p++;
            start = s.p;
            if ( !aml_pkglength(&s, &len) )
                return -EINVAL;
            s.p = start + len;
            continue;
        }
        else
            break;              /* an encoding we do not model */

        start = s.p;
        if ( !aml_pkglength(&s, &len) || start + len > s.end )
            return -EINVAL;

        inner.p = s.p;
        inner.end = start + len;
        s.p = start + len;

        if ( !aml_namestring(&inner, &seg) )
            return -EINVAL;

        if ( device )
            scan_device(inner, search);
        else
            scan_terms(inner, search, depth + 1);
    }

    return 0;
}

int __init acpi_pci_get_host_bridge_windows(uint16_t segment,
                                            struct rangeset *windows)
{
    struct acpi_table_header *dsdt;
    struct crs_search search = { .segment = segment, .windows = windows };
    struct aml_span s;
    acpi_status status;

    status = acpi_get_table(ACPI_SIG_DSDT, 0, &dsdt);
    if ( ACPI_FAILURE(status) )
        return -ENODEV;

    if ( dsdt->length <= sizeof(*dsdt) )
        return -EINVAL;

    s.p = (const uint8_t *)dsdt + sizeof(*dsdt);
    s.end = (const uint8_t *)dsdt + dsdt->length;

    scan_terms(s, &search, 0);

    return search.found ? 0 : -ENODEV;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
