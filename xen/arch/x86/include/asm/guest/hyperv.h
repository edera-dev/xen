/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/guest/hyperv.h
 *
 * Copyright (c) 2019 Microsoft.
 */

#ifndef __X86_GUEST_HYPERV_H__
#define __X86_GUEST_HYPERV_H__

#include <xen/types.h>

/*
 * The specification says: "The partition reference time is computed
 * by the following formula:
 *
 * ReferenceTime = ((VirtualTsc * TscScale) >> 64) + TscOffset
 *
 * The multiplication is a 64 bit multiplication, which results in a
 * 128 bit number which is then shifted 64 times to the right to obtain
 * the high 64 bits."
 */
static inline uint64_t hv_scale_tsc(uint64_t tsc, uint64_t scale,
                                    int64_t offset)
{
    uint64_t result;

    /*
     * Quadword MUL takes an implicit operand in RAX, and puts the result
     * in RDX:RAX. Because we only want the result of the multiplication
     * after shifting right by 64 bits, we therefore only need the content
     * of RDX.
     */
    asm ( "mulq %[scale]"
          : "+a" (tsc), "=d" (result)
          : [scale] "rm" (scale) );

    return result + offset;
}

#ifdef CONFIG_HYPERV_GUEST

#include <asm/guest/hypervisor.h>

struct ms_hyperv_info {
    uint32_t features;
    uint32_t misc_features;
    uint32_t hints;
    uint32_t nested_features;
    uint32_t max_vp_index;
    uint32_t max_lp_index;
};
extern struct ms_hyperv_info ms_hyperv;

/* True when Xen has detected that it is running as a Hyper-V guest. */
extern bool hyperv_guest;

const struct hypervisor_ops *hyperv_probe(void);

#else

#define hyperv_guest 0

static inline const struct hypervisor_ops *hyperv_probe(void) { return NULL; }

#endif /* CONFIG_HYPERV_GUEST */
#endif /* __X86_GUEST_HYPERV_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
