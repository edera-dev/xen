/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Logarithms in 16-bit fixed point (Q16), for code that runs without floating
 * point. log2_q16() truncates, so it is never above the exact value and at
 * most about 1/65536 below it. ln_ratio_q16() is within 2/65536 of it.
 */

#include <xen/bitops.h>
#include <xen/init.h>
#include <xen/lib.h>

/* log2(x) in Q16, for x >= 1. */
unsigned long __init log2_q16(unsigned long x)
{
    unsigned int i, ip = flsl(x) - 1;
    unsigned long y = (unsigned long)ip << 16;
    /* x / 2^ip, in [1, 2) as Q30, so that z * z below fits in 64 bits. */
    uint64_t z = ip >= 30 ? x >> (ip - 30) : (uint64_t)x << (30 - ip);

    /* Squaring z doubles its log, which shifts the next bit into place. */
    for ( i = 16; i-- > 0; )
    {
        z = (z * z) >> 30;
        if ( z >= (2ULL << 30) )
        {
            z >>= 1;
            y |= 1UL << i;
        }
    }

    return y;
}

#define LN2_Q32 2977044472ULL

/* ln(n / d) in Q16, for n >= d >= 1. */
unsigned long __init ln_ratio_q16(unsigned long n, unsigned long d)
{
    return (LN2_Q32 * (log2_q16(n) - log2_q16(d))) >> 32;
}
