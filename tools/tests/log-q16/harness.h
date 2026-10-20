/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for the Q16 logarithms.
 */

#ifndef _TEST_HARNESS_
#define _TEST_HARNESS_

#include <stdint.h>

#define __init

static inline unsigned int flsl(unsigned long x)
{
    return x ? 8 * sizeof(x) - __builtin_clzl(x) : 0;
}

unsigned long log2_q16(unsigned long x);
unsigned long ln_ratio_q16(unsigned long n, unsigned long d);

#endif
