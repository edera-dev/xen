/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for the Q16 logarithms, against libm's long double ones.
 */

#include <limits.h>
#include <math.h>
#include <stdio.h>

#include "harness.h"

#define Q16 65536.0L
/*
 * Errors count steps of the Q16 format, so an error of 1 means the result is
 * 1/65536 off the exact value. These are the bounds xen/lib/log-q16.c
 * documents: log2_q16() truncates, so it is never above the exact value.
 */
#define LOG2_MAX_ERROR 1.001L
#define LN_MAX_ERROR 2.0L

static unsigned int failures;
static long double worst_log2, worst_ln;

#define report(fmt, args...) do { printf(fmt, ## args); failures++; } while ( 0 )

static void check_log2(unsigned long x)
{
    long double got = log2_q16(x) / Q16, want = log2l(x);
    long double error = (want - got) * Q16;

    if ( error > worst_log2 )
        worst_log2 = error;
    if ( error < 0 || error > LOG2_MAX_ERROR )
        report("log2_q16(%lu) = %.8Lf, want %.8Lf\n", x, got, want);
    if ( x > 1 && log2_q16(x) < log2_q16(x - 1) )
        report("log2_q16(%lu) is below log2_q16(%lu)\n", x, x - 1);
}

static void check_ln_ratio(unsigned long n, unsigned long d)
{
    long double got = ln_ratio_q16(n, d) / Q16;
    long double want = logl((long double)n / d);
    long double error = fabsl(got - want) * Q16;

    if ( error > worst_ln )
        worst_ln = error;
    if ( error > LN_MAX_ERROR )
        report("ln_ratio_q16(%lu, %lu) = %.8Lf, want %.8Lf\n", n, d, got, want);
    if ( n > d && ln_ratio_q16(n, d) < ln_ratio_q16(n - 1, d) )
        report("ln_ratio_q16(%lu, %lu) is below ln_ratio_q16(%lu, %lu)\n",
               n, d, n - 1, d);
}

/* 4 KiB pages in a GiB. */
#define GIB (1UL << 18)

int main(void)
{
    unsigned int i, bits = sizeof(unsigned long) * 8;
    unsigned long x, d;

    /* Each power of two exactly, and its neighbours. */
    for ( i = 0; i < bits; i++ )
    {
        if ( log2_q16(1UL << i) != (unsigned long)i << 16 )
            report("log2_q16(2^%u) is not %u\n", i, i);
        if ( i )
            check_log2((1UL << i) - 1);
        check_log2((1UL << i) + 1);
    }
    check_log2(ULONG_MAX);

    /* Every x below 2^20, then 65536 evenly spaced x per power of two. */
    for ( x = 1; x < (1UL << 20); x++ )
        check_log2(x);
    for ( i = 20; i < bits; i++ )
        for ( x = 1UL << i; x >> i == 1; x += 1UL << (i - 16) )
            check_log2(x);

    /*
     * Host sizes up to 2 TiB in 0.5 GiB steps, in 4 KiB pages, against a
     * divisor at every GiB up to 64 GiB and every power of two up to 1 TiB.
     */
    for ( d = GIB; d <= 1024 * GIB; d += d < 64 * GIB ? GIB : d )
        for ( x = 0; x <= 2048 * GIB; x += GIB / 2 )
            check_ln_ratio(d + x, d);
    check_ln_ratio(1, 1);
    check_ln_ratio(ULONG_MAX, 1);
    check_ln_ratio(ULONG_MAX, ULONG_MAX);

    printf("worst error: log2_q16 %.3Lf/65536, ln_ratio_q16 %.3Lf/65536\n",
           worst_log2, worst_ln);
    printf("%s\n", failures ? "FAIL" : "PASS");

    return failures != 0;
}
