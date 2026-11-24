/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * As Linux's asm/lse.h: LSE atomics always complete, where load/store
 * exclusive loops can livelock under contention. Each atomic keeps the
 * barriers of its load/store exclusive version.
 */
#ifndef __ASM_ARM64_LSE_H
#define __ASM_ARM64_LSE_H

#include <asm/alternative.h>

#define __LSE_PREAMBLE ".arch_extension lse\n"

/* Patched at boot, like Linux's alternative_has_cap_likely(). */
static always_inline bool system_uses_lse_atomics(void)
{
    register_t ret;

    asm_inline volatile ( ALTERNATIVE("mov %0, #0", "mov %0, #1",
                                      ARM64_HAS_LSE_ATOMICS)
                          : "=r" (ret) );

    return likely(ret);
}

#endif /* __ASM_ARM64_LSE_H */
