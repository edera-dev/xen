/* Portions taken from Linux arch arm64 */
#ifndef __ASM_ARM64_SYSTEM_H
#define __ASM_ARM64_SYSTEM_H

#include <asm/arm64/cmpxchg.h>

/* Uses uimm4 as a bitmask to select the clearing of one or more of
 * the DAIF exception mask bits:
 * bit 3 selects the D mask,
 * bit 2 the A mask,
 * bit 1 the I mask and
 * bit 0 the F mask.
*/

/*
 * Which DAIF bits local_irq_{disable,enable}() act on.
 *
 * Normally just I: FIQ belongs to the Secure world, Xen never receives one,
 * and head.S leaves PSTATE.F masked forever.
 *
 * Apple's AIC has no Secure world to belong to and delivers Xen's own
 * interrupts -- the timers and fast IPIs -- as FIQs.  There, F must track I:
 *
 *  - leave F masked and nothing is ever delivered.  The first thing to notice
 *    is setup_virt_paging()'s smp_call_function(), which waits forever for
 *    secondaries that cannot take the IPI.
 *  - unmask F independently of I and AIC handlers run inside
 *    local_irq_disable() sections, defeating the very protection those
 *    sections exist to provide.
 *
 * So move them together.  arm64 Linux does the same, for the same reason.
 */
#ifdef CONFIG_APPLE_AIC
# define DAIF_IRQ_BITS "3"    /* I and F */
#else
# define DAIF_IRQ_BITS "2"    /* I only */
#endif

#define local_fiq_disable()   asm volatile ( "msr daifset, #1\n" ::: "memory" )
#define local_fiq_enable()    asm volatile ( "msr daifclr, #1\n" ::: "memory" )
#define local_irq_disable()   \
    asm volatile ( "msr daifset, #" DAIF_IRQ_BITS "\n" ::: "memory" )
#define local_irq_enable()    \
    asm volatile ( "msr daifclr, #" DAIF_IRQ_BITS "\n" ::: "memory" )
#define local_abort_disable() asm volatile ( "msr daifset, #4\n" ::: "memory" )
#define local_abort_enable()  asm volatile ( "msr daifclr, #4\n" ::: "memory" )

#define local_save_flags(x)                                      \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile(                                                \
        "mrs    %0, daif    // local_save_flags\n"               \
                : "=r" (x)                                       \
                :                                                \
                : "memory");                                     \
})

#define local_irq_save(x)                                        \
({                                                               \
    local_save_flags(x);                                         \
    local_irq_disable();                                         \
})
#define local_irq_restore(x)                                     \
({                                                               \
    BUILD_BUG_ON(sizeof(x) != sizeof(long));                     \
    asm volatile (                                               \
        "msr    daif, %0                // local_irq_restore"    \
        :                                                        \
        : "r" (x)                                                \
        : "memory");                                             \
})

static inline int local_irq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !(flags & PSR_IRQ_MASK);
}

static inline int local_fiq_is_enabled(void)
{
    unsigned long flags;
    local_save_flags(flags);
    return !(flags & PSR_FIQ_MASK);
}

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
