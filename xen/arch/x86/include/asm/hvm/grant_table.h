/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asm-x86/hvm/grant_table.h
 *
 * Grant table interfaces for HVM guests
 *
 * Copyright (C) 2017 Wei Liu <wei.liu2@citrix.com>
 */

#ifndef __X86_HVM_GRANT_TABLE_H__
#define __X86_HVM_GRANT_TABLE_H__

#include <xen/mm-frame.h>

/* A caller's page of grant ops, kept translated and mapped across the ops. */
struct gnttab_ops_pin {
    struct page_info *page;
    void *va;
    gfn_t gfn;
    mfn_t pt[4];
};

#ifdef CONFIG_HVM

int create_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                             unsigned int flags,
                             unsigned int cache_flags);
int replace_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                              uint64_t new_addr, unsigned int flags);
void grant_p2m_unmap_batch_begin(void);
int grant_p2m_unmap_batch_end(void);
void *grant_ops_pin(struct gnttab_ops_pin *pin, unsigned long addr);
void grant_ops_unpin(struct gnttab_ops_pin *pin);
bool grant_ops_pin_stale(const struct gnttab_ops_pin *pin, mfn_t written);

#else

#include <public/grant_table.h>

static inline int create_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                                           unsigned int flags,
                                           unsigned int cache_flags)
{
    return GNTST_general_error;
}

static inline int replace_grant_p2m_mapping(uint64_t addr, mfn_t frame,
                                            uint64_t new_addr, unsigned int flags)
{
    return GNTST_general_error;
}

static inline void grant_p2m_unmap_batch_begin(void) {}
static inline int grant_p2m_unmap_batch_end(void) { return 0; }

static inline void *grant_ops_pin(struct gnttab_ops_pin *pin,
                                  unsigned long addr)
{
    return NULL;
}

static inline void grant_ops_unpin(struct gnttab_ops_pin *pin) {}

static inline bool grant_ops_pin_stale(const struct gnttab_ops_pin *pin,
                                       mfn_t written)
{
    return false;
}

#endif

#endif /* __X86_HVM_GRANT_TABLE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
