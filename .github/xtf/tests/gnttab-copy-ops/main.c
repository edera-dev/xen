/**
 * @file tests/gnttab-copy-ops/main.c
 * @ref test-gnttab-copy-ops
 *
 * @page test-gnttab-copy-ops gnttab-copy-ops
 *
 * How Xen reads the array of operations handed to GNTTABOP_copy, and writes
 * each status back.
 *
 * Xen must read each operation after every earlier operation of the same
 * hypercall has completed, through the mapping the guest has at that point,
 * and must write only the status field.  Three cases:
 *
 * - An array that runs across a page boundary, so one operation straddles
 *   it, with one operation that must fail.
 * - A copy that overwrites a later operation of the same array.
 * - (HVM only) A copy that rewrites the L1 entry mapping the array, so later
 *   operations live in a different frame.
 *
 * Xen keeps the array's page translated across the operations of a 64-bit HAP
 * guest.  The other cases have the same outcome when it does not, so a last
 * case (HVM only) checks that it did.
 *
 * @see tests/gnttab-copy-ops/main.c
 */
#include <xtf.h>

const char test_title[] = "GNTTABOP_copy operation array handling";

#define GNTTABOP_copy 5

struct gnttab_copy {
    struct gnttab_copy_ptr {
        union {
            uint32_t ref;
            unsigned long gmfn;
        } u;
        uint16_t domid;
        uint16_t offset;
    } source, dest;
    uint16_t len;
    uint16_t flags;
    int16_t status;
};

/* A value Xen never writes as a status. */
#define UNTOUCHED 0x5a5a

#define NR_OPS 150 /* More than fit in one page. */

static uint8_t ops_buf[2 * PAGE_SIZE] __page_aligned_bss;
static uint8_t src[PAGE_SIZE] __page_aligned_bss;
static uint8_t dst1[PAGE_SIZE] __page_aligned_bss;
static uint8_t dst2[PAGE_SIZE] __page_aligned_bss;
static uint8_t scratch[PAGE_SIZE] __page_aligned_bss;

static struct gnttab_copy mk_op(const void *from, unsigned int from_off,
                                void *to, unsigned int to_off,
                                unsigned int len)
{
    return (struct gnttab_copy){
        .source = { .u.gmfn = virt_to_gfn(from), .domid = DOMID_SELF,
                    .offset = from_off },
        .dest   = { .u.gmfn = virt_to_gfn(to), .domid = DOMID_SELF,
                    .offset = to_off },
        .len = len,
        .status = UNTOUCHED,
    };
}

static bool test_straddle(void)
{
    struct gnttab_copy *ops = _p(ops_buf);
    unsigned int i, bad = 7;
    int rc;

    memset(ops_buf, 0, sizeof(ops_buf));
    memset(dst1, 0, sizeof(dst1));
    for ( i = 0; i < NR_OPS; ++i )
    {
        src[i] = i * 7 + 1;
        ops[i] = mk_op(src, i, dst1, i, 1);
    }
    /* Runs off the end of the source page. */
    ops[bad] = mk_op(src, PAGE_SIZE - 8, dst1, bad, 16);

    rc = hypercall_grant_table_op(GNTTABOP_copy, ops, NR_OPS);
    if ( rc )
    {
        xtf_failure("Fail: straddle: hypercall returned %d\n", rc);
        return false;
    }

    for ( i = 0; i < NR_OPS; ++i )
    {
        if ( i == bad )
        {
            if ( ops[i].status != GNTST_bad_copy_arg || dst1[i] != 0 )
            {
                xtf_failure("Fail: straddle: bad op %u status %d dst %#x\n",
                            i, ops[i].status, dst1[i]);
                return false;
            }
        }
        else if ( ops[i].status != GNTST_okay || dst1[i] != src[i] )
        {
            xtf_failure("Fail: straddle: op %u status %d dst %#x want %#x\n",
                        i, ops[i].status, dst1[i], src[i]);
            return false;
        }
    }

    return true;
}

static bool test_rewrite_later_op(void)
{
    struct gnttab_copy *ops = _p(ops_buf);
    struct gnttab_copy *staged = _p(scratch);
    int rc;

    memset(ops_buf, 0, sizeof(ops_buf));
    memset(dst1, 0, sizeof(dst1));
    memset(dst2, 0, sizeof(dst2));
    memset(src, 0xa5, 16);

    /* Op 0 replaces op 1, so the second copy must go to dst2. */
    staged[0] = mk_op(src, 0, dst2, 0, 16);
    ops[0] = mk_op(scratch, 0, ops_buf, sizeof(*ops), sizeof(*ops));
    ops[1] = mk_op(src, 0, dst1, 0, 16);

    rc = hypercall_grant_table_op(GNTTABOP_copy, ops, 2);
    if ( rc || ops[0].status != GNTST_okay || ops[1].status != GNTST_okay )
    {
        xtf_failure("Fail: rewrite: rc %d status %d,%d\n",
                    rc, ops[0].status, ops[1].status);
        return false;
    }
    if ( dst2[0] != 0xa5 || dst1[0] != 0 )
    {
        xtf_failure("Fail: rewrite: the replaced op ran (dst1 %#x dst2 %#x)\n",
                    dst1[0], dst2[0]);
        return false;
    }
    if ( ops[1].dest.u.gmfn != virt_to_gfn(dst2) )
    {
        xtf_failure("Fail: rewrite: Xen wrote more than the status field\n");
        return false;
    }

    return true;
}

#ifdef CONFIG_HVM
static uint8_t ops_alt[PAGE_SIZE] __page_aligned_bss;

static bool test_remap_array(void)
{
    struct gnttab_copy *ops = _p(ops_buf);
    struct gnttab_copy *alt = _p(ops_alt);
    intpte_t *slot = &l1_identmap[l1_table_offset(_u(ops_buf))];
    intpte_t orig = *slot;
    static intpte_t new_pte;
    int16_t a0, a1;
    int rc;

    memset(ops_buf, 0, sizeof(ops_buf));
    memset(ops_alt, 0, sizeof(ops_alt));
    memset(dst1, 0, sizeof(dst1));
    memset(dst2, 0, sizeof(dst2));
    memset(src, 0xc3, 16);

    new_pte = pte_from_virt(ops_alt, PF_SYM(AD, RW, P));

    /*
     * Op 0 points the array's own L1 entry at ops_alt.  Its status, and op 1,
     * must then come from ops_alt.
     */
    ops[0] = mk_op(&new_pte, _u(&new_pte) & ~PAGE_MASK,
                   l1_identmap, _u(slot) & ~PAGE_MASK, sizeof(new_pte));
    ops[1] = mk_op(src, 0, dst1, 0, 16);
    alt[0].status = UNTOUCHED;
    alt[1] = mk_op(src, 0, dst2, 0, 16);

    rc = hypercall_grant_table_op(GNTTABOP_copy, ops, 2);

    /* ops_buf's address now maps ops_alt.  Put it back before looking. */
    *slot = orig;
    invlpg(ops_buf);

    a0 = ops[0].status;
    a1 = ops[1].status;

    if ( rc )
    {
        xtf_failure("Fail: remap: hypercall returned %d\n", rc);
        return false;
    }
    if ( dst2[0] != 0xc3 || dst1[0] != 0 )
    {
        xtf_failure("Fail: remap: op 1 was read from the old frame "
                    "(dst1 %#x dst2 %#x)\n", dst1[0], dst2[0]);
        return false;
    }
    if ( alt[0].status != GNTST_okay || alt[1].status != GNTST_okay )
    {
        xtf_failure("Fail: remap: statuses not in the new frame (%d,%d)\n",
                    alt[0].status, alt[1].status);
        return false;
    }
    if ( a0 != UNTOUCHED || a1 != UNTOUCHED )
    {
        xtf_failure("Fail: remap: a status was written to the old frame "
                    "(%d,%d)\n", a0, a1);
        return false;
    }

    return true;
}

static bool test_translation_kept(void)
{
    struct gnttab_copy *ops = _p(ops_buf);
    intpte_t *slot = &l1_identmap[l1_table_offset(_u(ops_buf))];
    static intpte_t seen;
    int rc;

    memset(ops_buf, 0, sizeof(ops_buf));
    seen = 0;

    /* Op 0 copies out the L1 entry mapping the array, as it is when it runs. */
    ops[0] = mk_op(l1_identmap, _u(slot) & ~PAGE_MASK,
                   &seen, _u(&seen) & ~PAGE_MASK, sizeof(seen));

    *slot &= ~_PAGE_DIRTY;
    invlpg(ops_buf);

    rc = hypercall_grant_table_op(GNTTABOP_copy, ops, 1);
    if ( rc || ops[0].status != GNTST_okay )
    {
        xtf_failure("Fail: kept: rc %d status %d\n", rc, ops[0].status);
        return false;
    }

    /*
     * Reading op 0 through the guest access helpers leaves Dirty clear until
     * its status is written.  Keeping the page translated walks for a write
     * first, so op 0 sees Dirty set.
     */
    if ( !(seen & _PAGE_DIRTY) )
    {
        xtf_failure("Fail: kept: Xen walked for each access to the array\n");
        return false;
    }

    return true;
}
#else
static bool test_remap_array(void)
{
    return true;
}

static bool test_translation_kept(void)
{
    return true;
}
#endif

void test_main(void)
{
    if ( !test_straddle() || !test_rewrite_later_op() || !test_remap_array() ||
         !test_translation_kept() )
        return;

    xtf_success(NULL);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
