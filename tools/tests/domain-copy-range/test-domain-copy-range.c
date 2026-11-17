/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for XENMEM_domain_copy_range.  A write copies pages of the
 * caller's buffer into a domain's frames and must leave a frame as it was when
 * its page of the buffer cannot be read; a read copies the frames out.  Each
 * case checks what the call returned, what the frames hold afterwards, and
 * that every reference was given back.  The caller is a PV or an HVM vCPU, and
 * its buffer is page-aligned or starts half way into a page, so that each
 * frame's page of it spans two of the caller's pages.
 */

#include "harness.h"

#define NR_FRAMES 2
#define DOMID     1

/* What a frame holds before the call, and what its page of the buffer holds. */
#define OLD(i) (0xa0 + (i))
#define NEW(i) (0x50 + (i))

static struct domain target = { .domain_id = DOMID };
static struct domain caller = { .domain_id = 0 };
static struct vcpu vcpu = { .domain = &caller };
struct vcpu *current = &vcpu;

static const char *test_name;

static uint8_t frames[NR_FRAMES][PAGE_SIZE];
static struct page_info pages[NR_FRAMES];

/*
 * The caller's memory: NR_FRAMES + 1 pages, so that a buffer starting half way
 * into the first still has NR_FRAMES pages of room.  A page of it can be made
 * unreadable.
 */
static uint8_t memory[(NR_FRAMES + 1) * PAGE_SIZE]
    __attribute__((__aligned__(PAGE_SIZE)));
static bool unreadable[NR_FRAMES + 1];
static uint8_t *buffer;

/* Copies the call made from the caller's memory. */
static unsigned int buffer_reads;

int xsm_add_to_physmap(int action, struct domain *d1, struct domain *d2)
{
    return 0;
}

int rcu_lock_remote_domain_by_id(domid_t dom, struct domain **d)
{
    if ( dom != DOMID )
        return -ESRCH;

    *d = &target;
    return 0;
}

void rcu_unlock_domain(struct domain *d)
{
}

int check_get_page_from_gfn(struct domain *d, gfn_t gfn, bool readonly,
                            p2m_type_t *p2mt_p, struct page_info **page_p)
{
    if ( gfn >= NR_FRAMES )
        return -EINVAL;

    pages[gfn].refs++;
    *p2mt_p = p2m_ram_rw;
    *page_p = &pages[gfn];

    return 0;
}

void put_page(struct page_info *page)
{
    page->refs--;
}

bool get_page_type(struct page_info *page, unsigned long type)
{
    page->type_refs++;

    return true;
}

void put_page_and_type(struct page_info *page)
{
    page->type_refs--;
    page->refs--;
}

void *__map_domain_page(struct page_info *page)
{
    return frames[page - pages];
}

void unmap_domain_page(const void *va)
{
}

/*
 * A page at a time, stopping at the first page of the caller's memory that
 * cannot be read.  For a PV vCPU the rest of the destination is zero-filled,
 * as x86's copy_from_guest_pv() does; for an HVM vCPU it is left as it was.
 */
unsigned long test_copy_from_guest(void *to, const void *from,
                                   unsigned long n)
{
    uintptr_t base = (uintptr_t)memory, src = (uintptr_t)from;
    unsigned long done = 0;

    if ( src < base || src >= base + sizeof(memory) )
    {
        memcpy(to, from, n);
        return 0;
    }

    buffer_reads++;

    while ( done < n )
    {
        unsigned long at = src + done - base;
        unsigned long chunk = MIN(n - done, PAGE_SIZE - (at % PAGE_SIZE));

        if ( at >= sizeof(memory) || unreadable[at / PAGE_SIZE] )
            break;

        memcpy((uint8_t *)to + done, memory + at, chunk);
        done += chunk;
    }

    if ( done < n && current->pv )
        memset((uint8_t *)to + done, 0, n - done);

    return n - done;
}

unsigned long test_copy_to_guest(void *to, const void *from,
                                 unsigned long n)
{
    memcpy(to, from, n);

    return 0;
}

bool hypercall_preempt_check(void)
{
    return false;
}

long hypercall_create_continuation(unsigned int op, const char *format, ...)
{
    return -ERESTART;
}

static long copy_range(uint16_t flags, unsigned int nr_frames, void *buf)
{
    struct xen_domain_copy_range xcr = {
        .domid = DOMID, .flags = flags, .nr_frames = nr_frames,
    };
    XEN_GUEST_HANDLE_PARAM(xen_domain_copy_range_t) arg = { .p = &xcr };

    set_xen_guest_handle(xcr.buffer, buf);

    return domain_copy_range(arg, 0);
}

static void caller_is(bool pv, bool aligned)
{
    unsigned int i;

    vcpu.pv = pv;
    buffer = memory + (aligned ? 0 : PAGE_SIZE / 2);

    for ( i = 0; i < NR_FRAMES; i++ )
        memset(buffer + i * PAGE_SIZE, NEW(i), PAGE_SIZE);
}

static bool all(const uint8_t *p, uint8_t val)
{
    unsigned long i;

    for ( i = 0; i < PAGE_SIZE; i++ )
        if ( p[i] != val )
            return false;

    return true;
}

static const char *frame_state(unsigned int i)
{
    if ( all(frames[i], OLD(i)) )
        return "as it was";
    if ( all(frames[i], NEW(i)) )
        return "written";
    if ( all(frames[i], 0) )
        return "zeroed";
    return "partly overwritten";
}

/* Every page reference and type reference given back. */
static bool balanced(void)
{
    unsigned int i;

    for ( i = 0; i < NR_FRAMES; i++ )
        if ( pages[i].refs || pages[i].type_refs )
            return false;

    return true;
}

/*
 * The call returned `want`, frame 0 and frame 1 are written or not as asked,
 * and everything taken was given back.
 */
static bool outcome(long rc, long want, bool written0, bool written1)
{
    if ( rc == want && all(frames[0], written0 ? NEW(0) : OLD(0)) &&
         all(frames[1], written1 ? NEW(1) : OLD(1)) && balanced() )
        return true;

    printf("%s: rc %ld, want %ld; frame 0 %s, frame 1 %s; references %d/%d "
           "and %d/%d\n", test_name, rc, want, frame_state(0), frame_state(1),
           pages[0].refs, pages[0].type_refs, pages[1].refs,
           pages[1].type_refs);
    return false;
}

static bool test_pv_write(void)
{
    caller_is(true, false);

    return outcome(copy_range(0, NR_FRAMES, buffer), 0, true, true);
}

static bool test_hvm_write(void)
{
    caller_is(false, true);

    if ( !outcome(copy_range(0, NR_FRAMES, buffer), 0, true, true) )
        return false;

    if ( buffer_reads == NR_FRAMES )
        return true;

    printf("%s: %u reads of the buffer, want %u\n", test_name, buffer_reads,
           NR_FRAMES);
    return false;
}

static bool test_pv_unreadable(void)
{
    caller_is(true, true);
    unreadable[0] = true;

    return outcome(copy_range(0, 1, buffer), -EFAULT, false, false);
}

static bool test_pv_first_unreadable(void)
{
    caller_is(true, false);
    unreadable[0] = true;

    return outcome(copy_range(0, 1, buffer), -EFAULT, false, false);
}

static bool test_pv_second_unreadable(void)
{
    caller_is(true, false);
    unreadable[1] = true;

    return outcome(copy_range(0, 1, buffer), -EFAULT, false, false);
}

static bool test_hvm_unreadable(void)
{
    caller_is(false, true);
    unreadable[0] = true;

    return outcome(copy_range(0, 1, buffer), -EFAULT, false, false);
}

static bool test_hvm_second_unreadable(void)
{
    caller_is(false, false);
    unreadable[1] = true;

    return outcome(copy_range(0, 1, buffer), -EFAULT, false, false);
}

static bool test_pv_later_page_unreadable(void)
{
    caller_is(true, true);
    unreadable[1] = true;

    return outcome(copy_range(0, NR_FRAMES, buffer), -EFAULT, true, false);
}

static bool test_no_frames(void)
{
    long rc;

    caller_is(true, true);
    rc = copy_range(0, 0, NULL);

    if ( !rc && !buffer_reads && outcome(rc, 0, false, false) )
        return true;

    printf("%s: rc %ld, %u reads of the buffer\n", test_name, rc,
           buffer_reads);
    return false;
}

static bool test_read(void)
{
    long rc;

    caller_is(true, true);
    rc = copy_range(XENMEM_DOMAIN_COPY_from_guest, NR_FRAMES, buffer);

    if ( !rc && all(buffer, OLD(0)) && all(buffer + PAGE_SIZE, OLD(1)) &&
         outcome(rc, 0, false, false) )
        return true;

    printf("%s: rc %ld, or the buffer does not hold the frames\n", test_name,
           rc);
    return false;
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "PV caller, write across pages: each frame holds its page of the "
      "buffer", test_pv_write },
    { "HVM caller, write from aligned pages: each frame holds its page, read "
      "once", test_hvm_write },
    { "PV caller, page unreadable: -EFAULT, and the frame is as it was",
      test_pv_unreadable },
    { "PV caller, first of two pages unreadable: -EFAULT, and the frame is as "
      "it was", test_pv_first_unreadable },
    { "PV caller, second of two pages unreadable: -EFAULT, and the frame is "
      "as it was", test_pv_second_unreadable },
    { "HVM caller, page unreadable: -EFAULT, and the frame is as it was",
      test_hvm_unreadable },
    { "HVM caller, second of two pages unreadable: -EFAULT, and the frame is "
      "as it was", test_hvm_second_unreadable },
    { "PV caller, second frame's page unreadable: the first frame is written, "
      "and the second is as it was", test_pv_later_page_unreadable },
    { "no frames, as a capability probe asks: 0, and no buffer read",
      test_no_frames },
    { "read: each page of the buffer holds its frame", test_read },
};

int main(void)
{
    unsigned int i, j, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        for ( j = 0; j < NR_FRAMES; j++ )
            memset(frames[j], OLD(j), PAGE_SIZE);
        memset(pages, 0, sizeof(pages));
        memset(memory, 0, sizeof(memory));
        memset(unreadable, 0, sizeof(unreadable));
        buffer_reads = 0;

        /* Named first, so that a fault shows which test it was. */
        test_name = tests[i].name;
        printf("%s\n", test_name);
        fflush(stdout);

        if ( !tests[i].run() )
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
