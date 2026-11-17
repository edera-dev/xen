/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for XENMEM_domain_copy_range.  A write copies pages of the
 * caller's buffer into a domain's frames and must leave a frame as it was
 * when the copy from the buffer faults; a read copies the frames out.  Each
 * case checks what the call returned, what the frames and the buffer hold
 * afterwards, and that every reference and scratch page was given back.
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
static uint8_t buffer[NR_FRAMES * PAGE_SIZE];

/* The part of the buffer a copy from the caller cannot read, if any. */
static const uint8_t *unreadable_from, *unreadable_to;

/* Scratch pages handed out and not freed, and whether the next one fails. */
static int scratch_live;
static bool scratch_fails;

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

void *alloc_xenheap_page(void)
{
    void *p;

    if ( scratch_fails )
        return NULL;

    p = malloc(PAGE_SIZE);
    if ( p )
        scratch_live++;

    return p;
}

void free_xenheap_page(void *v)
{
    if ( v )
        scratch_live--;
    free(v);
}

/*
 * As x86 copies from a PV caller: up to the first byte that cannot be read,
 * with the rest of the destination zero-filled.
 */
unsigned long test_copy_from_guest(void *to, const void *from,
                                   unsigned long n)
{
    uintptr_t start = (uintptr_t)from, end = start + n;
    unsigned long ok = n;

    if ( unreadable_from && start < (uintptr_t)unreadable_to &&
         end > (uintptr_t)unreadable_from )
        ok = (uintptr_t)unreadable_from > start
             ? (uintptr_t)unreadable_from - start : 0;

    memcpy(to, from, ok);
    memset((uint8_t *)to + ok, 0, n - ok);

    return n - ok;
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

static long copy_range(uint16_t flags, unsigned int nr_frames)
{
    struct xen_domain_copy_range xcr = {
        .domid = DOMID, .flags = flags, .nr_frames = nr_frames,
    };
    XEN_GUEST_HANDLE_PARAM(xen_domain_copy_range_t) arg = { .p = &xcr };

    set_xen_guest_handle(xcr.buffer, buffer);

    return domain_copy_range(arg, 0);
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

/* Every page reference, type reference and scratch page given back. */
static bool balanced(void)
{
    unsigned int i;

    for ( i = 0; i < NR_FRAMES; i++ )
        if ( pages[i].refs || pages[i].type_refs )
            return false;

    return !scratch_live;
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
           "and %d/%d, %d scratch pages held\n", test_name, rc, want,
           frame_state(0), frame_state(1), pages[0].refs, pages[0].type_refs,
           pages[1].refs, pages[1].type_refs, scratch_live);
    return false;
}

static void unreadable(unsigned long from, unsigned long to)
{
    unreadable_from = buffer + from;
    unreadable_to = buffer + to;
}

static bool test_write(void)
{
    return outcome(copy_range(0, NR_FRAMES), 0, true, true);
}

static bool test_unreadable_page(void)
{
    unreadable(0, PAGE_SIZE);

    return outcome(copy_range(0, 1), -EFAULT, false, false);
}

static bool test_unreadable_part_way(void)
{
    unreadable(PAGE_SIZE / 2, PAGE_SIZE);

    return outcome(copy_range(0, 1), -EFAULT, false, false);
}

static bool test_second_page_unreadable(void)
{
    unreadable(PAGE_SIZE, 2 * PAGE_SIZE);

    return outcome(copy_range(0, NR_FRAMES), -EFAULT, true, false);
}

static bool test_no_scratch(void)
{
    scratch_fails = true;

    return outcome(copy_range(0, NR_FRAMES), -ENOMEM, false, false);
}

static bool test_read(void)
{
    long rc = copy_range(XENMEM_DOMAIN_COPY_from_guest, NR_FRAMES);

    if ( !rc && all(buffer, OLD(0)) && all(buffer + PAGE_SIZE, OLD(1)) &&
         all(frames[0], OLD(0)) && all(frames[1], OLD(1)) && balanced() )
        return true;

    printf("%s: rc %ld; the buffer does not hold the frames, the frames "
           "changed, or references %d/%d and %d/%d or %d scratch pages are "
           "still held\n", test_name, rc, pages[0].refs, pages[0].type_refs,
           pages[1].refs, pages[1].type_refs, scratch_live);
    return false;
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "write: each frame holds its page of the buffer", test_write },
    { "write from an unreadable page: -EFAULT, and the frame is as it was",
      test_unreadable_page },
    { "write from a page that faults part way: -EFAULT, and the frame is as "
      "it was", test_unreadable_part_way },
    { "write whose second page is unreadable: the first frame is written, "
      "and the second is as it was", test_second_page_unreadable },
    { "write with no scratch page: -ENOMEM, and no frame is touched",
      test_no_scratch },
    { "read: each page of the buffer holds its frame", test_read },
};

int main(void)
{
    unsigned int i, j, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        for ( j = 0; j < NR_FRAMES; j++ )
        {
            memset(frames[j], OLD(j), PAGE_SIZE);
            memset(buffer + j * PAGE_SIZE, NEW(j), PAGE_SIZE);
        }
        memset(pages, 0, sizeof(pages));
        unreadable_from = unreadable_to = NULL;
        scratch_live = 0;
        scratch_fails = false;

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
