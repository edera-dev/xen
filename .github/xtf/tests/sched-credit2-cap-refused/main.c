/**
 * @file tests/sched-credit2-cap-refused/main.c
 * @ref test-sched-credit2-cap-refused
 *
 * @page test-sched-credit2-cap-refused sched-credit2-cap-refused
 *
 * A credit2 XEN_DOMCTL_SCHEDOP_putinfo that Xen refuses must leave the
 * domain as it was.
 *
 * Xen refuses a cap above 100 per vCPU.  It used to set the weight first,
 * so a request with a new weight and a cap that is too high returned
 * -EINVAL with the domain at the new weight.  The test sends that request
 * for dom0, and reads the weight back before and after.  The same request
 * with no cap must then change the weight, so a getinfo that never reports
 * a change cannot pass.
 *
 * The test needs the credit2 scheduler, which the shipped configuration
 * runs by default, and skips on any other.
 *
 * @see tests/sched-credit2-cap-refused/main.c
 */
#include <xtf.h>

const char test_title[] = "Refused credit2 putinfo leaves the weight alone";

/* XTF has no domctl header, so these mirror public/domctl.h. */
#define XEN_DOMCTL_INTERFACE_VERSION 0x00000018
#define XEN_DOMCTL_scheduler_op 16

#define XEN_SCHEDULER_CREDIT2 6
#define XEN_DOMCTL_SCHEDOP_putinfo 0
#define XEN_DOMCTL_SCHEDOP_getinfo 1

struct xen_domctl {
    uint32_t cmd;
    uint32_t interface_version;
    domid_t domain;
    uint16_t _pad[3];
    union {
        struct {
            uint32_t sched_id;
            uint32_t cmd;
            struct {
                uint16_t weight;
                uint16_t cap;
            } credit2;
        } scheduler_op;
        uint8_t pad[128];
    } u;
};

/* Above 100 per vCPU for any number of vCPUs dom0 can have. */
#define CAP_TOO_HIGH 65535

static long sched_op(unsigned int cmd, uint16_t weight, uint16_t cap,
                     uint16_t *weight_out, uint16_t *cap_out)
{
    struct xen_domctl domctl = {
        .cmd = XEN_DOMCTL_scheduler_op,
        .interface_version = XEN_DOMCTL_INTERFACE_VERSION,
        .domain = 0,
        .u.scheduler_op = {
            .sched_id = XEN_SCHEDULER_CREDIT2,
            .cmd = cmd,
            .credit2 = { .weight = weight, .cap = cap },
        },
    };
    long rc = HYPERCALL1(long, __HYPERVISOR_domctl, &domctl);

    if ( weight_out )
        *weight_out = domctl.u.scheduler_op.credit2.weight;
    if ( cap_out )
        *cap_out = domctl.u.scheduler_op.credit2.cap;

    return rc;
}

void test_main(void)
{
    uint16_t old_weight, old_cap, weight, cap, new_weight;
    long rc;

    rc = sched_op(XEN_DOMCTL_SCHEDOP_getinfo, 0, 0, &old_weight, &old_cap);
    if ( rc == -EINVAL )
        return xtf_skip("Skip: dom0 does not run under credit2\n");
    if ( rc )
        return xtf_error("Error: getinfo returned %ld\n", rc);

    new_weight = old_weight == 512 ? 513 : 512;

    rc = sched_op(XEN_DOMCTL_SCHEDOP_putinfo, new_weight, CAP_TOO_HIGH,
                  NULL, NULL);
    if ( rc != -EINVAL )
        return xtf_failure("Fail: putinfo with cap %u returned %ld, "
                           "expected %d\n", CAP_TOO_HIGH, rc, -EINVAL);

    rc = sched_op(XEN_DOMCTL_SCHEDOP_getinfo, 0, 0, &weight, &cap);
    if ( rc )
        return xtf_error("Error: getinfo returned %ld\n", rc);
    if ( weight != old_weight || cap != old_cap )
        return xtf_failure("Fail: refused putinfo changed weight %u -> %u, "
                           "cap %u -> %u\n", old_weight, weight, old_cap, cap);

    rc = sched_op(XEN_DOMCTL_SCHEDOP_putinfo, new_weight, 0, NULL, NULL);
    if ( rc )
        return xtf_error("Error: putinfo without a cap returned %ld\n", rc);

    rc = sched_op(XEN_DOMCTL_SCHEDOP_getinfo, 0, 0, &weight, NULL);
    if ( rc )
        return xtf_error("Error: getinfo returned %ld\n", rc);
    if ( weight != new_weight )
        return xtf_failure("Fail: putinfo without a cap left weight %u, "
                           "expected %u\n", weight, new_weight);

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
