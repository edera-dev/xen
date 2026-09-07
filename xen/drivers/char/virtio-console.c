/*
 * xen/drivers/char/virtio-console.c
 *
 * Console driver for a virtio-console device on a PCI bus.
 *
 * Written for Apple's Virtualization.framework, where it is not a convenience
 * but the only serial port that exists: the platform has no PL011, no 8250 and
 * no UART of any kind, and the one serial device the VMM can be configured
 * with is a virtio-console behind the PCI host bridge.  Without this Xen boots
 * with no console at all and its log is unreachable until dom0 is up far
 * enough to run `xl dmesg`.  With it, console_init_preirq()'s conring_flush()
 * replays the entire log from the very first message, so there is no dark
 * window at all.
 *
 * Deliberately small.  It drives one port in polled mode with one descriptor
 * per character, which is what every other UART driver here effectively does
 * (a PL011 is one MMIO store per byte) and which cannot lose a partial line
 * the way a buffer flushed on newline can.  Xen's serial layer already knows
 * how to wait: tx_ready() reports free descriptors and it spins.
 *
 * Two things about the device it will not do.
 *
 * It refuses any device offering VIRTIO_CONSOLE_F_MULTIPORT.  Ports on such a
 * device have to be opened through the control queue, and until that handshake
 * completes the driver has no idea whether anything on the host is attached to
 * the port -- and writing to a virtio-console port that nothing is draining is
 * what killed the VMM outright during this port's bring-up (see
 * plans/asahi/11-virtualization-framework.md section 2).  A device without
 * MULTIPORT has exactly one port, port 0, which the specification says is the
 * console and is always open, so there is nothing to get wrong.  On the
 * motivating platform the serial device the user sees is such a device and the
 * one that crashed is not, so this rule also happens to pick the right one.
 *
 * It negotiates nothing but VIRTIO_F_VERSION_1, so the rings are split rings
 * with no event index and no indirect descriptors.  A device that offers those
 * must still work without them.
 *
 * Xen owns the device it picks; the hardware domain must not also drive it.
 * See the runbook.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/serial.h>
#include <xen/sizes.h>
#include <xen/timer.h>
#include <xen/vmap.h>

#include <asm/io.h>

/* PCI configuration space -- only what is needed to find one device. */
#define PCI_VENDOR_ID               0x00
#define PCI_DEVICE_ID               0x02
#define PCI_COMMAND                 0x04
#define  PCI_COMMAND_MEMORY         0x0002
#define  PCI_COMMAND_MASTER         0x0004
#define PCI_STATUS                  0x06
#define  PCI_STATUS_CAP_LIST        0x0010
#define PCI_HEADER_TYPE             0x0e
#define  PCI_HEADER_TYPE_MASK       0x7f
#define PCI_BASE_ADDRESS_0          0x10
#define  PCI_BASE_ADDRESS_SPACE_IO  0x01
#define  PCI_BASE_ADDRESS_MEM_TYPE_64 0x04
#define  PCI_BASE_ADDRESS_MEM_MASK  (~0x0fULL)
#define PCI_CAPABILITY_LIST         0x34
#define PCI_CAP_LIST_ID             0x00
#define PCI_CAP_LIST_NEXT           0x01
#define  PCI_CAP_ID_VNDR            0x09

#define PCI_VENDOR_ID_REDHAT_QUMRANET   0x1af4
#define PCI_DEVICE_ID_VIRTIO_CONSOLE    0x1043  /* 0x1040 + virtio ID 3 */

#define PCI_ECAM_CFG_OFFSET(bus, dev, fn) \
    (((bus) << 20) | ((dev) << 15) | ((fn) << 12))

/* struct virtio_pci_cap, offsets from the start of the capability. */
#define VIRTIO_PCI_CAP_CFG_TYPE     3
#define VIRTIO_PCI_CAP_BAR          4
#define VIRTIO_PCI_CAP_OFFSET       8
#define VIRTIO_PCI_CAP_LENGTH       12
#define VIRTIO_PCI_NOTIFY_CAP_MULT  16      /* notify capability only */

#define VIRTIO_PCI_CAP_COMMON_CFG   1
#define VIRTIO_PCI_CAP_NOTIFY_CFG   2

/* struct virtio_pci_common_cfg, offsets within the common configuration. */
#define VIRTIO_PCI_COMMON_DFSELECT  0x00
#define VIRTIO_PCI_COMMON_DF        0x04
#define VIRTIO_PCI_COMMON_GFSELECT  0x08
#define VIRTIO_PCI_COMMON_GF        0x0c
#define VIRTIO_PCI_COMMON_MSIX      0x10
#define VIRTIO_PCI_COMMON_NUMQ      0x12
#define VIRTIO_PCI_COMMON_STATUS    0x14
#define VIRTIO_PCI_COMMON_Q_SELECT  0x16
#define VIRTIO_PCI_COMMON_Q_SIZE    0x18
#define VIRTIO_PCI_COMMON_Q_MSIX    0x1a
#define VIRTIO_PCI_COMMON_Q_ENABLE  0x1c
#define VIRTIO_PCI_COMMON_Q_NOFF    0x1e
#define VIRTIO_PCI_COMMON_Q_DESCLO  0x20
#define VIRTIO_PCI_COMMON_Q_DESCHI  0x24
#define VIRTIO_PCI_COMMON_Q_AVAILLO 0x28
#define VIRTIO_PCI_COMMON_Q_AVAILHI 0x2c
#define VIRTIO_PCI_COMMON_Q_USEDLO  0x30
#define VIRTIO_PCI_COMMON_Q_USEDHI  0x34
#define VIRTIO_PCI_COMMON_CFG_SIZE  0x38

#define VIRTIO_CONFIG_S_ACKNOWLEDGE 0x01
#define VIRTIO_CONFIG_S_DRIVER      0x02
#define VIRTIO_CONFIG_S_DRIVER_OK   0x04
#define VIRTIO_CONFIG_S_FEATURES_OK 0x08
#define VIRTIO_CONFIG_S_NEEDS_RESET 0x40
#define VIRTIO_CONFIG_S_FAILED      0x80

#define VIRTIO_CONSOLE_F_MULTIPORT  1
#define VIRTIO_F_VERSION_1          32

#define VIRTIO_MSI_NO_VECTOR        0xffff

#define VRING_DESC_F_WRITE          2
#define VRING_USED_F_NO_NOTIFY      1

struct vring_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct vring_used_elem {
    uint32_t id;
    uint32_t len;
};

/*
 * Queue depth, per direction.  Must be a power of two, and is clamped to
 * whatever the device reports it can do.  Bigger than a console needs, which
 * is the point: tx_ready() then almost never has to say zero, so output does
 * not serialise on the host draining the ring.
 */
#define VTCON_QSIZE                 64

/* Port 0's queues, which are the only ones a device without MULTIPORT has. */
#define VTCON_VQ_RX                 0
#define VTCON_VQ_TX                 1

/*
 * Ring layout within one page.  The alignments virtio 1.0 requires are 16 for
 * the descriptor table, 2 for the available ring and 4 for the used ring; a
 * page-aligned base plus these offsets satisfies all three.  One byte of
 * payload per descriptor sits at the end.
 */
#define VTCON_DESC_OFF  0
#define VTCON_AVAIL_OFF (VTCON_DESC_OFF + VTCON_QSIZE * 16)
#define VTCON_USED_OFF  ROUNDUP(VTCON_AVAIL_OFF + 6 + 2 * VTCON_QSIZE, 4)
#define VTCON_BUF_OFF   ROUNDUP(VTCON_USED_OFF + 6 + 8 * VTCON_QSIZE, 8)
#define VTCON_RING_SIZE (VTCON_BUF_OFF + VTCON_QSIZE)

struct vtcon_vq {
    unsigned int idx;               /* virtqueue index, for the notification */
    unsigned int size;
    struct vring_desc *desc;
    uint16_t *avail_flags;
    uint16_t *avail_idx;
    uint16_t *avail_ring;
    uint16_t *used_flags;
    uint16_t *used_idx;
    struct vring_used_elem *used_ring;
    char *buf;
    void __iomem *notify;
    uint16_t next_avail;            /* what we have published in *avail_idx */
    uint16_t last_used;             /* used entries we have consumed        */
};

static struct vtcon {
    /* Where the device was found, kept for the log and for init_preirq(). */
    void __iomem *ecam;             /* configuration space of this function */
    unsigned int bus, dev, fn;

    void __iomem *common;
    void __iomem *notify_base;
    uint32_t notify_mult;

    struct vtcon_vq rx, tx;

    bool ready;                     /* bring-up completed; safe to write */

    /* Receive is polled: see the comment on vtcon_rx_poll(). */
    struct timer rx_timer;
} vtcon_com;

/* vtcon=<bus>:<dev>.<fn>, to override which device is used. */
static char __initdata opt_vtcon[16];
string_param("vtcon", opt_vtcon);

#define RX_POLL_INTERVAL    MILLISECS(10)
#define RX_POLL_BUDGET      64

/*
 * A bounded spin for the handful of places the specification says to wait for
 * the device.  Deliberately a plain iteration count rather than a real
 * timebase: this runs from init_preirq(), and depending on the timer here
 * would be one more thing that has to already work before Xen can say
 * anything at all.
 */
#define VTCON_SPIN_LIMIT    1000000

static uint8_t __init cfg_readb(unsigned int off)
{
    return readb(vtcon_com.ecam + off);
}

static uint16_t __init cfg_readw(unsigned int off)
{
    return readw(vtcon_com.ecam + off);
}

static uint32_t __init cfg_readl(unsigned int off)
{
    return readl(vtcon_com.ecam + off);
}

/*
 * Find the virtio capability of the given type and return its offset in
 * configuration space, or 0.  Also yields the BAR it lives in and the offset
 * within that BAR.
 */
static unsigned int __init find_virtio_cap(unsigned int type, unsigned int *bar,
                                           uint32_t *offset, uint32_t *len)
{
    unsigned int pos, guard;

    if ( !(cfg_readw(PCI_STATUS) & PCI_STATUS_CAP_LIST) )
        return 0;

    pos = cfg_readb(PCI_CAPABILITY_LIST) & ~3;

    /* A malformed or circular list must not be able to hang the boot. */
    for ( guard = 0; pos >= 0x40 && pos < 0x100 && guard < 48; guard++ )
    {
        if ( cfg_readb(pos + PCI_CAP_LIST_ID) == PCI_CAP_ID_VNDR &&
             cfg_readb(pos + VIRTIO_PCI_CAP_CFG_TYPE) == type )
        {
            *bar = cfg_readb(pos + VIRTIO_PCI_CAP_BAR);
            *offset = cfg_readl(pos + VIRTIO_PCI_CAP_OFFSET);
            *len = cfg_readl(pos + VIRTIO_PCI_CAP_LENGTH);
            return pos;
        }

        pos = cfg_readb(pos + PCI_CAP_LIST_NEXT) & ~3;
    }

    return 0;
}

/* Read BAR @bar, coping with a 64-bit BAR spanning two dwords. */
static paddr_t __init read_bar(unsigned int bar)
{
    uint32_t lo;
    uint64_t addr;

    if ( bar > 5 )
        return 0;

    lo = cfg_readl(PCI_BASE_ADDRESS_0 + bar * 4);
    if ( lo & PCI_BASE_ADDRESS_SPACE_IO )
        return 0;                   /* I/O BARs are not usable here */

    addr = lo & (uint32_t)PCI_BASE_ADDRESS_MEM_MASK;
    if ( (lo & PCI_BASE_ADDRESS_MEM_TYPE_64) && bar < 5 )
        addr |= (uint64_t)cfg_readl(PCI_BASE_ADDRESS_0 + (bar + 1) * 4) << 32;

    return addr;
}

/*
 * Whether this function is a virtio-console we are willing to drive.  The
 * MULTIPORT test is the safety rule described at the top of the file, and is
 * applied to an explicitly selected device too: without the control-queue
 * handshake there is no way to know the port is attached, and writing to one
 * that is not is the failure this driver exists downstream of.
 */
static bool __init vtcon_usable(bool verbose)
{
    unsigned int bar;
    uint32_t off, len, feat;
    void __iomem *common;
    bool multiport;

    if ( cfg_readw(PCI_VENDOR_ID) != PCI_VENDOR_ID_REDHAT_QUMRANET ||
         cfg_readw(PCI_DEVICE_ID) != PCI_DEVICE_ID_VIRTIO_CONSOLE )
        return false;

    if ( !find_virtio_cap(VIRTIO_PCI_CAP_COMMON_CFG, &bar, &off, &len) ||
         len < VIRTIO_PCI_COMMON_CFG_SIZE )
    {
        printk(XENLOG_WARNING
               "vtcon: %02x:%02x.%u has no usable common configuration\n",
               vtcon_com.bus, vtcon_com.dev, vtcon_com.fn);
        return false;
    }

    /*
     * Reading the offered features needs the common configuration mapped,
     * which needs the firmware to have assigned the BAR.  Selecting which
     * feature word to read is a write, but only to device_feature_select,
     * which has no effect on anything but the next read of device_feature --
     * nothing on the data path is touched by a device we then reject.
     */
    if ( !read_bar(bar) )
    {
        printk(XENLOG_WARNING "vtcon: %02x:%02x.%u BAR%u is unassigned\n",
               vtcon_com.bus, vtcon_com.dev, vtcon_com.fn, bar);
        return false;
    }

    common = ioremap_nocache(read_bar(bar) + off, VIRTIO_PCI_COMMON_CFG_SIZE);
    if ( !common )
        return false;

    writel(VIRTIO_CONSOLE_F_MULTIPORT / 32, common + VIRTIO_PCI_COMMON_DFSELECT);
    feat = readl(common + VIRTIO_PCI_COMMON_DF);
    multiport = feat & (1U << (VIRTIO_CONSOLE_F_MULTIPORT % 32));
    iounmap(common);

    if ( multiport )
    {
        if ( verbose )
            printk(XENLOG_INFO
                   "vtcon: skipping %02x:%02x.%u: offers MULTIPORT, whose "
                   "ports must be opened through the control queue\n",
                   vtcon_com.bus, vtcon_com.dev, vtcon_com.fn);
        return false;
    }

    return true;
}

/*
 * Find the device.  Only the first bus is scanned, and only function 0 of a
 * single-function device: that is the whole of what the motivating platform
 * puts on its root bus, and a console driver is a poor place to grow a PCI
 * enumerator.  vtcon= overrides the choice.
 */
static bool __init vtcon_find(void __iomem *ecam, unsigned int bus)
{
    unsigned int dev;

    if ( opt_vtcon[0] )
    {
        const char *s = opt_vtcon;
        unsigned long b, d, f;

        b = simple_strtoul(s, &s, 16);
        if ( *s++ != ':' )
            goto badparam;
        d = simple_strtoul(s, &s, 16);
        if ( *s++ != '.' )
            goto badparam;
        f = simple_strtoul(s, &s, 10);
        if ( *s || d > 31 || f > 7 )
            goto badparam;

        vtcon_com.ecam = ecam + PCI_ECAM_CFG_OFFSET(0, d, f);
        vtcon_com.bus = b;
        vtcon_com.dev = d;
        vtcon_com.fn = f;

        if ( b != bus )
        {
            printk(XENLOG_ERR "vtcon: bus %02lx is not the scanned bus %02x\n",
                   b, bus);
            return false;
        }

        if ( vtcon_usable(true) )
            return true;

        printk(XENLOG_ERR "vtcon: %s is not a usable virtio-console\n",
               opt_vtcon);
        return false;

     badparam:
        printk(XENLOG_ERR "vtcon: cannot parse vtcon=%s, "
               "expected <bus>:<dev>.<fn>\n", opt_vtcon);
        return false;
    }

    for ( dev = 0; dev < 32; dev++ )
    {
        vtcon_com.ecam = ecam + PCI_ECAM_CFG_OFFSET(0, dev, 0);
        vtcon_com.bus = bus;
        vtcon_com.dev = dev;
        vtcon_com.fn = 0;

        if ( cfg_readw(PCI_VENDOR_ID) == 0xffff )
            continue;

        if ( vtcon_usable(true) )
            return true;
    }

    return false;
}

static void __init vq_layout(struct vtcon_vq *vq, unsigned int idx,
                             void *page, unsigned int size)
{
    vq->idx = idx;
    vq->size = size;
    vq->desc = page + VTCON_DESC_OFF;
    vq->avail_flags = page + VTCON_AVAIL_OFF;
    vq->avail_idx = page + VTCON_AVAIL_OFF + 2;
    vq->avail_ring = page + VTCON_AVAIL_OFF + 4;
    vq->used_flags = page + VTCON_USED_OFF;
    vq->used_idx = page + VTCON_USED_OFF + 2;
    vq->used_ring = page + VTCON_USED_OFF + 4;
    vq->buf = page + VTCON_BUF_OFF;
    vq->next_avail = 0;
    vq->last_used = 0;
}

/* Program one queue into the device and enable it. */
static bool __init vq_setup(struct vtcon_vq *vq, unsigned int idx, void *page)
{
    void __iomem *cfg = vtcon_com.common;
    paddr_t base = virt_to_maddr(page);
    unsigned int size;

    writew(idx, cfg + VIRTIO_PCI_COMMON_Q_SELECT);

    size = readw(cfg + VIRTIO_PCI_COMMON_Q_SIZE);
    if ( !size )
    {
        printk(XENLOG_ERR "vtcon: queue %u does not exist\n", idx);
        return false;
    }
    size = min(size, (unsigned int)VTCON_QSIZE);
    writew(size, cfg + VIRTIO_PCI_COMMON_Q_SIZE);

    vq_layout(vq, idx, page, size);

    writel((uint32_t)(base + VTCON_DESC_OFF), cfg + VIRTIO_PCI_COMMON_Q_DESCLO);
    writel((base + VTCON_DESC_OFF) >> 32, cfg + VIRTIO_PCI_COMMON_Q_DESCHI);
    writel((uint32_t)(base + VTCON_AVAIL_OFF), cfg + VIRTIO_PCI_COMMON_Q_AVAILLO);
    writel((base + VTCON_AVAIL_OFF) >> 32, cfg + VIRTIO_PCI_COMMON_Q_AVAILHI);
    writel((uint32_t)(base + VTCON_USED_OFF), cfg + VIRTIO_PCI_COMMON_Q_USEDLO);
    writel((base + VTCON_USED_OFF) >> 32, cfg + VIRTIO_PCI_COMMON_Q_USEDHI);

    writew(VIRTIO_MSI_NO_VECTOR, cfg + VIRTIO_PCI_COMMON_Q_MSIX);

    vq->notify = vtcon_com.notify_base +
                 readw(cfg + VIRTIO_PCI_COMMON_Q_NOFF) * vtcon_com.notify_mult;

    writew(1, cfg + VIRTIO_PCI_COMMON_Q_ENABLE);

    return true;
}

static void vq_kick(struct vtcon_vq *vq, uint16_t idx)
{
    /*
     * The device reads the descriptor and the available ring out of memory, so
     * both must be visible before the index that publishes them, and the index
     * before the notification.  ACCESS_PLATFORM is not negotiated, so the
     * device addresses memory directly and an inner-shareable barrier is
     * enough -- the host side of a virtio device is software on another core of
     * the same coherent system, which is exactly what smp_wmb() orders against.
     */
    smp_wmb();
    write_atomic(vq->avail_idx, idx);
    smp_wmb();
    writew(vq->idx, vq->notify);
}

/* Publish descriptor @slot, which is already filled in. */
static void vq_publish(struct vtcon_vq *vq, unsigned int slot)
{
    vq->avail_ring[vq->next_avail % vq->size] = slot;
    vq->next_avail++;
    vq_kick(vq, vq->next_avail);
}

/* How many used entries the device has returned but we have not consumed. */
static unsigned int vq_used_pending(struct vtcon_vq *vq)
{
    uint16_t idx = read_atomic(vq->used_idx);

    smp_rmb();

    return (uint16_t)(idx - vq->last_used);
}

static void __init vtcon_init_preirq(struct serial_port *port)
{
    struct vtcon *v = port->uart;
    void __iomem *cfg = v->common;
    void *page;
    unsigned int i, spin;
    uint8_t status;

    BUILD_BUG_ON(2 * VTCON_RING_SIZE > PAGE_SIZE);
    BUILD_BUG_ON(VTCON_QSIZE & (VTCON_QSIZE - 1));

    page = alloc_xenheap_page();
    if ( !page )
    {
        printk(XENLOG_ERR "vtcon: cannot allocate ring memory\n");
        return;
    }
    clear_page(page);

    /* Reset, and wait for the device to agree that it is reset. */
    writeb(0, cfg + VIRTIO_PCI_COMMON_STATUS);
    for ( spin = 0; spin < VTCON_SPIN_LIMIT; spin++ )
    {
        if ( !readb(cfg + VIRTIO_PCI_COMMON_STATUS) )
            break;
        cpu_relax();
    }
    if ( readb(cfg + VIRTIO_PCI_COMMON_STATUS) )
    {
        printk(XENLOG_ERR "vtcon: device will not reset\n");
        goto fail;
    }

    writeb(VIRTIO_CONFIG_S_ACKNOWLEDGE, cfg + VIRTIO_PCI_COMMON_STATUS);
    writeb(VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER,
           cfg + VIRTIO_PCI_COMMON_STATUS);

    /* Require VERSION_1 and ask for nothing else.  See the file comment. */
    writel(VIRTIO_F_VERSION_1 / 32, cfg + VIRTIO_PCI_COMMON_DFSELECT);
    if ( !(readl(cfg + VIRTIO_PCI_COMMON_DF) &
           (1U << (VIRTIO_F_VERSION_1 % 32))) )
    {
        printk(XENLOG_ERR "vtcon: device is not virtio 1.0\n");
        goto fail;
    }

    writel(0, cfg + VIRTIO_PCI_COMMON_GFSELECT);
    writel(0, cfg + VIRTIO_PCI_COMMON_GF);
    writel(VIRTIO_F_VERSION_1 / 32, cfg + VIRTIO_PCI_COMMON_GFSELECT);
    writel(1U << (VIRTIO_F_VERSION_1 % 32), cfg + VIRTIO_PCI_COMMON_GF);

    status = VIRTIO_CONFIG_S_ACKNOWLEDGE | VIRTIO_CONFIG_S_DRIVER |
             VIRTIO_CONFIG_S_FEATURES_OK;
    writeb(status, cfg + VIRTIO_PCI_COMMON_STATUS);
    if ( !(readb(cfg + VIRTIO_PCI_COMMON_STATUS) &
           VIRTIO_CONFIG_S_FEATURES_OK) )
    {
        printk(XENLOG_ERR "vtcon: device rejected the feature set\n");
        goto fail;
    }

    writew(VIRTIO_MSI_NO_VECTOR, cfg + VIRTIO_PCI_COMMON_MSIX);

    if ( readw(cfg + VIRTIO_PCI_COMMON_NUMQ) <= VTCON_VQ_TX )
    {
        printk(XENLOG_ERR "vtcon: device has no transmit queue\n");
        goto fail;
    }

    if ( !vq_setup(&v->rx, VTCON_VQ_RX, page) ||
         !vq_setup(&v->tx, VTCON_VQ_TX, page + VTCON_RING_SIZE) )
        goto fail;

    writeb(status | VIRTIO_CONFIG_S_DRIVER_OK,
           cfg + VIRTIO_PCI_COMMON_STATUS);

    /*
     * Offer the whole receive ring to the device up front.  Each descriptor
     * carries one byte, so a used entry is exactly one character and getc()
     * needs no partial-buffer state.
     */
    for ( i = 0; i < v->rx.size; i++ )
    {
        v->rx.desc[i].addr = virt_to_maddr(&v->rx.buf[i]);
        v->rx.desc[i].len = 1;
        v->rx.desc[i].flags = VRING_DESC_F_WRITE;
        v->rx.desc[i].next = 0;
        v->rx.avail_ring[i] = i;
    }
    v->rx.next_avail = v->rx.size;
    vq_kick(&v->rx, v->rx.next_avail);

    v->ready = true;
    printk("vtcon: console on virtio-console %02x:%02x.%u, "
           "%u tx and %u rx descriptors\n",
           v->bus, v->dev, v->fn, v->tx.size, v->rx.size);
    return;

 fail:
    /*
     * Tell the device the driver gave up, and keep the page: the queues may
     * already point into it, ->ready stays false so nothing will use them, and
     * one leaked page is a better trade than a dangling ring.
     */
    writeb(VIRTIO_CONFIG_S_FAILED, cfg + VIRTIO_PCI_COMMON_STATUS);
}

/*
 * Receive is polled.  The device's interrupt is an MSI-X, which would mean an
 * MSI controller and a routed SPI for a debug console's benefit; 10ms is
 * imperceptible for typing and costs nothing.  Drain at most a ring's worth
 * per tick so that a host pasting a lot of input cannot monopolise the timer.
 */
static void cf_check vtcon_rx_poll(void *data)
{
    struct serial_port *port = data;
    struct vtcon *v = port->uart;
    unsigned int budget = RX_POLL_BUDGET;

    while ( budget-- && vq_used_pending(&v->rx) )
        serial_rx_interrupt(port);

    set_timer(&v->rx_timer, NOW() + RX_POLL_INTERVAL);
}

static void __init vtcon_init_postirq(struct serial_port *port)
{
    struct vtcon *v = port->uart;

    if ( !v->ready )
        return;

    init_timer(&v->rx_timer, vtcon_rx_poll, port, 0);
    set_timer(&v->rx_timer, NOW() + RX_POLL_INTERVAL);
}

/*
 * Free transmit descriptors.  Reclaiming here rather than in putc() is what
 * lets the serial layer do the waiting: it spins on this returning zero.
 */
static int cf_check vtcon_tx_ready(struct serial_port *port)
{
    struct vtcon *v = port->uart;
    unsigned int used;

    if ( !v->ready )
        return -EINVAL;             /* discard rather than spin forever */

    v->tx.last_used += vq_used_pending(&v->tx);
    used = (uint16_t)(v->tx.next_avail - v->tx.last_used);

    return v->tx.size - used;
}

static void cf_check vtcon_putc(struct serial_port *port, char c)
{
    struct vtcon *v = port->uart;
    unsigned int slot;

    if ( !v->ready )
        return;

    slot = v->tx.next_avail % v->tx.size;

    v->tx.buf[slot] = c;
    v->tx.desc[slot].addr = virt_to_maddr(&v->tx.buf[slot]);
    v->tx.desc[slot].len = 1;
    v->tx.desc[slot].flags = 0;
    v->tx.desc[slot].next = 0;

    vq_publish(&v->tx, slot);
}

static int cf_check vtcon_getc(struct serial_port *port, char *pc)
{
    struct vtcon *v = port->uart;
    struct vring_used_elem *e;
    unsigned int slot;

    if ( !v->ready || !vq_used_pending(&v->rx) )
        return 0;

    e = &v->rx.used_ring[v->rx.last_used % v->rx.size];
    slot = e->id % v->rx.size;

    *pc = e->len ? v->rx.buf[slot] : '\0';
    v->rx.last_used++;

    /* Hand the descriptor straight back so input keeps flowing. */
    vq_publish(&v->rx, slot);

    return e->len ? 1 : 0;
}

static int cf_check vtcon_irq(struct serial_port *port)
{
    return -1;                      /* polled; see vtcon_rx_poll() */
}

static struct uart_driver __read_mostly vtcon_driver = {
    .init_preirq  = vtcon_init_preirq,
    .init_postirq = vtcon_init_postirq,
    .tx_ready     = vtcon_tx_ready,
    .putc         = vtcon_putc,
    .getc         = vtcon_getc,
    .irq          = vtcon_irq,
};

/*
 * Discover the device and register it, without touching it.  Called from
 * platform code, which runs after vm_init() so that ioremap() works and before
 * console_init_preirq() so that console=vtcon can find the registration.  The
 * device itself is brought up in init_preirq(), by which point there is a
 * timebase and an allocator.
 */
void __init virtio_console_init(void)
{
    const struct dt_device_node *node;
    unsigned int bar, nbar, notify_cap, bus = 0;
    uint32_t off, len, noff, nlen;
    paddr_t ecam_base, ecam_size, barbase;
    void __iomem *ecam;
    const __be32 *prop;

    node = dt_find_compatible_node(NULL, NULL, "pci-host-ecam-generic");
    if ( !node )
    {
        printk(XENLOG_WARNING
               "vtcon: no pci-host-ecam-generic node to search\n");
        return;
    }

    if ( dt_device_get_paddr(node, 0, &ecam_base, &ecam_size) )
    {
        printk(XENLOG_WARNING "vtcon: %s has no address\n",
               dt_node_full_name(node));
        return;
    }

    /* Only the first bus is searched; say which one that is. */
    prop = dt_get_property(node, "bus-range", &len);
    if ( prop && len >= 4 )
        bus = be32_to_cpu(prop[0]);

    /*
     * One bus is 1MB of configuration space.  Map just that, not the whole
     * (typically 256MB) ECAM window.
     */
    ecam = ioremap_nocache(ecam_base + ((paddr_t)bus << 20), SZ_1M);
    if ( !ecam )
    {
        printk(XENLOG_WARNING "vtcon: cannot map ECAM at %#"PRIpaddr"\n",
               ecam_base);
        return;
    }

    if ( !vtcon_find(ecam, bus) )
    {
        printk(XENLOG_INFO "vtcon: no usable virtio-console on bus %02x\n",
               bus);
        goto unmap;
    }

    notify_cap = find_virtio_cap(VIRTIO_PCI_CAP_NOTIFY_CFG, &nbar, &noff,
                                 &nlen);
    if ( !find_virtio_cap(VIRTIO_PCI_CAP_COMMON_CFG, &bar, &off, &len) ||
         !notify_cap )
        goto unmap;

    if ( nbar != bar )
    {
        printk(XENLOG_WARNING "vtcon: common and notify are in different "
               "BARs (%u, %u), which this driver does not handle\n",
               bar, nbar);
        goto unmap;
    }

    barbase = read_bar(bar);
    if ( !barbase )
        goto unmap;

    /*
     * Enable memory decoding and bus mastering explicitly.  The firmware has
     * almost certainly done both -- it was using this device as its own
     * console -- but the rings are useless without mastering and finding that
     * out from a silent absence of output would be miserable.
     */
    writew(cfg_readw(PCI_COMMAND) | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
           vtcon_com.ecam + PCI_COMMAND);

    vtcon_com.common = ioremap_nocache(barbase + off, len);
    vtcon_com.notify_base = ioremap_nocache(barbase + noff, nlen);
    vtcon_com.notify_mult = cfg_readl(notify_cap + VIRTIO_PCI_NOTIFY_CAP_MULT);

    if ( !vtcon_com.common || !vtcon_com.notify_base )
    {
        printk(XENLOG_WARNING "vtcon: cannot map the device's registers\n");
        goto unmap;
    }

    serial_register_uart(SERHND_VTCON, &vtcon_driver, &vtcon_com);
    printk("vtcon: virtio-console at %02x:%02x.%u, "
           "BAR%u %#"PRIpaddr" (use console=vtcon)\n",
           vtcon_com.bus, vtcon_com.dev, vtcon_com.fn, bar, barbase);
    return;

 unmap:
    iounmap(ecam);
    vtcon_com.ecam = NULL;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
