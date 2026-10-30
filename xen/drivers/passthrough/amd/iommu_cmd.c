/*
 * Copyright (C) 2011 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "iommu.h"
#include "../ats.h"

#define CMD_COMPLETION_INIT 0
#define CMD_COMPLETION_DONE 1

/*
 * A rejected command halts the command processor: the head pointer stops and
 * nothing further is consumed. Restart the ring so later commands still run,
 * which is what Linux does on ILLEGAL_COMMAND_ERROR from its event handler.
 * Anything still queued is discarded, as it is there too.
 */
static void reset_cmd_buffer(struct amd_iommu *iommu)
{
    unsigned long flags;

    spin_lock_irqsave(&iommu->lock, flags);

    iommu->ctrl.cmd_buf_en = false;
    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    writel(0, iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET);
    writel(0, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);
    iommu->cmd_buffer.head = 0;
    iommu->cmd_buffer.tail = 0;

    iommu->ctrl.cmd_buf_en = true;
    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    spin_unlock_irqrestore(&iommu->lock, flags);
}

/*
 * Stop every device that a domain other than the hardware domain owns
 * behind an IOMMU whose command buffer has died: turn off its bus
 * mastering so it can't use anything the IOMMU still caches, mark it
 * broken so it isn't handed to a guest again, and crash its owner.
 * Runs as a tasklet so it can take pcidevs_lock.
 */
static void cf_check amd_iommu_contain_dead(void *unused)
{
    struct domain *d;

    pcidevs_lock();
    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        struct pci_dev *pdev;

        if ( is_hardware_domain(d) )
            continue;

        read_lock(&d->pci_lock);
        for_each_pdev ( d, pdev )
        {
            const struct amd_iommu *iommu = find_iommu_for_device(pdev->sbdf);
            uint16_t cmd;

            if ( !iommu || !iommu->cmd_buffer_dead )
                continue;

            cmd = pci_conf_read16(pdev->sbdf, PCI_COMMAND);
            pci_conf_write16(pdev->sbdf, PCI_COMMAND,
                             cmd & ~PCI_COMMAND_MASTER);
            pdev->broken = true;

            printk(XENLOG_ERR
                   "AMD IOMMU %pp: stopped %pp and crashing %pd\n",
                   &iommu->sbdf, &pdev->sbdf, d);
            domain_crash(d);
        }
        read_unlock(&d->pci_lock);
    }

    rcu_read_unlock(&domlist_read_lock);
    pcidevs_unlock();
}

static DECLARE_TASKLET(amd_iommu_dead_tasklet, amd_iommu_contain_dead, NULL);

/*
 * Called when invalidations can no longer be issued or confirmed. From here
 * on nothing is sent, so nothing cached by this IOMMU can be trusted to go
 * away: stop relying on it for any domain but the hardware domain.
 */
void amd_iommu_cmd_buffer_died(struct amd_iommu *iommu)
{
    if ( iommu->cmd_buffer_dead )
        return;

    iommu->cmd_buffer_dead = true;
    printk(XENLOG_ERR "AMD IOMMU %pp: command buffer is dead\n",
           &iommu->sbdf);

    tasklet_schedule(&amd_iommu_dead_tasklet);
}

static void send_iommu_command(struct amd_iommu *iommu,
                               const uint32_t cmd[4])
{
    uint32_t tail;
    unsigned long flags;
    s_time_t timeout;
    bool died = false;

    spin_lock_irqsave(&iommu->lock, flags);

    if ( iommu->cmd_buffer_dead )
        goto out;

    tail = iommu->cmd_buffer.tail + sizeof(cmd_entry_t);
    if ( tail == iommu->cmd_buffer.size )
        tail = 0;

    timeout = NOW() + MILLISECS(100);
    while ( tail == (readl(iommu->mmio_base +
                           IOMMU_CMD_BUFFER_HEAD_OFFSET) &
                     IOMMU_RING_BUFFER_PTR_MASK) )
    {
        if ( NOW() > timeout )
        {
            printk(XENLOG_ERR
                   "AMD IOMMU %pp: command buffer never drains, "
                   "giving up on invalidation\n", &iommu->sbdf);
            died = true;
            goto out;
        }
        cpu_relax();
    }

    memcpy(iommu->cmd_buffer.buffer + iommu->cmd_buffer.tail,
           cmd, sizeof(cmd_entry_t));

    iommu->cmd_buffer.tail = tail;

    writel(tail, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);

 out:
    spin_unlock_irqrestore(&iommu->lock, flags);

    if ( died )
        amd_iommu_cmd_buffer_died(iommu);
}

/*
 * A completion wait is a round trip to the IOMMU. Where that IOMMU is emulated
 * it can cost far more than the invalidation it confirms, which is not visible
 * from outside, so count them and time them. Dumped and reset by the 'y' key.
 */
DEFINE_PER_CPU(uint64_t, amd_iommu_cw_done);
DEFINE_PER_CPU(uint64_t, amd_iommu_cw_ns);

static void invalidate_iommu_all(struct amd_iommu *iommu);
static void invalidate_iommu_pages(struct amd_iommu *iommu,
                                   u64 io_addr, u16 domain_id, u16 order);
static void invalidate_dev_table_entry(struct amd_iommu *iommu,
                                       u16 device_id);
static void invalidate_interrupt_table(struct amd_iommu *iommu, u16 device_id);
static bool skip_dte_invalidation(const struct amd_iommu *iommu,
                                  uint16_t bdf);

/*
 * Queue commands that leave nothing cached that Xen relies on being gone:
 * Invalidate All where the IOMMU has it. Otherwise name everything Xen can
 * have caused to be cached: the TLB entries of every DomainID currently
 * allocated on this IOMMU (a DID is only freed after its last invalidation
 * has been confirmed, and 0 is never handed out), and every valid device
 * table entry and interrupt table behind this IOMMU, leaving out the
 * entries skip_dte_invalidation() says an emulated IOMMU would reject.
 */
static void queue_invalidate_everything(struct amd_iommu *iommu)
{
    const struct amd_iommu_dte *dte = iommu->dev_table.buffer;
    const struct ivrs_mappings *ivrs = get_ivrs_mappings(iommu->sbdf.seg);
    unsigned int i;

    if ( iommu->features.flds.ia_sup )
    {
        invalidate_iommu_all(iommu);
        return;
    }

    for ( i = find_next_bit(iommu->domid_map, IOMMU_DOMID_MAP_SIZE, 1);
          i < IOMMU_DOMID_MAP_SIZE;
          i = find_next_bit(iommu->domid_map, IOMMU_DOMID_MAP_SIZE, i + 1) )
        invalidate_iommu_pages(iommu, INV_IOMMU_ALL_PAGES_ADDRESS, i, 0);

    if ( !dte || !ivrs )
        return;

    for ( i = 0; i < ivrs_bdf_entries; i++ )
    {
        if ( ivrs[i].iommu != iommu || !dte[i].v )
            continue;

        if ( !skip_dte_invalidation(iommu, i) )
            invalidate_dev_table_entry(iommu, i);

        if ( dte[i].iv )
            invalidate_interrupt_table(iommu, i);
    }
}

/* Queue a completion wait and poll for it, giving up at the deadline. */
static bool completion_wait(struct amd_iommu *iommu, uint64_t *poll_slot,
                            const uint32_t cmd[4], s_time_t timeout)
{
    ACCESS_ONCE(*poll_slot) = CMD_COMPLETION_INIT;

    send_iommu_command(iommu, cmd);

    if ( iommu->cmd_buffer_dead )
        return false;

    while ( ACCESS_ONCE(*poll_slot) != CMD_COMPLETION_DONE )
    {
        if ( NOW() > timeout )
            return false;
        cpu_relax();
    }

    return true;
}

static void dump_cmd_buffer_state(struct amd_iommu *iommu, bool iotlb,
                                  paddr_t store)
{
    const uint32_t *ring = iommu->cmd_buffer.buffer;
    unsigned int i;

    printk(XENLOG_WARNING
           "AMD IOMMU %pp: %scompletion wait timed out "
           "(head %#x tail %#x status %#x store %#"PRIpaddr")\n",
           &iommu->sbdf, iotlb ? "iotlb " : "",
           readl(iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET),
           readl(iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET),
           readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET),
           store);

    for ( i = 0; i < 2; ++i )
        printk(XENLOG_WARNING
               "AMD IOMMU %pp: ring[%u] %08x %08x %08x %08x\n",
               &iommu->sbdf, i, ring[i * 4], ring[i * 4 + 1],
               ring[i * 4 + 2], ring[i * 4 + 3]);

    printk(XENLOG_WARNING
           "AMD IOMMU %pp: event log head %#x tail %#x\n",
           &iommu->sbdf,
           readl(iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET),
           readl(iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET));

    iommu_check_event_log(iommu);
}

static void flush_command_buffer(struct amd_iommu *iommu,
                                 unsigned int timeout_base)
{
    static DEFINE_PER_CPU(uint64_t, poll_slot);
    uint64_t *this_poll_slot = &this_cpu(poll_slot);
    paddr_t addr = virt_to_maddr(this_poll_slot);
    /* send a COMPLETION_WAIT command to flush command buffer */
    uint32_t cmd[4] = {
        addr | MASK_INSR(IOMMU_CONTROL_ENABLED,
                         IOMMU_COMP_WAIT_S_FLAG_MASK),
        (addr >> 32) | MASK_INSR(IOMMU_CMD_COMPLETION_WAIT,
                                 IOMMU_CMD_OPCODE_MASK),
        CMD_COMPLETION_DONE,
        0
    };
    s_time_t cw_start;
    static unsigned int __read_mostly threshold = 1;

    if ( iommu->cmd_buffer_dead )
        return;

    this_cpu(amd_iommu_cw_done)++;
    cw_start = NOW();

    if ( completion_wait(iommu, this_poll_slot, cmd,
                         NOW() + (timeout_base ?: 100) * MILLISECS(threshold)) )
    {
        /* The ring is answering. */
        iommu->cmd_failures = 0;
        this_cpu(amd_iommu_cw_ns) += NOW() - cw_start;
        return;
    }

    if ( iommu->cmd_buffer_dead )
        return;

    threshold |= threshold << 1;
    dump_cmd_buffer_state(iommu, timeout_base, addr);

    /*
     * The commands this wait was meant to confirm may not have run, and
     * restarting the ring below discards anything still queued, including
     * other CPUs' invalidations. Returning now would let callers go on to
     * free page tables or frames the IOMMU may still have cached. So only
     * return once a full invalidation is confirmed to have completed after
     * the restart, and declare the command buffer dead if that can't be
     * done.
     */
    for ( ; ; )
    {
        if ( ++iommu->cmd_failures >= 8 )
        {
            printk(XENLOG_ERR
                   "AMD IOMMU %pp: giving up on the command buffer\n",
                   &iommu->sbdf);
            amd_iommu_cmd_buffer_died(iommu);
            return;
        }

        reset_cmd_buffer(iommu);
        queue_invalidate_everything(iommu);

        if ( completion_wait(iommu, this_poll_slot, cmd,
                             NOW() + 100 * MILLISECS(threshold)) )
        {
            printk(XENLOG_WARNING
                   "AMD IOMMU %pp: command buffer restarted, all caches invalidated\n",
                   &iommu->sbdf);
            iommu->cmd_failures = 0;
            return;
        }

        if ( iommu->cmd_buffer_dead )
            return;
    }
}

/* Build low level iommu command messages */
static void invalidate_iommu_pages(struct amd_iommu *iommu,
                                   u64 io_addr, u16 domain_id, u16 order)
{
    u64 addr_lo, addr_hi;
    u32 cmd[4], entry;
    int sflag = 0, pde = 0;

    ASSERT ( order == 0 || order == 9 || order == 18 );

    /* All pages associated with the domainID are invalidated */
    if ( order || (io_addr == INV_IOMMU_ALL_PAGES_ADDRESS ) )
    {
        sflag = 1;
        pde = 1;
    }

    /* If sflag == 1, the size of the invalidate command is determined
     by the first zero bit in the address starting from Address[12] */
    if ( order )
    {
        u64 mask = 1ULL << (order - 1 + PAGE_SHIFT);
        io_addr &= ~mask;
        io_addr |= mask - 1;
    }

    addr_lo = io_addr & DMA_32BIT_MASK;
    addr_hi = io_addr >> 32;

    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOMMU_PAGES, entry,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    set_field_in_reg_u32(sflag, 0,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_SHIFT, &entry);
    set_field_in_reg_u32(pde, entry,
                         IOMMU_INV_IOMMU_PAGES_PDE_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_PDE_FLAG_SHIFT, &entry);
    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, entry,
                         IOMMU_INV_IOMMU_PAGES_ADDR_LOW_MASK,
                         IOMMU_INV_IOMMU_PAGES_ADDR_LOW_SHIFT, &entry);
    cmd[2] = entry;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_MASK,
                         IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_SHIFT, &entry);
    cmd[3] = entry;

    cmd[0] = 0;
    send_iommu_command(iommu, cmd);
}

static void invalidate_iotlb_pages(struct amd_iommu *iommu,
                                   u16 maxpend, u32 pasid, u16 queueid,
                                   u64 io_addr, u16 dev_id, u16 order)
{
    u64 addr_lo, addr_hi;
    u32 cmd[4], entry;
    int sflag = 0;

    ASSERT ( order == 0 || order == 9 || order == 18 );

    if ( order || (io_addr == INV_IOMMU_ALL_PAGES_ADDRESS ) )
        sflag = 1;

    /* If sflag == 1, the size of the invalidate command is determined
     by the first zero bit in the address starting from Address[12] */
    if ( order )
    {
        u64 mask = 1ULL << (order - 1 + PAGE_SHIFT);
        io_addr &= ~mask;
        io_addr |= mask - 1;
    }

    addr_lo = io_addr & DMA_32BIT_MASK;
    addr_hi = io_addr >> 32;

    set_field_in_reg_u32(dev_id, 0,
                         IOMMU_INV_IOTLB_PAGES_DEVICE_ID_MASK,
                         IOMMU_INV_IOTLB_PAGES_DEVICE_ID_SHIFT, &entry);

    set_field_in_reg_u32(maxpend, entry,
                         IOMMU_INV_IOTLB_PAGES_MAXPEND_MASK,
                         IOMMU_INV_IOTLB_PAGES_MAXPEND_SHIFT, &entry);

    set_field_in_reg_u32(pasid & 0xff, entry,
                         IOMMU_INV_IOTLB_PAGES_PASID1_MASK,
                         IOMMU_INV_IOTLB_PAGES_PASID1_SHIFT, &entry);
    cmd[0] = entry;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOTLB_PAGES, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);

    set_field_in_reg_u32(pasid >> 8, entry,
                         IOMMU_INV_IOTLB_PAGES_PASID2_MASK,
                         IOMMU_INV_IOTLB_PAGES_PASID2_SHIFT,
                         &entry);

    set_field_in_reg_u32(queueid, entry,
                         IOMMU_INV_IOTLB_PAGES_QUEUEID_MASK,
                         IOMMU_INV_IOTLB_PAGES_QUEUEID_SHIFT,
                         &entry);
    cmd[1] = entry;

    set_field_in_reg_u32(sflag, 0,
                         IOMMU_INV_IOTLB_PAGES_S_FLAG_MASK,
                         IOMMU_INV_IOTLB_PAGES_S_FLAG_SHIFT, &entry);

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, entry,
                         IOMMU_INV_IOTLB_PAGES_ADDR_LOW_MASK,
                         IOMMU_INV_IOTLB_PAGES_ADDR_LOW_SHIFT, &entry);
    cmd[2] = entry;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_INV_IOTLB_PAGES_ADDR_HIGH_MASK,
                         IOMMU_INV_IOTLB_PAGES_ADDR_HIGH_SHIFT, &entry);
    cmd[3] = entry;

    send_iommu_command(iommu, cmd);
}

static void invalidate_dev_table_entry(struct amd_iommu *iommu,
                                       u16 device_id)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(device_id, 0,
                         IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_MASK,
                         IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_SHIFT, &entry);
    cmd[0] = entry;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_DEVTAB_ENTRY, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    send_iommu_command(iommu, cmd);
}

static void invalidate_interrupt_table(struct amd_iommu *iommu, u16 device_id)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(device_id, 0,
                         IOMMU_INV_INT_TABLE_DEVICE_ID_MASK,
                         IOMMU_INV_INT_TABLE_DEVICE_ID_SHIFT, &entry);
    cmd[0] = entry;
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_INT_TABLE, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;
    send_iommu_command(iommu, cmd);
}

static void invalidate_iommu_all(struct amd_iommu *iommu)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = cmd[0] = 0;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOMMU_ALL, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    send_iommu_command(iommu, cmd);
}

void amd_iommu_flush_iotlb(u8 devfn, const struct pci_dev *pdev,
                           daddr_t daddr, unsigned int order)
{
    struct amd_iommu *iommu;
    unsigned int req_id, queueid, maxpend;

    if ( !ats_enabled )
        return;

    if ( !pci_ats_enabled(pdev) )
        return;

    iommu = find_iommu_for_device(pdev->sbdf);

    if ( !iommu )
    {
        AMD_IOMMU_WARN("can't find IOMMU for %pp\n",
                       &PCI_SBDF(pdev->seg, pdev->bus, devfn));
        return;
    }

    if ( !iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
        return;

    req_id = get_dma_requestor_id(iommu->sbdf.seg, PCI_BDF(pdev->bus, devfn));
    queueid = req_id;
    maxpend = pdev->ats.queue_depth & 0xff;

    /* send INVALIDATE_IOTLB_PAGES command */
    invalidate_iotlb_pages(iommu, maxpend, 0, queueid, daddr, req_id, order);
    flush_command_buffer(iommu, iommu_dev_iotlb_timeout);
}

static void amd_iommu_flush_all_iotlbs(const struct domain *d, daddr_t daddr,
                                       unsigned int order)
{
    struct pci_dev *pdev;

    for_each_pdev( d, pdev )
    {
        u8 devfn = pdev->devfn;

        do {
            amd_iommu_flush_iotlb(devfn, pdev, daddr, order);
            devfn += pdev->phantom_stride;
        } while ( devfn != pdev->devfn &&
                  PCI_SLOT(devfn) == PCI_SLOT(pdev->devfn) );
    }
}

/* Flush iommu cache after p2m changes. */
static void _amd_iommu_flush_pages(struct domain *d, struct iommu_context *ctx,
                                   daddr_t daddr, unsigned int order)
{
    struct amd_iommu *iommu;

    /* send INVALIDATE_IOMMU_PAGES command */
    for_each_amd_iommu ( iommu )
    {
        if ( ctx->arch.amd.iommu_dev_cnt[iommu->index] )
        {
            domid_t dom_id = ctx->arch.amd.didmap[iommu->index];

            invalidate_iommu_pages(iommu, daddr, dom_id, order);
            flush_command_buffer(iommu, 0);
        }
    }

    if ( ats_enabled )
    {
        amd_iommu_flush_all_iotlbs(d, daddr, order);

        /*
         * Hidden devices are associated with DomXEN but usable by the
         * hardware domain. Hence they need dealing with here as well.
         */
        if ( is_hardware_domain(d) )
            amd_iommu_flush_all_iotlbs(dom_xen, daddr, order);
    }
}

void amd_iommu_flush_all_pages(struct domain *d, struct iommu_context *ctx)
{
    _amd_iommu_flush_pages(d, ctx, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
}

void amd_iommu_flush_pages(struct domain *d, struct iommu_context *ctx,
                           unsigned long dfn, unsigned int order)
{
    _amd_iommu_flush_pages(d, ctx, __dfn_to_daddr(dfn), order);
}

/*
 * An emulated AMD-Vi (seen on Google Compute Engine) halts its command
 * processor with ILLEGAL_COMMAND_ERROR on two forms of
 * INVALIDATE_DEVTAB_ENTRY that Linux never sends: one naming an entry with
 * TV clear (Linux prefills V and TV together, Xen prefills V alone), and,
 * with amd-iommu-guest-pt-levels set, one naming an entry deeper than Linux
 * would program. Leave those out when Xen runs as a guest. On bare metal
 * every entry Xen changes is invalidated.
 */
static bool skip_dte_invalidation(const struct amd_iommu *iommu,
                                  uint16_t bdf)
{
    const struct amd_iommu_dte *dte = iommu->dev_table.buffer;

    if ( !cpu_has_hypervisor || !dte )
        return false;

    if ( !dte[bdf].tv )
        return true;

    return amd_iommu_guest_pt_levels &&
           dte[bdf].paging_mode > amd_iommu_guest_pt_levels;
}

void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf,
                            domid_t domid)
{
    if ( !skip_dte_invalidation(iommu, bdf) )
    {
        invalidate_dev_table_entry(iommu, bdf);
        flush_command_buffer(iommu, 0);
    }

    /*
     * Invalidate the IOMMU TLB entries of the domain the entry translated
     * for, even if the entry itself had to be left out above: they are
     * tagged by DomainID, not by entry.
     */
    if ( domid != DOMID_INVALID )
    {
        invalidate_iommu_pages(iommu, INV_IOMMU_ALL_PAGES_ADDRESS, domid, 0);
        flush_command_buffer(iommu, 0);
    }
}

void amd_iommu_flush_intremap(struct amd_iommu *iommu, uint16_t bdf)
{
    invalidate_interrupt_table(iommu, bdf);
    flush_command_buffer(iommu, 0);
}

void amd_iommu_probe_cmd_buffer(struct amd_iommu *iommu)
{
    printk(XENLOG_INFO "AMD IOMMU %pp: probing command buffer\n",
           &iommu->sbdf);
    flush_command_buffer(iommu, 0);
    if ( !iommu->cmd_buffer_dead )
        printk(XENLOG_INFO "AMD IOMMU %pp: command buffer works\n",
               &iommu->sbdf);
}

void amd_iommu_flush_all_caches(struct amd_iommu *iommu)
{
    invalidate_iommu_all(iommu);
    flush_command_buffer(iommu, 0);
}

void cf_check amd_iommu_dump_flush_stats(unsigned char key)
{
    uint64_t done = 0, ns = 0;
    unsigned int cpu;

    for_each_online_cpu ( cpu )
    {
        done += per_cpu(amd_iommu_cw_done, cpu);
        ns += per_cpu(amd_iommu_cw_ns, cpu);
        per_cpu(amd_iommu_cw_done, cpu) = 0;
        per_cpu(amd_iommu_cw_ns, cpu) = 0;
    }

    printk("AMD-Vi: %"PRIu64" completion waits, %"PRIu64" ms, %"PRIu64" ns each\n",
           done, ns / 1000000, done ? ns / done : 0);

    done = ns = 0;
    for_each_online_cpu ( cpu )
    {
        done += per_cpu(pv_mmu_update_calls, cpu);
        ns += per_cpu(pv_mmu_update_ns, cpu);
        per_cpu(pv_mmu_update_calls, cpu) = 0;
        per_cpu(pv_mmu_update_ns, cpu) = 0;
    }

    printk("PV: %"PRIu64" mmu_update calls, %"PRIu64" ms inside, %"PRIu64" ns each\n",
           done, ns / 1000000, done ? ns / done : 0);
}
