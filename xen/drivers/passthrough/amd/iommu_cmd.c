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

static void send_iommu_command(struct amd_iommu *iommu,
                               const uint32_t cmd[4])
{
    uint32_t tail;
    unsigned long flags;
    s_time_t timeout;

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
            iommu->cmd_buffer_dead = true;
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
}

/*
 * A completion wait is a round trip to the IOMMU. Where that IOMMU is emulated
 * it can cost far more than the invalidation it confirms, which is not visible
 * from outside, so count them and time them. Dumped and reset by the 'y' key.
 */
DEFINE_PER_CPU(uint64_t, amd_iommu_cw_done);
DEFINE_PER_CPU(uint64_t, amd_iommu_cw_ns);

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
    s_time_t start, timeout, cw_start;
    static unsigned int __read_mostly threshold = 1;

    if ( iommu->cmd_buffer_dead )
        return;

    this_cpu(amd_iommu_cw_done)++;
    cw_start = NOW();

    ACCESS_ONCE(*this_poll_slot) = CMD_COMPLETION_INIT;

    send_iommu_command(iommu, cmd);

    if ( iommu->cmd_buffer_dead )
        return;

    start = NOW();
    timeout = start + (timeout_base ?: 100) * MILLISECS(threshold);
    while ( ACCESS_ONCE(*this_poll_slot) != CMD_COMPLETION_DONE )
    {
        if ( NOW() > timeout )
        {
            threshold |= threshold << 1;
            /*
             * An IOMMU that never stores the completion word would otherwise
             * wedge us here forever, so report what it did with the command
             * and carry on rather than hanging the boot.
             */
            printk(XENLOG_WARNING
                   "AMD IOMMU %pp: %scompletion wait timed out "
                   "(head %#x tail %#x status %#x store %#"PRIpaddr")\n",
                   &iommu->sbdf,
                   timeout_base ? "iotlb " : "",
                   readl(iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET),
                   readl(iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET),
                   readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET),
                   addr);
            {
                const uint32_t *ring = iommu->cmd_buffer.buffer;
                unsigned int i;

                for ( i = 0; i < 2; ++i )
                    printk(XENLOG_WARNING
                           "AMD IOMMU %pp: ring[%u] %08x %08x %08x %08x\n",
                           &iommu->sbdf, i, ring[i * 4], ring[i * 4 + 1],
                           ring[i * 4 + 2], ring[i * 4 + 3]);
            }
            printk(XENLOG_WARNING
                   "AMD IOMMU %pp: event log head %#x tail %#x\n",
                   &iommu->sbdf,
                   readl(iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET),
                   readl(iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET));
            iommu_check_event_log(iommu);
            /*
             * Restart the ring rather than give up on it. Only stop using it
             * altogether once restarting has repeatedly failed to help, so a
             * genuinely dead command buffer cannot cost a timeout per flush.
             */
            reset_cmd_buffer(iommu);

            if ( ++iommu->cmd_failures >= 8 )
            {
                printk(XENLOG_WARNING
                       "AMD IOMMU %pp: giving up on the command buffer\n",
                       &iommu->sbdf);
                iommu->cmd_buffer_dead = true;
            }
            return;
        }
        cpu_relax();
    }

    /* The ring is answering again. */
    iommu->cmd_failures = 0;

    this_cpu(amd_iommu_cw_ns) += NOW() - cw_start;
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
                         IOMMU_INV_IOTLB_PAGES_S_FLAG_MASK, &entry);

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

void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf,
                            domid_t domid)
{
    const struct amd_iommu_dte *dte = iommu->dev_table.buffer;

    /*
     * An entry with TV clear translates nothing, so there is nothing cached
     * to invalidate. Skipping it also avoids naming such an entry at all:
     * Linux prefills V and TV together and never invalidates a V-only entry,
     * and an emulated IOMMU has been seen to reject the command outright and
     * halt its command processor, starving every later invalidation.
     */
    if ( dte && !dte[bdf].tv )
        return;

    /*
     * Likewise skip an entry deeper than the shape guests are capped to. Xen
     * derives the hardware domain's depth from the address width and lands on
     * five levels where Linux programs three, and an IOMMU that has only seen
     * Linux may reject the command naming such an entry.
     */
    if ( dte && amd_iommu_guest_pt_levels &&
         dte[bdf].paging_mode > amd_iommu_guest_pt_levels )
        return;

    invalidate_dev_table_entry(iommu, bdf);
    flush_command_buffer(iommu, 0);

    /* Also invalidate IOMMU TLB entries when flushing the DTE. */
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
