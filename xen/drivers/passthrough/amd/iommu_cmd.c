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

#include <xen/param.h>

#include <asm/pv/mm.h>

#include "iommu.h"
#include "../ats.h"

#define CMD_COMPLETION_INIT 0
#define CMD_COMPLETION_DONE 1

/*
 * Whether to recover from a command buffer that stops making progress rather
 * than wait on it indefinitely.  Negative to decide from the platform: an
 * emulated IOMMU has been seen to reject commands real hardware accepts and
 * halt its command processor, whereas on real hardware a stuck command buffer
 * is a fault that recovering from would only hide.
 */
static int8_t __ro_after_init opt_cmd_recovery = -1;
boolean_param("amd-iommu-cmd-recovery", opt_cmd_recovery);

/* Consecutive failed completion waits after which the ring is given up on. */
#define CMD_MAX_FAILURES 8

static bool cmd_recovery(void)
{
    return opt_cmd_recovery < 0 ? cpu_has_hypervisor : opt_cmd_recovery;
}

static uint32_t cmd_buffer_head(const struct amd_iommu *iommu)
{
    return readl(iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET) &
           IOMMU_RING_BUFFER_PTR_MASK;
}

/*
 * A command the IOMMU rejects halts its command processor with the head
 * pointer left on it: CmdBufRun clears and nothing further is consumed.  Step
 * the head past the rejected command and restart, so everything queued behind
 * it -- other CPUs' commands included -- still runs.  Only the rejected
 * command is lost, and it is reported.
 *
 * Returns whether the command processor was halted.  Call with the lock held.
 */
static bool restart_cmd_buffer(struct amd_iommu *iommu)
{
    uint32_t head;
    const uint32_t *cmd;

    ASSERT(spin_is_locked(&iommu->lock));

    if ( readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET) &
         IOMMU_STATUS_CMD_BUFFER_RUN )
        return false;

    head = cmd_buffer_head(iommu);
    cmd = iommu->cmd_buffer.buffer + head;
    printk(XENLOG_ERR
           "AMD IOMMU %pp: command processor halted at %#x (tail %#x): "
           "skipping %08x %08x %08x %08x\n",
           &iommu->sbdf, head, iommu->cmd_buffer.tail,
           cmd[0], cmd[1], cmd[2], cmd[3]);

    iommu->ctrl.cmd_buf_en = false;
    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    if ( head != iommu->cmd_buffer.tail )
    {
        head += sizeof(cmd_entry_t);
        if ( head == iommu->cmd_buffer.size )
            head = 0;
    }
    writel(head, iommu->mmio_base + IOMMU_CMD_BUFFER_HEAD_OFFSET);

    iommu->ctrl.cmd_buf_en = true;
    writeq(iommu->ctrl.raw, iommu->mmio_base + IOMMU_CONTROL_MMIO_OFFSET);

    return true;
}

/* Returns whether the command was queued. */
static bool send_iommu_command(struct amd_iommu *iommu,
                               const uint32_t cmd[4])
{
    uint32_t tail, head, stuck_head = ~0U;
    unsigned long flags;
    s_time_t timeout;
    bool queued = false;

    spin_lock_irqsave(&iommu->lock, flags);

    if ( iommu->cmd_buffer_dead )
        goto out;

    tail = iommu->cmd_buffer.tail + sizeof(cmd_entry_t);
    if ( tail == iommu->cmd_buffer.size )
        tail = 0;

    timeout = NOW() + MILLISECS(100);
    while ( tail == (head = cmd_buffer_head(iommu)) )
    {
        printk_once(XENLOG_ERR "AMD IOMMU %pp: no cmd slot available\n",
                    &iommu->sbdf);

        /*
         * A full ring behind a halted command processor never drains by
         * itself.  Restarting it, once the head has sat still for a whole
         * timeout period, is all that can be done here: whether to give up on
         * the ring altogether is left to the completion waits, which know
         * whether anything is still getting through.
         */
        if ( cmd_recovery() && NOW() > timeout )
        {
            if ( head == stuck_head && restart_cmd_buffer(iommu) )
                stuck_head = ~0U;
            else
                stuck_head = head;
            timeout = NOW() + MILLISECS(100);
        }
        cpu_relax();
    }

    memcpy(iommu->cmd_buffer.buffer + iommu->cmd_buffer.tail,
           cmd, sizeof(cmd_entry_t));

    iommu->cmd_buffer.tail = tail;

    writel(tail, iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET);
    queued = true;

 out:
    spin_unlock_irqrestore(&iommu->lock, flags);

    return queued;
}

/*
 * A completion wait is a round trip to the IOMMU. Where that IOMMU is emulated
 * it can cost far more than the invalidation it confirms, which is not visible
 * from outside, so count them and time them. Dumped and reset by the 'y' key.
 */
DEFINE_PER_CPU(uint64_t, amd_iommu_cw_done);
DEFINE_PER_CPU(uint64_t, amd_iommu_cw_ns);

static void report_cmd_timeout(struct amd_iommu *iommu,
                               unsigned int timeout_base, paddr_t store)
{
    uint32_t head = cmd_buffer_head(iommu);
    const uint32_t *cmd = iommu->cmd_buffer.buffer + head;

    printk(XENLOG_WARNING
           "AMD IOMMU %pp: %scompletion wait taking too long "
           "(head %#x tail %#x status %#x store %#"PRIpaddr")\n",
           &iommu->sbdf, timeout_base ? "iotlb " : "", head,
           readl(iommu->mmio_base + IOMMU_CMD_BUFFER_TAIL_OFFSET),
           readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET), store);
    printk(XENLOG_WARNING
           "AMD IOMMU %pp: command at head %08x %08x %08x %08x, "
           "event log head %#x tail %#x\n",
           &iommu->sbdf, cmd[0], cmd[1], cmd[2], cmd[3],
           readl(iommu->mmio_base + IOMMU_EVENT_LOG_HEAD_OFFSET),
           readl(iommu->mmio_base + IOMMU_EVENT_LOG_TAIL_OFFSET));

    /* A command the IOMMU rejected is named in its event log. */
    iommu_check_event_log(iommu);
}

/*
 * Wait for everything queued so far to complete.  Without recovery (see
 * opt_cmd_recovery) this waits for as long as it takes, as the invalidations
 * it confirms must not be lost.  With it, a halted command processor is
 * restarted past the command it rejected, and after CMD_MAX_FAILURES waits in
 * a row fail to complete the ring is given up on: every flush then fails with
 * -EIO rather than pretend to have invalidated anything.
 */
static int flush_command_buffer(struct amd_iommu *iommu,
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
    s_time_t start, timeout;
    static unsigned int __read_mostly threshold = 1;
    uint32_t stuck_head = ~0U;
    bool slow = false;
    int rc = 0;

    this_cpu(amd_iommu_cw_done)++;
    start = NOW();

    ACCESS_ONCE(*this_poll_slot) = CMD_COMPLETION_INIT;

    if ( !send_iommu_command(iommu, cmd) )
    {
        rc = -EIO;
        goto out;
    }

    timeout = start + (timeout_base ?: 100) * MILLISECS(threshold);
    while ( ACCESS_ONCE(*this_poll_slot) != CMD_COMPLETION_DONE )
    {
        unsigned long flags;
        bool resend = false;
        uint32_t head;

        if ( !timeout || NOW() <= timeout )
        {
            cpu_relax();
            continue;
        }

        slow = true;
        report_cmd_timeout(iommu, timeout_base, addr);

        if ( !cmd_recovery() )
        {
            /* Wait for as long as it takes. */
            threshold |= threshold << 1;
            timeout = 0;
            continue;
        }

        spin_lock_irqsave(&iommu->lock, flags);

        head = cmd_buffer_head(iommu);
        if ( head != stuck_head )
        {
            /*
             * Still consuming commands, just slowly (or this is the first
             * look).  Give it longer before judging it stuck.
             */
            stuck_head = head;
            threshold |= threshold << 1;
        }
        else
        {
            /*
             * The head has not moved in a whole timeout period.  Only then
             * is a clear CmdBufRun trusted to mean the command at the head
             * was rejected, so a slow IOMMU never has a pending command
             * skipped.
             */
            restart_cmd_buffer(iommu);
            stuck_head = cmd_buffer_head(iommu);

            if ( ++iommu->cmd_failures >= CMD_MAX_FAILURES &&
                 !iommu->cmd_buffer_dead )
            {
                printk(XENLOG_ERR
                       "AMD IOMMU %pp: command buffer not completing, "
                       "failing all further invalidation\n", &iommu->sbdf);
                iommu->cmd_buffer_dead = true;
            }
        }

        /*
         * With nothing left in the ring and still no completion, this wait
         * was itself either the command rejected or consumed without its
         * store taking effect.  Queue it again rather than wait for nothing.
         */
        if ( cmd_buffer_head(iommu) == iommu->cmd_buffer.tail )
            resend = ACCESS_ONCE(*this_poll_slot) != CMD_COMPLETION_DONE;

        spin_unlock_irqrestore(&iommu->lock, flags);

        if ( iommu->cmd_buffer_dead )
        {
            rc = -EIO;
            goto out;
        }

        if ( resend )
        {
            ACCESS_ONCE(*this_poll_slot) = CMD_COMPLETION_INIT;
            if ( !send_iommu_command(iommu, cmd) )
            {
                rc = -EIO;
                goto out;
            }
        }

        timeout = NOW() + (timeout_base ?: 100) * MILLISECS(threshold);
    }

    /* The ring is answering again. */
    iommu->cmd_failures = 0;

    if ( slow )
        printk(XENLOG_WARNING
               "AMD IOMMU %pp: %scompletion wait took %"PRI_stime"ms\n",
               &iommu->sbdf, timeout_base ? "iotlb " : "",
               (NOW() - start) / MILLISECS(1));

 out:
    this_cpu(amd_iommu_cw_ns) += NOW() - start;

    return rc;
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

int amd_iommu_flush_iotlb(u8 devfn, const struct pci_dev *pdev,
                          daddr_t daddr, unsigned int order)
{
    struct amd_iommu *iommu;
    unsigned int req_id, queueid, maxpend;

    if ( !ats_enabled )
        return 0;

    if ( !pci_ats_enabled(pdev) )
        return 0;

    iommu = find_iommu_for_device(pdev->sbdf);

    if ( !iommu )
    {
        AMD_IOMMU_WARN("can't find IOMMU for %pp\n",
                       &PCI_SBDF(pdev->seg, pdev->bus, devfn));
        return 0;
    }

    if ( !iommu_has_cap(iommu, PCI_CAP_IOTLB_SHIFT) )
        return 0;

    req_id = get_dma_requestor_id(iommu->sbdf.seg, PCI_BDF(pdev->bus, devfn));
    queueid = req_id;
    maxpend = pdev->ats.queue_depth & 0xff;

    /* send INVALIDATE_IOTLB_PAGES command */
    invalidate_iotlb_pages(iommu, maxpend, 0, queueid, daddr, req_id, order);
    return flush_command_buffer(iommu, iommu_dev_iotlb_timeout);
}

static int amd_iommu_flush_all_iotlbs(const struct domain *d, daddr_t daddr,
                                      unsigned int order)
{
    struct pci_dev *pdev;
    int rc = 0;

    for_each_pdev( d, pdev )
    {
        u8 devfn = pdev->devfn;

        do {
            int ret = amd_iommu_flush_iotlb(devfn, pdev, daddr, order);

            if ( !rc )
                rc = ret;
            devfn += pdev->phantom_stride;
        } while ( devfn != pdev->devfn &&
                  PCI_SLOT(devfn) == PCI_SLOT(pdev->devfn) );
    }

    return rc;
}

/*
 * Flush iommu cache after p2m changes.  Every IOMMU is flushed even once one
 * has failed, and the first failure is returned.
 */
static int _amd_iommu_flush_pages(struct domain *d, struct iommu_context *ctx,
                                  daddr_t daddr, unsigned int order)
{
    struct amd_iommu *iommu;
    int rc = 0, ret;

    /* send INVALIDATE_IOMMU_PAGES command */
    for_each_amd_iommu ( iommu )
    {
        if ( ctx->arch.amd.iommu_dev_cnt[iommu->index] )
        {
            domid_t dom_id = ctx->arch.amd.didmap[iommu->index];

            invalidate_iommu_pages(iommu, daddr, dom_id, order);
            ret = flush_command_buffer(iommu, 0);
            if ( !rc )
                rc = ret;
        }
    }

    if ( ats_enabled )
    {
        ret = amd_iommu_flush_all_iotlbs(d, daddr, order);
        if ( !rc )
            rc = ret;

        /*
         * Hidden devices are associated with DomXEN but usable by the
         * hardware domain. Hence they need dealing with here as well.
         */
        if ( is_hardware_domain(d) )
        {
            ret = amd_iommu_flush_all_iotlbs(dom_xen, daddr, order);
            if ( !rc )
                rc = ret;
        }
    }

    return rc;
}

int amd_iommu_flush_all_pages(struct domain *d, struct iommu_context *ctx)
{
    return _amd_iommu_flush_pages(d, ctx, INV_IOMMU_ALL_PAGES_ADDRESS, 0);
}

int amd_iommu_flush_pages(struct domain *d, struct iommu_context *ctx,
                          unsigned long dfn, unsigned int order)
{
    return _amd_iommu_flush_pages(d, ctx, __dfn_to_daddr(dfn), order);
}

void amd_iommu_flush_device(struct amd_iommu *iommu, uint16_t bdf,
                            domid_t domid)
{
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
    if ( !flush_command_buffer(iommu, 0) )
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

#ifdef CONFIG_PV
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
#endif
}
