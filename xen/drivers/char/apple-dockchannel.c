/*
 * xen/drivers/char/apple-dockchannel.c
 *
 * Console driver for the Apple "dockchannel" debug FIFO.
 *
 * On Apple Silicon the port controller decides which of two completely
 * different pieces of hardware carries the debug console: in "serial" mode it
 * is the s5l UART on the SBU pins (see s5l-uart.c), and in "debugusb" mode the
 * dockchannel FIFO is tunnelled to the host over USB.  Where the local end
 * cannot be put into serial mode, the dockchannel is the only console there is.
 *
 * Unlike the s5l UART this device has no node in the Linux-style device tree --
 * it exists only in Apple's own ADT, which Xen does not parse -- so it cannot be
 * probed.  It is registered from the Apple platform code instead, using the
 * address the early-printk backend was already configured with, which also
 * guarantees the two agree about which port they are talking to.
 *
 * Receive is polled.  The FIFO's interrupt is described in the ADT and not in
 * the device tree, so its AIC event number is not knowable here; a timer is
 * enough for a debug console and avoids guessing.
 *
 * The address is the *data window*, i.e. the controller base plus 0x4000, which
 * is what CONFIG_EARLY_UART_BASE_ADDRESS holds for this backend.  Offsets below
 * are relative to that, matching m1n1's src/dockchannel_uart.c.
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

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/serial.h>
#include <xen/timer.h>
#include <asm/io.h>

#define DOCKCHANNEL_DATA_TX8        0x04
#define DOCKCHANNEL_DATA_TX_FREE    0x14
#define DOCKCHANNEL_DATA_RX8        0x1c
#define DOCKCHANNEL_DATA_RX_COUNT   0x2c

/*
 * 10ms is imperceptible for typing and cheap.  Drain at most a FIFO's worth per
 * tick so a host pasting a large amount of input cannot monopolise the timer.
 */
#define RX_POLL_INTERVAL    MILLISECS(10)
#define RX_POLL_BUDGET      64

static struct apple_dockchannel {
    void __iomem *regs;
    struct timer rx_timer;
} dockchannel_com;

static void cf_check dockchannel_rx_poll(void *data)
{
    struct serial_port *port = data;
    struct apple_dockchannel *uart = port->uart;
    unsigned int budget = RX_POLL_BUDGET;

    while ( budget-- && readl(uart->regs + DOCKCHANNEL_DATA_RX_COUNT) )
        serial_rx_interrupt(port);

    set_timer(&uart->rx_timer, NOW() + RX_POLL_INTERVAL);
}

static void __init dockchannel_init_preirq(struct serial_port *port)
{
    /*
     * m1n1 has already brought the FIFO up -- it was using it as its own
     * console moments ago -- so there is nothing to program, and programming it
     * would risk the console this is being debugged over.
     */
}

static void __init dockchannel_init_postirq(struct serial_port *port)
{
    struct apple_dockchannel *uart = port->uart;

    init_timer(&uart->rx_timer, dockchannel_rx_poll, port, 0);
    set_timer(&uart->rx_timer, NOW() + RX_POLL_INTERVAL);
}

static int cf_check dockchannel_tx_ready(struct serial_port *port)
{
    struct apple_dockchannel *uart = port->uart;

    return readl(uart->regs + DOCKCHANNEL_DATA_TX_FREE);
}

static void cf_check dockchannel_putc(struct serial_port *port, char c)
{
    struct apple_dockchannel *uart = port->uart;

    writel(c, uart->regs + DOCKCHANNEL_DATA_TX8);
}

static int cf_check dockchannel_getc(struct serial_port *port, char *pc)
{
    struct apple_dockchannel *uart = port->uart;

    if ( !readl(uart->regs + DOCKCHANNEL_DATA_RX_COUNT) )
        return 0;

    /* The received byte sits in bits 15:8 of the data register. */
    *pc = (readl(uart->regs + DOCKCHANNEL_DATA_RX8) >> 8) & 0xff;

    return 1;
}

static int cf_check dockchannel_irq(struct serial_port *port)
{
    return -1;                          /* polled; see the comment above */
}

static struct uart_driver __read_mostly dockchannel_driver = {
    .init_preirq  = dockchannel_init_preirq,
    .init_postirq = dockchannel_init_postirq,
    .tx_ready     = dockchannel_tx_ready,
    .putc         = dockchannel_putc,
    .getc         = dockchannel_getc,
    .irq          = dockchannel_irq,
};

void __init apple_dockchannel_console_init(paddr_t base)
{
    struct apple_dockchannel *uart = &dockchannel_com;

    /*
     * One page covers every register used here.  The FIFO is device memory and
     * must not be speculated into or write-combined.
     */
    uart->regs = ioremap_nocache(base, PAGE_SIZE);
    if ( !uart->regs )
    {
        printk(XENLOG_ERR "dockchannel: cannot map %#"PRIpaddr"\n", base);
        return;
    }

    serial_register_uart(SERHND_DTUART, &dockchannel_driver, uart);
    printk("dockchannel: console at %#"PRIpaddr" (polled receive)\n", base);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
