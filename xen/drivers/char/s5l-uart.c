/*
 * xen/drivers/char/s5l-uart.c
 *
 * Driver for the Apple "s5l" UART (compatible "apple,s5l-uart").
 *
 * This is the Samsung S3C2410-derived UART on Apple Silicon.  It is closely
 * related to the Exynos 4210 UART (see exynos4210-uart.c), but requires 32-bit
 * MMIO accesses and uses the plain S3C register layout.
 *
 * Scope / status (see plans/asahi/07-platform-console-and-drivers.md):
 *   - m1n1/iBoot has already initialised, clocked and set the baud rate of the
 *     UART before Xen runs, so init_preirq deliberately does NOT reconfigure
 *     it (that would risk breaking console output).
 *   - Transmit works immediately in polled mode (the serial core busy-waits on
 *     ->tx_ready), so this is usable as the Xen "dtuart" console right away.
 *   - Receive is interrupt-driven and therefore deferred: the UART interrupt is
 *     an AIC line, and the AIC is not yet registered as Xen's interrupt
 *     controller (see plans/asahi/03).  ->irq returns -1 until then, so the
 *     port operates polled.  The Apple RX interrupt is signalled/acked via
 *     UTRSTAT threshold/timeout bits, unlike the Exynos UINTP/UINTM model.
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

#include <xen/console.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/serial.h>
#include <asm/device.h>
#include <asm/io.h>

/* S3C2410 register offsets (see include/linux/serial_s3c.h in the kernel). */
#define ULCON       0x00
#define UCON        0x04
#define UFCON       0x08
#define UTRSTAT     0x10
#define UFSTAT      0x18
#define UTXH        0x20
#define URXH        0x24

#define UTRSTAT_TXFE    (1U << 1)   /* Tx buffer/FIFO empty        */
#define UTRSTAT_TXE     (1U << 2)   /* Transmitter empty           */
#define UFSTAT_RX_MASK  0xfU        /* Rx FIFO count               */
#define UFSTAT_RX_FULL  (1U << 8)   /* Rx FIFO full                */
#define UFSTAT_TX_FULL  (1U << 9)   /* Tx FIFO full                */

static struct s5l_uart {
    void __iomem *regs;
    struct vuart_info vuart;
} s5l_com = { 0 };

#define s5l_read(uart, off)         readl((uart)->regs + (off))
#define s5l_write(uart, off, val)   writel((val), (uart)->regs + (off))

static void __init s5l_uart_init_preirq(struct serial_port *port)
{
    /*
     * Intentionally left minimal: the bootloader (m1n1) has already configured
     * line control, baud rate and the FIFO.  Reprogramming them here risks
     * losing the console, and we have no reliable clock/divisor to recompute
     * the baud rate from.  See the file header.
     */
}

static int s5l_uart_tx_ready(struct serial_port *port)
{
    struct s5l_uart *uart = port->uart;

    return (s5l_read(uart, UFSTAT) & UFSTAT_TX_FULL) ? 0 : 1;
}

static void s5l_uart_putc(struct serial_port *port, char c)
{
    struct s5l_uart *uart = port->uart;

    s5l_write(uart, UTXH, (uint32_t)(unsigned char)c);
}

static int s5l_uart_getc(struct serial_port *port, char *pc)
{
    struct s5l_uart *uart = port->uart;
    uint32_t ufstat = s5l_read(uart, UFSTAT);

    if ( !(ufstat & (UFSTAT_RX_FULL | UFSTAT_RX_MASK)) )
        return 0;

    *pc = s5l_read(uart, URXH) & 0xff;
    return 1;
}

static int __init s5l_uart_irq(struct serial_port *port)
{
    /*
     * No serviceable interrupt until the AIC is registered as Xen's interrupt
     * controller (plans/asahi/03); run polled (transmit only) until then.
     */
    return -1;
}

static const struct vuart_info *s5l_vuart_info(struct serial_port *port)
{
    struct s5l_uart *uart = port->uart;

    return &uart->vuart;
}

static struct uart_driver __read_mostly s5l_uart_driver = {
    .init_preirq = s5l_uart_init_preirq,
    .tx_ready    = s5l_uart_tx_ready,
    .putc        = s5l_uart_putc,
    .getc        = s5l_uart_getc,
    .irq         = s5l_uart_irq,
    .vuart_info  = s5l_vuart_info,
};

static int __init s5l_uart_init(struct dt_device_node *dev, const void *data)
{
    const char *config = data;
    struct s5l_uart *uart = &s5l_com;
    paddr_t addr, size;
    int res;

    if ( strcmp(config, "") )
        printk("WARNING: UART configuration is not supported\n");

    res = dt_device_get_paddr(dev, 0, &addr, &size);
    if ( res )
    {
        printk("s5l: Unable to retrieve the base address of the UART\n");
        return res;
    }

    /*
     * NOTE: on real Apple hardware this mapping must be Device-nGnRnE; the
     * ioremap_nocache() memory type must be confirmed/overridden there.
     */
    uart->regs = ioremap_nocache(addr, size);
    if ( !uart->regs )
    {
        printk("s5l: Unable to map the UART memory\n");
        return -ENOMEM;
    }

    uart->vuart.base_addr   = addr;
    uart->vuart.size        = size;
    uart->vuart.data_off    = UTXH;
    uart->vuart.status_off  = UTRSTAT;
    uart->vuart.status      = UTRSTAT_TXE | UTRSTAT_TXFE;

    /* Register with the generic serial driver. */
    serial_register_uart(SERHND_DTUART, &s5l_uart_driver, uart);

    dt_device_set_used_by(dev, DOMID_XEN);

    return 0;
}

static const struct dt_device_match s5l_uart_dt_match[] __initconst =
{
    DT_MATCH_COMPATIBLE("apple,s5l-uart"),
    { /* sentinel */ },
};

DT_DEVICE_START(s5l_uart, "Apple s5l UART", DEVICE_SERIAL)
    .dt_match = s5l_uart_dt_match,
    .init = s5l_uart_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
