/*
 * xen/arch/arm/arm64/debug-s5l.inc
 *
 * Apple "s5l" UART (compatible "apple,s5l-uart") early printk support.
 *
 * This is the Samsung S3C2410-derived UART found on Apple Silicon SoCs.  It
 * requires 32-bit MMIO accesses.  m1n1 (or iBoot) has already initialised and
 * clocked the UART before Xen is entered, so no early_uart_init is needed.
 *
 * Register offsets match include/linux/serial_s3c.h in the Asahi kernel.
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

#define S5L_UTXH          0x20    /* Transmit holding register */
#define S5L_UFSTAT        0x18    /* FIFO status register       */

#define S5L_UFSTAT_TXFULL_BIT   9 /* TX FIFO full (S3C2410_UFSTAT_TXFULL) */

/*
 * Apple s5l UART wait for the transmit FIFO to have room.
 * xb: register which contains the UART base address
 * c: scratch register
 */
.macro early_uart_ready xb c
1:
        ldr   w\c, [\xb, #S5L_UFSTAT]              /* FIFO status register    */
        tbnz  w\c, #S5L_UFSTAT_TXFULL_BIT, 1b      /* Wait while TX FIFO full */
.endm

/*
 * Apple s5l UART transmit character.  32-bit MMIO access is mandatory.
 * xb: register which contains the UART base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb wt
        str   \wt, [\xb, #S5L_UTXH]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
