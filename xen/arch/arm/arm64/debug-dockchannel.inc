/*
 * xen/arch/arm/arm64/debug-dockchannel.inc
 *
 * Apple "dockchannel" debug console early printk support.
 *
 * On Apple Silicon the SoC's debug console can leave the package by two
 * different routes, selected by the USB-C port controller (Ace2), not by the
 * SoC:
 *
 *   - "serial" mode: the apple,s5l-uart lines are muxed onto the port's SBU
 *     pins and read by the host as a raw 1.5 Mbaud UART.  Use debug-s5l.inc.
 *
 *   - "debugusb" mode: the port controller tunnels the *dockchannel* FIFO to
 *     the host over USB, where it appears as /dev/cu.kis-100000-ch-0.  That is
 *     this file.
 *
 * The dockchannel is not a UART: it has no baud rate or line control, just a
 * byte FIFO with a free-space count.
 *
 * CONFIG_EARLY_UART_BASE_ADDRESS must be the *data window* base, which is the
 * controller base (reg[0] of the ADT's /arm-io/dockchannel-uart) plus 0x4000 —
 * the same split the Asahi kernel models as the separate "data" reg resource
 * in drivers/soc/apple/dockchannel.c.  m1n1's src/dockchannel_uart.c folds the
 * 0x4000 into its constants instead (0x4004/0x4014), which is why the offsets
 * here look different from m1n1's for the same registers.
 *
 * Pointing the config at the controller base and using m1n1's offsets is not
 * an option: 0x4014 exceeds the 16380-byte range of the 32-bit scaled
 * immediate, and neither caller of early_uart_transmit (head.S asm_puts /
 * asm_putn) has a spare register to fold the addition into.
 *
 * iBoot and m1n1 have both already brought the channel up, so as with the s5l
 * UART there is no early_uart_init: EARLY_UART_DOCKCHANNEL does not select
 * CONFIG_EARLY_UART_INIT.
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

#define DOCKCHANNEL_DATA_TX8       0x04    /* Transmit one byte            */
#define DOCKCHANNEL_DATA_TX_FREE   0x14    /* Free space in the TX FIFO    */

/*
 * Apple dockchannel wait for space in the transmit FIFO.
 * xb: register which contains the dockchannel data window base address
 * c: scratch register
 */
.macro early_uart_ready xb c
1:
        ldr   w\c, [\xb, #DOCKCHANNEL_DATA_TX_FREE] /* Free bytes in TX FIFO */
        cbz   w\c, 1b                               /* Wait while full      */
.endm

/*
 * Apple dockchannel transmit character.  32-bit MMIO access is mandatory.
 * xb: register which contains the dockchannel data window base address
 * wt: register which contains the character to transmit
 */
.macro early_uart_transmit xb wt
        str   \wt, [\xb, #DOCKCHANNEL_DATA_TX8]
.endm

/*
 * Local variables:
 * mode: ASM
 * indent-tabs-mode: nil
 * End:
 */
