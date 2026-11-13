/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for hiding the SPCR's PCI UART from the hardware domain.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <xen-tools/common-macros.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t paddr_t;

/*
 * The tables are laid out by Xen's own ACPICA headers, so the test reads them
 * as the hypervisor does.  These stand in for ACPICA's platform header.
 */
#define ACPI_MACHINE_WIDTH        64
#define COMPILER_DEPENDENT_UINT64 uint64_t
#define COMPILER_DEPENDENT_INT64  int64_t

#include <acpi/actypes.h>
#include <acpi/acconfig.h>
#include <acpi/actbl.h>

#include "pci_regs.h"

#define __init
#define __iomem

#define XENLOG_WARNING ""
#define printk         printf

#define PAGE_SIZE   ((paddr_t)4096)
#define PAGE_MASK   (~(PAGE_SIZE - 1))
#define PFN_DOWN(x) ((x) >> 12)
#define SZ_1M       (1UL << 20)

#define AE_OK                0
#define AE_NOT_FOUND         5
#define ACPI_FAILURE(status) ((status) != AE_OK)

acpi_status acpi_get_table(const char *signature, u32 instance,
                           struct acpi_table_header **out_table);

/* As xen/include/xen/macros.h and xen/include/xen/pci.h define them. */
#define count_args_(dot, a1, a2, a3, a4, a5, a6, a7, a8, x, ...) x
#define count_args(args...) \
    count_args_(., ## args, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define PCI_FUNC(bdf)   ((bdf) & 0x07)

#define PCI_DEVFN1_(df)   ((df) & 0xff)
#define PCI_DEVFN2_(d, f) ((((d) & 0x1f) << 3) | ((f) & 7))
#define PCI_SBDF4_(s, b, d, f...) \
    ((pci_sbdf_t){ .sbdf = (((s) & 0xffff) << 16) | PCI_BDF(b, d, ##f) })
#define PCI_SBDF3_ PCI_SBDF4_

#define PCI__(what, nr) PCI_##what##nr##_
#define PCI_(what, nr)  PCI__(what, nr)

#define PCI_DEVFN(d, f...)   PCI_(DEVFN, count_args(d, ##f))(d, ##f)
#define PCI_BDF(b, d, f...)  ((((b) & 0xff) << 8) | PCI_DEVFN(d, ##f))
#define PCI_SBDF(s, b, d...) PCI_(SBDF, count_args(s, b, ##d))(s, b, ##d)

typedef union {
    uint32_t sbdf;
    struct {
        union {
            uint16_t bdf;
            struct {
                union {
                    struct {
                        uint8_t fn   : 3,
                                dev  : 5;
                    };
                    uint8_t     devfn,
                                extfunc;
                };
                uint8_t         bus;
            };
        };
        uint16_t                seg;
    };
} pci_sbdf_t;

/*
 * As in the shipped arm64 config, the hardware domain has a vuart, which
 * answers the console's first register.
 */
#define CONFIG_HWDOM_VUART

/* As xen/include/xen/serial.h defines it. */
struct vuart_info {
    paddr_t base_addr;          /* Base address of the UART */
    unsigned long size;         /* Size of the memory region */
    unsigned long data_off;     /* Data register offset */
    unsigned long status_off;   /* Status register offset */
    unsigned long status;       /* Ready status value */
};

/* The hardware domain, as far as the code reads it. */
struct domain {
    bool vpci;
    struct {
        struct {
            const struct vuart_info *info;
        } vuart;
    } arch;
};

#define has_vpci(d) ((d)->vpci)

typedef unsigned long gfn_t;
typedef unsigned long mfn_t;
#define _gfn(x) (x)
#define _mfn(x) (x)

/* The configuration space that each test lays out. */
void __iomem *ioremap_nocache(paddr_t pa, size_t len);
static inline void iounmap(void __iomem *va) {}

#define readb(a) (*(const volatile uint8_t *)(a))
#define readw(a) (*(const volatile uint16_t *)(a))
#define readl(a) (*(const volatile uint32_t *)(a))

/* What the code does to the hardware domain, which the tests record. */
void register_unmapped_mmio_handler(struct domain *d, paddr_t addr,
                                    paddr_t size);
int register_ro_pci_config_handler(struct domain *d, paddr_t cfg,
                                   unsigned int clear_reg,
                                   uint32_t clear_bits);
int hide_pci_function_from_hwdom(struct domain *d, paddr_t cfg);
int unmap_mmio_regions(struct domain *d, gfn_t start_gfn, unsigned long nr,
                       mfn_t mfn);
int iomem_deny_access(struct domain *d, unsigned long s, unsigned long e);

int acpi_hide_spcr_pci_uart(struct domain *d,
                            const struct acpi_table_spcr *spcr);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
