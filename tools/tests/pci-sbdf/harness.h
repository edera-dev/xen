/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for PCI_SBDF() and the macros it is built from, taken from
 * xen/include/xen/pci.h as they are, together with pci_sbdf_t.
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <xen-tools/common-macros.h>

/* As xen/include/xen/macros.h defines them. */
#define count_args_(dot, a1, a2, a3, a4, a5, a6, a7, a8, x, ...) x
#define count_args(args...) \
    count_args_(., ## args, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#include "pci-sbdf.h"

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
