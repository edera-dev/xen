/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unit tests for hiding the SPCR's PCI UART, Xen's console, from the hardware
 * domain.  Each case lays out the configuration space of a PCI segment and an
 * MCFG, and checks what acpi_hide_spcr_pci_uart() does with an SPCR: which
 * parts of the UART's page it makes read as all ones, which function it hides,
 * and which port it makes read-only.
 */

#include "harness.h"

/* Graviton4's console: 1d0f:8250 on segment 3, with 8-bit registers. */
#define SEGMENT     3
#define UART_VENDOR 0x1d0f
#define UART_DEVICE 0x8250
#define UART_BAR    0x83700000UL
#define UART_PAGE   (UART_BAR & PAGE_MASK)

/* The hardware domain's vuart answers one register of that width. */
#define VUART_SIZE 1

#define OTHER_VENDOR 0x1b36
#define OTHER_DEVICE 0x0001

/* The segment of a two-socket Graviton4's other root complex. */
#define OTHER_SEGMENT 0xb

/* Where the MCFG puts the configuration space of the segment's bus 0. */
#define ECAM_BASE 0xb730000000UL
#define LAST_BUS  3

/* An MCFG base with no configuration space behind it. */
#define NO_ECAM (ECAM_BASE + sizeof(ecam))

#define MULTI_FUNCTION 0x80

/* Where add_port() puts the PCI Express capability. */
#define PCIE_CAP 0x60

static uint8_t ecam[(LAST_BUS + 1) << 20];

static struct {
    struct acpi_table_mcfg header;
    struct acpi_mcfg_allocation window[3];
} mcfg;
static unsigned int mcfg_windows;

struct range {
    paddr_t start, size;
};

/* What acpi_hide_spcr_pci_uart() did to the hardware domain. */
static struct {
    struct range emptied[4];
    unsigned int nr_emptied;
    paddr_t hidden;
    paddr_t locked;
    unsigned int locked_reg;
    uint32_t locked_bits;
    paddr_t unmapped;
    paddr_t denied;
} seen;

/* What register_ro_pci_config_handler() returns. */
static int lock_rc;

static const char *test_name;

acpi_status acpi_get_table(const char *signature, u32 instance,
                           struct acpi_table_header **out_table)
{
    if ( strncmp(signature, ACPI_SIG_MCFG, ACPI_NAME_SIZE) || instance )
        return AE_NOT_FOUND;

    *out_table = &mcfg.header.header;

    return AE_OK;
}

void __iomem *ioremap_nocache(paddr_t pa, size_t len)
{
    if ( pa < ECAM_BASE || pa + len > ECAM_BASE + sizeof(ecam) )
        return NULL;

    return ecam + (pa - ECAM_BASE);
}

void register_unmapped_mmio_handler(struct domain *d, paddr_t addr,
                                    paddr_t size)
{
    if ( seen.nr_emptied < ARRAY_SIZE(seen.emptied) )
        seen.emptied[seen.nr_emptied] = (struct range){ addr, size };
    seen.nr_emptied++;
}

int register_ro_pci_config_handler(struct domain *d, paddr_t cfg,
                                   unsigned int clear_reg,
                                   uint32_t clear_bits)
{
    seen.locked = cfg;
    seen.locked_reg = clear_reg;
    seen.locked_bits = clear_bits;

    return lock_rc;
}

int hide_pci_function_from_hwdom(struct domain *d, paddr_t cfg)
{
    seen.hidden = cfg;

    return 0;
}

int unmap_mmio_regions(struct domain *d, gfn_t start_gfn, unsigned long nr,
                       mfn_t mfn)
{
    if ( nr == 1 && start_gfn == mfn )
        seen.unmapped = (paddr_t)mfn << 12;

    return 0;
}

int iomem_deny_access(struct domain *d, unsigned long s, unsigned long e)
{
    if ( s == e )
        seen.denied = (paddr_t)s << 12;

    return 0;
}

static void add_window(unsigned int segment, unsigned int first_bus,
                       unsigned int last_bus, paddr_t base)
{
    struct acpi_mcfg_allocation *window = &mcfg.window[mcfg_windows++];

    window->address = base;
    window->pci_segment = segment;
    window->start_bus_number = first_bus;
    window->end_bus_number = last_bus;
    mcfg.header.header.length = sizeof(mcfg.header) +
                                mcfg_windows * sizeof(*window);
}

static uint8_t *config(unsigned int bus, unsigned int dev, unsigned int fn)
{
    return ecam + ((size_t)bus << 20) + (dev << 15) + (fn << 12);
}

static paddr_t config_address(unsigned int bus, unsigned int dev,
                              unsigned int fn)
{
    return ECAM_BASE + (config(bus, dev, fn) - ecam);
}

static uint8_t *add_function(unsigned int bus, unsigned int dev,
                             unsigned int fn, uint16_t vendor,
                             uint16_t device, uint8_t header)
{
    uint8_t *cfg = config(bus, dev, fn);

    memset(cfg, 0, 4096);
    cfg[PCI_VENDOR_ID] = vendor;
    cfg[PCI_VENDOR_ID + 1] = vendor >> 8;
    cfg[PCI_DEVICE_ID] = device;
    cfg[PCI_DEVICE_ID + 1] = device >> 8;
    cfg[PCI_HEADER_TYPE] = header;

    return cfg;
}

static uint8_t *add_uart(unsigned int bus, unsigned int dev, unsigned int fn)
{
    return add_function(bus, dev, fn, UART_VENDOR, UART_DEVICE,
                        PCI_HEADER_TYPE_NORMAL);
}

/* A conventional PCI bridge to @secondary. */
static uint8_t *add_bridge(unsigned int bus, unsigned int dev,
                           unsigned int fn, unsigned int secondary)
{
    uint8_t *cfg = add_function(bus, dev, fn, OTHER_VENDOR, OTHER_DEVICE,
                                PCI_HEADER_TYPE_BRIDGE);

    cfg[PCI_SECONDARY_BUS] = secondary;

    return cfg;
}

/*
 * A PCI Express port to @secondary.  Its PCI Express capability comes after a
 * power management one, so that finding it takes a step along the list.
 */
static uint8_t *add_port(unsigned int bus, unsigned int dev, unsigned int fn,
                         unsigned int secondary)
{
    uint8_t *cfg = add_bridge(bus, dev, fn, secondary);

    cfg[PCI_STATUS] = PCI_STATUS_CAP_LIST;
    cfg[PCI_CAPABILITY_LIST] = 0x40;
    cfg[0x40 + PCI_CAP_LIST_ID] = PCI_CAP_ID_PM;
    cfg[0x40 + PCI_CAP_LIST_NEXT] = PCIE_CAP;
    cfg[PCIE_CAP + PCI_CAP_LIST_ID] = PCI_CAP_ID_EXP;

    return cfg;
}

/*
 * The ports that lead to bus 3 through a PCI Express switch, as on Graviton:
 * a root port to bus 1, the switch's upstream port there to bus 2, and its
 * downstream port there to bus 3.
 */
static void add_switch(void)
{
    add_port(0, 1, 0, 1);
    add_port(1, 0, 0, 2);
    add_port(2, 0, 0, 3);
}

static struct acpi_table_spcr spcr_for(unsigned int bus, unsigned int dev,
                                       unsigned int fn)
{
    struct acpi_table_spcr spcr = {
        .serial_port.address = UART_BAR,
        .pci_device_id = UART_DEVICE,
        .pci_vendor_id = UART_VENDOR,
        .pci_bus = bus,
        .pci_device = dev,
        .pci_function = fn,
        .pci_segment = SEGMENT,
    };

    return spcr;
}

/* The vuart answers at the console's registers, as ns16550 sets it up. */
static int run_hide(const struct acpi_table_spcr *spcr, bool vpci)
{
    struct vuart_info vuart = {
        .base_addr = spcr->serial_port.address,
        .size = VUART_SIZE,
    };
    struct domain d = {
        .vpci = vpci,
        .arch.vuart.info = &vuart,
    };

    return acpi_hide_spcr_pci_uart(&d, spcr);
}

static bool hide(const struct acpi_table_spcr *spcr, bool vpci)
{
    int rc = run_hide(spcr, vpci);

    if ( rc )
        printf("%s: returned %d\n", test_name, rc);

    return !rc;
}

static void print_ranges(const struct range *ranges, unsigned int nr)
{
    unsigned int i;

    for ( i = 0; i < nr; i++ )
        printf(" [%#"PRIx64", +%#"PRIx64")", ranges[i].start, ranges[i].size);
}

/* Check that the @nr ranges in @want, and nothing else, read as all ones. */
static bool emptied(const struct range *want, unsigned int nr)
{
    unsigned int i;

    if ( seen.nr_emptied == nr )
    {
        for ( i = 0; i < nr; i++ )
            if ( seen.emptied[i].start != want[i].start ||
                 seen.emptied[i].size != want[i].size )
                break;
        if ( i == nr )
            return true;
    }

    printf("%s: %u ranges read as all ones:", test_name, seen.nr_emptied);
    print_ranges(seen.emptied, min(seen.nr_emptied,
                                   (unsigned int)ARRAY_SIZE(seen.emptied)));
    printf("; want %u:", nr);
    print_ranges(want, nr);
    printf("\n");

    return false;
}

/* The UART's page reads as all ones, but for the vuart's register. */
static bool emptied_but_vuart(void)
{
    static const struct range rest = {
        UART_BAR + VUART_SIZE, UART_PAGE + PAGE_SIZE - UART_BAR - VUART_SIZE
    };

    return emptied(&rest, 1);
}

/*
 * Check that the function at @uart is hidden, and that the port at @port is
 * read-only, without its hot-plug bit, and can no longer be mapped.  Zero
 * means none.
 */
static bool expect(paddr_t uart, paddr_t port)
{
    unsigned int reg = port ? PCIE_CAP + PCI_EXP_SLTCAP : 0;
    uint32_t bits = port ? PCI_EXP_SLTCAP_HPC : 0;

    if ( seen.hidden == uart && seen.locked == port &&
         seen.locked_reg == reg && seen.locked_bits == bits &&
         seen.unmapped == port && seen.denied == port )
        return true;

    printf("%s: hidden %#"PRIx64", port %#"PRIx64" (register %#x, bits %#x)"
           ", unmapped %#"PRIx64", denied %#"PRIx64"; want hidden %#"PRIx64
           ", port %#"PRIx64"\n",
           test_name, seen.hidden, seen.locked, seen.locked_reg,
           seen.locked_bits, seen.unmapped, seen.denied, uart, port);

    return false;
}

static bool kept(void)
{
    return emptied_but_vuart() && expect(0, 0);
}

static bool hidden_at(paddr_t uart, paddr_t port)
{
    return emptied_but_vuart() && expect(uart, port);
}

static bool test_not_pci(void)
{
    struct acpi_table_spcr spcr = spcr_for(0, 2, 0);

    spcr.pci_vendor_id = 0xffff;
    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_uart(0, 2, 0);

    return hide(&spcr, false) && emptied(NULL, 0) && expect(0, 0);
}

static bool test_root_bus(void)
{
    struct acpi_table_spcr spcr = spcr_for(0, 2, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_uart(0, 2, 0);

    return hide(&spcr, false) && hidden_at(config_address(0, 2, 0), 0);
}

static bool test_behind_switch(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_uart(3, 0, 0);

    return hide(&spcr, false) &&
           hidden_at(config_address(3, 0, 0), config_address(2, 0, 0));
}

static bool test_vuart_mid_page(void)
{
    static const struct range around[] = {
        { UART_PAGE, 0x800 },
        { UART_PAGE + 0x800 + VUART_SIZE, 0x800 - VUART_SIZE },
    };
    struct acpi_table_spcr spcr = spcr_for(0, 2, 0);

    spcr.serial_port.address = UART_PAGE + 0x800;
    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_uart(0, 2, 0);

    return hide(&spcr, false) && emptied(around, ARRAY_SIZE(around)) &&
           expect(config_address(0, 2, 0), 0);
}

static bool test_vpci(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_uart(3, 0, 0);

    return hide(&spcr, true) && kept();
}

static bool test_no_window(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(OTHER_SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_uart(3, 0, 0);

    return hide(&spcr, false) && kept();
}

static bool test_other_vendor(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_function(3, 0, 0, OTHER_VENDOR, UART_DEVICE, PCI_HEADER_TYPE_NORMAL);

    return hide(&spcr, false) && kept();
}

static bool test_other_device(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_function(3, 0, 0, UART_VENDOR, OTHER_DEVICE, PCI_HEADER_TYPE_NORMAL);

    return hide(&spcr, false) && kept();
}

static bool test_function_1(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 1);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_function(3, 0, 0, OTHER_VENDOR, OTHER_DEVICE, MULTI_FUNCTION);
    add_uart(3, 0, 1);

    return hide(&spcr, false) && kept();
}

static bool test_multi_function(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);
    uint8_t *uart;

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    uart = add_uart(3, 0, 0);
    uart[PCI_HEADER_TYPE] |= MULTI_FUNCTION;
    add_function(3, 0, 1, OTHER_VENDOR, OTHER_DEVICE, PCI_HEADER_TYPE_NORMAL);

    return hide(&spcr, false) && kept();
}

static bool test_no_bridge(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_uart(3, 0, 0);

    return hide(&spcr, false) && kept();
}

static bool test_conventional_bridge(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_port(0, 1, 0, 1);
    add_port(1, 0, 0, 2);
    add_bridge(2, 0, 0, 3);
    add_uart(3, 0, 0);

    return hide(&spcr, false) && kept();
}

static bool test_port_multi_function(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);
    uint8_t *port;

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_port(0, 1, 0, 1);
    add_port(1, 0, 0, 2);
    port = add_port(2, 0, 0, 3);
    port[PCI_HEADER_TYPE] |= MULTI_FUNCTION;
    add_uart(3, 0, 0);

    return hide(&spcr, false) &&
           hidden_at(config_address(3, 0, 0), config_address(2, 0, 0));
}

static bool test_port_after_single_function(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_port(0, 1, 0, 1);
    add_port(1, 0, 0, 2);
    add_function(2, 0, 0, OTHER_VENDOR, OTHER_DEVICE, PCI_HEADER_TYPE_NORMAL);
    add_port(2, 0, 1, 3);
    add_uart(3, 0, 0);

    return hide(&spcr, false) && kept();
}

static bool test_port_without_function_0(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_port(0, 1, 0, 1);
    add_port(1, 0, 0, 2);
    add_port(2, 0, 1, 3);
    add_uart(3, 0, 0);

    return hide(&spcr, false) && kept();
}

static bool test_lock_fails(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);
    int rc;

    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_uart(3, 0, 0);
    lock_rc = -ENOMEM;

    rc = run_hide(&spcr, false);
    if ( rc != -ENOMEM )
    {
        printf("%s: returned %d, want %d\n", test_name, rc, -ENOMEM);
        return false;
    }

    return emptied_but_vuart() && expect(0, config_address(2, 0, 0));
}

static bool test_window_of_segment(void)
{
    struct acpi_table_spcr spcr = spcr_for(3, 0, 0);

    add_window(OTHER_SEGMENT, 0, LAST_BUS, NO_ECAM);
    add_window(SEGMENT, 0, LAST_BUS, ECAM_BASE);
    add_switch();
    add_uart(3, 0, 0);

    return hide(&spcr, false) &&
           hidden_at(config_address(3, 0, 0), config_address(2, 0, 0));
}

static bool test_windows_split_segment(void)
{
    struct acpi_table_spcr spcr = spcr_for(1, 0, 0);

    add_window(SEGMENT, 0, 0, NO_ECAM);
    add_window(SEGMENT, 2, LAST_BUS, NO_ECAM);
    add_window(SEGMENT, 1, 1, ECAM_BASE);
    add_uart(1, 0, 0);

    return hide(&spcr, false) && hidden_at(config_address(1, 0, 0), 0);
}

static const struct {
    const char *name;
    bool (*run)(void);
} tests[] = {
    { "not a PCI function: nothing changes", test_not_pci },
    { "on the root bus: hidden, with no port to make read-only",
      test_root_bus },
    { "behind a switch: hidden, and its port read-only", test_behind_switch },
    { "registers in the middle of a page: all ones on both sides of the vuart",
      test_vuart_mid_page },
    { "with vPCI: kept", test_vpci },
    { "on a segment with no MCFG window: kept", test_no_window },
    { "another vendor's function with its device ID: kept",
      test_other_vendor },
    { "another device of its vendor: kept", test_other_device },
    { "function 1 of its device: kept", test_function_1 },
    { "function 0 of a multi-function device: kept", test_multi_function },
    { "no bridge leads to its bus: kept", test_no_bridge },
    { "its port is a conventional PCI bridge: kept",
      test_conventional_bridge },
    { "its port is function 0 of a multi-function device: hidden",
      test_port_multi_function },
    { "its port is function 1 of a single-function device: kept",
      test_port_after_single_function },
    { "its port is function 1 of a device with no function 0: kept",
      test_port_without_function_0 },
    { "its port cannot be made read-only: the error is passed up",
      test_lock_fails },
    { "two MCFG windows: the one for its segment", test_window_of_segment },
    { "windows that split its segment: the one for its bus, based at bus 0",
      test_windows_split_segment },
};

int main(void)
{
    unsigned int i, failed = 0;

    for ( i = 0; i < ARRAY_SIZE(tests); i++ )
    {
        memset(ecam, 0xff, sizeof(ecam));
        memset(&mcfg, 0, sizeof(mcfg));
        mcfg_windows = 0;
        memset(&seen, 0, sizeof(seen));
        lock_rc = 0;

        /* Named first, so that a fault shows which test it was. */
        test_name = tests[i].name;
        printf("%s\n", test_name);
        fflush(stdout);

        if ( !tests[i].run() )
            failed++;
    }

    printf("%s\n", failed ? "FAIL" : "PASS");

    return failed != 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
