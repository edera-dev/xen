# What checks this repo has, and what runs on a PR

Start with the fact that shapes every coverage answer: **a GitHub pull request
boots the arm64 builds, the shipped one and two debug ones, only on emulated
machines and only as far as a busybox dom0, and boots the x86_64 build only
with an XTF test as dom0.** A pull request is compiled, unit tested, and booted
that far:

- `.github/workflows/build.yml` compiles the hypervisor in the configurations
  Edera ships, x86_64 and arm64. It also compiles arm64 with PCI passthrough,
  with DEBUG and UBSAN, and with all three, which Edera does not ship. Then it
  boots the shipped arm64 build and the two debug builds; see "Boot tests"
  below. It also boots the x86_64 build with each XTF test in
  `.github/xtf/tests`; see "XTF tests" below.
- `.github/workflows/unit-tests.yml` runs the host unit tests in `tools/tests`;
  see "Unit tests" below.
- `.github/workflows/qa-dispatch.yml` hands the pull request to
  `edera-dev/xen-qa`, which boots x86 Xen under QEMU, but only when the
  `XENQA_DISPATCH_TOKEN` secret is set, and its result is advisory.

`.github/workflows/coverity.yml` is `workflow_dispatch` and `schedule` only,
with a comment saying so explicitly: it scans release code, not pull requests.
The upstream project's own CI is GitLab-based, under `automation/gitlab-ci/`,
and does not trigger from this repository's pull requests. The other workflows
that run on a pull request build nothing: the advisory review checks, and the
upstream rebase self-test, which runs only when the rebase scripts change.

So a coverage review here is mostly not "which test file covers this". It is
"what would have to run, and where does it live", except for code that a test
in `tools/tests` compiles, that the arm64 boot reaches, or that an XTF test in
`.github/xtf/tests` exercises.

## Unit tests

`.github/workflows/unit-tests.yml` runs on every pull request and every push to
an `edera/**` branch, on x86_64 and arm64 runners. It runs every directory in
`tools/tests` except a skip list:

- `mem-claim`, `paging-mempool`, `resource`, `tsx` and `xenstore`, which call a
  running Xen;
- `x86_emulator`, whose EVEX cases run only on a CPU with AVX-512, so its
  result depends on the hardware the runner gets;
- on arm64, the x86-only `cpu-policy`, `tsx` and `x86_emulator`.

A new test directory runs with no change to the workflow. Each test compiles
one hypervisor source file into a host program with a small harness, so it
covers the logic of that file, not how the hypervisor uses it.

Four of the tests cover downstream code; the rest are upstream's tests of
upstream code:

- `tools/tests/dsdt` covers the Arm AML walker in `xen/arch/arm/acpi/dsdt.c`,
  `acpi_pci_get_host_bridge_windows()`: finding a host bridge by a string or
  EisaId `_HID` or `_CID`, reading `_SEG` in every integer encoding and
  refusing a `_SEG` it cannot read, taking the memory windows from `_CRS`, and
  stepping over Methods, Packages and nested Devices. Its tables are compiled
  by iasl, and each ends where an unreadable page begins, so a read past the
  end of a table fails the test. It does not cover a host bridge in an SSDT,
  which the walker does not read, or several host bridges on one segment.
- `tools/tests/iort` covers the IORT parser in `xen/arch/arm/acpi/iort.c`:
  translating a requester ID through an SMMUv3 to its StreamID and its
  DeviceID, stopping a mapping loop, and the IORT built for the hardware
  domain, which has no SMMUv3, gives the same DeviceIDs, keeps each root
  complex on its own ITS group, and is refused when a range cannot stay
  contiguous. It also covers a node whose mapping offset is past the table,
  taking the MSI base from the first ITS that the MADT describes, and which
  mapping takes an ID that two mappings claim, single mappings among them. A
  root complex whose first mapping has an ID count one too large, as QEMU's
  has, is covered both in a lookup and in the IORT built for the hardware
  domain. Its tables are built from Xen's own ACPICA structures, except the
  IORTs of a Graviton3 and a one-socket Graviton4 instance, kept as their
  firmware gives them. Those have what no built table has: a node longer
  than its mappings, root complex node data that is not zero, and a PMCG
  node that refers to the SMMUv3. For them the hardware domain's IORT must
  also keep the root complex's revision and node data. Both the firmware's
  table and the hardware domain's buffer end where an unreadable page
  begins. It does not cover a single mapping in the hardware domain's IORT,
  an SMMUv3's own single mapping, `iort_init()` refusing a table, named
  components, or the table of a real platform with more than one ITS group.
- `tools/tests/log-q16` covers the fixed-point logarithms in
  `xen/lib/log-q16.c` that `dom0_mem=ln` sizes dom0 with, but not the parsing
  of `dom0_mem` or the sizing curve itself.
- `tools/tests/spcr` covers `xen/arch/arm/acpi/spcr.c`, which decides whether
  to hide the SPCR's PCI UART, Xen's console, from the hardware domain: each
  reason to keep it visible, the bridge scan that finds the port above it, an
  error from making that port read-only, the choice of MCFG window, and the
  parts of the UART's page that read as all ones around the hardware domain's
  vuart. Each case lays out a configuration space in memory. It does not
  cover a hardware domain without a vuart, or several host bridges in one
  MCFG window.

## Boot tests

The `boot` job in `.github/workflows/build.yml` runs on every pull request and
every push to an `edera/**` branch. It boots the shipped arm64 build with
`.github/boot/run-arm64.sh` on QEMU's virt machine, which describes itself
only through UEFI and ACPI, with GICv3, an ITS and an SMMUv3. dom0 is the
arm64 host kernel that protect ships, with a busybox init. A boot fails on a
crash or a warning from Xen or dom0, when dom0 gets no IORT from Xen, and when
dom0 does not run init to the end.

The job also boots the debug build on the graviton4 machine, where a failed
ASSERT or a report from UBSAN fails the boot. That build leaves out UBSAN's
alignment check: ACPICA reads misaligned XSDT entries on purpose, and arm64
handles misaligned loads.

The job also boots the debug build with PCI passthrough on the graviton4
machine, with the `pci-passthrough` cases. In that build Xen registers the
host bridge from the MCFG, and dom0 reports each PCI device to Xen. The build
has no SMMUv3 driver, so the IOMMU is off and dom0 gets no vPCI. The release
build with PCI passthrough is compiled but not booted.

Each file in `.github/boot/machines` imitates the platform of a Graviton
generation: its core, as near as QEMU has one, and its sockets, each a NUMA
node. Every machine has the same four cores and 2G of memory. A boot checks
that Xen brings up every core, that dom0 gets them all, and the Spectre-BHB
sequence that Xen picks for the core.

Each directory in `.github/boot/cases` holds the cases for one Xen option. A
case changes the Xen command line or the memory, and checks what Xen does with
it. The boot job's matrix names each directory that runs, and one job boots
its cases in turn; a directory the matrix does not name never runs.
`dom0-mem-default` covers the size arm64 Xen gives dom0 when `dom0_mem` is not
set. `pci-passthrough` covers the host bridge that Xen registers from the
MCFG and the windows it reads for it, and Xen accepting each PCI device that
dom0 reports.

What the boots do not reach:

- Graviton's console, a 16550 behind a PCI switch. QEMU's console is a PL011,
  so the code that hides the SPCR's PCI UART from dom0 stops early;
  `tools/tests/spcr` covers its decisions.
- Graviton's PCI layout: a host bridge on segment 1, described in an SSDT,
  whose firmware BARs Linux keeps. QEMU's host bridge is on segment 0, in the
  DSDT.
- What only many cores or much memory reach.
- The GIC redistributor layout and the memory map of Graviton firmware.
- vPCI, which needs an IOMMU: no build has the SMMUv3 driver, and QEMU's
  SMMUv3 offers only stage-1 translation unless told otherwise.
- A guest with a PCI device passed through: the builds with PCI passthrough
  boot only dom0.
- x86.

## XTF tests

The `xtf` job in `.github/workflows/build.yml` runs on every pull request and
every push to an `edera/**` branch. It boots the shipped x86_64 build with
`.github/xtf/run-x86_64.sh` in a Fedora container, with one XTF test as dom0. QEMU emulates the CPU,
SVM and nested paging included, so an `hvm64` test runs as a PVH dom0 with
HAP, and a `pv64` test as a PV dom0. XTF is cloned at the commit the script
pins. A run fails when the test does not print a successful verdict.

Each directory in `.github/xtf/tests` is a test in XTF's layout. The job's
matrix names each test and environment that runs; a directory the matrix does
not name never runs. `gnttab-copy-ops` covers how `GNTTABOP_copy` reads its
array of operations and writes each status: an array across a page boundary,
a copy that overwrites a later operation, and, on `hvm64`, a copy that
rewrites the page table entry mapping the array. Its last `hvm64` case fails
when Xen does not keep the array's page translated across the operations.

What the tests do not reach: Intel VT-x and EPT, since QEMU emulates SVM, an
HVM or PVH domU, and anything that needs more than one domain.

## Build configurations

`automation/gitlab-ci/` describes the build matrix upstream uses: architectures,
compilers, and config variations. The first question for most changes is which
of those configurations compiles the changed code at all. A change under an
architecture or a config symbol outside the built set is unexercised even where
the pipeline does run.

`automation/scripts/build-test.sh` and the containerised build helpers under
`automation/scripts/containerize` are how a build configuration is reproduced
locally.

## Smoke tests

`automation/scripts/` holds the boot tests, and naming the right one is usually
the most useful thing a coverage review can do:

- `qemu-smoke-dom0-arm64.sh`, `qemu-smoke-dom0-arm32.sh` — boot with a dom0.
- `qemu-smoke-dom0less-arm64.sh`, `qemu-smoke-dom0less-arm32.sh` — dom0less.
- `qemu-alpine-x86_64.sh`, `qubes-x86_64.sh` — x86 boot paths.
- `qemu-smoke-ppc64le.sh`, `qemu-smoke-riscv64.sh` — the other ports.
- `qemu-xtf.sh` — XTF, for guest-visible hypervisor behaviour.
- `run-tools-tests` — the tools test suite.
- `xilinx-smoke-*.sh` — hardware-specific boots.

These boot a hypervisor and check it gets somewhere. They are coarse, and that
is the point: they catch a hypervisor that does not come up, which is the
failure mode most worth catching automatically.

## Static analysis

`automation/eclair_analysis/` holds the MISRA configuration and its recorded
deviations. A new deviation is a suppression and should say why.

The Coverity workflow runs on a schedule against the branch, not against pull
requests.

## Nightly upstream rebase

`.github/workflows/upstream-rebase.yml` replays the downstream series onto
upstream `staging-4.22` and builds the hypervisor for x86, arm64 defconfig and
arm64 with PCI passthrough before it moves `edera/4.22`. It runs only on nights
when upstream has new commits. It is the first build of a merged change on top
of those commits, and it happens after merge: a change that only breaks with
them stops the next rebase rather than failing its own pull request. It does
not build the tools.

`.github/workflows/upstream-rebase-selftest.yml` runs the tests for
`verify-upstream-rebase.sh` and `report-needs-decision.sh` on pull requests
that change the rebase machinery.

## The review checks themselves

`.github/workflows/pr-review.yml` runs the two advisory review checks,
including this one, through the shared workflow in `edera-dev/actions`. They
build, lint and test nothing this repository ships. Never count them as
coverage for a change.

## What nothing checks

- Behaviour that only appears under a guest doing something specific. XTF is the
  place for that, and coverage there is selective.
- Error and unwinding paths. Almost nothing exercises the failure path of a
  hypercall.
- Anything under a configuration the build matrix does not include.

## Where a gap usually is

- The changed code is not compiled by any configuration that gets built.
- The change alters a boot path that no smoke script boots — a different
  firmware interface, a different guest layout, a platform variation.
- The change adds an error path that nothing reaches.
- A guest-visible behaviour change with no XTF case.
