# What checks this repo has, and what runs on a PR

Start with the fact that shapes every coverage answer: **nothing boots this
tree on a GitHub pull request.** A pull request is compiled and unit tested,
nothing more:

- `.github/workflows/build.yml` compiles the hypervisor in the configurations
  Edera ships: x86_64, arm64, and arm64 with PCI passthrough.
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
in `tools/tests` compiles.

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

Three of the tests cover downstream code; the rest are upstream's tests of
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
  and taking the MSI base from the first ITS that the MADT describes. Its
  tables are built from Xen's own ACPICA structures, and both the firmware's
  table and the hardware domain's buffer end where an unreadable page begins.
  It does not cover the single-mapping flag, `iort_init()` refusing a table,
  named components, or the table of any real platform.
- `tools/tests/log-q16` covers the fixed-point logarithms in
  `xen/lib/log-q16.c` that `dom0_mem=ln` sizes dom0 with, but not the parsing
  of `dom0_mem` or the sizing curve itself.

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
