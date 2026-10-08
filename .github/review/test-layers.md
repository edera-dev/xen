# What checks this repo has, and what runs on a PR

Start with the fact that shapes every coverage answer: **nothing compiles or
boots this tree on a GitHub pull request.** `.github/workflows/coverity.yml` is
`workflow_dispatch` and `schedule` only, with a comment saying so explicitly —
it scans release code, not pull requests. The upstream project's own CI is
GitLab-based, under `automation/gitlab-ci/`, and does not trigger from this
repository's pull requests. The only workflows that do run on a pull request
are the advisory review checks described under The review checks themselves, and they
build nothing.

So a coverage review here is not "which test file covers this". It is "what
would have to run, and where does it live".

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
