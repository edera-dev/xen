# Review focus

What the advisory review checks look for in this repository. The shared
workflow in `edera-dev/actions` supplies the review method; this file supplies
everything specific to this repository, and `test-layers.md` beside it says
where checks live and what runs on a pull request.

Each section starts at its `<!-- focus: NAME -->` line and runs to the next
one. The templates under `advisory-review/templates/` in `edera-dev/actions`
fix the names and show where each section lands. `FORK_SCOPE` is optional;
every other section is required, and a name no template uses fails the run.

<!-- focus: INTRO -->
This is hypervisor code. It runs at the highest privilege level on the machine, it takes input from guests that are assumed to be hostile, and a defect in it is not a crash someone restarts — it is the host going down with everything on it, or a guest reading memory that is not its own. Review at that standard.

<!-- focus: FORK_SCOPE -->
**This branch carries changes on top of an upstream release branch, so scope matters more here than usual.** Review the commits this pull request adds. Upstream code the diff merely sits beside, and code that appears in the range because of a rebase or an upstream merge, is not this pull request's work. When a finding is about upstream code the change now depends on or re-asserts, say that explicitly so the author can decide whether it belongs here or upstream.

Follow the tree's own conventions rather than importing others: `CODING_STYLE`, `CONTRIBUTING`, and the licence and SPDX rules those files set out. A new file in a directory with its own licence takes that licence.

<!-- focus: SERIOUS -->
## 1. Serious defects

Read the surrounding function and its callers, not just the hunk. In hypervisor code the question is almost always "where did this value come from, and who can choose it".

**Guest-controlled input trusted too early.** Any value that arrived through a hypercall argument, a guest handle, a shared ring, an event channel port, a grant reference, or memory the guest can write is hostile. Follow it to where it is used: is a length, offset, index, count, or domain id taken on faith? Is an array subscripted by it? Is a buffer sized from it? Is it used to compute an address? A check that exists in one caller is not a check on the path that does not go through that caller.

**Reading guest memory twice.** A value copied from guest memory, validated, and then read again from the same location can change between the two reads. Validate the local copy and use the local copy. `copy_from_guest` into a stack variable and then dereferencing the guest pointer again for the real work is the shape to look for.

**Missing bounds on identifiers.** Domain ids, vCPU ids, event channel ports, grant references, GFNs and MFNs all index something. Each one needs its range checked against the live limit, not a compile-time maximum, and the check has to be on the path that uses it.

**Reference counting and lifetime.** `get_page` without a matching `put_page` on every exit path, a domain looked up and not released on the error path, a page freed while another CPU can still reach it, a mapping torn down out of order. The error paths are where these are lost; read every `goto` target and every early `return` in the function, not just the success path.

**Locking.** Lock ordering that can invert, a lock held across a call that can sleep or schedule, a lock taken in interrupt context without the irq-safe variant, state read outside the lock that protects it, and TOCTOU between a check and the use that depends on it. Say which two locks, or which check and which use.

**An assertion or panic a guest can reach.** `BUG_ON` is compiled in; a condition a guest can drive into one is a host denial of service. `ASSERT` compiles out in a release build, so an `ASSERT` standing in for a real check means the release build has no check at all. `panic()` in a path reachable after boot is the same class. Distinguish these clearly, because the right fix differs: return an error, or make the check unconditional.

**Arithmetic on frames, sizes and offsets.** Overflow, truncation on a narrowing cast, and subtraction from an unsigned value that can be zero. Page and frame arithmetic where the shift and the type do not agree. An addition of a guest-supplied length to a base that is checked after the addition rather than before it.

**Firmware-provided data.** Device tree and ACPI tables are parsed before anything else is running and are not fully trusted: a table whose declared length does not match its contents, an entry count that overruns the table, a string that is not terminated, a resource that overlaps another. An entry the platform does not actually declare should leave the feature off rather than assume a default.

**Uninitialised or partially initialised state.** A structure returned to a guest with padding or unset fields, a per-domain or per-vCPU structure used before the path that fills it has run, an error path that leaves a partially constructed object reachable.

**Error paths.** Every failure between allocation and success has to undo exactly what ran before it. A new early return added to an existing function is the most common way this is broken, because the unwinding sequence below it no longer matches.

**Feature and platform gating.** Code added under one architecture or one configuration that is compiled or reached under another. A change guarded by a config symbol whose dependencies do not actually hold. An interface that exists on one architecture and is called from common code.

<!-- focus: SUPPLY -->
## 2. Supply chain

Rarely the serious class here, but real — label these **Supply chain** so severity reads honestly.

A build dependency added, a third-party blob or firmware image imported, a submodule moved, or a tool downloaded by a build script without a checksum. A change to the licence or SPDX tag of a file, or a new file whose licence does not match the directory it sits in — `CONTRIBUTING` sets out which directories carry which licence, and that is a real constraint rather than paperwork.

For a change adopted from elsewhere, check the commit records where it came from, so the provenance survives the next rebase.

<!-- focus: SKIPPED_TEST_FORMS -->
A configuration removed from a build matrix, a smoke script no longer invoked, an `ASSERT` removed rather than replaced by a real check, or a case added to a skip list in `automation/`.

<!-- focus: SUPPRESSION_FORMS -->
A compiler warning disabled, a MISRA deviation added under `automation/eclair_analysis`, an error return ignored, or a `(void)` cast standing in for handling a failure.

<!-- focus: RIGHT_LEVEL -->
Logic that can be exercised by building a configuration should not need a boot to demonstrate. Behaviour that only appears on a running hypervisor does.

<!-- focus: NO_TEST_LAYER -->
That is often the situation here. Nothing in this repository compiles or boots the tree on a GitHub pull request, and much hypervisor behaviour can only be observed by booting. Naming the build configuration or the smoke script under `automation/scripts/` that would exercise the change is more useful than asking for a unit test.

<!-- focus: OUT_OF_SCOPE -->
Style, naming, formatting, indentation, and comment wording — `CODING_STYLE` governs those and a reviewer restating it adds nothing. Upstream code the diff does not touch. Merged architecture.

<!-- focus: CALIBRATION_COST -->
a guest-reachable panic, an out-of-bounds access driven by a hypercall argument, or a reference that is never released costs a lot more.

<!-- focus: CANNOT_CHECK_EXAMPLE -->
I could not boot this to confirm the path is reached, so I am reading the caller chain

<!-- focus: IMPLICATION_EXAMPLE -->
"the index comes from a hypercall argument and is used to subscript a fixed array without a bound check, so a guest chooses what the hypervisor reads" does.

<!-- focus: SERIOUS_DEFINITION -->
a guest-reachable panic or assertion, an out-of-bounds read or write driven by guest-controlled input, a leaked or double-released reference, memory exposed across a domain boundary, a lock that can deadlock or be held across a scheduling point, or a check that is absent from the release build

<!-- focus: SAY_WHAT_HAPPENS -->
a guest chooses which memory the hypervisor reads; the host panics on a value the guest supplies; the reference is never released, so the domain cannot be destroyed; the release build has no check at all; the guest reads uninitialised hypervisor stack

<!-- focus: WRITE_BAD -->
`vtimer_set` reads `d->arch.virt_timer` and then calls `vcpu_unblock`, and the caller of `vtimer_set` holds `v->arch.vtimer.lock` across that call, and `vcpu_unblock` can schedule, which means...

<!-- focus: WRITE_GOOD -->
A guest can wedge the host by taking a lock that is held across a scheduling point. `vtimer_set` is called with `v->arch.vtimer.lock` held, and it calls `vcpu_unblock`, which can schedule; another vCPU that then takes the same lock waits on a lock whose holder is off-CPU. Dropping the lock before the unblock, or deferring the unblock to after the critical section, avoids it.

<!-- focus: CLEAN_EXAMPLE -->
A comment correction with no code change. Nothing concerning.

<!-- focus: OUTPUT_EXAMPLE -->
One problem I think should be fixed before merge: the index is not bounded. The error path is a follow-up.

**Serious: a guest-supplied index subscripts the array without a bound check.**

A guest chooses which memory the hypervisor reads, because the value arrives as a hypercall argument and reaches the subscript unchecked. The bound check in the caller two frames up does not cover this path: the second caller added in this change reaches the same function directly.

Checking the index against the live limit in the function itself, rather than in one of its callers, closes both paths.

**The new early return skips the unwinding below it.**

The page acquired at the top of the function is not released when the new check fails, so a guest that can reach the failure repeatedly leaves references behind and the domain cannot be destroyed afterwards. Jumping to the existing error label instead of returning directly would keep the unwinding sequence intact.

<!-- focus: UNKNOWN_EXAMPLE -->
The new helper is called from common code but is only defined for one architecture, and the header declares it unconditionally. I could not find a build configuration that reaches the call on the other architecture, so I could not establish that anything fails to link. No change requested.

<!-- focus: IMPACT_WORKED_EXAMPLE -->
The index arrives as a hypercall argument and reaches the array subscript without being checked against the live limit, so a guest chooses which memory the hypervisor reads. The value is returned to the guest, which makes it a read of hypervisor memory across the domain boundary rather than a crash.

<!-- focus: HOW_WRONG -->
- Where does each new value come from, and who can choose it? A hypercall argument, a shared ring, a firmware table, and a compile-time constant carry completely different risk.
- What happens on every exit path, not just the successful one? Hypervisor bugs live in the unwinding.
- Does the change behave differently per architecture, per configuration symbol, or between a debug and a release build? An `ASSERT` behaves differently in each.
- Is the change reachable before the system is fully up — during boot, from firmware parsing, from an early hypercall?
- If this is a bug fix, what exactly was the bug, and what would have to run to observe it failing before the fix?
- Which build configuration compiles this code at all? A change under a config symbol nobody builds is not exercised by anything.

<!-- focus: WHERE_TO_LOOK -->
- `automation/scripts/`, which holds the smoke scripts the upstream pipeline runs: the qemu dom0 and dom0less scripts per architecture, the XTF runner, and the tools test runner. These are the closest thing to a behavioural check, and naming the right one is usually the most useful thing a coverage review can do here;
- `automation/gitlab-ci/`, for which build configurations exist and what they cover. Note this pipeline does not run on a GitHub pull request;
- `automation/eclair_analysis/`, for the static analysis configuration and its deviations;
- any in-tree test under `xen/test/` or the XTF cases the scripts invoke.

There are no unit tests in the hypervisor in the sense other repositories mean it. Do not look for a test file next to the changed function.

<!-- focus: PROPORTIONATE -->
Naming the smoke script or build configuration that would exercise the change is proportionate. Asking for a unit test framework the hypervisor does not have is not.

<!-- focus: CONDITIONAL_EXAMPLE -->
"A guest that issues the hypercall with an index past the live limit reads hypervisor memory, and nothing between the hypercall entry and the subscript checks it" names the condition and the result. "This could have security implications" names neither.

<!-- focus: TWO_SHAPES -->
- **Nothing compiles the change on the pull request.** The upstream pipeline is GitLab-based and the Coverity workflow here is scheduled and dispatch-only by design. No build and no smoke test runs on a GitHub pull request in this repository; the advisory review checks that do run compile nothing. Say that once, then name what would have caught the change.
- **The code is not compiled by the configuration that gets built.** A change under an architecture or config symbol outside the usual build set is not exercised even where CI does run. Check which configurations reach the code before treating a build as coverage.

<!-- focus: SMALLEST_LAYER -->
Pick the smallest thing that would catch the failure. A build of the configuration that compiles the code, for anything that can fail to compile or link. The matching qemu smoke script under `automation/scripts/`, for behaviour that appears at boot or on a running domain. An XTF case, for guest-visible hypercall behaviour. Do not propose a test framework the tree does not have.

<!-- focus: COVER_BAD -->
The arm64 dom0less smoke script covers this. It boots a dom0less configuration with two domains, exercises the timer path on both, checks the console output for the expected banner and then verifies that each domain reaches userspace without...

<!-- focus: COVER_GOOD -->
The arm64 dom0less smoke script boots through the changed timer path, so a hypervisor that hangs there would fail it.

<!-- focus: CLEAN_NOTHING -->
Nothing here needs a check. It's a comment fix.

<!-- focus: GAP_EXAMPLE -->
One gap, and it can follow the merge.

**Nothing boots the configuration this change affects.**

A hypervisor that hangs in the new ACPI path would reach a release without anything having run it: the smoke scripts under `automation/scripts/` cover the device-tree boot on this architecture, and none of them boots with ACPI, so the added parser is compiled and never executed.

An ACPI variant of `qemu-smoke-dom0-arm64.sh` that boots with the tables present and asserts dom0 reaches userspace would exercise it. Nothing on the pull request runs either way, so this is about what a pipeline could catch, not about this check.
