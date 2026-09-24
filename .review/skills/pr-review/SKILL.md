---
name: pr-review
description: First-pass review of a pull request diff against a Xen hypervisor branch. Hunts for the things that actually hurt in hypervisor code — guest-controlled values trusted too early, missing bounds and reference counting, locking and error paths that leave partial state, an assertion a guest can reach, arithmetic on frame numbers — scoped to the commits this branch adds on top of upstream. Suggestions only, never a gate.
user-invocable: true
---

# PR Review Skill

This is hypervisor code. It runs at the highest privilege level on the machine, it takes input from guests that are assumed to be hostile, and a defect in it is not a crash someone restarts — it is the host going down with everything on it, or a guest reading memory that is not its own. Review at that standard.

Work in this order and stop being interested past step 4:

1. **Serious defects** — could this corrupt state, break a boundary, lose data, or silently not work?
2. **Supply chain** — did a pin move out from under something?
3. **Quietly skipped work** — what got deferred, suppressed, or disabled without leaving a trace?
4. **Test quality** — does the new behaviour have a test, and would that test fail if the code were wrong?

## Calibration

The two failure modes are not symmetric, so the bar moves by severity.

- **For a possible serious defect, report it even if one link in the chain is unverified.** Say which link. A false alarm costs someone two minutes; a guest-reachable panic, an out-of-bounds access driven by a hypercall argument, or a reference that is never released costs a lot more.
- **For everything else, stay quiet unless you are confident.** Speculative small stuff is what trains people to scroll past the bot.

Be specific about what you could not check, in ordinary words: "I could not boot this to confirm the path is reached, so I am reading the caller chain" tells the author more than a confidence label does. Do not tag items **confirmed**, **likely**, or **possible**, and do not present an unverified possibility as a confirmed bug. Do not narrate what you did verify. A finding that holds up needs no account of the reading that produced it.

Never invent a finding to look useful. Most PRs have nothing serious in them — say so in a line and move on. Padding a clean diff with manufactured concerns is worse than saying nothing was wrong.

**A defect the diff perpetuates counts. A defect it merely sits near does not.** If the change moves a pin, touches a call site, or re-asserts an assumption, whether that thing is still correct is fair game even when the diff did not introduce it. Nearby code nobody touched is out of scope.

**This branch carries changes on top of an upstream release branch, so scope matters more here than usual.** Review the commits this pull request adds. Upstream code the diff merely sits beside, and code that appears in the range because of a rebase or an upstream merge, is not this pull request's work. When a finding is about upstream code the change now depends on or re-asserts, say that explicitly so the author can decide whether it belongs here or upstream.

Follow the tree's own conventions rather than importing others: `CODING_STYLE`, `CONTRIBUTING`, and the licence and SPDX rules those files set out. A new file in a directory with its own licence takes that licence.

## What counts as a finding

An observation is not a finding until its importance is established. Two code paths behaving differently, a value bypassing a helper, or an implementation that looks unusual is not, on its own, something to report.

Before a finding goes in the review, establish four things: the behaviour is reachable in the current code; a concrete input, caller, configuration, or stored value can trigger it; the result has a practical implication; and the evidence supports the implication you are claiming. Work through observation, reachability, implication, recommendation in that order, internally. The review is written in ordinary engineering language, not as that template.

**Trace where the value comes from.** For a data-flow finding, showing that a value can pass through a path is not enough. Find where the value is created; which field, argument, configuration, API, or input supplies it; whether the concerning value can actually appear there; where it ends up; and who or what can observe the result. A theoretically possible value is not enough.

**State the practical implication, not the category.** The implication can be correctness, security, isolation, performance, reliability, backward compatibility, operability, maintainability, or consistency with an established convention of this repository, but it is always the result spelled out. "This has security implications" says nothing. "the index comes from a hypercall argument and is used to subscript a fixed array without a bound check, so a guest chooses what the hypervisor reads" does.

**Follow it through to what it does to someone.** `../references/finding-impact.md` is the contract, shared with the coverage skill: code or configuration condition, then actual behaviour, then concrete operational consequence. "The configured value is ignored" is the middle step, and a finding that stops there has given the mechanism without the reason you rated it the way you did. The consequence names what is affected and what happens to it, and it is one sentence in the explanation, not a section. Read that file before rating anything Serious. *Could not determine importance* items are exempt: recording that the consequence could not be established is what they are for.

**Do not manufacture importance.** "Could be a security issue", "may affect performance", "could cause unexpected behaviour", "may become difficult to maintain", "might break callers" are claims, and each needs a concrete path or supporting evidence. What counts as evidence depends on the kind of finding:

- Performance: a hot path, a repeated operation, a meaningful resource increase, or another reason the cost matters. An extra allocation or loop is not automatically a problem.
- Security or isolation: the protected value or boundary, how the code reaches it, and what access or exposure becomes possible. No theoretical attack without a reachable path.
- Backward compatibility: the existing caller, configuration, API, stored data, or documented behaviour that stops working.
- Maintainability: the failure mode. Duplicated contracts that can drift, behaviour that cannot be tested, misleading ownership, an existing pattern this change makes harder to extend. Personal style preference is not a maintainability finding.
- Non-idiomatic code: only when it conflicts with an established repository convention or creates a concrete correctness, safety, or maintenance problem. Not because another implementation would look cleaner.

**Advice requires justification.** A recommendation follows from a reproduced failure, a reachable path with a concrete consequence, an existing test or documented contract, an established repository convention, or a clearly identified maintenance failure mode. If you cannot justify the change, do not give the advice. Do not turn a question into a finding. When important context is genuinely missing, ask the question directly, or put the observation under *Could not determine importance*.

**Severity comes last**, after reachability and impact are established. Behaving differently from another path does not set severity; the consequence does, and so does the amount of code involved and the fact that a value is ignored: none of those are consequences. Do not label anything Serious unless you can say who or what is affected, under what real condition, what happens when it occurs, and why that is worth fixing before merge. If you cannot, use the lower rating rather than inventing an impact to keep the higher one, and do not present the item as a confirmed problem. Verify the things the consequence rests on before you claim it.

**When the behaviour is real but its importance cannot be established**, either leave it out, or, when it is unusual enough that someone with more context may want to look, put it under a *Could not determine importance* section at the end of the review. An item there says exactly what was observed, what evidence you searched for, and what you could not establish. It carries no severity, makes no recommendation, and never counts toward the merge stance. Include an item only when the observation is concrete and missing repository context could plausibly make it matter; this is not a place for every unusual detail.

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

## 2. Supply chain

Rarely the serious class here, but real — label these **Supply chain** so severity reads honestly.

A build dependency added, a third-party blob or firmware image imported, a submodule moved, or a tool downloaded by a build script without a checksum. A change to the licence or SPDX tag of a file, or a new file whose licence does not match the directory it sits in — `CONTRIBUTING` sets out which directories carry which licence, and that is a real constraint rather than paperwork.

For a change adopted from elsewhere, check the commit records where it came from, so the provenance survives the next rebase.

## 3. Quietly skipped work

Things that disappear silently and resurface as bugs. Often the most valuable thing you can surface, because nobody is looking for it.

- **A disabled or skipped test or check.** A configuration removed from a build matrix, a smoke script no longer invoked, an `ASSERT` removed rather than replaced by a real check, or a case added to a skip list in `automation/`. Always ask what covers that behaviour now.
- **A new suppression.** A compiler warning disabled, a MISRA deviation added under `automation/eclair_analysis`, an error return ignored, or a `(void)` cast standing in for handling a failure. Is the reason written down?
- **A TODO or FIXME with no issue link**, or a comment deferring work with nothing to find it by. Also ask whether the deferred thing matters.
- **Behaviour quietly reverted or reintroduced.** A change undoing an earlier fix, or restoring a pattern removed on purpose.

## 4. Test quality

Presence is not coverage. Read the tests the diff adds or changes and judge whether they would fail if the code were wrong.

First: **did observable behaviour change, and did any test change with it?** Judge from the diff, not the PR title. Pure refactors, comment-only edits, and version bumps need no test — say nothing.

When a test is present:

- **Does it assert the new behaviour specifically**, or just that nothing exploded?
- **For a bug fix, would this test have failed before the fix?** The single most useful question on a fix PR.
- **Is the call site covered, or only the helper?** If deleting the line that *invokes* the new logic would leave the suite green, the integration point is untested even though the checklist looks satisfied.
- **Does it cover the failure path** — errors, timeouts, rejected input? Happy-path-only is the most common gap.
- **Are boundaries tested** — zero, empty, max, off-by-one, the value that triggers a retry?
- **Is it actually enabled and actually asserting** — not skipped, not filtered out, not a tautology?
- **Is it at the right level?** Logic that can be exercised by building a configuration should not need a boot to demonstrate. Behaviour that only appears on a running hypervisor does.

When a change touches something with no coverage and testing it is genuinely hard, say so plainly rather than pretending a test is cheap. That is often the situation here. Nothing in this repository compiles or boots the tree on a GitHub pull request, and much hypervisor behaviour can only be observed by booting. Naming the build configuration or the smoke script under `automation/scripts/` that would exercise the change is more useful than asking for a unit test.

## Out of scope

Style, naming, formatting, indentation, and comment wording — `CODING_STYLE` governs those and a reviewer restating it adds nothing. Upstream code the diff does not touch. Merged architecture. Do not restate what the code does. Do not relitigate merged architecture.

## How to write it

Write the way a strong engineer writes on a teammate's pull request. Keep the technical depth, use ordinary direct English, and leave the author knowing what is wrong, why it matters, and what to do next. Not an audit report, not a proof, not a transcript of the investigation. The analysis behind the review can be exhaustive; the text posted to the PR is not. `../references/review-writing.md` is the shared contract for how much gets posted and how it reads. Read it before writing, and hold the whole review to it.

**Every finding explains four things, in this order:** what can go wrong, why someone should care, which code path causes it, and what should probably change. That is the order the explanation should make sense in, not four headings to repeat.

"Why someone should care" is the runtime behaviour and what it does to an operator, a consumer of this repository's output, a build, or a security boundary. One sentence usually carries it. Never as an `Impact:` or `Why this matters:` heading, and never as the same severity sentence pasted onto every finding.

**The consequence comes first.** The reader learns why the finding matters from the first sentence or two, before any implementation detail. The code path follows as the proof.

Bad:

> `vtimer_set` reads `d->arch.virt_timer` and then calls `vcpu_unblock`, and the caller of `vtimer_set` holds `v->arch.vtimer.lock` across that call, and `vcpu_unblock` can schedule, which means...

Good:

> A guest can wedge the host by taking a lock that is held across a scheduling point. `vtimer_set` is called with `v->arch.vtimer.lock` held, and it calls `vcpu_unblock`, which can schedule; another vCPU that then takes the same lock waits on a lock whose holder is off-CPU. Dropping the lock before the unblock, or deferring the unblock to after the critical section, avoids it.

**Say what actually happens.** Not "this could cause problems", "this may be risky", "this may result in incorrect behaviour", "this weakens the guarantee". Say it: a guest chooses which memory the hypervisor reads; the host panics on a value the guest supplies; the reference is never released, so the domain cannot be destroyed; the release build has no check at all; the guest reads uninitialised hypervisor stack. When the consequence is limited, say so. Do not make a narrow edge case sound catastrophic.

**Shape.** A short bold title that states the problem, one paragraph with the consequence and the code path, one paragraph with the fix or the missing test. One to three short paragraphs, usually under 150 words. File and line references go in the body, where they let the author verify the finding, and only where they do; the review is not a record of the investigation, so do not list every symbol, line, commit, and branch you inspected.

**Titles** state the actual problem. Not a path, not "Potential logic concern", not "Finding 3".

**Severity** reflects what happens if the code ships, not how hard the finding was to reach. **Serious** is for a guest-reachable panic or assertion, an out-of-bounds read or write driven by guest-controlled input, a leaked or double-released reference, memory exposed across a domain boundary, a lock that can deadlock or be held across a scheduling point, or a check that is absent from the release build. Smaller correctness issues, maintainability, and defensive improvements are plain findings or suggestions.

**Say whether it should block.** Marking findings Serious and then writing that nothing blocks the merge is contradictory. The summary says plainly which findings you think should be fixed before merge and which are follow-ups. Say it once, in the summary, not after every finding. Ask for a fix before merge only when shipping the finding can produce incorrect behaviour, a regression, a false result, a security problem, or defeats what the PR exists to do; everything else is a follow-up, and a test gap is a test gap. Do not exaggerate a finding to make it block. This review cannot block anything on its own and the author decides, so say what you actually think. Items under *Could not determine importance* do not count either way.

**Confidence** appears only where it changes what the author should do with the finding, and then in plain words: "I could not run the build, but...", "this looks wrong, but I may be missing another caller that handles it". A finding you are sure of carries no confidence statement at all. "I confirmed this by tracing" and "I verified" add nothing the code path does not already show; leave them out. Never as a label: not "Confirmed by reading", "Likely:", "Verdict:", "UNVERIFIABLE".

**The fix.** When it is clear, say what should change. When it needs a design decision, say that rather than inventing one. Do not prescribe a rewrite when a smaller change fixes it.

**Test findings** name the regression the test would catch, not the test. For an integration gap, name the two parts that can drift apart and why the current tests would still pass.

**Phrases and habits to avoid** unless nothing simpler says it: load-bearing property, the property that matters, the seam between, pins the fallback, widens what runs, guard against it, falls through, on the strength of, feature is inert, suggestions only, nothing here blocks the merge, read through this. Openers that narrate ("I went through", "I checked", "I also checked", "I verified") and praise ("looks good overall", "well thought out", "the approach is sound") tell the author nothing; leave them out. No dramatic metaphors, no clever phrasing, no compressed internal jargon, no generated-sounding transitions. Use the codebase's own terms and explain the consequence in ordinary English.

Refer to the code, never to whoever wrote it — no author names, no "you forgot", no comparisons to other PRs.

**Before posting, check each finding:** did you find a real producer, caller, input, or configuration that reaches this behaviour, and trace what happens after it is reached; does it say who or what is affected and what fails, degrades, becomes exposed, or becomes misleading; would that sentence still read as true if you moved it onto a different finding, which means it is generic and does not count; is the consequence concrete, and supported by code, tests, documentation, or reproduced behaviour; can the author tell what goes wrong from the first two sentences; is the severity based on impact rather than complexity; is the evidence enough without being a transcript; is it clear whether you reproduced, traced, or inferred it; are you recommending a change because something matters, or because the code looks unusual; would the finding still make sense with every "could", "may", and "might" removed; would it sound normal coming from a senior engineer on the team. Do not post a finding until every answer is yes.

**Then cut.** Remove investigation narration, reasoning stated twice, file references the finding does not need, descriptions of code the diff already shows, evidence that does not change the conclusion, and any sentence whose only purpose is to sound thorough.

## Output

**Always leave a review, even when the diff is clean.** Silence is ambiguous — the author cannot tell "read it, looks fine" from "never ran". Give a verdict every time.

Open with a summary of one to three sentences. It carries three things and nothing else: whether anything should be fixed before merge, the most important technical conclusion, and any material limitation of the review, such as a build that could not be run in this environment, said here once and not repeated under the findings. It does not say what was read, list what was inspected, restate the change, or walk through the parts that turned out fine.

If nothing concerns you, one or two specific sentences are the whole review. Naming what the change actually is shows you read it; "LGTM" does not:

```markdown
A comment correction with no code change. Nothing concerning.
```

If something does, the summary, then one block per finding. Each block starts with a bold single line stating the problem, with a severity word in front when it helps the author decide what to fix first. Then the consequence, the code path, and the fix, in ordinary paragraphs with the file and line in the prose:

```markdown
One problem I think should be fixed before merge: the index is not bounded. The error path is a follow-up.

**Serious: a guest-supplied index subscripts the array without a bound check.**

A guest chooses which memory the hypervisor reads, because the value arrives as a hypercall argument and reaches the subscript unchecked. The bound check in the caller two frames up does not cover this path: the second caller added in this change reaches the same function directly.

Checking the index against the live limit in the function itself, rather than in one of its callers, closes both paths.

**The new early return skips the unwinding below it.**

The page acquired at the top of the function is not released when the new check fails, so a guest that can reach the failure repeatedly leaves references behind and the domain cannot be destroyed afterwards. Jumping to the existing error label instead of returning directly would keep the unwinding sequence intact.
```

Report **every** serious defect. Cap the rest at three, keeping the ones you are surest of, and say if you stopped there. When one problem is also untested and also has no issue link, explain it once and give the tracking gap a line rather than repeating it as a second finding.

Something real that you could not tie to a consequence goes after the findings, under its own heading, with no severity and no recommendation. Leave the heading out entirely when there is nothing for it:

```markdown
**Could not determine importance**

The new helper is called from common code but is only defined for one architecture, and the header declares it unconditionally. I could not find a build configuration that reaches the call on the other architecture, so I could not establish that anything fails to link. No change requested.
```

One to three short paragraphs per finding, usually under 150 words. The whole review is usually under 500 words; only several independent substantive findings take it past that. Length comes from the number and weight of real findings, never from the amount of analysis behind them.

## Running it yourself

```bash
git fetch origin edera/4.22
git diff origin/edera/4.22...HEAD
```

Then work the sections above against that diff, same rules — including staying quiet when the change is fine.
