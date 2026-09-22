---
name: test-coverage-review
description: Review a pull request against a Xen hypervisor branch for the check that is missing. Nothing in this repository runs on a GitHub pull request, so the useful answer is usually which build configuration or smoke script under automation/ would have exercised the change. Advisory only.
user-invocable: true
---

# Test coverage review

Bugs keep reaching a release that a check at the right layer would have caught. This skill exists to name that check while the PR is still open.

The job is not to judge whether a PR has "enough tests". It is to understand what the change does, work out how it could realistically be wrong, read the checks that exist, and decide whether those checks would fail if it were. If they would not, say which scenario is uncovered and what check would catch it. If they would, say so in a line and stop.

Nothing here blocks a merge. The review is comment-only, and every line of it is the author's to act on or ignore.

## How to work

### 1. Understand the change

Read the diff, then the surrounding code. Write down, for yourself, one sentence per behaviour that changed. Judge from the code, not from the PR title or description.

Sort the change into one of these before going further:

- **No behaviour change.** Dependency and image bumps, comment and doc edits, renames, formatting, CI wiring, pure refactors that move code without altering what it does. These need no test. Say so in a line and stop.

  A bump is not a behaviour change of this repo, even across major versions. The test for a bump is the existing checks passing. Do not go reading the bumped dependency's changelog for something to say. The only exception is a bump that also edits a call site in this repo; then review that call site like any other change, and nothing else.
- **Test-only change.** Ask only whether the changed test still proves what it claims to. Nothing else.
- **Behaviour change.** Continue.

### 2. List how it could be wrong

For each behaviour that changed, write down the concrete ways it could be wrong in this codebase. Not "edge cases" in general. Ask:

- Where does each new value come from, and who can choose it? A hypercall argument, a shared ring, a firmware table, and a compile-time constant carry completely different risk.
- What happens on every exit path, not just the successful one? Hypervisor bugs live in the unwinding.
- Does the change behave differently per architecture, per configuration symbol, or between a debug and a release build? An `ASSERT` behaves differently in each.
- Is the change reachable before the system is fully up — during boot, from firmware parsing, from an early hypercall?
- If this is a bug fix, what exactly was the bug, and what would have to run to observe it failing before the fix?
- Which build configuration compiles this code at all? A change under a config symbol nobody builds is not exercised by anything.

Keep only the ones a strong engineer here would agree are realistic. Three is plenty. If you cannot state how someone would actually hit it, drop it.

Stay on the diff. The failure modes come from the lines the PR changed and the code that directly calls or is called by them. If you find yourself reading code the PR did not touch to build a case, the case is not about this PR.

### 3. Read the checks that exist

Find every check that touches the changed behaviour, then read it. `references/test-layers.md` says where each kind of check lives in this repo and what CI actually runs on a PR. Look in:

- `automation/scripts/`, which holds the smoke scripts the upstream pipeline runs: the qemu dom0 and dom0less scripts per architecture, the XTF runner, and the tools test runner. These are the closest thing to a behavioural check, and naming the right one is usually the most useful thing a coverage review can do here;
- `automation/gitlab-ci/`, for which build configurations exist and what they cover. Note this pipeline does not run on a GitHub pull request;
- `automation/eclair_analysis/`, for the static analysis configuration and its deviations;
- any in-tree test under `xen/test/` or the XTF cases the scripts invoke.

There are no unit tests in the hypervisor in the sense other repositories mean it. Do not look for a test file next to the changed function.

For each failure mode from step 2, decide honestly: covered, covered on one path only, covered by a check that would pass anyway, or not covered. "A test in that file exists" is not "covered". Read the assertions and ask what would make them pass when the code is wrong. When a test asserts two values are equal, name what else could make them equal: both empty, both a default. When a test asserts something happened, work out what it would see if it had not. If you find such a path, that is a gap in the test itself, and it is worth a line even when the production code is right.

### 4. Check what has already been said

Read the PR description, the review comments, the review threads, and any comment left by another bot. If someone has already raised a gap, do not raise it again in your own words. If the author explained why a test was skipped, take the explanation at face value unless it is wrong on the facts. A test the author says is hard to write is usually hard to write.

Your own earlier review does not count as already said. When this review runs again on a new push, the Test Coverage section of the review carrying the `<!-- pr-review -->` marker is the one you are about to replace. Re-derive the verdict from the current diff; if the gap is still there, say it again.

### 5. Decide

Report a gap only when all of these hold:

- the failure mode is realistic and specific to this change;
- a check at some layer would actually catch it;
- the check is proportionate to the change. Naming the smoke script or build configuration that would exercise the change is proportionate. Asking for a unit test framework the hypervisor does not have is not.

Everything else stays unsaid. Most PRs in this repo will get the one-line "looks right" comment, and that is the correct outcome, not a failure to find something. A reviewer that invents a gap on every PR is one people stop reading, and then it misses the real one.

A gap is an observation until its importance is established. Before it goes in the review, say who hits the failure and how, what happens when they do, and why the current checks let it through. If the gap only makes sense with a "could", "may", or "might" in it, it is not established. When you cannot find the input, caller, or configuration that reaches the failure, leave it out rather than dress it up. This review has no "could not determine importance" section: a gap with no reachable failure is not a gap.

`../references/finding-impact.md` is the shared contract for that, and it applies here with one difference. A gap describes a defect that has not happened yet, so the consequence is allowed to be conditional — but the condition has to be concrete. "A guest that issues the hypercall with an index past the live limit reads hypervisor memory, and nothing between the hypercall entry and the subscript checks it" names the condition and the result. "This could have security implications" names neither.

When you have read the changed code and the checks around it and found nothing, stop there. Do not go hunting through the rest of the repository hoping something turns up. Finding nothing after a careful read is the answer.

A well-covered change with one more branch you could name is clean. When the PR already covers the failure paths of the new code at the right layer, report a remaining branch only if hitting it in production is realistic and the outcome would be wrong, not merely unexercised. "This arm has no test" is not a finding on its own.

Two shapes come up constantly and are worth naming so you weigh them properly:

- **Nothing runs on the pull request.** The upstream pipeline is GitLab-based and the Coverity workflow here is scheduled and dispatch-only by design. No build and no smoke test runs on a GitHub pull request in this repository. Say that once, then name what would have caught the change.
- **The code is not compiled by the configuration that gets built.** A change under an architecture or config symbol outside the usual build set is not exercised even where CI does run. Check which configurations reach the code before treating a build as coverage.

Pick the smallest thing that would catch the failure. A build of the configuration that compiles the code, for anything that can fail to compile or link. The matching qemu smoke script under `automation/scripts/`, for behaviour that appears at boot or on a running domain. An XTF case, for guest-visible hypercall behaviour. Do not propose a test framework the tree does not have.

## What to write

One review, short enough to read without scrolling. Write it the way you would say it to a teammate, not the way a report reads. Short sentences, one idea each. Do not compress the whole chain of reasoning into one long sentence. `../references/review-writing.md` is the shared contract for how much gets posted and how it reads; read it before writing. The section answers three questions: what behaviour is covered, what meaningful behaviour is not, and whether there is a gap the author should act on. The whole section is usually under 150 words.

**When the checks fit the change**, one or two sentences naming the behaviour they cover, at the level of the path or the scenario. Then stop. The sentence naming what is covered is the verdict; do not put "testing looks right" or another verdict phrase in front of it. Do not walk through every arm, case, or test name to show the coverage is there. Do not append observations, caveats, or things worth knowing. If a gap from an earlier round is now covered, leaving it out says so; do not add a paragraph confirming it. If it is not a gap, it does not go in the review.

Bad:

> The arm64 dom0less smoke script covers this. It boots a dom0less configuration with two domains, exercises the timer path on both, checks the console output for the expected banner and then verifies that each domain reaches userspace without...

Good:

> The arm64 dom0less smoke script boots through the changed timer path, so a hypervisor that hangs there would fail it.

```markdown
Nothing here needs a check. It's a comment fix.
```

**When there is a gap**, open with a plain line saying how many there are and whether you think the checks should land with this PR or can follow, then one block per gap. Say what is missing. Do not introduce it with a description of the shape of the problem:

```markdown
One gap, and it can follow the merge.

**Nothing boots the configuration this change affects.**

A hypervisor that hangs in the new ACPI path would reach a release without anything having run it: the smoke scripts under `automation/scripts/` cover the device-tree boot on this architecture, and none of them boots with ACPI, so the added parser is compiled and never executed.

An ACPI variant of `qemu-smoke-dom0-arm64.sh` that boots with the tables present and asserts dom0 reaches userspace would exercise it. Nothing on the pull request runs either way, so this is about what a pipeline could catch, not about this check.
```

Each gap states four things: the behaviour or transition that has no coverage, the defect that can escape because of it, what that defect does to a consumer, an operator, or a supported operation when it escapes, and the check to add with its layer, file, and assertion. Written in that order, the first sentence carries the consequence and the last one names the assertion that protects against it. A test proposed without the failure it prevents is not a gap. Two or three short paragraphs rather than one dense one, and under about 120 words; with the opening line the section stays under about 150, and only several independent gaps take it past that. Leave out how you traced it. Name the file and the function so the author can go straight there, and name the assertion, not just "add a test for X".

Name the regression, not the test. For an integration gap, name the two parts that can drift apart and why the current checks would still pass.

Cap it at three gaps. If there are more, pick the three most likely to bite and say you stopped there.

### Wording

Write like a strong engineer on a teammate's pull request, not like a report. Specific, direct, easy to act on, and the consequence before the mechanism.

- Say what actually happens. Not "this may result in incorrect behaviour" or "this weakens the guarantee" but the real outcome. When the consequence is limited, say so.
- Do not narrate. Not what you read, traced, drove, or checked; say what is covered and what is not. If something could not be run in this environment, say so once in the opening line and not again per gap.
- No enumeration of test names or arms to show coverage exists. Name the behaviour the checks cover.
- No praise or filler. "Testing looks right", "good coverage", "well tested", "looks good overall" carry nothing; the sentence naming what is covered replaces them.
- No scores, grades, severities, or "risk" language. No headings other than the bold line naming the gap.
- No asides. Nothing "for the record" or "worth knowing", no observations that are not a gap.
- No hedging filler ("it might be worth considering", "you may want to"). Say what the check is. Real uncertainty is different and worth saying plainly. Never as a label: not "Confirmed by reading", "Likely:", "Verdict:", "UNVERIFIABLE".
- No generic asks. "Add more integration tests" and "increase coverage" are never the answer. If you cannot name the scenario and the assertion, you do not have a finding.
- No metaphors or compressed jargon where plain English is shorter: load-bearing, the seam between, escape hatch, widens what runs, guard against it, falls through, feature is inert, read through this. Use the codebase's own terms and say what the check asserts.
- No boilerplate disclaimer. Not "suggestions only", not "nothing here blocks the merge". Whether the checks should land with the PR belongs in the opening line, said once.
- Refer to the code, never to the person. No author names, no "you forgot", no comparisons with other PRs.
- Do not restate what the change does beyond what the reader needs to place the gap.

## Running it yourself

```bash
git fetch origin edera/4.22
git diff origin/edera/4.22...HEAD
```

Work the steps above against that diff. On an open PR, also read the review comments so you do not repeat them:

```bash
gh pr view <n> --comments
gh api repos/edera-dev/xen/pulls/<n>/comments --jq '.[].body'
```
