---
name: upstream-rebase
description: Nightly rebase of the downstream edera/4.22 series onto upstream xen-project staging-4.22, run unattended in CI by .github/workflows/upstream-rebase.yml. Covers the replay, conflict resolution, build checks, the XSA audit, and the report the workflow publishes.
---

# Nightly upstream rebase

You are rebasing a long downstream Xen series (170+ commits) onto the upstream
branch it tracks. The goal is a replay that changes **nothing downstream**:
every difference in the final tree must come from the upstream delta alone.
Where that is impossible, because upstream and downstream touched the same
code, you resolve the conflict the way a careful Xen maintainer would and you
say exactly what you did.

This runs unattended. Nobody is watching while you work, and nobody can answer
a question. Everything a reviewer needs has to end up in the report.

## What happens to your result

You cannot push, and nothing you write decides whether the branch is pushed.
When you finish, the workflow independently:

1. runs `.github/scripts/verify-upstream-rebase.sh` against your branch, which
   checks from git alone that the series sits on the upstream tip, is linear,
   lost or gained no commit, and changed the tree by exactly the upstream
   delta;
2. builds x86, arm64 `defconfig`, and arm64 with the vPCI passthrough stack.

If all of that passes, `edera/4.22` is force-pushed to your branch. If any of
it fails, your branch goes up as a pull request with your report as the body,
and a maintainer reads it.

So: a conflict you resolve **will** show up as drift and **will** go to a
human. That is the intended outcome, not a failure. Do not try to make a
resolution look clean, and never drop, squash, reorder or reword a downstream
commit to get past the checks. A rebase that reaches review with an honest
report is a success; one that hides a judgement call is not.

## Inputs

The workflow gives you, in the prompt:

- `OLD_TIP`: the `edera/4.22` commit you are rebasing (already checked out).
- `UPSTREAM`: the upstream `staging-4.22` commit to rebase onto, fetched as
  the local branch `upstream-target`.
- `RESULT`: the local branch name your result must end up on.
- `REPORT`: the path your report must be written to.

### How to run commands here

Your shell commands are checked against an allowlist that matches the
command's first word. Shell variables, `$(...)`, `<(...)` and `VAR=x cmd`
prefixes will be refused, so in every snippet below `OLD_TIP`, `UPSTREAM`,
`RESULT`, `MB` and `<...>` are placeholders: substitute the literal SHA or
path, or a path you choose. Put scratch files and worktrees under `.rebase-scratch/` in the
repository root (`mkdir -p .rebase-scratch`); it is untracked and nothing reads it after you. Use
`-j4` for builds.

## 1. Survey

```sh
git merge-base OLD_TIP UPSTREAM               # call the result MB
git rev-list --count MB..OLD_TIP              # downstream commits
git log --oneline MB..UPSTREAM                # what is new upstream
```

Read every new upstream commit message, and the diffs of any that touch areas
downstream also changes:

```sh
git diff --stat MB..UPSTREAM
git log --oneline MB..OLD_TIP -- <files upstream touched>
```

Upstream commits that land in files downstream also modifies are where a
textually clean replay can still be semantically wrong. Note them; you come
back to them in step 4.

## 2. Rebase

```sh
git switch -c RESULT OLD_TIP
git rebase --onto UPSTREAM MB RESULT
```

When a commit conflicts:

- Read the upstream change that caused it **and** the downstream commit's
  intent (its message, and the rest of its diff). Resolve so the downstream
  commit does what it did before, on top of what upstream now does.
- Upstream wins on security fixes. If an XSA or other fix changed the code a
  downstream commit edits, keep every guard, ordering constraint and check the
  fix introduced, and fit the downstream change around it.
- If upstream now contains the downstream change itself (it was upstreamed or
  backported), let the downstream commit go empty and let git drop it. Record
  that.
- If you cannot tell what the right resolution is, do not guess silently. Make
  the most conservative resolution you can defend, mark it **UNSURE** in the
  report, and explain both readings.
- Never use `-X ours`, `-X theirs`, `--skip`, or `git checkout --ours/--theirs`
  on a whole file to make a conflict go away.

For each conflict, record: the downstream commit (subject), the files, the
upstream commit it collided with, and in a sentence or two what you kept and
why.

Downstream commits that git drops as empty must be recorded too, with the
upstream commit that made them empty.

## 3. Build

The workflow re-runs these builds itself, but run them here so you can fix
what your resolutions broke. Use a scratch worktree for arm64 so it does not
collide with the in-tree x86 build:

```sh
make -C xen defconfig
make -C xen -j4

git worktree add --detach .rebase-scratch/wt-arm64 RESULT
make -C .rebase-scratch/wt-arm64/xen XEN_TARGET_ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
make -C .rebase-scratch/wt-arm64/xen XEN_TARGET_ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j4
.rebase-scratch/wt-arm64/xen/scripts/config --file .rebase-scratch/wt-arm64/xen/.config --enable EXPERT --enable PCI_PASSTHROUGH
make -C .rebase-scratch/wt-arm64/xen XEN_TARGET_ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
make -C .rebase-scratch/wt-arm64/xen XEN_TARGET_ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j4
git worktree remove --force .rebase-scratch/wt-arm64
```

If a build fails because of the rebase (a resolution, or an upstream change a
downstream commit has not caught up with), fix it **in the downstream commit
that is wrong**. Interactive editors do not work here, so drive the todo list
with sed: `git -c sequence.editor="sed -i 's/^pick <sha>/edit <sha>/'" rebase
-i UPSTREAM`, amend, then `git rebase --continue`. Do not add a fix-up
commit on top unless there is no single commit it belongs to; if you must, its
subject starts with `rebase: ` and the report says why.

If a build fails on the pristine upstream tree too, it is not yours: build
UPSTREAM the same way (in another `.rebase-scratch/` worktree) to confirm, and report it as pre-existing.

## 4. Audit what upstream brought in

For every upstream commit flagged in step 1, and for every XSA in the new
upstream range, check that the fix **survived the replay**. Ancestry is not
enough: a downstream commit replayed on top can edit the very lines a fix
added.

```sh
git log --format='%h %s' --grep='XSA-' MB..UPSTREAM
```

For each XSA:

```sh
# a. How many patches does the advisory ship? Check master and staging too;
#    some XSAs are multi-patch and a stable branch may carry only some.
git fetch https://github.com/xen-project/xen master staging
git log --oneline --grep='XSA-<N>' FETCH_HEAD    # repeat per branch

# b. Is each backport the same change as the master fix? Compare only the
#    +/- lines: hunk offsets and context legitimately differ between branches.
git show --format= <master-fix> --output=.rebase-scratch/master.patch
git show --format= <backport>   --output=.rebase-scratch/backport.patch
#    then read both and compare their +/- lines

# c. Did a downstream commit touch the fixed files afterwards?
git log --oneline UPSTREAM..RESULT -- <files the fix touched>
```

If (c) returns anything, read the **final tree**, not the commit graph:
confirm the fix's guards and ordering are intact and that downstream code
added after it is covered by them. Grep tree-wide for any flag or helper the
fix deliberately removed, in case a downstream commit brought it back.

## 5. Check yourself

Run the same checker the workflow will run, so the report can explain its
result rather than be surprised by it:

```sh
bash .github/scripts/verify-upstream-rebase.sh OLD_TIP RESULT UPSTREAM
```

Every drift line and every changed commit it lists must be accounted for in
your report by a conflict resolution, a dropped-empty commit or a build fix.
If one is not, you made a change you did not mean to: find it and undo it.

## 6. Report

Write the report to the `REPORT` path, in Markdown. It becomes a pull request body when a human has
to look, so lead with what they must decide. No preamble, no sign-off.

```markdown
## Summary
One paragraph: upstream range (N commits, short SHAs), downstream commits
replayed, conflicts resolved, commits dropped, and whether you expect the
checker to pass.

## Needs a decision
Only if anything is marked UNSURE. One bullet each, with both readings.

## Conflicts resolved
Per conflict: downstream commit, files, colliding upstream commit, what you
kept and why. "None." if none.

## Dropped downstream commits
Subject and the upstream commit that made it empty. "None." if none.

## Build fixes
What broke, which commit you fixed it in, why. "None." if none.

## New upstream commits
`short-sha subject` for each.

## XSA audit
Per XSA: patches shipped, present (yes/no), identical to master (yes/no),
downstream commits touching the fixed files after it, and your reading of
the final tree. "No XSAs in this range." if none.

## Builds
x86, arm64 defconfig, arm64 + PCI_PASSTHROUGH: pass, fail (with the first
error), or pre-existing failure (confirmed on pristine upstream).
```

Then stop. Leave RESULT checked out or not; the workflow reads the branch,
not the working tree.

## If you cannot finish

If the rebase cannot be completed (a conflict you cannot resolve at all, a
toolchain that will not run), run `git rebase --abort`, do not create
the RESULT branch, and write the report explaining where you stopped and why. The
workflow treats a missing RESULT branch as a failed night and opens an issue with
your report.
