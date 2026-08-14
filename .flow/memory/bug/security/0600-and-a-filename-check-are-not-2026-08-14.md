---
title: 0600 and a filename check are not containment for a token in a repo
date: "2026-08-14"
track: bug
category: security
module: internal/agent/harness/detect.go
tags: [secrets, git, path-traversal, symlinks, fail-closed]
problem_type: security
symptoms: A grant token could be written into a git worktree via CODEX_HOME or a symlinked ~/.codex; a git-managed home was explicitly exempted
root_cause: Containment was checked by filename and file mode instead of by whether the resolved destination is committable
resolution_type: fix
related_to: [bug/security/authoritative-audit-must-commit-with-2026-08-13, bug/security/verification-must-query-current-state-2026-08-13]
---

## Problem
Writing a bearer token to `~/.codex/config.toml` at 0600, with a check that only
refused the filename `.mcp.json`, is not containment. The DIRECTORY is
attacker- or accident-controlled: `CODEX_HOME` is an environment variable and
`~/.codex` can be a symlink, so the file — and its timestamped backups — can
land inside a git working tree, where 0600 stops nothing that `git add` does.

## What Didn't Work
Two weaker positions, both rejected in review:
- **Name-based refusal only.** It answers "is this the project-scope config
  file?" when the question is "can this file be committed?".
- **Exempting `$HOME` from the repository walk.** The reasoning was that a
  dotfiles-repo home is the owner's deliberate choice and refusing there would
  be a false positive breaking the normal case. The reviewer was right that this
  contradicts the requirement outright: the owner versioning their home does not
  make the token less committable, and an exemption written to avoid a false
  positive silently reintroduced the exact leak.

## Solution
Judge the destination by where it LANDS, and ask git the precise question:
1. Resolve symlinks as far up the path as exists (`filepath.EvalSymlinks` on the
   deepest existing ancestor), then re-join the remainder.
2. Walk to the filesystem root looking for a `.git` entry. Use `Lstat`, not
   `Stat` for a directory: a linked worktree's `.git` is a FILE and is every bit
   as committable.
3. Inside a repository, permit ONLY when `git check-ignore --quiet -- <path>`
   exits 0. Do NOT pass `--no-index`: without it git refuses to call a TRACKED
   file ignored even when a rule matches, which is exactly right — a force-added
   config is already committable whatever `.gitignore` says. (A regression test
   for the tracked case caught this; the first implementation had the flag.)
4. Git missing, timing out, or erroring ⇒ refuse. The answer permits writing a
   secret, so an unprovable file is treated as exposed.

This has no false positives: a dotfiles user who already ignores their secrets
passes, and one who does not gets a message naming the fix.
`internal/agent/harness/detect.go` (`assertUserScope`, `gitIgnores`).

## Prevention
- For any secret-bearing file, the containment test is "can this be committed?",
  not "is it named right?" and not "is it 0600?". Resolve symlinks first — the
  path you were handed is not the path you write.
- Resist exemptions introduced to dodge a false positive on a security rule.
  Find the precise predicate instead (here: ignored-and-untracked). If the
  precise predicate needs an external tool, shell out and fail closed.
- Write the "already tracked despite an ignore rule" case as a test. It is the
  one an ignore-rule check gets wrong, and it is invisible otherwise.
