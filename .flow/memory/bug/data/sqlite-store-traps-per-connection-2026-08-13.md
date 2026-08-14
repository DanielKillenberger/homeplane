---
title: "SQLite store traps: per-connection pragmas, variable-width timestamps, WAL/SHM p"
date: "2026-08-13"
track: bug
category: data
module: internal/store/sqlite.go
tags: [sqlite, go, pragmas, timestamps, file-permissions]
problem_type: data
symptoms: Foreign keys unenforced on most connections; --since filtering wrong at fractional-second boundaries; -wal/-shm files world-readable
root_cause: "PRAGMA Exec'd on a pooled sql.DB, RFC3339Nano trimming trailing zeros in text comparisons, and chmod applied after SQLite created its sidecars"
resolution_type: fix
---

## Problem
Three independent defects in the first `modernc.org/sqlite` control-plane store,
all found by codex review rather than by a green test suite:

1. **PRAGMAs applied per connection.** `db.Exec("PRAGMA foreign_keys=ON")` on a
   pooled `*sql.DB` configures exactly ONE arbitrary pooled connection. Every
   other connection silently ran with foreign keys off and no busy timeout.
2. **Variable-width timestamps compared lexicographically.** `time.RFC3339Nano`
   trims trailing zeros, so `...:00.1Z` sorts BEFORE `...:00.000000000Z` even
   though it happens later. `--since` filtering and `ORDER BY ts` were wrong at
   precision boundaries — invisible until a fractional-second row appears.
3. **WAL/SHM sidecars world-readable.** SQLite derives `-wal` / `-shm` modes
   from the main database file AT CREATION TIME, so opening the DB and then
   chmodding it to 0600 leaves sidecars at the umask default (0644) — holding
   the same live machine, grant, audit, and encrypted-secret pages.

## Solution
1. Put pragmas in the DSN so the driver applies them per connection:
   `path?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)`,
   plus `SetMaxOpenConns(1)` for a single-operator control plane (caveat: never
   start a second query while iterating open `*sql.Rows`, or the two deadlock).
2. Store timestamps in a FIXED-WIDTH layout (`2006-01-02T15:04:05.000000000Z`)
   so text order and chronological order coincide; parse with a fallback list
   for rows written by older builds.
3. `os.OpenFile(path, O_CREATE, 0600)` BEFORE `sql.Open`, and chmod any existing
   `-wal` / `-shm` on open.

## Prevention
- Foreign-key/pragma enforcement deserves a test that runs the same operation
  several times (pool churn), not once — a single call may hit the one
  configured connection and pass.
- Any timestamp compared or sorted as TEXT must be fixed-width; add a
  mixed-precision boundary test (`.0`, `.1`, whole second) whenever `--since`
  or `ORDER BY ts` exists.
- File-permission assertions must cover sidecars, under an explicit
  `syscall.Umask(0o022)` — the default test umask can hide the bug.
