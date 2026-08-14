---
name: homeplane-capabilities
description: >-
  How to use Daniel's Homeplane capability plane: retrieve from his Daniel-OS
  vault via gno before guessing about his life, notes, projects, or people;
  read his Google Drive and read/write his Calendar through the homeplane MCP
  server. Load whenever a request involves Daniel's personal context — his
  schedule, his notes, something "I wrote", a project or person he mentions, a
  file in his Drive, an appointment — or when you are about to answer a
  question about Daniel from memory instead of from his data.
---

# Homeplane capabilities

Daniel runs Homeplane: his machines' agent harnesses all share the same
capability plane. Two MCP surfaces matter:

**Reading this skill does NOT mean this harness is enrolled.** Some harnesses
discover other vendors' skill directories (grok scans `~/.claude/skills` by
default), so this file can reach a harness that holds no grant of its own — and
an MCP entry it inherited the same way would act under a *different* harness's
identity, with that harness's audit trail and revocation. If you need to rely
on having your own grant, verify the Homeplane MCP entry is configured for THIS
harness rather than inherited from another one; do not infer it from the fact
that you can read this.

## 1. Vault retrieval (`gno` MCP server, local)

Daniel's Obsidian vault (Daniel-OS: notes, project logs, decision ledgers,
people, journals) is indexed locally.

- **Reach for it BEFORE answering anything about Daniel's life, projects,
  history, or preferences from memory.** If he references a note, a decision,
  a person, a past event, or "what did I say about X" — search first.
- `gno_search` — exact keywords, names, identifiers (BM25; always available).
- `gno_query` / `gno_ask` — semantic; may be unavailable while embeddings are
  not configured — fall back to `gno_search` with a few keyword variants.
- `gno_get` / `gno_multi_get` retrieve full context around a hit.
- The index is local and disposable; the vault files are the truth. Cite the
  note path when you use one.

## 2. Google connectors (`homeplane` MCP server, via Daniel's server)

Calls go through Daniel's self-hosted server; credentials never live on this
machine. Every call is audited (metadata, not contents) under this harness's
own grant.

- **Drive is read-only by policy.** Search/read tools work; every write tool
  is excluded and will be refused. Do not retry a refused write — refusal
  means not granted, not an error.
- **Calendar is read/write, guarded.** `manage_event` REQUIRES
  `send_updates: "none"` — sending attendee notifications is a separately
  granted authority this grant does not have. Create/update/delete without
  notifying attendees is fine; anything that would email someone is not.
- Check his schedule with `get_events` before proposing times — it is the only
  read surface this grant has. `list_calendars`, `query_freebusy`,
  `manage_focus_time` and `manage_out_of_office` are **excluded by the
  connector manifest** and will be refused; work from `get_events` on the
  default calendar instead of reaching for them.

## Rules

- A policy refusal (`excluded_tool`, `capability_missing`) is the system
  working. Report it plainly; never work around it or retry variants.
- Never ask Daniel for Google credentials or tokens — the server holds them.
  An auth error has **two different causes with two different fixes**, so
  report which one it is rather than guessing:
  - **This harness's grant is invalid or revoked** — the failure is at the
    Homeplane edge, before any provider call. Tell him to check
    `homeplane-agent status` and re-run `homeplane-agent configure-harnesses`.
  - **The Google credential itself needs re-authorising** — the connector says
    so explicitly. Tell him to run `homeplane-agent add-credentials google
    -replace`; without `-replace` an existing credential returns 409 and
    nothing changes.

  Then stop — do not retry the call either way.
- Homeplane distributes access and instructions, not initiative: do not set up
  recurring jobs, watches, or scheduled actions through these connectors
  unless Daniel explicitly asks.
