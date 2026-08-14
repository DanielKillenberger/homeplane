---
name: Homeplane
last_updated: 2026-08-13
generator: flow-next-strategy
---

# Homeplane Strategy

## Target problem

Every machine and every agent harness (Claude Code, Codex, later Hermes, Cursor, Grok) that should work with Daniel's personal data currently needs its own copy of remote-service credentials, its own OAuth dances, its own hand-configured path to the Daniel-OS vault and GNO, and its own hand-wired copies of Daniel's authored skills. Credentials end up scattered across machines with no per-machine/per-harness revocation, no audit trail, skills drift into divergent editable copies, and every new machine costs hours of repeated setup — the crux is that capability (what an agent may touch and know how to do) is entangled with configuration (where secrets, services, and skills live).

## Our approach

Homeplane is Daniel's self-hosted, portable **personal data and skill layer** for AI agents: one bundle installed on a Mac or Linux machine enrols it with Daniel's server over Tailnet, remote-service connector credentials and OAuth sessions live only on the server, and three capability families reach every authorized harness — personal-data connectors (Google Workspace, Rize, Oura, TickTick) via MCP with independently revocable Homeplane access, a continuously synchronized Daniel-OS vault with supervised GNO (vault files sync; GNO indexes stay local and disposable), and vault-authored skills provisioned into each harness by linking, never by independent editable copies. We compose existing open-source components (e.g. ToolHive) rather than building another MCP gateway, and keep everything fully self-hosted with no third-party connector-management cloud. Homeplane distributes access and instructions, not initiative: ordinary clients never inherit scheduled or proactive workflows; one designated operating agent owns recurring jobs and monitoring.

## Who it's for

**Primary:** Daniel — hiring Homeplane to make any new machine or agent harness fully capable (vault + GNO, personal-data connectors, authored skills) in one enrolment, without repeating provider authentication, without spreading credentials, and without hand-maintaining skill copies.

## Key metrics

- **Time-to-capability** — wall-clock from bundle install on a fresh machine to a harness successfully using local GNO and a server-side connector; measured per enrolment.
- **Credential surface** — number of places remote-service connector credentials/OAuth sessions exist; target is exactly 1 (the server), verified by inspection of enrolled machines. (Named exception: Obsidian Sync credentials, inherent to hosting a synced vault locally.)
- **Revocation correctness** — revoking one machine or harness cuts its access and nothing else's; verified by post-revocation access checks.
- **Harness coverage** — number of detected agent harnesses configured automatically — connectors, GNO, and skills — without overwriting unrelated settings.

## Tracks

### Identity & enrolment

Machine enrolment over Tailnet and per-machine/per-harness identities with issuable, revocable grants. Tailnet provides private reachability, never sufficient authorization on its own.

_Why it serves the approach:_ separate revocable identities are what let one server hold all credentials while many agents act safely; the same layer is deliberately reusable by a future Phone Home supervision module.

### Server capability plane

Server-side personal-data connector hosting (OAuth broker, credential custody) exposed via MCP, composed from existing OSS such as ToolHive. Connector roadmap: Google Workspace (Gmail, Calendar, Drive, Docs, Sheets, Contacts incl. authorized writes), Rize, Oura (separately grantable), TickTick.

_Why it serves the approach:_ keeps credentials in exactly one self-hosted place and turns "authenticate a provider once" into a capability any enrolled harness can use — clients receive revocable Homeplane access, never provider credentials.

### Local capability bootstrap

The installed bundle detects or retrieves the Daniel-OS vault (via Obsidian Sync), keeps it continuously synchronized, installs/configures/launches/supervises GNO with a disposable per-machine index, provisions vault-authored skills into each harness (native external directories/symlinks where supported, thin adapters otherwise — never independent editable copies), and configures all detected agent harnesses without touching unrelated settings.

_Why it serves the approach:_ this is the plug-and-play half — a fresh machine reaches full local capability, data and skills, with zero hand-configuration.

### Operations & trust

Health checks, audit of authorized reads/writes/sends/deletes (metadata, not payload bodies), and revocation workflows across the plane. Connector access never itself authorizes a consequential action; provider tokens never appear in repositories, logs, argv, generated configs, or model context.

_Why it serves the approach:_ authorized side-effectful capability is only tenable when every action is auditable and every grant is cheaply revocable.

## Not working on

- A third-party or cloud-hosted connector-management service — Homeplane stays fully self-hosted.
- Building a new MCP gateway from scratch — compose existing open-source components (ToolHive et al.) instead.
- A general-purpose agent tool platform — Homeplane is Daniel's private life-data layer, nothing broader.
- Technical services clients can easily install or authenticate locally (GitHub, git, Vercel, shell, filesystem, web search) — they do not pass through Homeplane.
- Proactive/scheduled workflows for ordinary clients — initiative belongs to one designated operating agent, not to every harness that holds a skill.
- The Phone Home supervision module itself — a separate later module that reuses Homeplane's identity and enrolment layer.
