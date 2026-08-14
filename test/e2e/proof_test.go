//go:build live_e2e

// Package e2e_test is the walking skeleton's end-to-end proof: one machine, one
// server, both real, driven end to end in the order a person would drive them.
//
// It is behind the `live_e2e` build tag and an environment guard, so
// `go test ./...` never builds it. What it needs is a deployment, not a fixture:
// a live control plane on the tailnet, a container runtime running the connector
// workload, this machine's own harnesses, and — once, for the credential stage —
// a human at a browser.
//
//	HOMEPLANE_E2E=1 \
//	HOMEPLANE_E2E_SERVER=http://homeplane.example-tailnet.ts.net \
//	HOMEPLANE_E2E_SSH_HOST=server-host \
//	HOMEPLANE_E2E_ACCOUNT=you@example.com \
//	HOMEPLANE_E2E_VAULT=$HOME/Documents/daniel-os \
//	go test ./test/e2e/ -tags live_e2e -run TestEndToEndProof -count=1 -v -timeout 180m
//
// Stages are selectable (`HOMEPLANE_E2E_STAGES=enrol,vault`) and the evidence
// file carries stages forward, so an interactive proof can be completed in
// sittings and a single leg can be re-run without redoing the rest. Every stage
// records what it ran and what it concluded, pass or fail: an evidence file that
// only shows successes is a demo, not a proof.
//
// The authority for every connector claim is the SERVER'S audit log, read
// through the operator CLI on the server host. A harness's own account of what
// it did is recorded next to it, and never believed on its own.
package e2e_test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestEndToEndProof(t *testing.T) {
	e := loadEnv(t)
	commit, _ := exec.Command("git", "rev-parse", "HEAD").Output()

	rec := newRecorder(t, e, map[string]any{
		"schema_version": 1,
		"kind":           "live_e2e_proof",
		"task":           "fn-1-homeplane-walking-skeleton-install.7",
		"what_this_is": "The record of the end-to-end walking-skeleton proof: a real machine installed, " +
			"enrolled and configured against the live server, and every capability exercised from the " +
			"harnesses themselves. Nothing here can be produced by `go test ./...` — it needs a deployment " +
			"and, once, a human at a consent screen. Each stage carries the commands it ran with their exit " +
			"codes, and each assertion carries the observation that settles it. Connector claims are settled " +
			"by the server's own audit log, never by what a harness said it did.",
		"commit":     strings.TrimSpace(string(commit)),
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"deployment": map[string]string{
			"server_url":  e.serverURL,
			"server_host": e.sshHost,
			"account":     e.account,
			"calendar_id": e.calendarID,
			"vault":       e.vaultPath,
			"agent":       agentBin(),
		},
	})

	// The order is the product's order. A stage that depends on an earlier one
	// is not skipped when it fails — it runs and records what it found, because
	// "the harness leg failed because enrolment failed" is worth knowing.
	runStage(t, e, rec, "install", stageInstall)
	runStage(t, e, rec, "enrol", stageEnrol)
	runStage(t, e, rec, "vault", stageVault)
	runStage(t, e, rec, "gno", stageGNO)
	runStage(t, e, rec, "skills", stageSkills)
	runStage(t, e, rec, "harnesses", stageHarnesses)
	runStage(t, e, rec, "gno-retrieval", stageGNORetrieval)
	runStage(t, e, rec, "credentials", stageCredentials)
	runStage(t, e, rec, "connector", stageConnector)
	runStage(t, e, rec, "calendar", stageCalendar)
	runStage(t, e, rec, "revocation", stageRevocation)
	runStage(t, e, rec, "truth-table", stageTruthTable)
	runStage(t, e, rec, "audit", stageAuditReview)

	t.Logf("evidence: %s", e.evidencePath)
}

// stageTruthTable — R10, over the failure modes the demo path actually hits.
//
// The split under proof is which SIDE answers for what: a machine-local failure
// belongs in `status` and must never appear in the server's /healthz, and a
// degraded component must produce a non-zero exit and a non-2xx respectively —
// a report that stays cheerful is worse than no report.
func stageTruthTable(s *stage) {
	// 1. Server reachable, everything up: status is ok and exits 0.
	rep, res := s.status()
	s.assert("status exits 0 and reports ok when the machine is healthy",
		res.ExitCode == 0 && rep.Status == "ok", "exit %d, status %q", res.ExitCode, rep.Status)

	health := s.run("server /healthz over the tailnet", 30*time.Second, "curl", "-sf", "-m", "20",
		s.env.serverURL+"/healthz")
	s.assert("/healthz is 2xx and green while the server is healthy",
		health.ExitCode == 0 && strings.Contains(health.Stdout, `"status":"ok"`),
		"curl exit %d: %s", health.ExitCode, firstLine(health.Stdout))
	s.assert("/healthz reports server components only — no machine state",
		!strings.Contains(health.Stdout, "vault") && !strings.Contains(health.Stdout, "gno") &&
			!strings.Contains(health.Stdout, "harness"),
		"%s", firstLine(health.Stdout))

	// 2. A revoked grant. The revocation stage leaves the machine restored, so
	// this mode is produced here on purpose and undone at the end.
	rep, _ = s.status()
	var victim string
	for _, g := range rep.Grants {
		if g.State == "active" && g.Harness == "codex" {
			victim = g.GrantID
		}
	}
	if victim != "" {
		s.ssh("server: revoke the codex grant (truth-table mode)", 60*time.Second,
			fmt.Sprintf("%s/bin/homeplane-server admin revoke-grant -state-dir %s %s",
				serverPrefix(s.env), s.env.serverStateDir, victim))
		rep, res = s.status()
		var sawRevoked bool
		for _, g := range rep.Grants {
			if g.GrantID == victim && g.State == "revoked" {
				sawRevoked = true
			}
		}
		s.assert("status reports a revoked grant truthfully, reconciled live", sawRevoked,
			"grants %+v (exit %d)", rep.Grants, res.ExitCode)
		restore := s.agent("homeplane-agent configure-harnesses (undo the truth-table revocation)",
			5*time.Minute, "configure-harnesses", "-json")
		s.assert("the machine is restored after the revoked-grant mode", restore.ExitCode == 0,
			"exit %d%s", restore.ExitCode, tail(restore.Stderr))
	}

	// 3. Server unreachable. status must say `unknown (server unreachable)` for
	// grants rather than reporting cached state as live, and must not pretend
	// the machine is fine.
	unreachable := s.agent("homeplane-agent status against an unreachable server", 90*time.Second,
		"status", "-json", "-server", "http://127.0.0.1:9")
	s.assert("status distinguishes an unreachable server from an active grant",
		strings.Contains(unreachable.Stdout, "unknown") || strings.Contains(unreachable.Stdout, "unreachable") ||
			unreachable.ExitCode != 0,
		"exit %d: %s", unreachable.ExitCode, firstLine(unreachable.Stdout))

	// 4. The retrieval engine down. A machine-local failure: status degrades and
	// exits non-zero, and /healthz — which knows nothing about this machine —
	// must stay green.
	stop := s.agent("homeplane-agent gno deactivate (machine-local failure mode)", 3*time.Minute,
		"gno", "deactivate")
	if stop.ExitCode == 0 {
		rep, res = s.status()
		state, detail := s.component(rep, "gno")
		s.assert("status degrades and exits non-zero when the engine is down",
			res.ExitCode != 0 && state != "ok", "exit %d, gno %s (%s)", res.ExitCode, state, detail)

		health = s.run("server /healthz while THIS machine is degraded", 30*time.Second,
			"curl", "-sf", "-m", "20", s.env.serverURL+"/healthz")
		s.assert("a machine-local failure never reaches the server's /healthz",
			health.ExitCode == 0 && strings.Contains(health.Stdout, `"status":"ok"`),
			"curl exit %d: %s", health.ExitCode, firstLine(health.Stdout))

		restart := s.agent("homeplane-agent gno activate (restore)", 20*time.Minute, "gno", "activate")
		s.assert("the retrieval engine is restored", restart.ExitCode == 0,
			"exit %d%s", restart.ExitCode, tail(restart.Stderr))
	} else {
		s.recordLimitation("the engine-down mode was exercised",
			"gno deactivate exited "+fmt.Sprint(stop.ExitCode)+"; the mode was not produced, so nothing is claimed for it")
	}

	// 5. Vault missing. Pointing detection at a path that is not a vault must be
	// refused rather than recorded, which is the same truthfulness from the
	// other side: status never gains a vault the machine does not have.
	bogus := s.agent("homeplane-agent vault detect on a path that is not a vault", 60*time.Second,
		"vault", "detect", "-vault-path", "/tmp/homeplane-e2e-not-a-vault")
	s.assert("a missing vault is refused, not recorded", bogus.ExitCode != 0,
		"exit %d: %s", bogus.ExitCode, firstLine(bogus.Stderr))
	rep, _ = s.status()
	state, detail := s.component(rep, "vault")
	s.assert("the real vault is still what status reports", state == "ok" && strings.Contains(detail, s.env.vaultPath),
		"vault: %s (%s)", state, detail)
}

// stageAuditReview is the operator's read of the whole run: every step of the
// six-op sequence including the reads, the Drive read, both refusals, and the
// lifecycle events — each with the class the manifest resolved, the artifact it
// touched, and who did it.
func stageAuditReview(s *stage) {
	since := time.Now().UTC().Add(-6 * time.Hour)
	rows := s.audit("server audit: the whole run", since)
	s.assert("the operator CLI reads the authoritative log", len(rows) > 0, "%d row(s)", len(rows))

	byEvent := map[string]int{}
	classes := map[string]int{}
	harnesses := map[string]int{}
	var unattributed int
	for _, r := range rows {
		byEvent[r.Event]++
		if r.ActionClass != "" {
			classes[r.ActionClass]++
		}
		if r.Harness != "" {
			harnesses[r.Harness]++
		}
		// Every connector row must carry attribution: an audit that cannot say
		// who made a call is a log, not an audit.
		if r.Event == "connector_tool_call" && (r.Harness == "" || r.GrantID == "" || r.AuthMachineID == "") {
			unattributed++
		}
	}
	s.assert("every connector call is attributed to (machine, harness, grant)", unattributed == 0,
		"%d unattributed connector row(s) of %d", unattributed, byEvent["connector_tool_call"])
	s.assert("both harnesses appear in the audit",
		harnesses["claude-code"] > 0 && harnesses["codex"] > 0,
		"claude-code %d rows, codex %d rows", harnesses["claude-code"], harnesses["codex"])
	s.assert("all three action classes were exercised and recorded",
		classes["read"] > 0 && classes["write"] > 0 && classes["delete"] > 0,
		"read %d, write %d, delete %d", classes["read"], classes["write"], classes["delete"])
	s.assert("the lifecycle events are recorded",
		byEvent["enrolment"] > 0 && byEvent["grant_issued"] > 0 && byEvent["grant_revoked"] > 0,
		"enrolment %d, grant_issued %d, grant_revoked %d",
		byEvent["enrolment"], byEvent["grant_issued"], byEvent["grant_revoked"])
	s.assert("refusals are recorded rather than dropped",
		byEvent["policy_violation"] > 0, "policy_violation %d, connector_denied %d",
		byEvent["policy_violation"], byEvent["connector_denied"])

	// Metadata only, across the whole run: the closed detail vocabulary is what
	// structurally keeps payloads out, and this is the spot check that it held.
	var payloadish int
	for _, r := range rows {
		for _, v := range r.Detail {
			if len(v) > 512 {
				payloadish++
			}
		}
	}
	s.assert("no audit row carries anything payload-sized (metadata only)", payloadish == 0,
		"%d oversized detail value(s) across %d rows", payloadish, len(rows))
}
