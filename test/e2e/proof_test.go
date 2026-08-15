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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/health"
)

func TestEndToEndProof(t *testing.T) {
	e := loadEnv(t)
	commit, _ := exec.Command("git", "rev-parse", "HEAD").Output()

	// The proof runs for whichever task is driving it. fn-1 recorded the
	// walking-skeleton run; fn-3 re-runs the same machinery with the grok
	// stages selected and records its own artifact, so the task an artifact
	// claims is the task that actually drove it rather than a constant.
	task := strings.TrimSpace(os.Getenv("HOMEPLANE_E2E_TASK"))
	if task == "" {
		task = "fn-1-homeplane-walking-skeleton-install.7"
	}

	rec := newRecorder(t, e, map[string]any{
		"schema_version": 1,
		"kind":           "live_e2e_proof",
		"task":           task,
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
	runStage(t, e, rec, "vault-sync", stageVaultSync)
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

	// fn-3's stages: grok as a third harness, proven on the same machine
	// against the same server. They are additions rather than edits — the
	// stages above are fn-1's record of the two-harness skeleton and stay as
	// they were — and they are selected by name like any other stage.
	//
	// The order is load-bearing twice over: the skills stage needs the
	// configuration the harness stage writes, and the status stage's `revoked`
	// row is produced from a grant the revocation stage really revoked.
	runStage(t, e, rec, "grok-harness", stageGrokHarness)
	runStage(t, e, rec, "grok-rollout-gate", stageGrokRolloutGate)
	runStage(t, e, rec, "grok-skills", stageGrokSkills)
	runStage(t, e, rec, "grok-gno", stageGrokGNO)
	runStage(t, e, rec, "grok-connector", stageGrokConnector)
	runStage(t, e, rec, "grok-calendar", stageGrokCalendar)
	runStage(t, e, rec, "grok-revocation", stageGrokRevocation)
	runStage(t, e, rec, "grok-status-truth", stageGrokStatusTruth)
	runStage(t, e, rec, "grok-audit", stageGrokAudit)

	t.Logf("evidence: %s", e.evidencePath)
}

// stageTruthTable — R10, over the failure modes the demo path actually hits.
//
// The split under proof is which SIDE answers for what: a machine-local failure
// belongs in `status` and must never appear in the server's /healthz, and a
// degraded component must produce a non-zero exit and a non-2xx respectively —
// a report that stays cheerful is worse than no report.
func stageTruthTable(s *stage) {
	// 1. Server reachable, the machine as its owner chose to run it. The claim
	// under test is TRUTHFULNESS, not greenness: the components that are fully
	// configured report ok, the two that are deliberately not — the retrieval
	// engine in stdio mode and a vault whose sync is another client's job — say
	// so by name, and the overall exit code reflects that rather than rounding
	// it up to fine.
	rep, res := s.status()
	fullyConfigured := []string{"enrolment", "vault", "harnesses", "skills", "grants", "server"}
	var notOK []string
	for _, name := range fullyConfigured {
		if state, detail := s.component(rep, name); state != "ok" {
			notOK = append(notOK, name+"="+state+" ("+detail+")")
		}
	}
	s.assert("every fully configured component reports ok", len(notOK) == 0,
		"status %q (exit %d); not ok: %s", rep.Status, res.ExitCode, strings.Join(notOK, "; "))

	gnoState, gnoDetail := s.component(rep, "gno")
	syncState, syncDetail := s.component(rep, "sync")
	s.assert("the deliberately unconfigured components are named rather than rounded up to fine",
		gnoState != "ok" && syncState != "ok" && res.ExitCode != 0,
		"exit %d; gno=%s (%s); sync=%s (%s)", res.ExitCode, gnoState, firstLine(gnoDetail), syncState, syncDetail)

	healthyProbe := s.run("server /healthz over the tailnet", 30*time.Second, "curl", "-sf", "-m", "20",
		s.env.serverURL+"/healthz")
	s.assert("/healthz is 2xx and green while the server is healthy",
		healthyProbe.ExitCode == 0 && strings.Contains(healthyProbe.full, `"status":"ok"`),
		"curl exit %d: %s", healthyProbe.ExitCode, firstLine(healthyProbe.Stdout))
	s.assert("/healthz reports server components only — no machine state",
		!strings.Contains(healthyProbe.full, "vault") && !strings.Contains(healthyProbe.full, `"gno"`) &&
			!strings.Contains(healthyProbe.full, "harness"),
		"%s", firstLine(healthyProbe.Stdout))

	truthModeRevokedGrant(s)
	truthModeServerUnreachable(s)
	truthModeEngineDown(s)
	truthModeVaultMissing(s)
	truthModeGatewayDown(s)
}

// truthModeRevokedGrant — a grant revoked out from under the machine must show
// up in `status` because it was reconciled live, not because anything on this
// machine noticed.
func truthModeRevokedGrant(s *stage) {
	rep, _ := s.status()
	var victim string
	for _, g := range rep.Grants {
		if g.State == "active" && g.Harness == "codex" {
			victim = g.GrantID
		}
	}
	if victim == "" {
		s.assert("a grant was available to revoke for the truth table", false, "no active codex grant")
		return
	}
	rev := s.ssh("server: revoke the codex grant (truth-table mode)", 60*time.Second,
		fmt.Sprintf("%s/bin/homeplane-server admin revoke-grant -state-dir %s %s",
			serverPrefix(s.env), s.env.serverStateDir, victim))
	if !s.assert("the truth-table revocation was performed", rev.ExitCode == 0,
		"exit %d: %s", rev.ExitCode, firstLine(rev.Stdout+rev.Stderr)) {
		return
	}
	rep, res := s.status()
	var sawRevoked bool
	for _, g := range rep.Grants {
		if g.GrantID == victim && g.State == "revoked" {
			sawRevoked = true
		}
	}
	s.assert("status reports a revoked grant truthfully, reconciled live", sawRevoked,
		"grant %s state after revocation (exit %d)", victim, res.ExitCode)

	restore := s.agent("homeplane-agent configure-harnesses (undo the truth-table revocation)",
		5*time.Minute, "configure-harnesses", "-json")
	s.assert("the machine is restored after the revoked-grant mode", restore.ExitCode == 0,
		"exit %d%s", restore.ExitCode, tail(restore.Stderr))
}

// truthModeServerUnreachable — the mode is produced by pointing a COPY of this
// machine's state at an address nothing answers on.
//
// A copy, because the alternative is taking the real server away from a machine
// mid-proof; and a copy of the STATE rather than a flag, because `status` has no
// flag for this and inventing one would test the flag instead of the machine.
func truthModeServerUnreachable(s *stage) {
	dir, err := copyStateDir(s, "unreachable")
	if err != nil {
		s.assert("a state copy could be made for the unreachable-server mode", false, "%v", err)
		return
	}
	if err := rewriteState(dir, func(m map[string]any) { m["server_url"] = "http://127.0.0.1:9" }); err != nil {
		s.assert("the state copy could be pointed at an unreachable server", false, "%v", err)
		return
	}
	res := s.agent("homeplane-agent status against an unreachable server", 2*time.Minute,
		"status", "-json", "-state-dir", dir)
	var rep statusReport
	_ = json.Unmarshal([]byte(res.full), &rep)
	serverState, serverDetail := s.component(rep, "server")
	var live, unknown int
	for _, g := range rep.Grants {
		switch g.State {
		case "active", "revoked":
			live++
		default:
			unknown++
		}
	}
	s.assert("an unreachable server is reported as unreachable, and grant state as unknown",
		res.ExitCode != 0 && serverState != "ok" && live == 0,
		"exit %d; server=%s (%s); %d live-looking grant(s), %d unknown",
		res.ExitCode, serverState, firstLine(serverDetail), live, unknown)
}

// truthModeEngineDown — a machine-local failure, produced for real: the engine
// is deactivated, `status` must degrade and exit non-zero, and /healthz — which
// knows nothing about this machine — must stay green.
func truthModeEngineDown(s *stage) {
	stop := s.agent("homeplane-agent gno deactivate -execute (machine-local failure mode)", 3*time.Minute,
		"gno", "deactivate", "-execute")
	if !s.assert("the retrieval engine was actually deactivated", stop.ExitCode == 0,
		"exit %d%s", stop.ExitCode, tail(stop.Stderr)) {
		return
	}
	rep, res := s.status()
	state, detail := s.component(rep, "gno")
	s.assert("status degrades and exits non-zero when the engine is gone",
		res.ExitCode != 0 && state != "ok", "exit %d, gno %s (%s)", res.ExitCode, state, firstLine(detail))

	health := s.run("server /healthz while THIS machine is degraded", 30*time.Second,
		"curl", "-sf", "-m", "20", s.env.serverURL+"/healthz")
	s.assert("a machine-local failure never reaches the server's /healthz",
		health.ExitCode == 0 && strings.Contains(health.full, `"status":"ok"`),
		"curl exit %d: %s", health.ExitCode, firstLine(health.Stdout))

	restart := s.agent("homeplane-agent gno activate (restore)", 20*time.Minute, "gno", "activate")
	s.assert("the retrieval engine is restored", restart.ExitCode == 0,
		"exit %d%s", restart.ExitCode, tail(restart.Stderr))
}

// truthModeVaultMissing — again on a COPY, because the mode under test is "the
// recorded vault is gone" and the real vault is not something a proof may move.
func truthModeVaultMissing(s *stage) {
	dir, err := copyStateDir(s, "vault-missing")
	if err != nil {
		s.assert("a state copy could be made for the missing-vault mode", false, "%v", err)
		return
	}
	gone := filepath.Join(dir, "vault-that-is-not-there")
	if err := rewriteState(dir, func(m map[string]any) { m["vault_path"] = gone }); err != nil {
		s.assert("the state copy could be pointed at a missing vault", false, "%v", err)
		return
	}
	res := s.agent("homeplane-agent status with the recorded vault missing", 2*time.Minute,
		"status", "-json", "-state-dir", dir)
	var rep statusReport
	_ = json.Unmarshal([]byte(res.full), &rep)
	state, detail := s.component(rep, "vault")
	s.assert("a vault that is no longer there is named, and the machine exits non-zero",
		res.ExitCode != 0 && state != "ok",
		"exit %d; vault=%s (%s)", res.ExitCode, state, firstLine(detail))

	// And the real machine is untouched by any of it.
	real, _ := s.status()
	realState, realDetail := s.component(real, "vault")
	s.assert("the real vault is still what this machine reports",
		realState == "ok" && strings.Contains(realDetail, s.env.vaultPath),
		"vault: %s (%s)", realState, firstLine(realDetail))
}

// truthModeGatewayDown — the server's own degraded mode. `curl -sf` MUST fail
// (the spec says so: a degraded server answers non-2xx AND names the component),
// and it is the one mode that has to be produced on the server itself.
func truthModeGatewayDown(s *stage) {
	stop := s.ssh("server: stop the composed gateway", 3*time.Minute,
		"systemctl --user stop homeplane-gateway.service")
	if !s.assert("the gateway could be stopped for the degraded-server mode", stop.ExitCode == 0,
		"exit %d: %s", stop.ExitCode, firstLine(stop.Stderr)) {
		return
	}
	defer func() {
		start := s.ssh("server: start the composed gateway again", 5*time.Minute,
			"systemctl --user start homeplane-gateway.service")
		s.assert("the gateway is running again", start.ExitCode == 0,
			"exit %d: %s", start.ExitCode, firstLine(start.Stderr))
		// The workload takes a moment to answer; the proof waits for it rather
		// than leaving the next stage to discover a half-started server.
		ready := s.ssh("server: wait for the gateway to answer", 5*time.Minute,
			"for i in $(seq 1 60); do curl -sf http://127.0.0.1:44022/health | grep -q '\"available\":true' && exit 0; sleep 5; done; exit 1")
		s.assert("the gateway is serving again", ready.ExitCode == 0, "exit %d", ready.ExitCode)
	}()

	// `curl -sf` fails on a non-2xx, which is exactly the contract: a degraded
	// server must fail a plain health check rather than answering 200 with a sad
	// payload.
	failing := s.run("server /healthz with the gateway down (curl -sf must FAIL)", 60*time.Second,
		"curl", "-sf", "-m", "20", s.env.serverURL+"/healthz")
	body := s.run("server /healthz with the gateway down (read the payload)", 60*time.Second,
		"curl", "-s", "-m", "20", s.env.serverURL+"/healthz")
	s.assert("a degraded server fails a plain health check AND names the component",
		failing.ExitCode != 0 && strings.Contains(body.full, health.ComponentGatewayRuntime) &&
			strings.Contains(body.full, "degraded"),
		"curl -sf exit %d; payload: %s", failing.ExitCode, firstLine(body.Stdout))
}

// copyStateDir makes a throwaway copy of this machine's agent state, so a
// failure mode can be produced without doing anything to the machine itself.
func copyStateDir(s *stage, name string) (string, error) {
	s.t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dst := filepath.Join(s.t.TempDir(), name)
	cp := s.run("copy the agent state for the "+name+" mode", 2*time.Minute,
		"cp", "-R", filepath.Join(home, ".homeplane"), dst)
	if cp.ExitCode != 0 {
		return "", fmt.Errorf("cp exit %d: %s", cp.ExitCode, cp.Stderr)
	}
	return dst, nil
}

// rewriteState edits the copied state file. It is deliberately a plain JSON
// rewrite: the point is to produce a state a machine could genuinely be in.
func rewriteState(dir string, edit func(map[string]any)) error {
	path := filepath.Join(dir, "state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	edit(m)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
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
