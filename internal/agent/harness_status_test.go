package agent

import (
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent/harness"
)

// The five states must be DISTINGUISHABLE, because each one calls for a
// different action and three of them are invisible to the persisted list of
// configured harnesses:
//
//   - not_detected            → nothing to do; a machine without grok is healthy
//   - detected_unconfigured   → run configure-harnesses
//   - detected_unsupported    → re-capture the CLI contract; retrying will not help
//   - configured              → nothing to do
//   - revoked                 → run configure-harnesses to mint a new grant
//
// The one that most needs its own state is `revoked`: revocation happens
// server-side and touches nothing on this machine, so a status surface reading
// only local state reports the exact thing revocation was supposed to falsify.
func TestTheFiveHarnessStatesRenderDistinctly(t *testing.T) {
	detections := []harness.Detection{
		{Harness: harness.ClaudeCode, Installed: false, ConfigPath: "/h/.claude.json",
			Reason: "no claude executable on PATH and no configuration at /h/.claude.json", Support: harness.SupportUnknown},
		{Harness: harness.Codex, Installed: true, ConfigExists: true, ConfigPath: "/h/.codex/config.toml", Support: harness.SupportUnknown},
		{Harness: harness.Grok, Installed: true, ConfigExists: true, ConfigPath: "/h/.grok/config.toml", Version: "2.0.0",
			Support: harness.SupportUnsupported, SupportReason: "grok 2.0.0 is a different major version than the captured contract"},
	}
	records := []harness.Record{
		{Harness: harness.Codex, ConfigPath: "/h/.codex/config.toml", GrantID: "g-codex"},
	}
	grants := []GrantReport{{GrantID: "g-codex", Harness: harness.Codex, State: grantStateActive}}

	rows := reconcileHarnesses(detections, records, grants, true, nil)
	got := map[string]HarnessStatus{}
	for _, r := range rows {
		got[r.Harness] = r
	}
	if len(rows) != len(harness.Known()) {
		t.Fatalf("%d rows for %d known harnesses", len(rows), len(harness.Known()))
	}
	if s := got[harness.ClaudeCode]; s.State != HarnessNotDetected || s.Detail == "" {
		t.Errorf("claude-code = %+v, want not_detected with a reason", s)
	}
	if s := got[harness.Codex]; s.State != HarnessConfigured || s.GrantID != "g-codex" {
		t.Errorf("codex = %+v, want configured", s)
	}
	if s := got[harness.Grok]; s.State != HarnessDetectedUnsupported || !strings.Contains(s.Detail, "major version") {
		t.Errorf("grok = %+v, want detected_unsupported carrying the version reason", s)
	}

	// The same machine, one harness detected and never wired: a state the
	// persisted list cannot express at all, because "not in the list" is where
	// "not installed" also lives.
	detections[2] = harness.Detection{Harness: harness.Grok, Installed: true, ConfigExists: true,
		ConfigPath: "/h/.grok/config.toml", Version: "1.0.3", Support: harness.SupportSupported}
	rows = reconcileHarnesses(detections, records, grants, true, nil)
	if s := rows[2]; s.State != HarnessDetectedUnconfigured || !strings.Contains(s.Detail, "configure-harnesses") {
		t.Errorf("grok = %+v, want detected_unconfigured with the command to run", s)
	}

	// And the same machine after the server revoked codex's grant. Nothing on
	// disk changed; the row must.
	revoked := []GrantReport{{GrantID: "g-codex", Harness: harness.Codex, State: "revoked", RevokedAt: "2026-08-15T00:00:00Z"}}
	rows = reconcileHarnesses(detections, records, revoked, true, nil)
	if s := rows[1]; s.State != HarnessRevoked || !strings.Contains(s.Detail, "g-codex") {
		t.Errorf("codex = %+v, want revoked naming the dead grant", s)
	}

	// A grant the server does not list at all is equally dead: forgetting is a
	// perfectly good way to revoke.
	rows = reconcileHarnesses(detections, records, nil, true, nil)
	if s := rows[1]; s.State != HarnessRevoked {
		t.Errorf("codex = %+v, want revoked when the server lists no such grant", s)
	}
}

// A server that could not be reached is not a revocation. The machine IS
// locally configured — that is a fact about this disk — so the row says so and
// admits the grant was not checked, rather than inventing a revocation from a
// network failure.
func TestAnUnreachableServerDoesNotFabricateARevocation(t *testing.T) {
	detections := []harness.Detection{{Harness: harness.Codex, Installed: true, ConfigExists: true,
		ConfigPath: "/h/.codex/config.toml", Support: harness.SupportUnknown}}
	records := []harness.Record{{Harness: harness.Codex, ConfigPath: "/h/.codex/config.toml", GrantID: "g-codex"}}

	rows := reconcileHarnesses(detections, records, nil, false, nil)
	var codex HarnessStatus
	for _, r := range rows {
		if r.Harness == harness.Codex {
			codex = r
		}
	}
	if codex.State != HarnessConfigured {
		t.Fatalf("codex = %+v, want configured", codex)
	}
	if !strings.Contains(codex.Detail, "server was not reached") {
		t.Errorf("detail = %q, which does not admit the grant was unchecked", codex.Detail)
	}
}

// Inherited MCP sources travel with the row, so "configured" never quietly
// means "also reachable through someone else's grant". Homeplane closes the two
// user-config compat cells; the project-scope one cannot be closed from user
// config, so it stays visible instead of being assumed away.
func TestCompatSourcesTravelWithTheHarnessRow(t *testing.T) {
	detections := []harness.Detection{{Harness: harness.Grok, Installed: true, ConfigExists: true,
		ConfigPath: "/h/.grok/config.toml", Version: "1.0.3", Support: harness.SupportSupported,
		CompatSources: []string{harness.CompatSourceProject}}}
	records := []harness.Record{{Harness: harness.Grok, ConfigPath: "/h/.grok/config.toml", GrantID: "g-grok"}}
	grants := []GrantReport{{GrantID: "g-grok", Harness: harness.Grok, State: grantStateActive}}

	rows := reconcileHarnesses(detections, records, grants, true, nil)
	var grok HarnessStatus
	for _, r := range rows {
		if r.Harness == harness.Grok {
			grok = r
		}
	}
	if grok.State != HarnessConfigured {
		t.Fatalf("grok = %+v", grok)
	}
	if len(grok.CompatSources) == 0 {
		t.Fatal("the row dropped the compat sources")
	}
	if !strings.Contains(grok.Detail, harness.CompatSourceProject) {
		t.Errorf("detail = %q, which hides the source grok still inherits from", grok.Detail)
	}
}

// The rows an operator has to act on are named, so a caller does not have to
// re-derive the classification to decide whether the machine is healthy.
func TestDegradedHarnessesNamesTheActionableRows(t *testing.T) {
	rows := []HarnessStatus{
		{Harness: "a", State: HarnessConfigured},
		{Harness: "b", State: HarnessNotDetected},
		{Harness: "c", State: HarnessRevoked},
		{Harness: "d", State: HarnessDetectedUnconfigured},
		{Harness: "e", State: HarnessDetectedUnsupported},
	}
	got := DegradedHarnesses(rows)
	want := []string{"c", "d", "e"}
	if len(got) != len(want) {
		t.Fatalf("degraded = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("degraded = %v, want %v", got, want)
		}
	}
}

// A record is a memory; the config FILE is what the harness reads. Deleting it
// — or relocating GROK_HOME so the harness now loads a different file — means
// grok reads no Homeplane configuration at all, whatever the record and the
// server still agree about.
func TestARecordWithoutItsConfigFileIsNotConfigured(t *testing.T) {
	records := []harness.Record{{Harness: harness.Grok, ConfigPath: "/h/.grok/config.toml", GrantID: "g-grok"}}
	grants := []GrantReport{{GrantID: "g-grok", Harness: harness.Grok, State: grantStateActive}}

	deleted := []harness.Detection{{Harness: harness.Grok, Installed: true, ConfigExists: false,
		ConfigPath: "/h/.grok/config.toml", Support: harness.SupportSupported}}
	if got := rowFor(t, reconcileHarnesses(deleted, records, grants, true, nil), harness.Grok); got.State != HarnessDetectedUnconfigured ||
		!strings.Contains(got.Detail, "no longer exists") {
		t.Errorf("deleted config = %+v, want detected_unconfigured", got)
	}

	relocated := []harness.Detection{{Harness: harness.Grok, Installed: true, ConfigExists: true,
		ConfigPath: "/elsewhere/config.toml", Support: harness.SupportSupported}}
	got := rowFor(t, reconcileHarnesses(relocated, records, grants, true, nil), harness.Grok)
	if got.State != HarnessDetectedUnconfigured {
		t.Errorf("relocated config = %+v, want detected_unconfigured", got)
	}
	if !strings.Contains(got.Detail, "/elsewhere/config.toml") || !strings.Contains(got.Detail, "/h/.grok/config.toml") {
		t.Errorf("detail = %q, which does not say which file it now reads", got.Detail)
	}
}

// Records we could not READ are not records that say "unconfigured". The row
// has to carry the machine-side fault, or an operator chases a configuration
// problem that is really a permissions problem.
func TestUnreadableRecordsAreSurfacedRatherThanReadAsUnconfigured(t *testing.T) {
	detections := []harness.Detection{{Harness: harness.Codex, Installed: true, ConfigExists: true,
		ConfigPath: "/h/.codex/config.toml", Support: harness.SupportUnknown}}

	got := rowFor(t, reconcileHarnesses(detections, nil, nil, true, errStubRecords), harness.Codex)
	if got.State != HarnessDetectedUnconfigured {
		t.Fatalf("codex = %+v", got)
	}
	if !strings.Contains(got.Detail, "could not be read") {
		t.Errorf("detail = %q, which hides the record-read failure", got.Detail)
	}
}

var errStubRecords = stubError("permission denied reading ~/.homeplane/harnesses")

type stubError string

func (e stubError) Error() string { return string(e) }

func rowFor(t *testing.T, rows []HarnessStatus, name string) HarnessStatus {
	t.Helper()
	for _, r := range rows {
		if r.Harness == name {
			return r
		}
	}
	t.Fatalf("no row for %s", name)
	return HarnessStatus{}
}

// An actionable row must move the whole machine off `ok`. Reporting `homeplane:
// ok` with exit 0 while a harness row reads `revoked` would be the report
// contradicting itself — and the exit code is what a script reads.
func TestActionableHarnessRowsDegradeTheComponentAndTheReport(t *testing.T) {
	state := State{Harnesses: []string{harness.Codex}, Harness: &ComponentState{State: StateOK}}
	for _, actionable := range []string{HarnessRevoked, HarnessDetectedUnconfigured, HarnessDetectedUnsupported} {
		rows := []HarnessStatus{
			{Harness: harness.ClaudeCode, State: HarnessNotDetected},
			{Harness: harness.Codex, State: HarnessConfigured},
			{Harness: harness.Grok, State: actionable, Detail: "…"},
		}
		c := harnessComponent(state, rows)
		if c.State != StateDegraded {
			t.Errorf("%s: component = %+v, want degraded", actionable, c)
		}
		if !strings.Contains(c.Detail, "grok is "+actionable) {
			t.Errorf("%s: detail = %q, which does not name the actionable harness", actionable, c.Detail)
		}
		// And the report-level rollup follows the component, which is what the
		// exit code is derived from.
		r := Report{Status: OverallOK, Components: []ComponentReport{c}}
		if len(r.Degraded()) == 0 {
			t.Errorf("%s: the degraded component did not reach the report", actionable)
		}
	}

	// The mirror image: nothing actionable leaves the component alone.
	healthy := []HarnessStatus{
		{Harness: harness.ClaudeCode, State: HarnessNotDetected},
		{Harness: harness.Codex, State: HarnessConfigured},
		{Harness: harness.Grok, State: HarnessConfigured},
	}
	if c := harnessComponent(state, healthy); c.State != StateOK {
		t.Errorf("a healthy machine was degraded: %+v", c)
	}
}
