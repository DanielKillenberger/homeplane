package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
	"github.com/DanielKillenberger/homeplane/internal/agent/harness"
	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// These tests drive the CLI against the REAL control plane — the real store,
// the real grant lifecycle, the real per-harness policy — with HOME pointed at
// a temporary directory. The operator's own ~/.claude.json and
// ~/.codex/config.toml are never opened.

const connectorEndpointPath = "/mcp"

func newControlPlaneWithEdge(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})

	// The server must be told the endpoint URL its edge answers on, and that
	// URL is not known until the listener has a port. So the handler is wired
	// through an indirection and filled in once the address exists — the same
	// ordering the real `serve` command has, where the flag names the address
	// the listener will bind.
	var handler http.Handler
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(hs.Close)

	srv, err := server.New(st, fakeResolver{id: store.Identity{NodeID: "node-harness", NodeName: "harness-cli"}},
		checker, server.Config{Policy: policy.Default(), ConnectorEndpointURL: hs.URL + connectorEndpointPath})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	handler = srv.Handler()
	return hs
}

// fakeMachine points HOME, CODEX_HOME and GROK_HOME at temporary directories holding
// pre-existing harness configuration, and returns the paths.
type fakeMachine struct {
	home       string
	claudePath string
	codexPath  string
	grokPath   string
	stateDir   string
}

func newFakeMachine(t *testing.T) fakeMachine {
	t.Helper()
	root := t.TempDir()
	m := fakeMachine{
		home:     filepath.Join(root, "home"),
		stateDir: filepath.Join(root, "state"),
	}
	m.claudePath = filepath.Join(m.home, ".claude.json")
	m.codexPath = filepath.Join(m.home, ".codex", "config.toml")
	m.grokPath = filepath.Join(m.home, ".grok", "config.toml")
	for _, dir := range []string{filepath.Dir(m.codexPath), filepath.Dir(m.grokPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(m.claudePath, []byte(`{"numStartups":7,"mcpServers":{"rize":{"type":"http","url":"https://mcp.rize.io/mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.codexPath, []byte("model = \"gpt-5.6-sol\"\n\n# keep me\n[mcp_servers.blender]\ncommand = \"/x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.grokPath, []byte("[ui]\nmax_thoughts_width = 120\n\n# keep me\n[mcp_servers.preexisting-thing]\ncommand = \"/usr/bin/true\"\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", m.home)
	t.Setenv("CODEX_HOME", filepath.Dir(m.codexPath))
	t.Setenv("GROK_HOME", filepath.Dir(m.grokPath))
	// Pinned rather than inherited: an ambient CLAUDE_CONFIG_DIR would
	// otherwise aim these tests at the developer's own configuration.
	t.Setenv("CLAUDE_CONFIG_DIR", m.home)
	return m
}

func publishStubDescriptor(t *testing.T, stateDir string) {
	t.Helper()
	if err := gno.SaveDescriptor(stateDir, gno.Descriptor{
		Component: gno.ComponentRetrievalEngine, Engine: "gno", EngineVersion: "stub",
		Transport: gno.TransportStdio, Command: "/usr/local/bin/homeplane-agent",
		Args: gno.StdioWrapperArgs(stateDir), ServerName: "gno",
		Collection: "vault", VaultPath: filepath.Join(stateDir, "vault"),
		DerivedFrom: "test", WrittenAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigureHarnessesEndToEndAgainstTheRealControlPlane(t *testing.T) {
	cp := newControlPlaneWithEdge(t)
	m := newFakeMachine(t)

	if res := invoke(t, "enrol", "-server", cp.URL, "-name", "harness-machine", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("enrol exit = %d: %s", res.code, res.stderr)
	}
	publishStubDescriptor(t, m.stateDir)

	res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir, "-json")
	if res.code != 0 {
		t.Fatalf("configure-harnesses exit = %d\nstdout: %s\nstderr: %s", res.code, res.stdout, res.stderr)
	}

	var report harness.Report
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("report is not JSON: %v\n%s", err, res.stdout)
	}
	if len(report.Outcomes) != len(harness.Known()) {
		t.Fatalf("outcomes = %+v", report.Outcomes)
	}
	for _, o := range report.Outcomes {
		if o.Status != harness.StatusConfigured {
			t.Fatalf("%s: %s — %s", o.Harness, o.Status, o.Message)
		}
		if o.EndpointURL != cp.URL+connectorEndpointPath {
			t.Errorf("%s endpoint = %q, want the server's", o.Harness, o.EndpointURL)
		}
		want := []string{"connector.delete", "connector.read", "connector.write"}
		if strings.Join(o.Capabilities, ",") != strings.Join(want, ",") {
			t.Errorf("%s capabilities = %v; the SERVER decides these, and its default is %v", o.Harness, o.Capabilities, want)
		}
	}

	// Distinct grants, distinct tokens, and neither token anywhere it prints.
	claude, codex := report.Outcomes[0], report.Outcomes[1]
	if claude.GrantID == codex.GrantID {
		t.Fatal("both harnesses share a grant; revoking one would revoke both")
	}
	claudeToken := bearerIn(t, string(mustReadFile(t, m.claudePath)))
	codexToken := bearerIn(t, string(mustReadFile(t, m.codexPath)))
	if claudeToken == codexToken {
		t.Fatal("both harnesses hold the same grant token")
	}
	for _, token := range []string{claudeToken, codexToken} {
		if strings.Contains(res.stdout+res.stderr, token) {
			t.Error("the command printed a grant token")
		}
	}

	// Pre-existing configuration in both files survived.
	if !strings.Contains(string(mustReadFile(t, m.claudePath)), "mcp.rize.io") {
		t.Error("the Claude write lost the pre-existing rize server")
	}
	codexText := string(mustReadFile(t, m.codexPath))
	for _, keep := range []string{"# keep me", "[mcp_servers.blender]", `model = "gpt-5.6-sol"`} {
		if !strings.Contains(codexText, keep) {
			t.Errorf("the Codex write lost %q", keep)
		}
	}

	// The server agrees: two active grants, one per harness.
	grants := invoke(t, "status", "-state-dir", m.stateDir, "-json")
	var status struct {
		Grants []struct {
			Harness string `json:"harness"`
			State   string `json:"state"`
		} `json:"grants"`
		Components []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(grants.stdout), &status); err != nil {
		t.Fatalf("status is not JSON: %v\n%s", err, grants.stdout)
	}
	active := map[string]bool{}
	for _, g := range status.Grants {
		if g.State == "active" {
			active[g.Harness] = true
		}
	}
	if !active[harness.ClaudeCode] || !active[harness.Codex] {
		t.Errorf("the server reports active grants for %v, want both harnesses", active)
	}
	for _, c := range status.Components {
		if c.Name == "harnesses" && !strings.Contains(c.Detail, "codex") {
			t.Errorf("status does not report the configured harnesses: %+v", c)
		}
	}
}

func TestConfigureHarnessesTwiceSupersedesRatherThanAccumulates(t *testing.T) {
	cp := newControlPlaneWithEdge(t)
	m := newFakeMachine(t)
	if res := invoke(t, "enrol", "-server", cp.URL, "-name", "harness-machine", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("enrol: %s", res.stderr)
	}
	publishStubDescriptor(t, m.stateDir)

	if res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("first run: %s", res.stderr)
	}
	firstToken := bearerIn(t, string(mustReadFile(t, m.codexPath)))

	if res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("second run: %s", res.stderr)
	}
	secondToken := bearerIn(t, string(mustReadFile(t, m.codexPath)))
	if secondToken == firstToken {
		t.Error("the re-run did not rotate the grant token")
	}
	if strings.Contains(string(mustReadFile(t, m.codexPath)), firstToken) {
		t.Error("the superseded token is still in the config")
	}

	// Exactly one ACTIVE grant per harness — the superseded ones are revoked,
	// not merely ignored.
	res := invoke(t, "status", "-state-dir", m.stateDir, "-json")
	var status struct {
		Grants []struct {
			Harness string `json:"harness"`
			State   string `json:"state"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &status); err != nil {
		t.Fatal(err)
	}
	activePer := map[string]int{}
	for _, g := range status.Grants {
		if g.State == "active" {
			activePer[g.Harness]++
		}
	}
	for _, h := range []string{harness.ClaudeCode, harness.Codex} {
		if activePer[h] != 1 {
			t.Errorf("%s has %d active grants after two runs, want 1", h, activePer[h])
		}
	}
}

func TestConfigureHarnessesRefusesAnUnenrolledMachine(t *testing.T) {
	m := newFakeMachine(t)
	res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir)
	if res.code != 2 {
		t.Errorf("exit = %d, want 2 (not enrolled)", res.code)
	}
	if !strings.Contains(res.stderr, "not enrolled") {
		t.Errorf("stderr = %q", res.stderr)
	}
	// Nothing was touched.
	if strings.Contains(string(mustReadFile(t, m.codexPath)), "mcp_servers.homeplane") {
		t.Error("a config was written for an unenrolled machine")
	}
}

func TestConfigureHarnessesDetectReportsWithoutWriting(t *testing.T) {
	m := newFakeMachine(t)
	before := mustReadFile(t, m.codexPath)

	res := invoke(t, "configure-harnesses", "-detect", "-json")
	if res.code != 0 {
		t.Fatalf("exit = %d: %s", res.code, res.stderr)
	}
	var out struct {
		Harnesses []harness.Detection `json:"harnesses"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, res.stdout)
	}
	if len(out.Harnesses) != len(harness.Known()) {
		t.Fatalf("detections = %+v", out.Harnesses)
	}
	for _, d := range out.Harnesses {
		if !d.Installed || !d.ConfigExists {
			t.Errorf("%s: installed=%v configExists=%v", d.Harness, d.Installed, d.ConfigExists)
		}
		if !strings.HasPrefix(d.ConfigPath, m.home) {
			t.Errorf("%s resolved to %q, outside the fake home", d.Harness, d.ConfigPath)
		}
	}
	if string(mustReadFile(t, m.codexPath)) != string(before) {
		t.Error("-detect wrote to a config")
	}
}

// bearerIn extracts the single bearer token a config carries.
func bearerIn(t *testing.T, text string) string {
	t.Helper()
	const marker = "Bearer "
	i := strings.Index(text, marker)
	if i < 0 {
		t.Fatalf("no bearer token in:\n%s", text)
	}
	rest := text[i+len(marker):]
	end := strings.IndexAny(rest, "\"\\ \n")
	if end < 0 {
		t.Fatalf("unterminated bearer token in:\n%s", text)
	}
	return rest[:end]
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A targeted run must not erase what the machine knows about the harnesses it
// did not touch, and a harness that FAILED must drop out of the list rather
// than keep the machine looking healthy.
func TestHarnessStateMergesRatherThanReplaces(t *testing.T) {
	cases := []struct {
		name     string
		previous []string
		report   harness.Report
		want     []string
	}{
		{
			name:     "a targeted run leaves the untouched harness alone",
			previous: []string{harness.ClaudeCode, harness.Codex},
			report:   harness.Report{Outcomes: []harness.Outcome{{Harness: harness.Codex, Status: harness.StatusConfigured}}},
			want:     []string{harness.ClaudeCode, harness.Codex},
		},
		{
			name:     "a harness that failed drops out",
			previous: []string{harness.ClaudeCode, harness.Codex},
			report:   harness.Report{Outcomes: []harness.Outcome{{Harness: harness.Codex, Status: harness.StatusFailed}}},
			want:     []string{harness.ClaudeCode},
		},
		{
			name:     "a harness that was skipped drops out too",
			previous: []string{harness.Codex},
			report:   harness.Report{Outcomes: []harness.Outcome{{Harness: harness.Codex, Status: harness.StatusSkipped}}},
			want:     []string{},
		},
		{
			name:     "a partial run records only what actually worked",
			previous: nil,
			report: harness.Report{Outcomes: []harness.Outcome{
				{Harness: harness.ClaudeCode, Status: harness.StatusConfigured},
				{Harness: harness.Codex, Status: harness.StatusFailed},
			}},
			want: []string{harness.ClaudeCode},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeHarnessState(c.previous, c.report)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("merged = %v, want %v", got, c.want)
			}
		})
	}
}

// The same thing through the command, against the real control plane: a
// `-harness codex` run must not make `status` forget Claude Code.
func TestATargetedRunDoesNotEraseTheOtherHarnessFromStatus(t *testing.T) {
	cp := newControlPlaneWithEdge(t)
	m := newFakeMachine(t)
	if res := invoke(t, "enrol", "-server", cp.URL, "-name", "harness-machine", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("enrol: %s", res.stderr)
	}
	publishStubDescriptor(t, m.stateDir)

	if res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("full run: %s", res.stderr)
	}
	if res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir, "-harness", "codex"); res.code != 0 {
		t.Fatalf("targeted run: %s", res.stderr)
	}

	raw := mustReadFile(t, filepath.Join(m.stateDir, "state.json"))
	var state struct {
		Harnesses []string `json:"harnesses"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Harnesses) != len(harness.Known()) {
		t.Fatalf("harnesses = %v after a targeted run; the untouched harness was erased", state.Harnesses)
	}
}

// A run where one harness works and the other fails must report DEGRADED. The
// configured list alone cannot carry that: it looks identical to a run that
// only attempted the harness that worked.
func TestAPartiallyConfiguredMachineReportsDegraded(t *testing.T) {
	cp := newControlPlaneWithEdge(t)
	m := newFakeMachine(t)
	if res := invoke(t, "enrol", "-server", cp.URL, "-name", "harness-machine", "-state-dir", m.stateDir); res.code != 0 {
		t.Fatalf("enrol: %s", res.stderr)
	}
	publishStubDescriptor(t, m.stateDir)

	// Codex is installed and its config cannot be written: the directory is
	// read-only, so the atomic write has nowhere to put its temporary file.
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory would still be writable")
	}
	if err := os.Chmod(filepath.Dir(m.codexPath), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(m.codexPath), 0o700) })

	res := invoke(t, "configure-harnesses", "-state-dir", m.stateDir, "-json")
	if res.code == 0 {
		t.Fatalf("a half-failed run exited 0:\n%s", res.stdout)
	}

	status := invoke(t, "status", "-state-dir", m.stateDir, "-json")
	var report struct {
		Components []struct {
			Name   string `json:"name"`
			State  string `json:"state"`
			Detail string `json:"detail"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(status.stdout), &report); err != nil {
		t.Fatalf("status is not JSON: %v\n%s", err, status.stdout)
	}
	var found bool
	for _, c := range report.Components {
		if c.Name != "harnesses" {
			continue
		}
		found = true
		if c.State != "degraded" {
			t.Errorf("harness component = %q (%s); one harness is installed and NOT configured",
				c.State, c.Detail)
		}
		if !strings.Contains(c.Detail, "codex") {
			t.Errorf("the detail does not name the broken harness: %q", c.Detail)
		}
		// The one that DID work must still be visible; degradation is not amnesia.
		if !strings.Contains(c.Detail, "claude-code") {
			t.Errorf("the detail lost the harness that succeeded: %q", c.Detail)
		}
	}
	if !found {
		t.Fatal("status reports no harness component at all")
	}
}

// R1's acceptance surface is the EXISTING read-only mode, `configure-harnesses
// -detect` — not a new subcommand. Both of its output forms must carry the
// version and the support verdict, because "grok is installed" and "this build
// knows how to write grok's configuration" are different facts and an operator
// acts on them differently.
func TestDetectReportsVersionSupportAndInheritedSources(t *testing.T) {
	home := t.TempDir()
	grokHome := filepath.Join(home, ".grok")
	if err := os.MkdirAll(grokHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(grokHome, "config.toml"), []byte("[ui]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every source is pinned, including the version probe: this test asserts
	// what the surface RENDERS, and must not depend on which grok the developer
	// happens to have installed.
	locator := harness.Locator{
		Home:            home,
		ClaudeConfigDir: home,
		CodexHome:       filepath.Join(home, ".codex"),
		GrokHome:        grokHome,
		LookPath:        func(string) (string, error) { return "/fake/bin/grok", nil },
		Version:         func(string) (string, error) { return "grok 2.0.0 (future)", nil },
	}

	var jsonOut, stderr bytes.Buffer
	if code := reportDetection(locator, true, &jsonOut, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var machine struct {
		Harnesses []harness.Detection `json:"harnesses"`
	}
	if err := json.Unmarshal(jsonOut.Bytes(), &machine); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, jsonOut.String())
	}
	var grok harness.Detection
	for _, d := range machine.Harnesses {
		if d.Harness == harness.Grok {
			grok = d
		}
		if d.Support == "" {
			t.Errorf("%s carries no support verdict", d.Harness)
		}
	}
	if grok.Version != "2.0.0" || grok.Support != harness.SupportUnsupported {
		t.Fatalf("grok detection = %+v, want the observed version and an unsupported verdict", grok)
	}
	if len(grok.CompatSources) == 0 {
		t.Error("the machine-readable form hides which sources grok still inherits MCP servers from")
	}

	var humanOut bytes.Buffer
	if code := reportDetection(locator, false, &humanOut, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	human := humanOut.String()
	for _, want := range []string{"grok", "UNSUPPORTED", "2.0.0", "support:", "inherits MCP servers from:"} {
		if !strings.Contains(human, want) {
			t.Errorf("the human output does not mention %q:\n%s", want, human)
		}
	}
}
