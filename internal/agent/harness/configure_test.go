package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
)

// fakeIssuer stands in for the control plane. It reproduces the one property
// this package depends on: each issuance mints a NEW token and supersedes the
// previous grant for the same harness.
type fakeIssuer struct {
	mu       sync.Mutex
	endpoint string
	seq      int
	previous map[string]string
	issued   []string
	fail     error
	// observe runs inside IssueGrant, so a test can check what is true at the
	// exact moment authority moves.
	observe func()
}

func newFakeIssuer(endpoint string) *fakeIssuer {
	return &fakeIssuer{endpoint: endpoint, previous: map[string]string{}}
}

func (f *fakeIssuer) IssueGrant(_ context.Context, harnessName string) (Grant, error) {
	if f.observe != nil {
		f.observe()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return Grant{}, f.fail
	}
	f.seq++
	g := Grant{
		GrantID:           fmt.Sprintf("grant-%s-%d", harnessName, f.seq),
		Harness:           harnessName,
		Capabilities:      []string{"connector.read", "connector.write", "connector.delete"},
		EndpointURL:       f.endpoint,
		Token:             fmt.Sprintf("token-%s-%d", harnessName, f.seq),
		SupersededGrantID: f.previous[harnessName],
	}
	f.previous[harnessName] = g.GrantID
	f.issued = append(f.issued, g.GrantID)
	return g, nil
}

func (f *fakeIssuer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issued)
}

// machine builds a fake machine: a state directory with a published endpoint
// descriptor, and fixture copies of both harness configs.
type machine struct {
	stateDir   string
	home       string
	codexHome  string
	claudePath string
	codexPath  string
	locator    Locator
}

func newMachine(t *testing.T, withDescriptor bool) *machine {
	t.Helper()
	root := t.TempDir()
	m := &machine{
		stateDir:  filepath.Join(root, "state"),
		home:      filepath.Join(root, "home"),
		codexHome: filepath.Join(root, "home", ".codex"),
	}
	m.claudePath = filepath.Join(m.home, ".claude.json")
	m.codexPath = filepath.Join(m.codexHome, "config.toml")

	for _, dir := range []string{m.stateDir, m.home, m.codexHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(m.claudePath, []byte(claudeFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.codexPath, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	if withDescriptor {
		if err := gno.SaveDescriptor(m.stateDir, gno.Descriptor{
			Component:     gno.ComponentRetrievalEngine,
			Engine:        "gno",
			EngineVersion: "1.2.3",
			Transport:     gno.TransportStdio,
			Command:       "/usr/local/bin/homeplane-agent",
			Args:          gno.StdioWrapperArgs(m.stateDir),
			ServerName:    "gno",
			Collection:    "vault",
			VaultPath:     filepath.Join(root, "vault"),
			DerivedFrom:   "gno mcp install --dry-run --json",
			WrittenAt:     time.Now().UTC(),
		}); err != nil {
			t.Fatalf("publish endpoint descriptor: %v", err)
		}
	}

	// Both harnesses are "installed" because their config files exist; the
	// stub keeps the test off the real PATH either way.
	// Every path source is pinned explicitly, including the env-var overrides:
	// an ambient CODEX_HOME or CLAUDE_CONFIG_DIR on the developer's machine
	// must not be able to point a test at a real config.
	m.locator = Locator{
		Home:            m.home,
		CodexHome:       m.codexHome,
		ClaudeConfigDir: m.home,
		LookPath:        func(string) (string, error) { return "", errors.New("not on PATH") },
	}
	return m
}

func (m *machine) configurator(issuer GrantIssuer) Configurator {
	return Configurator{StateDir: m.stateDir, Locator: m.locator, Issuer: issuer}
}

func (m *machine) claudeTree(t *testing.T) map[string]any {
	t.Helper()
	tree, err := parseJSONTree(mustRead(t, m.claudePath))
	if err != nil {
		t.Fatalf("parse claude config: %v", err)
	}
	return tree
}

func (m *machine) codexTree(t *testing.T) map[string]any {
	t.Helper()
	tree, err := parseTOMLTree(mustRead(t, m.codexPath))
	if err != nil {
		t.Fatalf("parse codex config: %v", err)
	}
	return tree
}

func outcomeFor(t *testing.T, r Report, harnessName string) Outcome {
	t.Helper()
	for _, o := range r.Outcomes {
		if o.Harness == harnessName {
			return o
		}
	}
	t.Fatalf("no outcome for %s", harnessName)
	return Outcome{}
}

func TestBothHarnessesAreConfiguredWithDistinctGrantTokens(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")

	report, err := m.configurator(issuer).Configure(context.Background())
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := report.Err(); err != nil {
		t.Fatalf("report: %v", err)
	}
	if got := report.Configured(); len(got) != 2 {
		t.Fatalf("configured = %v, want both harnesses", got)
	}

	claudeAuth := authHeader(t, m.claudeTree(t), claudeContainer, "headers")
	codexAuth := authHeader(t, m.codexTree(t), codexContainer, "http_headers")

	if claudeAuth == codexAuth {
		t.Fatal("both harnesses were given the SAME grant token; each must be revocable on its own")
	}
	for name, auth := range map[string]string{ClaudeCode: claudeAuth, Codex: codexAuth} {
		if !strings.HasPrefix(auth, "Bearer token-"+name+"-") {
			t.Errorf("%s carries %q, which is not its own token", name, auth)
		}
	}
	// And neither file holds the other's token.
	if strings.Contains(string(mustRead(t, m.claudePath)), strings.TrimPrefix(codexAuth, "Bearer ")) {
		t.Error("the Claude config holds Codex's token")
	}
	if strings.Contains(string(mustRead(t, m.codexPath)), strings.TrimPrefix(claudeAuth, "Bearer ")) {
		t.Error("the Codex config holds Claude's token")
	}

	// Both engines point at the descriptor's command, not at anything invented.
	for _, tree := range []map[string]any{m.claudeTree(t), m.codexTree(t)} {
		entry := entryIn(t, tree, containerOf(tree), "gno")
		if entry["command"] != "/usr/local/bin/homeplane-agent" {
			t.Errorf("engine command = %v, want the descriptor's", entry["command"])
		}
	}

	// The grant token appears in the outcome nowhere.
	for _, o := range report.Outcomes {
		if strings.Contains(fmt.Sprintf("%+v", o), "token-") {
			t.Errorf("an outcome carries a grant token: %+v", o)
		}
	}
}

func containerOf(tree map[string]any) string {
	if _, ok := tree[claudeContainer]; ok {
		return claudeContainer
	}
	return codexContainer
}

func entryIn(t *testing.T, tree map[string]any, container, name string) map[string]any {
	t.Helper()
	c, ok := tree[container].(map[string]any)
	if !ok {
		t.Fatalf("no %s container in %v", container, sortedKeys(tree))
	}
	e, ok := c[name].(map[string]any)
	if !ok {
		t.Fatalf("no %s entry in %s", name, container)
	}
	return e
}

func authHeader(t *testing.T, tree map[string]any, container, headerKey string) string {
	t.Helper()
	entry := entryIn(t, tree, container, ConnectorServerName)
	h, ok := entry[headerKey].(map[string]any)
	if !ok {
		t.Fatalf("connector entry has no %s", headerKey)
	}
	v, _ := h["Authorization"].(string)
	return v
}

func TestReRunningSupersedesTheGrantAndLeavesOneTokenPerHarness(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")
	cfg := m.configurator(issuer)

	first, err := cfg.Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstAuth := authHeader(t, m.codexTree(t), codexContainer, "http_headers")

	second, err := cfg.Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Err(); err != nil {
		t.Fatalf("second run: %v", err)
	}

	firstCodex := outcomeFor(t, first, Codex)
	secondCodex := outcomeFor(t, second, Codex)
	if secondCodex.SupersededGrantID != firstCodex.GrantID {
		t.Errorf("second run superseded %q, want the first run's %q", secondCodex.SupersededGrantID, firstCodex.GrantID)
	}
	secondAuth := authHeader(t, m.codexTree(t), codexContainer, "http_headers")
	if secondAuth == firstAuth {
		t.Error("the re-run left the superseded token in place")
	}
	if strings.Contains(string(mustRead(t, m.codexPath)), strings.TrimPrefix(firstAuth, "Bearer ")) {
		t.Error("the superseded token is still somewhere in the config")
	}
	// Unrelated configuration survived two runs.
	for _, keep := range preservedMarkers(Codex) {
		if !strings.Contains(string(mustRead(t, m.codexPath)), keep) {
			t.Errorf("two runs lost %q", keep)
		}
	}
}

// R5's config-write failure path: a run that cannot write must not leave a
// half-configured machine that a re-run cannot repair.
func TestARunThatCannotWriteConvergesOnTheNextRun(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")

	// The induced fault: Codex's config directory is not writable, so the
	// atomic write's temporary file cannot be created.
	if err := os.Chmod(m.codexHome, 0o500); err != nil {
		t.Fatal(err)
	}
	broken, err := m.configurator(issuer).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	brokenCodex := outcomeFor(t, broken, Codex)
	if brokenCodex.Status != StatusFailed {
		t.Fatalf("codex status = %s, want %s (the write could not have succeeded)", brokenCodex.Status, StatusFailed)
	}
	if broken.Err() == nil {
		t.Error("the report claims success while a harness failed")
	}
	// The other harness is unaffected: one broken harness never blocks another.
	if outcomeFor(t, broken, ClaudeCode).Status != StatusConfigured {
		t.Error("a Codex write failure blocked Claude Code")
	}
	// The original Codex config was not damaged.
	if got := string(mustRead(t, m.codexPath)); got != codexFixture {
		t.Errorf("the failed write damaged the config:\n%s", got)
	}
	// No record was written for the harness that failed, so nothing later can
	// mistake it for configured.
	if _, err := os.Stat(RecordPath(m.stateDir, Codex)); err == nil {
		t.Error("a record was saved for a harness that was never configured")
	}

	// Repair the machine and re-run. The run must converge without any manual
	// cleanup — including minting a grant that supersedes the unusable one.
	if err := os.Chmod(m.codexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	fixed, err := m.configurator(issuer).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := fixed.Err(); err != nil {
		t.Fatalf("the repair run failed: %v", err)
	}
	fixedCodex := outcomeFor(t, fixed, Codex)
	if fixedCodex.Status != StatusConfigured {
		t.Fatalf("codex status = %s after repair", fixedCodex.Status)
	}
	if fixedCodex.SupersededGrantID != brokenCodex.GrantID {
		t.Errorf("the repair superseded %q, want the failed run's grant %q",
			fixedCodex.SupersededGrantID, brokenCodex.GrantID)
	}
	auth := authHeader(t, m.codexTree(t), codexContainer, "http_headers")
	if !strings.HasPrefix(auth, "Bearer token-codex-") {
		t.Errorf("the repaired config carries %q", auth)
	}
	for _, keep := range preservedMarkers(Codex) {
		if !strings.Contains(string(mustRead(t, m.codexPath)), keep) {
			t.Errorf("the repair lost %q", keep)
		}
	}
}

func TestAMalformedConfigSkipsThatHarnessAndCostsNoGrant(t *testing.T) {
	m := newMachine(t, true)
	if err := os.WriteFile(m.codexPath, []byte("model = \"x\"\n[mcp_servers.broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuer := newFakeIssuer("https://server.ts.net/mcp")

	report, err := m.configurator(issuer).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A skip is not a failure: R5 names it as the CORRECT response.
	if err := report.Err(); err != nil {
		t.Errorf("a skipped harness was reported as a failure: %v", err)
	}
	skipped := outcomeFor(t, report, Codex)
	if skipped.Status != StatusSkipped {
		t.Fatalf("status = %s, want %s", skipped.Status, StatusSkipped)
	}
	if !strings.Contains(skipped.Message, m.codexPath) || !strings.Contains(skipped.Message, "left untouched") {
		t.Errorf("the message does not tell the operator what happened: %q", skipped.Message)
	}
	if skipped.BackupPath == "" {
		t.Error("no backup of the malformed config")
	}
	if got := string(mustRead(t, skipped.BackupPath)); !strings.Contains(got, "[mcp_servers.broken") {
		t.Error("the backup does not hold the malformed original")
	}
	// Exactly one grant was minted — Claude's. A config we will not write to
	// must not consume authority.
	if issuer.count() != 1 {
		t.Errorf("%d grants minted, want 1: a skipped harness asked the server for a token", issuer.count())
	}
	if outcomeFor(t, report, ClaudeCode).Status != StatusConfigured {
		t.Error("the malformed Codex config blocked Claude Code")
	}
}

func TestAMachineWithoutTheEngineActivatedStillGetsItsConnector(t *testing.T) {
	m := newMachine(t, false) // no endpoint descriptor published
	report, err := m.configurator(newFakeIssuer("https://server.ts.net/mcp")).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Err(); err != nil {
		t.Fatalf("report: %v", err)
	}
	o := outcomeFor(t, report, Codex)
	if o.Status != StatusConfigured {
		t.Fatalf("status = %s: %s", o.Status, o.Message)
	}
	if !strings.Contains(o.Message, "gno activate") {
		t.Errorf("the operator is not told how to finish: %q", o.Message)
	}
	tree := m.codexTree(t)
	if _, ok := tree[codexContainer].(map[string]any)["gno"]; ok {
		t.Error("an engine entry was written for a machine with no published endpoint")
	}
	entryIn(t, tree, codexContainer, ConnectorServerName) // the connector is there
}

func TestAHarnessThatIsNotInstalledIsSkippedNotFailed(t *testing.T) {
	m := newMachine(t, true)
	if err := os.Remove(m.codexPath); err != nil {
		t.Fatal(err)
	}
	report, err := m.configurator(newFakeIssuer("https://server.ts.net/mcp")).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Err(); err != nil {
		t.Errorf("an absent harness was reported as a failure: %v", err)
	}
	o := outcomeFor(t, report, Codex)
	if o.Status != StatusSkipped {
		t.Fatalf("status = %s, want %s", o.Status, StatusSkipped)
	}
	if !strings.Contains(o.Message, "codex") {
		t.Errorf("reason = %q", o.Message)
	}
	if _, err := os.Stat(m.codexPath); err == nil {
		t.Error("a config was created for a harness that is not installed")
	}
}

func TestAnEngineRenameRetiresTheOldEntry(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")
	if _, err := m.configurator(issuer).Configure(context.Background()); err != nil {
		t.Fatal(err)
	}

	// .11 re-activates and publishes a descriptor under a different name.
	d, err := gno.LoadDescriptor(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	d.ServerName = "retrieval"
	if err := gno.SaveDescriptor(m.stateDir, d); err != nil {
		t.Fatal(err)
	}

	report, err := m.configurator(issuer).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	o := outcomeFor(t, report, Codex)
	if len(o.Retired) != 1 || o.Retired[0] != "gno" {
		t.Fatalf("retired = %v, want [gno]", o.Retired)
	}
	tree := m.codexTree(t)
	servers := tree[codexContainer].(map[string]any)
	if _, ok := servers["gno"]; ok {
		t.Error("the renamed entry was orphaned")
	}
	if _, ok := servers["retrieval"]; !ok {
		t.Error("the new engine entry is missing")
	}
	if _, ok := servers["blender"]; !ok {
		t.Error("retiring removed an unrelated server")
	}
}

func TestRecordsHoldNoTokenAndAreOwnerOnly(t *testing.T) {
	m := newMachine(t, true)
	if _, err := m.configurator(newFakeIssuer("https://server.ts.net/mcp")).Configure(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := LoadRecords(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("%d records, want 2", len(records))
	}
	for _, r := range records {
		raw := mustRead(t, RecordPath(m.stateDir, r.Harness))
		if strings.Contains(string(raw), "token-") {
			t.Errorf("%s's record holds a grant token", r.Harness)
		}
		info, err := os.Stat(RecordPath(m.stateDir, r.Harness))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s's record has mode %#o, want 0600", r.Harness, perm)
		}
	}
	info, err := os.Stat(RecordDir(m.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("the record directory has mode %#o, want 0700", perm)
	}
}

func TestAGrantFailureFailsOnlyItsOwnHarness(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")
	issuer.fail = errors.New("server at https://server.ts.net is unreachable")

	report, err := m.configurator(issuer).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range report.Outcomes {
		if o.Status != StatusFailed {
			t.Errorf("%s status = %s, want %s", o.Harness, o.Status, StatusFailed)
		}
		if !strings.Contains(o.Message, "unreachable") {
			t.Errorf("%s message = %q, which hides the transport failure", o.Harness, o.Message)
		}
	}
	// Nothing was written.
	if got := string(mustRead(t, m.codexPath)); got != codexFixture {
		t.Error("a config was written despite having no grant")
	}
}

func TestOnlyRestrictsTheRunAndUnknownHarnessesAreRefused(t *testing.T) {
	m := newMachine(t, true)
	cfg := m.configurator(newFakeIssuer("https://server.ts.net/mcp"))
	cfg.Only = []string{Codex}
	report, err := cfg.Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Outcomes) != 1 || report.Outcomes[0].Harness != Codex {
		t.Fatalf("outcomes = %+v", report.Outcomes)
	}
	if got := string(mustRead(t, m.claudePath)); got != claudeFixture {
		t.Error("a harness outside the selection was written to")
	}

	cfg.Only = []string{"hermes"}
	if _, err := cfg.Configure(context.Background()); err == nil {
		t.Fatal("an unknown harness was accepted")
	}
}

func TestEntryFromDescriptorRefusesADescriptorItCannotExpress(t *testing.T) {
	base := gno.Descriptor{
		Component: gno.ComponentRetrievalEngine, Transport: gno.TransportStdio,
		Command: "/usr/local/bin/homeplane-agent", Args: []string{"gno", "mcp"},
		ServerName: "gno",
	}
	if _, err := EntryFromDescriptor(base); err != nil {
		t.Fatalf("a valid descriptor was refused: %v", err)
	}
	for name, mutate := range map[string]func(*gno.Descriptor){
		"relative command":  func(d *gno.Descriptor) { d.Command = "homeplane-agent" },
		"no args":           func(d *gno.Descriptor) { d.Args = nil },
		"unsafe name":       func(d *gno.Descriptor) { d.ServerName = "gno engine" },
		"secret in the env": func(d *gno.Descriptor) { d.Env = map[string]string{"GNO_TOKEN": "s3cret"} },
	} {
		t.Run(name, func(t *testing.T) {
			d := base
			mutate(&d)
			if _, err := EntryFromDescriptor(d); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}
