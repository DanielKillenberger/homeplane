package harness

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two-phase configure transaction.
//
// Issuance SUPERSEDES the harness's previous grant server-side. So a local
// problem discovered AFTER issuance does not merely fail — it revokes a
// capability that was working, and leaves nothing written to replace it. Every
// test here fixes one local precondition and asserts the same thing: the issuer
// was never called.
//
// These are the cases the old ordering got wrong. Issuance used to happen at
// configure.go:206 and the destination checks lived inside Writer.Apply, so a
// relocated GROK_HOME pointing into a git checkout — or an unwritable directory,
// or a compat setting this writer cannot edit — cost the harness its grant
// before anything was even attempted.

// configureGrokOnly runs a configure limited to grok, so a precondition planted
// for grok cannot be masked by the other two harnesses succeeding.
func configureGrokOnly(t *testing.T, m *machine, issuer GrantIssuer) Outcome {
	t.Helper()
	cfg := m.configurator(issuer)
	cfg.Only = []string{Grok}
	report, err := cfg.Configure(context.Background())
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return outcomeFor(t, report, Grok)
}

func TestNoGrantIsMintedWhenAnyLocalPreconditionFails(t *testing.T) {
	cases := []struct {
		name string
		// plant breaks one local precondition, and returns the substring the
		// operator must be told.
		plant      func(t *testing.T, m *machine) string
		wantStatus string
	}{
		{
			name: "the destination is inside a git checkout that does not ignore it",
			plant: func(t *testing.T, m *machine) string {
				// A GROK_HOME (or a symlinked ~/.grok) inside a repository is a
				// bearer token one `git add` away from a public history. 0600
				// does nothing about that.
				if err := os.MkdirAll(filepath.Join(m.grokHome, ".git"), 0o700); err != nil {
					t.Fatal(err)
				}
				return "git repository"
			},
			wantStatus: StatusFailed,
		},
		{
			name: "the harness config directory is not writable",
			plant: func(t *testing.T, m *machine) string {
				if err := os.Chmod(m.grokHome, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(m.grokHome, 0o700) })
				return "not writable"
			},
			wantStatus: StatusFailed,
		},
		{
			name: "the compat settings are in a shape the writer cannot edit",
			plant: func(t *testing.T, m *machine) string {
				if err := os.WriteFile(m.grokPath, []byte("[compat]\nclaude.mcps = true\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "key granularity"
			},
			wantStatus: StatusFailed,
		},
		{
			name: "the existing config cannot be parsed",
			plant: func(t *testing.T, m *machine) string {
				if err := os.WriteFile(m.grokPath, []byte("[mcp_servers.broken\ncommand = 1\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "malformed"
			},
			wantStatus: StatusSkipped,
		},
		{
			name: "the state directory cannot hold a record",
			plant: func(t *testing.T, m *machine) string {
				// A run that configures a harness and then cannot remember it
				// would orphan the entries it wrote on the next rename.
				if err := os.WriteFile(RecordDir(m.stateDir), []byte("in the way\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return "harnesses"
			},
			wantStatus: StatusFailed,
		},
		{
			name: "the harness runs a version whose config surface nobody verified",
			plant: func(t *testing.T, m *machine) string {
				m.locator.LookPath = func(string) (string, error) { return "/fake/bin/grok", nil }
				m.locator.Version = func(string) (string, error) { return "grok 2.0.0 (future)", nil }
				return "different major version"
			},
			wantStatus: StatusSkipped,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMachine(t, true)
			wantMessage := c.plant(t, m)
			before := readIfExists(t, m.grokPath)

			issuer := newFakeIssuer("https://server.ts.net/mcp")
			out := configureGrokOnly(t, m, issuer)

			if issuer.count() != 0 {
				t.Errorf("%d grants minted: a local failure superseded the harness's working grant", issuer.count())
			}
			if out.Status != c.wantStatus {
				t.Errorf("status = %s, want %s (message: %s)", out.Status, c.wantStatus, out.Message)
			}
			if !strings.Contains(out.Message, wantMessage) {
				t.Errorf("message = %q, want it to mention %q", out.Message, wantMessage)
			}
			if got := readIfExists(t, m.grokPath); got != before {
				t.Errorf("the config was modified by a run that never got a grant:\n%s", got)
			}
		})
	}
}

func readIfExists(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

// The mirror image: when every precondition holds, exactly one grant is minted
// and the write lands. Without this, "no grant was minted" could be satisfied by
// a configure that never does anything at all.
func TestAHealthyGrokRunMintsExactlyOneGrantAndWrites(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")

	out := configureGrokOnly(t, m, issuer)
	if out.Status != StatusConfigured {
		t.Fatalf("status = %s: %s", out.Status, out.Message)
	}
	if issuer.count() != 1 {
		t.Fatalf("%d grants minted, want exactly 1", issuer.count())
	}

	tree := m.grokTree(t)
	servers, _ := tree[grokContainer].(map[string]any)
	entry, _ := servers[ConnectorServerName].(map[string]any)
	headers, _ := entry["headers"].(map[string]any)
	auth, _ := headers["Authorization"].(string)
	if !strings.HasPrefix(auth, "Bearer token-grok-") {
		t.Errorf("the connector entry does not carry grok's own grant token: %q", auth)
	}
	// The placeholder phase one merged with must never reach disk.
	if body := string(mustRead(t, m.grokPath)); strings.Contains(body, "preflight") {
		t.Errorf("a preflight placeholder was written to the config:\n%s", body)
	}
}

// Phase two substitutes the credential and commits; it must not be able to
// widen what phase one planned. A Commit called with a plan that was never
// prepared manages nothing — and therefore preserves nothing — so it is refused
// rather than silently run.
func TestCommitRefusesAPlanThatWasNeverPrepared(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	_, err := NewGrokWriter(path).Commit(Plan{}, grokEntries("tok"))
	if err == nil {
		t.Fatal("an unprepared plan was committed")
	}
	if got := string(mustRead(t, path)); got != grokFixture {
		t.Error("the config was written from an unprepared plan")
	}
}

// Prepare writes NOTHING to the config, however healthy the machine is. It is
// the half that runs before authority moves, and a phase-one write would be a
// change made on behalf of a grant that does not exist yet.
func TestPrepareTouchesNothingButTheBackup(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	w := NewGrokWriter(path)

	plan, err := w.Prepare(grokEntries("placeholder"), nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if got := string(mustRead(t, path)); got != grokFixture {
		t.Errorf("Prepare modified the config:\n%s", got)
	}
	// The backup is the one thing it does create: R5's skip contract is "clear
	// message AND a copy of the original", and the copy has to exist before the
	// bytes that might replace it.
	if plan.BackupPath == "" {
		t.Fatal("Prepare took no backup")
	}
	if got := string(mustRead(t, plan.BackupPath)); got != grokFixture {
		t.Error("the backup does not hold the original bytes")
	}

	// And the commit that follows reuses it rather than littering a second
	// identical copy beside the operator's config.
	res, err := w.Commit(plan, grokEntries("real"))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.BackupPath != plan.BackupPath {
		t.Errorf("commit took a second backup (%s) of bytes already copied to %s", res.BackupPath, plan.BackupPath)
	}
	backups, err := filepath.Glob(path + BackupSuffix + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Errorf("%d backups for one write: %v", len(backups), backups)
	}
}

// A file that CHANGED between the two phases must not be rolled back to a stale
// copy: the backup is only reusable while it still holds the current bytes.
func TestCommitTakesAFreshBackupWhenTheFileChangedAfterPrepare(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	w := NewGrokWriter(path)

	plan, err := w.Prepare(grokEntries("placeholder"), nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := grokFixture + "\n# the user edited this between the two phases\n"
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := w.Commit(plan, grokEntries("real"))
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.BackupPath == plan.BackupPath {
		t.Fatal("a stale backup was kept: restoring it would have discarded the user's edit")
	}
	if got := string(mustRead(t, res.BackupPath)); got != changed {
		t.Error("the fresh backup does not hold the bytes that were actually replaced")
	}
	if !strings.Contains(string(mustRead(t, path)), "the user edited this") {
		t.Error("the edit made between the phases was discarded")
	}
}

// The copy Prepare took must reach the operator even when the run then refuses
// to write. A backup nobody is told about is a backup they do not have.
func TestAFailedPreparationStillReportsWhereTheCopyIs(t *testing.T) {
	m := newMachine(t, true)
	// A compat shape the writer cannot edit at key granularity: Prepare backs
	// the file up, then refuses.
	body := "# mine\n[compat]\nclaude.mcps = true\n"
	if err := os.WriteFile(m.grokPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	issuer := newFakeIssuer("https://server.ts.net/mcp")
	out := configureGrokOnly(t, m, issuer)

	if issuer.count() != 0 {
		t.Fatalf("%d grants minted for a run that never wrote", issuer.count())
	}
	if out.BackupPath == "" {
		t.Fatal("the outcome does not say where the copy of the config is")
	}
	if got := string(mustRead(t, out.BackupPath)); got != body {
		t.Errorf("the reported backup does not hold the original bytes:\n%s", got)
	}
	if !strings.Contains(out.Message, out.BackupPath) {
		t.Errorf("message = %q, which does not mention the backup", out.Message)
	}
	if got := string(mustRead(t, m.grokPath)); got != body {
		t.Error("the config was modified by a refused run")
	}
}

// A config DELETED between the two phases has "absent" as the state a rollback
// must restore. Reusing the phase-one copy would resurrect bytes the user threw
// away — the opposite of putting things back.
func TestAConfigDeletedBetweenThePhasesIsNotResurrectedByARollback(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	// A writer that passes the dry merge and then fails verification at COMMIT
	// time, so the rollback path is the one under test. (Failing in phase one
	// would prove nothing: nothing has been written to roll back.)
	merges := 0
	w := fileWriter{harness: Grok, path: path, format: format{
		container: grokContainer,
		parse:     parseTOMLTree,
		rewrite: func(before []byte, entries []Entry, managed []string) ([]byte, error) {
			out, err := rewriteGrok(before, entries, managed)
			if err != nil {
				return nil, err
			}
			merges++
			if merges == 1 {
				return out, nil // the dry merge in Prepare
			}
			// Something no preservation check can accept: an unrelated key
			// invented by the writer.
			return append(out, []byte("\n[unrelated]\ninvented = true\n")...), nil
		},
		exempt:      [][]string{{"compat", "claude", "mcps"}, {"compat", "cursor", "mcps"}},
		assertAfter: assertGrokCompatClosed,
	}}

	plan, err := w.Prepare(grokEntries("placeholder"), nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Commit(plan, grokEntries("real")); err == nil {
		t.Fatal("a write that invents an unrelated key was accepted")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("the rollback resurrected a file the user deleted:\n%s", mustRead(t, path))
	}
	// The phase-one copy still exists on disk; it just is not what "before"
	// means any more.
	if _, err := os.Stat(plan.BackupPath); err != nil {
		t.Errorf("the operator's copy was removed too: %v", err)
	}
}
