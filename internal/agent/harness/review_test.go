package harness

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
)

// Regression tests for the findings of the codex impl-review (gpt-5.6-sol,
// xhigh). Each one fails against the behaviour that was reviewed.

// ── Path containment ─────────────────────────────────────────────────────────

// A grant token in a git working tree is a grant token in git history, and 0600
// does nothing to stop `git add`. CODEX_HOME is an environment variable and
// ~/.codex can be a symlink, so the DESTINATION — not just the file name — has
// to be checked, after symlinks are resolved.
func TestAConfigPathInsideARepositoryIsRefused(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	repo := filepath.Join(home, "Projects", "homeplane")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"config directly in the checkout": filepath.Join(repo, "config.toml"),
		"config in a dot-dir below it":    filepath.Join(repo, ".codex", "config.toml"),
		"config nested several levels":    filepath.Join(repo, "a", "b", "c", "config.toml"),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if err := assertUserScope(path); !errors.Is(err, ErrProjectScope) {
				t.Fatalf("err = %v, want ErrProjectScope for %s", err, path)
			}
			if _, err := NewCodexWriter(path).Apply(managedEntries("tok"), nil); !errors.Is(err, ErrProjectScope) {
				t.Fatalf("the writer accepted %s (err = %v)", path, err)
			}
			if _, err := os.Stat(path); err == nil {
				t.Error("the refused path was created anyway")
			}
		})
	}
}

// A worktree's `.git` is a FILE, not a directory, and its contents are just as
// committable.
func TestALinkedWorktreeIsRefusedToo(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	worktree := filepath.Join(home, "wt")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := assertUserScope(filepath.Join(worktree, ".codex", "config.toml")); !errors.Is(err, ErrProjectScope) {
		t.Fatalf("err = %v, want ErrProjectScope", err)
	}
	_ = home
}

func TestASymlinkedConfigDirIsJudgedByWhereItActuallyLands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows, which Homeplane does not target")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	repo := filepath.Join(home, "Projects", "app")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	realCodex := filepath.Join(repo, "dotcodex")
	if err := os.MkdirAll(realCodex, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".codex")
	if err := os.Symlink(realCodex, link); err != nil {
		t.Fatal(err)
	}

	// The path LOOKS like a plain ~/.codex/config.toml. Only resolving the
	// symlink reveals that it lands inside a checkout.
	if err := assertUserScope(filepath.Join(link, "config.toml")); !errors.Is(err, ErrProjectScope) {
		t.Fatalf("err = %v, want ErrProjectScope — the symlink was not resolved", err)
	}
	_ = home
}

// A home directory that is itself a dotfiles repository gets no exemption:
// R5 says a token never lands in a git-shared file, and the owner having chosen
// to version their home does not make the token less committable. What DOES
// make it safe is the file being ignored — so that is the question asked, of
// git itself.
func TestAGitManagedHomeIsRefusedUnlessTheConfigIsIgnored(t *testing.T) {
	home := initRepo(t, t.TempDir())
	claude := filepath.Join(home, ".claude.json")
	codex := filepath.Join(home, ".codex", "config.toml")

	for _, path := range []string{claude, codex} {
		err := assertUserScope(path)
		if !errors.Is(err, ErrProjectScope) {
			t.Fatalf("assertUserScope(%s) = %v, want ErrProjectScope", path, err)
		}
		if !strings.Contains(err.Error(), ".gitignore") {
			t.Errorf("the refusal does not tell the operator how to fix it: %v", err)
		}
	}

	// Ignore them, and the same paths become writable — no false positive for a
	// dotfiles user who already protects their secrets.
	if err := os.WriteFile(filepath.Join(home, ".gitignore"), []byte(".claude.json\n.codex/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{claude, codex} {
		if err := assertUserScope(path); err != nil {
			t.Errorf("assertUserScope(%s) = %v after it was gitignored, want nil", path, err)
		}
	}
}

// A file git is already TRACKING must never be treated as safe, whatever the
// ignore rules say.
func TestATrackedConfigIsRefusedEvenWhenAnIgnoreRuleWouldMatch(t *testing.T) {
	home := initRepo(t, t.TempDir())
	path := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".gitignore"), []byte(".claude.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, home, "add", "-f", ".claude.json")
	git(t, home, "commit", "-m", "track it")

	if err := assertUserScope(path); !errors.Is(err, ErrProjectScope) {
		t.Fatalf("a tracked config was accepted (err = %v); its token is already committable", err)
	}
}

// initRepo makes dir a real git repository — real, because the containment
// check asks git itself and a hand-made `.git` directory would not answer.
func initRepo(t *testing.T, dir string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; the containment check delegates to it")
	}
	git(t, dir, "init", "-q")
	git(t, dir, "config", "user.email", "test@example.invalid")
	git(t, dir, "config", "user.name", "test")
	if err := os.MkdirAll(filepath.Join(dir, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// ── CLAUDE_CONFIG_DIR ────────────────────────────────────────────────────────

// Verified against the installed CLI: with CLAUDE_CONFIG_DIR set, Claude Code
// lists servers from $CLAUDE_CONFIG_DIR/.claude.json and ignores
// $HOME/.claude.json. Writing to HOME on such a machine would configure a file
// the harness never reads.
func TestClaudeConfigDirRelocatesTheUserConfig(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(root, "elsewhere")

	l := Locator{Home: home, ClaudeConfigDir: configDir}
	got, err := l.ClaudeConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(configDir, ".claude.json"); got != want {
		t.Fatalf("ClaudeConfigPath = %q, want %q", got, want)
	}

	// And the environment variable is honoured when the field is not set.
	t.Setenv(EnvClaudeConfigDir, configDir)
	got, err = Locator{Home: home}.ClaudeConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(configDir, ".claude.json"); got != want {
		t.Fatalf("with %s set, ClaudeConfigPath = %q, want %q", EnvClaudeConfigDir, got, want)
	}

	// With neither, it falls back to home.
	t.Setenv(EnvClaudeConfigDir, "")
	got, err = Locator{Home: home}.ClaudeConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".claude.json"); got != want {
		t.Fatalf("fallback ClaudeConfigPath = %q, want %q", got, want)
	}
}

// ── Descriptor validated before any grant is requested ───────────────────────

// A purely local problem — a descriptor this writer cannot express — must not
// cost the machine its connector access. Before the fix, the grant was minted
// first and the conversion failed afterwards, so an unusable descriptor
// superseded BOTH harnesses' working grants and wrote nothing.
func TestAnUnusableDescriptorCostsNoGrantAtAll(t *testing.T) {
	m := newMachine(t, true)

	// A descriptor that passes gno's own validation but names a server this
	// writer cannot place unambiguously.
	raw := mustRead(t, gno.DescriptorPath(m.stateDir))
	poisoned := strings.Replace(string(raw), `"server_name": "gno"`, `"server_name": "gno engine"`, 1)
	if poisoned == string(raw) {
		t.Fatal("the descriptor fixture changed shape; this test no longer poisons it")
	}
	if err := os.WriteFile(gno.DescriptorPath(m.stateDir), []byte(poisoned), 0o600); err != nil {
		t.Fatal(err)
	}

	issuer := newFakeIssuer("https://server.ts.net/mcp")
	_, err := m.configurator(issuer).Configure(context.Background())
	if err == nil {
		t.Fatal("Configure accepted a descriptor it cannot express")
	}
	if !strings.Contains(err.Error(), "no grant was requested") {
		t.Errorf("err = %v, which does not tell the operator that no authority moved", err)
	}
	if issuer.count() != 0 {
		t.Fatalf("%d grants were minted for a run that could never write; want 0", issuer.count())
	}
	// And nothing was written.
	if got := string(mustRead(t, m.codexPath)); got != codexFixture {
		t.Error("a config was written despite the descriptor being unusable")
	}
}

// A corrupt descriptor file is the same class of local problem.
func TestACorruptDescriptorCostsNoGrantAtAll(t *testing.T) {
	m := newMachine(t, true)
	if err := os.WriteFile(gno.DescriptorPath(m.stateDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	issuer := newFakeIssuer("https://server.ts.net/mcp")
	if _, err := m.configurator(issuer).Configure(context.Background()); err == nil {
		t.Fatal("Configure accepted a corrupt descriptor")
	}
	if issuer.count() != 0 {
		t.Fatalf("%d grants minted; want 0", issuer.count())
	}
}

// ── Serialisation ────────────────────────────────────────────────────────────

// Two runs that interleave as "A issues, B issues, B writes, A writes" leave A's
// already-superseded token in the config while both report success — a window
// no per-run check can see, because each run's own view is consistent.
func TestConfigureHoldsTheLockAcrossTheWholeRun(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")

	var mu sync.Mutex
	var held, releases int
	var issuedWhileUnlocked bool

	cfg := m.configurator(issuer)
	cfg.Lock = func() (func(), error) {
		mu.Lock()
		held++
		mu.Unlock()
		return func() {
			mu.Lock()
			releases++
			mu.Unlock()
		}, nil
	}
	issuer.observe = func() {
		mu.Lock()
		if held == 0 || held == releases {
			issuedWhileUnlocked = true
		}
		mu.Unlock()
	}

	if _, err := cfg.Configure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if held != 1 {
		t.Errorf("the lock was taken %d times, want exactly 1 for the whole run", held)
	}
	if releases != 1 {
		t.Errorf("the lock was released %d times, want 1", releases)
	}
	if issuedWhileUnlocked {
		t.Error("a grant was issued outside the lock; another run could interleave its own issuance there")
	}
}

func TestConfigureRefusesToRunWhenTheLockCannotBeTaken(t *testing.T) {
	m := newMachine(t, true)
	issuer := newFakeIssuer("https://server.ts.net/mcp")
	cfg := m.configurator(issuer)
	cfg.Lock = func() (func(), error) { return nil, errors.New("another configure-harnesses is running") }

	if _, err := cfg.Configure(context.Background()); err == nil {
		t.Fatal("Configure ran without the lock it was given")
	}
	if issuer.count() != 0 {
		t.Errorf("%d grants minted without the lock", issuer.count())
	}
}

// ── Concurrent edits to the config file ──────────────────────────────────────

// Claude Code and Codex rewrite their own config files on their own schedule.
// A read-modify-write that does not re-check would discard whatever landed in
// between — and its preservation check, comparing against the stale snapshot,
// would report success.
func TestAnEditLandingDuringTheMergeIsNotLost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	// Simulate the harness writing to its own config in the window between our
	// read and our write: the injected rewrite runs after `before` was read.
	var once sync.Once
	const concurrent = "\n[mcp_servers.written_by_the_harness_itself]\ncommand = \"/late\"\n"
	racing := fileWriter{harness: Codex, path: path, format: format{
		container: codexContainer,
		parse:     parseTOMLTree,
		rewrite: func(before []byte, entries []Entry, managed []string) ([]byte, error) {
			once.Do(func() {
				current, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(current, []byte(concurrent)...), 0o600); err != nil {
					t.Fatal(err)
				}
			})
			return rewriteCodex(before, entries, managed)
		},
	}}

	if _, err := racing.Apply(managedEntries("tok"), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	tree, err := parseTOMLTree(mustRead(t, path))
	if err != nil {
		t.Fatalf("the merged config does not parse: %v", err)
	}
	servers := tree[codexContainer].(map[string]any)
	if _, ok := servers["written_by_the_harness_itself"]; !ok {
		t.Error("the edit that landed during the merge was silently discarded")
	}
	if _, ok := servers[ConnectorServerName]; !ok {
		t.Error("the retry did not write the managed entry")
	}
	if _, ok := servers["blender"]; !ok {
		t.Error("the retry lost pre-existing configuration")
	}
}

func TestAConfigThatNeverStopsChangingIsReportedRatherThanSpunOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var attempts int
	hopeless := fileWriter{harness: Codex, path: path, format: format{
		container: codexContainer,
		parse:     parseTOMLTree,
		rewrite: func(before []byte, entries []Entry, managed []string) ([]byte, error) {
			attempts++
			current, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(path, append(current, []byte("\n# again\n")...), 0o600); err != nil {
				return nil, err
			}
			return rewriteCodex(before, entries, managed)
		},
	}}

	_, err := hopeless.Apply(managedEntries("tok"), nil)
	if err == nil {
		t.Fatal("a config being rewritten in a loop was reported as a success")
	}
	if !strings.Contains(err.Error(), "kept changing") {
		t.Errorf("err = %v", err)
	}
	if attempts > maxMergeAttempts+1 {
		t.Errorf("%d merge attempts; the retry is not bounded", attempts)
	}
}

// ── Backup failures on the skip path ─────────────────────────────────────────

// The skip contract is "clear message + backup intact". A backup that could not
// be written makes the second half false, so the run must say so instead of
// reporting a clean skip.
func TestAMalformedConfigThatCannotBeBackedUpFailsRatherThanSkipsQuietly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: an unwritable directory would still be writable")
	}
	m := newMachine(t, true)
	if err := os.WriteFile(m.codexPath, []byte("model = \"x\"\n[mcp_servers.broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The config is readable but its directory is not writable, so no backup
	// can be created beside it.
	if err := os.Chmod(m.codexHome, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(m.codexHome, 0o700) })

	report, err := m.configurator(newFakeIssuer("https://server.ts.net/mcp")).Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	o := outcomeFor(t, report, Codex)
	if o.Status != StatusFailed {
		t.Fatalf("status = %s, want %s: a skip promises a backup that does not exist here", o.Status, StatusFailed)
	}
	if !strings.Contains(o.Message, "could not be backed up") {
		t.Errorf("message = %q, which does not say why", o.Message)
	}
	if report.Err() == nil {
		t.Error("the report claims success")
	}
}
