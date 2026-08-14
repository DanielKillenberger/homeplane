package harness

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// grokLocator builds a locator pinned entirely to a temporary home: no ambient
// GROK_HOME, no real PATH, and a version seam that answers whatever the test
// says. Nothing here may touch the operator's ~/.grok.
func grokLocator(t *testing.T, versionOutput string, versionErr error, onPath bool) (Locator, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv(EnvGrokHome, "")
	l := Locator{
		Home:     home,
		GrokHome: filepath.Join(home, ".grok"),
		LookPath: func(name string) (string, error) {
			if onPath && name == "grok" {
				return "/fake/bin/grok", nil
			}
			return "", errors.New("not on PATH")
		},
		Version: func(string) (string, error) { return versionOutput, versionErr },
	}
	return l, filepath.Join(home, ".grok", "config.toml")
}

// GROK_HOME relocates grok's entire config home — the CODEX_HOME equivalent —
// and it was PROVEN to, not assumed: the capture seeds a decoy at $HOME/.grok
// and observes zero references to it from a relocated home. A locator that
// ignored it would configure a grok nobody runs.
func TestGrokConfigPathHonoursGrokHome(t *testing.T) {
	home := t.TempDir()
	relocated := filepath.Join(t.TempDir(), "elsewhere")

	t.Setenv(EnvGrokHome, "")
	fromHome, err := Locator{Home: home}.GrokConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".grok", "config.toml"); fromHome != want {
		t.Fatalf("default path = %q, want %q", fromHome, want)
	}

	t.Setenv(EnvGrokHome, relocated)
	fromEnv, err := Locator{Home: home}.GrokConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(relocated, "config.toml"); fromEnv != want {
		t.Fatalf("GROK_HOME ignored: %q", fromEnv)
	}

	// The explicit field beats the environment, so a test (or a caller with its
	// own opinion) is never at the mercy of an ambient variable.
	explicit := filepath.Join(t.TempDir(), "explicit")
	fromField, err := Locator{Home: home, GrokHome: explicit}.GrokConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(explicit, "config.toml"); fromField != want {
		t.Fatalf("explicit GrokHome ignored: %q", fromField)
	}
}

// A grok that has never been launched has NO config.toml at all, and its read
// verbs answer cleanly on an empty home. That is DETECTED — the first write
// creates the file — and reporting it as absent would refuse to configure a
// freshly installed harness.
func TestNeverLaunchedGrokIsDetectedNotAbsent(t *testing.T) {
	l, configPath := grokLocator(t, "grok 1.0.3 (1a29d5bc12d4)", nil, true)

	d, err := l.Detect(Grok)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Installed {
		t.Fatal("an installed grok with no config was reported as not installed")
	}
	if d.ConfigExists {
		t.Fatal("ConfigExists is true for a home that has no config.toml")
	}
	if !d.NeverLaunched {
		t.Fatal("the never-launched state was not reported")
	}
	if d.ConfigPath != configPath {
		t.Fatalf("config path = %q, want %q", d.ConfigPath, configPath)
	}
	if !d.Usable() {
		t.Fatalf("a never-launched grok on a supported version must still be configurable: %s", d.SupportReason)
	}
	// The first launch populates the home with docs/, logs/ and
	// active_sessions.json but no config, so a non-empty DIRECTORY is not
	// evidence of configuration. Detection must key on the file.
	if err := os.MkdirAll(filepath.Join(filepath.Dir(configPath), "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	again, err := l.Detect(Grok)
	if err != nil {
		t.Fatal(err)
	}
	if again.ConfigExists {
		t.Fatal("a populated grok home was mistaken for a configured one")
	}
}

func TestGrokVersionVerdicts(t *testing.T) {
	cases := []struct {
		name        string
		output      string
		err         error
		onPath      bool
		wantVersion string
		wantSupport string
		usable      bool
	}{
		{
			name:   "the captured contract version is supported outright",
			output: "grok " + GrokContractVersion + " (1a29d5bc12d4)\n", onPath: true,
			wantVersion: GrokContractVersion, wantSupport: SupportSupported, usable: true,
		},
		{
			name:   "a newer release in the same major line is drift, and still written",
			output: "grok 1.4.0 (deadbeef)\n", onPath: true,
			wantVersion: "1.4.0", wantSupport: SupportDrifted, usable: true,
		},
		{
			name:   "an older release than the contract is refused",
			output: "grok 0.9.9 (deadbeef)\n", onPath: true,
			wantVersion: "0.9.9", wantSupport: SupportUnsupported, usable: false,
		},
		{
			name:   "a different major version is refused",
			output: "grok 2.0.0 (deadbeef)\n", onPath: true,
			wantVersion: "2.0.0", wantSupport: SupportUnsupported, usable: false,
		},
		{
			name:   "an unreadable version line is unknown, never unsupported",
			output: "grok, the build tui\n", onPath: true,
			wantSupport: SupportUnknown, usable: true,
		},
		{
			name: "a version probe that fails is unknown, never unsupported",
			err:  errors.New("exec: signal: killed"), onPath: true,
			wantSupport: SupportUnknown, usable: true,
		},
		{
			name: "a config with no CLI on PATH cannot be version-checked, and is still repairable",
			// No binary at all: the config file below makes it installed.
			onPath: false, wantSupport: SupportUnknown, usable: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, configPath := grokLocator(t, c.output, c.err, c.onPath)
			if !c.onPath {
				if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(configPath, []byte("[ui]\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d, err := l.Detect(Grok)
			if err != nil {
				t.Fatal(err)
			}
			if d.Version != c.wantVersion {
				t.Errorf("version = %q, want %q", d.Version, c.wantVersion)
			}
			if d.Support != c.wantSupport {
				t.Errorf("support = %q, want %q", d.Support, c.wantSupport)
			}
			if d.Usable() != c.usable {
				t.Errorf("usable = %v, want %v (%s)", d.Usable(), c.usable, d.SupportReason)
			}
			// Every verdict except a plain "supported" must explain itself: a
			// refusal an operator cannot act on is a refusal they will work
			// around.
			if c.wantSupport != SupportSupported && d.SupportReason == "" {
				t.Error("the verdict carries no reason")
			}
			if c.wantSupport == SupportSupported && d.SupportReason != "" {
				t.Errorf("a plain supported verdict should be quiet, got %q", d.SupportReason)
			}
		})
	}
}

// The other two harnesses are not version-gated — fn-1 pinned no contract for
// them — and that must read as UNKNOWN with a reason, never as a silent
// "supported". Claiming a verdict nobody established is the same dishonesty in
// the other direction.
func TestUnpinnedHarnessesReportUnknownSupportRatherThanClaimSupported(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvClaudeConfigDir, "")
	t.Setenv(EnvCodexHome, "")
	l := Locator{Home: home, ClaudeConfigDir: home, CodexHome: filepath.Join(home, ".codex"),
		LookPath: func(string) (string, error) { return "", errors.New("nope") }}

	for _, h := range []string{ClaudeCode, Codex} {
		d, err := l.Detect(h)
		if err != nil {
			t.Fatal(err)
		}
		if d.Support != SupportUnknown || d.SupportReason == "" {
			t.Errorf("%s support = %q (%q)", h, d.Support, d.SupportReason)
		}
		if !d.Usable() {
			t.Errorf("%s must not be gated by a contract nobody pinned", h)
		}
	}
}

// Detection reports which OTHER vendors' configurations grok would still
// inherit MCP servers from. It is read from the config file, never by invoking
// grok: `mcp doctor` performs real network connections, and a status surface
// that dials the internet is not a status surface.
func TestCompatSourcesAreReportedFromTheConfigFile(t *testing.T) {
	l, configPath := grokLocator(t, "grok "+GrokContractVersion+" (x)", nil, true)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}

	// Nothing configured: grok's defaults inherit from BOTH vendors, and the
	// pessimistic answer is the honest one.
	if err := os.WriteFile(configPath, []byte("[ui]\nmax_thoughts_width = 120\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := l.Detect(Grok)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{CompatSourceClaude, CompatSourceCursor, CompatSourceProject}
	if got := d.CompatSources; !equalStrings(got, want) {
		t.Fatalf("compat sources = %v, want %v", got, want)
	}

	// Both user-config cells closed: only the project-scope source remains, and
	// it is still reported — no user-config key can close it, so claiming it
	// absent would be the one dishonest thing this list could do.
	closed := "[compat.claude]\nmcps = false\nskills = true\n\n[compat.cursor]\nmcps = false\n"
	if err := os.WriteFile(configPath, []byte(closed), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err = l.Detect(Grok)
	if err != nil {
		t.Fatal(err)
	}
	if got := d.CompatSources; !equalStrings(got, []string{CompatSourceProject}) {
		t.Fatalf("compat sources after closing both cells = %v", got)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
