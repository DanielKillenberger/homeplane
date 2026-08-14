package skills

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent/harness"
)

// The two registries must move together.
//
// A harness in one and not the other is a half-configured machine that reports
// itself healthy: configured for MCP but invisible to skills provisioning, or
// provisioned with skills and never wired to the plane. skills.Known() delegates
// to harness.Known() so the lockstep is structural — and this test is what fails
// if someone re-introduces a second list, whichever list they forget to update.
func TestKnownRegistriesAreInLockstep(t *testing.T) {
	if got, want := Known(), harness.Known(); !reflect.DeepEqual(got, want) {
		t.Fatalf("skills.Known() = %v, harness.Known() = %v — the registries have drifted", got, want)
	}
	for _, registry := range map[string][]string{"skills": Known(), "harness": harness.Known()} {
		if !contains(registry, Grok) {
			t.Fatalf("grok is missing from a registry: %v", registry)
		}
	}
	// Every known harness must have a skills directory, or provisioning fails
	// the moment Known() includes it.
	l := Locator{Home: t.TempDir()}
	for _, h := range Known() {
		if _, err := l.SkillsDir(h); err != nil {
			t.Errorf("SkillsDir(%s): %v", h, err)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// grok's skills root is ~/.grok/skills, and GROK_HOME relocates it — the same
// override that relocates the config file, proven by the capture's decoy test.
func TestGrokSkillsDirHonoursGrokHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv(EnvGrokHome, "")

	got, err := Locator{Home: home}.SkillsDir(Grok)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".grok", "skills"); got != want {
		t.Fatalf("default = %q, want %q", got, want)
	}

	relocated := t.TempDir()
	t.Setenv(EnvGrokHome, relocated)
	got, err = Locator{Home: home}.SkillsDir(Grok)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(relocated, "skills"); got != want {
		t.Fatalf("GROK_HOME ignored: %q", got)
	}

	explicit := t.TempDir()
	got, err = Locator{Home: home, GrokHome: explicit}.SkillsDir(Grok)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(explicit, "skills"); got != want {
		t.Fatalf("explicit GrokHome ignored: %q", got)
	}
}

// grok becomes a KNOWN profile key, with absent-key defaults — and the reader
// stays fail-closed on everything else.
//
// Warn-and-skip would be the friendly choice and the wrong one: a profile that
// says `[harness.grock]` would silently provision nothing to grok while looking
// like it configured something, which is precisely the failure the vault owner
// wrote the key to prevent.
func TestGrokIsAKnownProfileKeyAndTyposStillFailClosed(t *testing.T) {
	good := writeProfile(t, `
schema  = 1
profile = "p"

[defaults]
skills = ["a"]

[harness.grok]
skills = ["a", "b"]

[unsupported.c]
reason = "grok cannot run it"
harnesses = ["grok"]
`)
	p, err := LoadProfile(good)
	if err != nil {
		t.Fatalf("a profile naming grok was rejected: %v", err)
	}
	if got := p.Assign("", Grok); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("grok assignment = %v", got)
	}
	// An absent key is a default, not an error: a profile written before grok
	// existed still assigns it the defaults.
	if got := p.Assign("", ClaudeCode); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("claude-code fell back to %v, want the defaults", got)
	}
	if reason, blocked := p.UnsupportedOn("c", Grok); !blocked || reason == "" {
		t.Fatal("an unsupported marking naming grok was not honoured")
	}

	bad := writeProfile(t, `
schema  = 1
profile = "p"

[unsupported.c]
reason = "typo"
harnesses = ["grock"]
`)
	if _, err := LoadProfile(bad); err == nil {
		t.Fatal("a misspelled harness key was accepted; the reader must fail closed")
	} else if !strings.Contains(err.Error(), "grock") {
		t.Errorf("err = %v, which does not name the typo", err)
	}
}
