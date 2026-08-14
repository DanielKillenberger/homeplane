package skills

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ProfileFileName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const skeletonProfile = `
schema  = 1
profile = "daniel-skeleton"

[defaults]
skills = ["professional-writing", "casual-writing", "karpathy-guidelines"]
`

func TestProfileAssignsDefaultsToEveryHarness(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, skeletonProfile))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	want := []string{"casual-writing", "karpathy-guidelines", "professional-writing"}
	for _, h := range Known() {
		if got := p.Assign("any-machine", h); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s assign = %v, want %v", h, got, want)
		}
	}
}

// Most-specific-wins, and a block REPLACES rather than adds. The subtraction
// case is the one an additive model cannot express, so it is the one asserted.
func TestProfileResolutionPrecedence(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `
schema  = 1
profile = "layered"

[defaults]
skills = ["a", "b"]

[harness.codex]
skills = ["b"]

[machine."studio"]
skills = ["a"]

[machine."studio".harness.claude-code]
skills = []
`))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	cases := []struct {
		machine, harness string
		want             []string
	}{
		{"laptop", ClaudeCode, []string{"a", "b"}}, // defaults
		{"laptop", Codex, []string{"b"}},           // harness override
		{"studio", Codex, []string{"a"}},           // machine override beats harness
		{"studio", ClaudeCode, []string{}},         // machine+harness beats machine, and can subtract
	}
	for _, tc := range cases {
		got := p.Assign(tc.machine, tc.harness)
		if len(got) != len(tc.want) {
			t.Fatalf("%s/%s assign = %v, want %v", tc.machine, tc.harness, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s/%s assign = %v, want %v", tc.machine, tc.harness, got, tc.want)
			}
		}
	}
}

func TestProfileNormalizesSets(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `
schema  = 1
profile = "messy"

[defaults]
skills = ["b", "a", "b", "a"]
`))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if got := p.Assign("m", ClaudeCode); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("assign = %v, want sorted and de-duplicated", got)
	}
}

func TestProfileRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"wrong schema":    "schema = 2\nprofile = \"x\"\n",
		"no name":         "schema = 1\n",
		"unknown harness": "schema = 1\nprofile = \"x\"\n[harness.cursor]\nskills = []\n",
		"unknown key":     "schema = 1\nprofile = \"x\"\nskils = [\"a\"]\n",
		"path traversal":  "schema = 1\nprofile = \"x\"\n[defaults]\nskills = [\"../../etc\"]\n",
		"absolute path":   "schema = 1\nprofile = \"x\"\n[defaults]\nskills = [\"/etc/passwd\"]\n",
		"hidden name":     "schema = 1\nprofile = \"x\"\n[defaults]\nskills = [\".ssh\"]\n",
		"blank name":      "schema = 1\nprofile = \"x\"\n[defaults]\nskills = [\"a\", \"  \"]\n",
		"not toml":        "{\"schema\": 1}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadProfile(writeProfile(t, body)); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// An unknown key is a typo or a newer schema; either way the operator's intent
// is not what this build would do, so the message names the key.
func TestProfileUnknownKeyNamesIt(t *testing.T) {
	_, err := LoadProfile(writeProfile(t, "schema = 1\nprofile = \"x\"\n[defaults]\nskilz = [\"a\"]\n"))
	if err == nil || !strings.Contains(err.Error(), "skilz") {
		t.Fatalf("err = %v, want it to name the unknown key", err)
	}
}

// Per-harness incompatibility must be representable, and a marking without a
// reason is not a marking (R15).
func TestProfileUnsupportedMarkings(t *testing.T) {
	p, err := LoadProfile(writeProfile(t, `
schema  = 1
profile = "marked"

[defaults]
skills = ["everywhere", "server-only"]

[unsupported.server-only]
reason = "bound to the always-on server session"
harnesses = ["claude-code"]

[unsupported.nowhere]
reason = "not a skill any harness can act on"
`))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	if reason, blocked := p.UnsupportedOn("server-only", ClaudeCode); !blocked || reason == "" {
		t.Fatalf("server-only must be blocked on claude-code with a reason (got %q, %v)", reason, blocked)
	}
	if _, blocked := p.UnsupportedOn("server-only", Codex); blocked {
		t.Fatal("server-only must be allowed on codex; the marking named only claude-code")
	}
	// No `harnesses` means everywhere.
	for _, h := range Known() {
		if _, blocked := p.UnsupportedOn("nowhere", h); !blocked {
			t.Fatalf("an unqualified marking must apply to %s", h)
		}
	}
	if _, blocked := p.UnsupportedOn("everywhere", ClaudeCode); blocked {
		t.Fatal("an unmarked skill must not be blocked")
	}
}

func TestProfileRejectsBadUnsupportedMarkings(t *testing.T) {
	cases := map[string]string{
		"no reason":       "schema = 1\nprofile = \"x\"\n[unsupported.a]\nharnesses = [\"codex\"]\n",
		"blank reason":    "schema = 1\nprofile = \"x\"\n[unsupported.a]\nreason = \"  \"\n",
		"unknown harness": "schema = 1\nprofile = \"x\"\n[unsupported.a]\nreason = \"r\"\nharnesses = [\"cursor\"]\n",
		"bad slug":        "schema = 1\nprofile = \"x\"\n[unsupported.\"../a\"]\nreason = \"r\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadProfile(writeProfile(t, body)); err == nil {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

func TestFindProfileReportsMissing(t *testing.T) {
	root := t.TempDir()
	_, err := FindProfile("", root)
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("err = %v, want ErrNoProfile", err)
	}
	if !strings.Contains(err.Error(), DefaultProfilePath(root)) {
		t.Fatalf("err = %v, want it to name the expected path", err)
	}
}

// The reference profile shipped in configs/ must be readable by the parser that
// reads the vault's. A documented format nobody parsed is a format that drifts.
func TestShippedReferenceProfileParses(t *testing.T) {
	p, err := LoadProfile(filepath.Join("..", "..", "..", "configs", "skills", ProfileFileName))
	if err != nil {
		t.Fatalf("the shipped reference profile does not parse: %v", err)
	}
	if p.Name != "daniel-skeleton" {
		t.Fatalf("profile name = %q", p.Name)
	}
	want := []string{"casual-writing", "karpathy-guidelines", "professional-writing"}
	for _, h := range Known() {
		if got := p.Assign("", h); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s assign = %v, want the skeleton three", h, got)
		}
	}
	// The shipped profile carries the one incompatibility no rule can infer.
	for _, h := range Known() {
		reason, blocked := p.UnsupportedOn("phone-home-coordinator", h)
		if !blocked {
			t.Fatalf("phone-home-coordinator must be marked unsupported on %s", h)
		}
		if reason == "" {
			t.Fatal("the marking carries no reason")
		}
	}
}
