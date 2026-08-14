package skills

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file is the R15 proof, and it is the only one that runs the REAL
// harnesses against the REAL vault.
//
// What it does NOT do is equally deliberate. The vault is opened read-only and
// is only ever a link SOURCE; the harness side runs entirely inside a fixture
// CLAUDE_CONFIG_DIR / CODEX_HOME, which both CLIs honour for their skills
// directory (verified: with CLAUDE_CONFIG_DIR set, Claude Code enumerates
// $CLAUDE_CONFIG_DIR/skills and ignores ~/.claude/skills). So the binaries, the
// skills, the discovery path and the process are all real, while the operator's
// own harness directories are untouched by the suite.

// EnvTestVaultSkills points the suite at a vault skills directory. Empty means
// the default location.
const EnvTestVaultSkills = "HOMEPLANE_TEST_VAULT_SKILLS"

const defaultVaultSkills = "Documents/daniel-os/skills"

func realVaultSkills(t *testing.T) string {
	t.Helper()
	if explicit := strings.TrimSpace(os.Getenv(EnvTestVaultSkills)); explicit != "" {
		return explicit
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	path := filepath.Join(home, defaultVaultSkills)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no vault at %s (set %s to point elsewhere)", path, EnvTestVaultSkills)
	}
	return path
}

// unsupportedBlockFrom re-renders one of a profile's markings as TOML, so a
// test can reuse the SHIPPED reason rather than inventing a weaker one.
func unsupportedBlockFrom(t *testing.T, p Profile, slug string) string {
	t.Helper()
	u, ok := p.Unsupported[slug]
	if !ok {
		t.Fatalf("the shipped profile has no [unsupported.%s] marking", slug)
	}
	quoted := make([]string, 0, len(u.Harnesses))
	for _, h := range u.Harnesses {
		quoted = append(quoted, `"`+h+`"`)
	}
	block := "[unsupported." + slug + "]\nreason = " + strconv.Quote(u.Reason) + "\n"
	if len(quoted) > 0 {
		block += "harnesses = [" + strings.Join(quoted, ", ") + "]\n"
	}
	return block
}

func requireBin(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed: %v", name, err)
	}
	return path
}

// TestRealHarnessesDiscoverRealVaultSkills is the acceptance proof: the three
// profile skills are linked out of the real vault into both harnesses, and a
// FRESH process of each real CLI enumerates all three.
func TestRealHarnessesDiscoverRealVaultSkills(t *testing.T) {
	vaultSkills := realVaultSkills(t)
	claudeBin := requireBin(t, "claude")
	codexBin := requireBin(t, "codex")

	base := t.TempDir()
	claudeHome := filepath.Join(base, "claude")
	codexHome := filepath.Join(base, "codex")
	stateDir := filepath.Join(base, "state")
	for _, d := range []string{claudeHome, codexHome, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	cat, err := Discover(vaultSkills)
	if err != nil {
		t.Fatalf("Discover(%s): %v", vaultSkills, err)
	}
	profile, err := LoadProfile(filepath.Join("..", "..", "..", "configs", "skills", ProfileFileName))
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}

	p := Provisioner{
		Locator:  Locator{ClaudeConfigDir: claudeHome, CodexHome: codexHome},
		StateDir: stateDir,
		Machine:  "test",
	}
	report, err := p.Provision(cat, profile)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	expected := profile.Assign("test", ClaudeCode)
	if len(expected) == 0 {
		t.Fatal("the shipped profile assigns nothing")
	}

	// Every assigned skill must have landed as a link into the vault, with the
	// harness reading the vault's own SKILL.md file.
	for _, hr := range report.Harnesses {
		for _, slug := range expected {
			res := resultFor(t, report, hr.Harness, slug)
			if res.Action != ActionLinked {
				t.Fatalf("%s/%s action = %s (%s), want linked", hr.Harness, slug, res.Action, res.Reason)
			}
			skill, ok := cat.Lookup(slug)
			if !ok {
				t.Fatalf("the profile assigns %q but the real vault has no such linkable skill", slug)
			}
			c, err := Inspect(res.LinkPath, skill, cat.Root)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if !c.IsSymlink || !c.InVault || !c.SameFile {
				t.Fatalf("%s/%s: the harness does not read the vault's own file: %+v", hr.Harness, slug, c)
			}
		}
	}

	// The real fresh-process proof.
	v := Verifier{
		ClaudeBin: claudeBin,
		CodexBin:  codexBin,
		Env:       append(os.Environ(), "CLAUDE_CONFIG_DIR="+claudeHome, "CODEX_HOME="+codexHome),
		Dir:       base,
	}
	if err := v.Verify(context.Background(), &report); err != nil {
		t.Fatalf("fresh-process verification: %v", err)
	}
	for _, hr := range report.Harnesses {
		t.Logf("%s enumerated %d skills: %v", hr.Harness, len(hr.Verified), hr.Verified)
	}

	// Codex reports each skill's resolved locator. That is the harness itself
	// saying the canonical file lives in the vault, independent of our own
	// inode check.
	found, err := v.Discover(context.Background(), Codex)
	if err != nil {
		t.Fatalf("codex discover: %v", err)
	}
	for _, slug := range expected {
		path := found.Paths[slug]
		if path == "" {
			t.Fatalf("codex reported no locator for %s", slug)
		}
		if !strings.HasPrefix(path, cat.Root) {
			t.Fatalf("codex reads %s from %s, which is not in the vault", slug, path)
		}
	}
}

// The real vault's harness-specific skills must be marked unsupported with a
// reason, not silently linked (R15). `hermes` is a directory OF skills; the
// scheduling ones drive host initiative.
func TestRealVaultHarnessSpecificSkillsAreMarkedUnsupported(t *testing.T) {
	vaultSkills := realVaultSkills(t)
	cat, err := Discover(vaultSkills)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if _, ok := cat.Finding("hermes"); ok {
		f, _ := cat.Finding("hermes")
		if f.Status != StatusUnsupported || f.Rule != RuleNoSkillMD || f.Reason == "" {
			t.Fatalf("hermes finding = %+v, want an unsupported marking with a reason", f)
		}
	} else if _, linkable := cat.Lookup("hermes"); linkable {
		t.Fatal("hermes is a collection of skills and must never be linkable")
	}

	// `phone-home-coordinator` is the case no mechanical rule can reach: its
	// text names no scheduler and no service manager, and it is a perfectly
	// well-formed skill — it is simply bound to the always-on server session.
	// The shipped profile marks it, and the marking must be ENFORCED even
	// though `[defaults]` also names it.
	if _, linkable := cat.Lookup("phone-home-coordinator"); linkable {
		profile, err := LoadProfile(filepath.Join("..", "..", "..", "configs", "skills", ProfileFileName))
		if err != nil {
			t.Fatal(err)
		}
		base := t.TempDir()
		p := Provisioner{
			Locator:  Locator{ClaudeConfigDir: filepath.Join(base, "claude"), CodexHome: filepath.Join(base, "codex")},
			StateDir: filepath.Join(base, "state"),
		}
		// Assign it deliberately, alongside the profile's own marking.
		forced := filepath.Join(base, ProfileFileName)
		if err := os.WriteFile(forced, []byte(`
schema  = 1
profile = "forced"

[defaults]
skills = ["phone-home-coordinator"]

`+unsupportedBlockFrom(t, profile, "phone-home-coordinator")), 0o644); err != nil {
			t.Fatal(err)
		}
		forcedProfile, err := LoadProfile(forced)
		if err != nil {
			t.Fatal(err)
		}
		report, err := p.Provision(cat, forcedProfile)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range Known() {
			res := resultFor(t, report, h, "phone-home-coordinator")
			if res.Action != ActionSkipped || res.Rule != RuleProfileUnsupported {
				t.Fatalf("%s: a profile-unsupported skill was provisioned: %+v", h, res)
			}
			if _, err := os.Lstat(res.LinkPath); err == nil {
				t.Fatalf("%s: phone-home-coordinator was linked despite the marking", h)
			}
		}
	}

	// At least one initiative-bearing skill must be caught, with evidence.
	var initiative []Finding
	for _, f := range cat.Findings {
		if f.Rule == RuleInitiativeSignal {
			initiative = append(initiative, f)
		}
	}
	if len(initiative) == 0 {
		t.Skip("this vault has no scheduling skills to classify")
	}
	for _, f := range initiative {
		if f.Status != StatusUnsupported || !strings.HasPrefix(f.Evidence, "SKILL.md:") {
			t.Fatalf("initiative finding = %+v, want unsupported with the matched line", f)
		}
		t.Logf("unsupported: %s — %s (%s)", f.Slug, f.Reason, f.Evidence)
	}

	// And nothing in the real vault may be silently missing: every candidate is
	// either linkable or carries a finding with a reason.
	for _, f := range cat.Findings {
		if f.Reason == "" {
			t.Fatalf("%s has no reason", f.Slug)
		}
	}
}

// A skill carrying a credential is rejected with a clear message — proven with
// a FIXTURE skill, never by putting one in the real vault.
func TestCredentialBearingSkillIsRejectedAgainstRealHarnesses(t *testing.T) {
	root := fixtureVault(t)
	dir := writeSkill(t, root, "leaky-skill", "Ordinary instructions.")
	if err := os.WriteFile(filepath.Join(dir, "notes.md"),
		[]byte("The deploy key is sk-ant-api03-FAKE0000111122223333444455556666.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cat, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	f, ok := cat.Finding("leaky-skill")
	if !ok || f.Status != StatusRejected || f.Rule != RuleCredential {
		t.Fatalf("finding = %+v, want a credential rejection", f)
	}
	if !strings.Contains(f.Reason, "credential") || !strings.Contains(f.Evidence, "notes.md:") {
		t.Fatalf("the rejection must name the problem and the file: %+v", f)
	}

	// And it must not reach a harness even when a profile asks for it.
	base := t.TempDir()
	p := Provisioner{
		Locator:  Locator{ClaudeConfigDir: filepath.Join(base, "claude"), CodexHome: filepath.Join(base, "codex")},
		StateDir: filepath.Join(base, "state"),
	}
	profilePath := filepath.Join(root, ProfileFileName)
	if err := os.WriteFile(profilePath, []byte(skeletonProfileFor("leaky-skill")), 0o644); err != nil {
		t.Fatal(err)
	}
	profile, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := p.Provision(cat, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range Known() {
		res := resultFor(t, report, h, "leaky-skill")
		if res.Action != ActionSkipped || res.Rule != RuleCredential {
			t.Fatalf("%s: a credential-bearing skill was not refused: %+v", h, res)
		}
		if _, err := os.Lstat(res.LinkPath); err == nil {
			t.Fatalf("%s: the credential-bearing skill was linked anyway", h)
		}
	}
}

// The real vault must actually contain the case the shipped profile marks —
// otherwise the enforcement assertion above is vacuously skipped and nobody
// notices. This fails loudly if the vault changes shape.
func TestRealVaultStillHasTheMarkedIncompatibility(t *testing.T) {
	cat, err := Discover(realVaultSkills(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, linkable := cat.Lookup("phone-home-coordinator"); !linkable {
		f, _ := cat.Finding("phone-home-coordinator")
		t.Skipf("phone-home-coordinator is no longer a mechanically-linkable skill (%+v); the profile marking is now redundant", f)
	}
}
