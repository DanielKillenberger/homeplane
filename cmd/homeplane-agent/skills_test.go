package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/skills"
)

// skillsMachine is a whole machine for the CLI: a vault with a profile, an
// agent state directory that already names that vault, and fixture harness
// directories. Nothing here reaches the operator's own vault or harnesses.
type skillsMachine struct {
	vault    string
	stateDir string
	claude   string
	codex    string
}

func newSkillsMachine(t *testing.T, profile string, slugs ...string) skillsMachine {
	t.Helper()
	base := t.TempDir()
	m := skillsMachine{
		vault:    filepath.Join(base, "vault"),
		stateDir: filepath.Join(base, "state"),
		claude:   filepath.Join(base, "claude"),
		codex:    filepath.Join(base, "codex"),
	}
	skillsRoot := filepath.Join(m.vault, "skills")
	for _, d := range []string{skillsRoot, m.stateDir, m.claude, m.codex} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, slug := range slugs {
		dir := filepath.Join(skillsRoot, slug)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		md := "---\nname: " + slug + "\ndescription: The " + slug + " skill.\n---\n\n# " + slug + "\nInstructions.\n"
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if profile != "" {
		if err := os.WriteFile(filepath.Join(skillsRoot, skills.ProfileFileName), []byte(profile), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The vault path comes from state, exactly as it does in production: `vault
	// detect -record` puts it there and every later command reads it.
	store, err := agent.Open(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(agent.State{
		SchemaVersion: agent.StateSchemaVersion,
		ServerURL:     "http://example.invalid",
		MachineID:     "machine-1",
		MachineName:   "studio",
		VaultPath:     m.vault,
	}); err != nil {
		t.Fatal(err)
	}

	t.Setenv(skills.EnvClaudeConfigDir, m.claude)
	t.Setenv(skills.EnvCodexHome, m.codex)
	return m
}

func (m skillsMachine) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	full := append([]string{"skills"}, args...)
	full = append(full, "-state-dir", m.stateDir)
	code := run(context.Background(), full, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

const cliProfile = `
schema  = 1
profile = "cli-test"

[defaults]
skills = ["professional-writing", "casual-writing"]

[harness.codex]
skills = ["professional-writing"]
`

func TestSkillsListShowsVaultAndAssignments(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing", "casual-writing")

	code, stdout, stderr := m.run(t, "list", "-json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var listing struct {
		Profile  string              `json:"profile"`
		Skills   []skills.Skill      `json:"skills"`
		Assigned map[string][]string `json:"assigned"`
	}
	if err := json.Unmarshal([]byte(stdout), &listing); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if listing.Profile != "cli-test" || len(listing.Skills) != 2 {
		t.Fatalf("listing = %+v", listing)
	}
	if len(listing.Assigned[skills.ClaudeCode]) != 2 || len(listing.Assigned[skills.Codex]) != 1 {
		t.Fatalf("assignments = %v; the per-harness override did not apply", listing.Assigned)
	}
}

func TestSkillsProvisionLinksAndRecordsState(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing", "casual-writing")

	code, stdout, stderr := m.run(t, "provision")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "linked") {
		t.Fatalf("stdout does not report links:\n%s", stdout)
	}

	for _, pair := range []struct{ dir, slug string }{
		{m.claude, "professional-writing"},
		{m.claude, "casual-writing"},
		{m.codex, "professional-writing"},
	} {
		link := filepath.Join(pair.dir, "skills", pair.slug)
		info, err := os.Lstat(link)
		if err != nil {
			t.Fatalf("%s was not linked: %v", link, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s is not a symlink", link)
		}
	}
	// The per-harness override must have kept casual-writing out of Codex.
	if _, err := os.Lstat(filepath.Join(m.codex, "skills", "casual-writing")); err == nil {
		t.Fatal("codex got a skill its harness block does not assign")
	}

	store, err := agent.Open(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Skills) != 2 {
		t.Fatalf("state.Skills = %v, want the provisioned set", state.Skills)
	}
	// Recording must not clobber what the rest of the agent owns.
	if state.VaultPath != m.vault || state.MachineName != "studio" {
		t.Fatalf("provisioning overwrote unrelated state: %+v", state)
	}
}

// Status must describe the MACHINE, not the last run. A run narrowed to one
// harness leaves the other harness's links in place, so forgetting them would
// report a machine that has fewer skills than it does.
func TestSkillsStatusComesFromTheManifestNotTheRun(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing", "casual-writing")
	if code, _, stderr := m.run(t, "provision"); code != 0 {
		t.Fatalf("provision: %s", stderr)
	}

	// A later run touching only Codex must not erase Claude Code's skills.
	if code, _, stderr := m.run(t, "provision", "-harness", "codex"); code != 0 {
		t.Fatalf("narrowed provision: %s", stderr)
	}

	store, err := agent.Open(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Skills) != 2 {
		t.Fatalf("state.Skills = %v after a codex-only run; the claude-code links are still installed", state.Skills)
	}
	if state.SkillsHealth == nil || state.SkillsHealth.State != agent.StateOK {
		t.Fatalf("skills health = %+v, want ok", state.SkillsHealth)
	}
}

// A run whose links landed but whose harness could not see them is degraded.
// Recording ok there would tell an operator the skills layer works when no
// harness can read it.
func TestSkillsVerificationFailureIsRecordedDegraded(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing", "casual-writing")
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))

	if code, _, _ := m.run(t, "provision", "-verify"); code == 0 {
		t.Fatal("a failed verification must not exit 0")
	}
	store, err := agent.Open(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.SkillsHealth == nil || state.SkillsHealth.State != agent.StateDegraded {
		t.Fatalf("skills health = %+v, want degraded", state.SkillsHealth)
	}
	// And status must surface it rather than reporting the list as healthy.
	for _, c := range statusComponents(t, m.stateDir) {
		if c.Name == agent.ComponentSkills {
			if c.State != agent.StateDegraded {
				t.Fatalf("status skills component = %+v, want degraded", c)
			}
			return
		}
	}
	t.Fatal("status has no skills component")
}

func statusComponents(t *testing.T, stateDir string) []agent.ComponentReport {
	t.Helper()
	report, err := agent.Status(context.Background(), agent.StatusOptions{StateDir: stateDir, SkipServer: true})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return report.Components
}

func TestSkillsRefreshWithdrawsDroppedSkills(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing", "casual-writing")
	if code, _, stderr := m.run(t, "provision"); code != 0 {
		t.Fatalf("provision: %s", stderr)
	}

	narrowed := "schema = 1\nprofile = \"cli-test\"\n\n[defaults]\nskills = [\"professional-writing\"]\n"
	if err := os.WriteFile(filepath.Join(m.vault, "skills", skills.ProfileFileName), []byte(narrowed), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := m.run(t, "refresh")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "removed") {
		t.Fatalf("refresh did not report the withdrawal:\n%s", stdout)
	}
	if _, err := os.Lstat(filepath.Join(m.claude, "skills", "casual-writing")); err == nil {
		t.Fatal("the dropped skill is still linked")
	}
	if _, err := os.Lstat(filepath.Join(m.claude, "skills", "professional-writing")); err != nil {
		t.Fatalf("the still-assigned skill was withdrawn: %v", err)
	}
}

func TestSkillsRefusesWithoutAProfile(t *testing.T) {
	m := newSkillsMachine(t, "", "professional-writing")
	code, _, stderr := m.run(t, "list")
	if code == 0 {
		t.Fatal("a missing profile must not be a silent success")
	}
	if !strings.Contains(stderr, skills.ProfileFileName) {
		t.Fatalf("stderr must name the expected profile path: %s", stderr)
	}
}

func TestSkillsRefusesWithoutAVault(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"skills", "list", "-state-dir", stateDir}, &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "vault detect") {
		t.Fatalf("exit %d, stderr %q — a machine with no vault must be told what to run", code, stderr.String())
	}
}

func TestSkillsUsageErrors(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing")
	if code, _, _ := m.run(t, "frobnicate"); code != exitUsage {
		t.Fatalf("unknown subcommand exit = %d, want %d", code, exitUsage)
	}
	if code, _, _ := m.run(t, "list", "-harness", "cursor"); code != exitUsage {
		t.Fatal("an unknown harness must be a usage error")
	}
	if code, _, _ := m.run(t, "list", "extra-arg"); code != exitUsage {
		t.Fatal("an unexpected argument must be a usage error")
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"skills"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("bare `skills` exit = %d", code)
	}
}

// -verify must FAIL the command when the harness does not enumerate what was
// linked. Without that, `provision -verify` would be decoration.
func TestSkillsProvisionVerifyFailsClosed(t *testing.T) {
	m := newSkillsMachine(t, cliProfile, "professional-writing", "casual-writing")
	// No claude/codex binary can satisfy this probe, because PATH is emptied.
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))

	code, _, stderr := m.run(t, "provision", "-verify")
	if code == 0 {
		t.Fatal("verification that could not run must not report success")
	}
	if !strings.Contains(stderr, "verification failed") {
		t.Fatalf("stderr = %q", stderr)
	}
}
