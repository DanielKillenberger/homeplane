package skills

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stubBin writes an executable shell script and returns its path. The stubs
// reproduce the two harnesses' REAL output shapes, captured from the installed
// CLIs (claude 2.1.227, codex-cli 0.146.0), so the parsers are tested against
// the format they will actually meet.
func stubBin(t *testing.T, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub binaries are shell scripts")
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// The real first line of `claude -p --output-format stream-json --verbose`,
// trimmed to the fields the probe reads. The `skills` array is the harness's
// own enumeration, which is the whole proof.
const claudeInitLine = `{"type":"system","subtype":"init","cwd":"/w","session_id":"s","tools":["Bash"],"mcp_servers":[],"model":"m","slash_commands":["professional-writing","doctor"],"skills":["professional-writing","casual-writing"],"plugins":[]}`

// The real `codex debug prompt-input` shape: a developer message whose text
// carries the <skills_instructions> block, each entry ending in its resolved
// file locator.
const codexPromptInput = `[
  {"type":"message","role":"developer","content":[{"type":"input_text","text":"<skills_instructions>\n## Skills\n### Available skills\n- professional-writing: How Daniel writes. (file: /vault/skills/professional-writing/SKILL.md)\n- imagegen: Generate images. (file: /sys/imagegen/SKILL.md)\n- hosted-thing: An orchestrator resource. (orchestrator resource: opaque)\n</skills_instructions>"}]},
  {"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}
]`

func TestDiscoverClaudeReadsInitEvent(t *testing.T) {
	// Trailing output after the init line must not matter: the probe reads one
	// line and kills the process.
	bin := stubBin(t, "claude", "echo '"+claudeInitLine+"'\necho '{\"type\":\"assistant\"}'\n")
	v := Verifier{ClaudeBin: bin}

	got, err := v.Discover(context.Background(), ClaudeCode)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !got.Has("professional-writing") || !got.Has("casual-writing") {
		t.Fatalf("slugs = %v", got.Slugs)
	}
	if got.Has("nope") {
		t.Fatal("Has must not match an absent skill")
	}
}

func TestDiscoverCodexReadsPromptInput(t *testing.T) {
	bin := stubBin(t, "codex", "cat <<'EOF'\n"+codexPromptInput+"\nEOF\n")
	v := Verifier{CodexBin: bin}

	got, err := v.Discover(context.Background(), Codex)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !got.Has("professional-writing") {
		t.Fatalf("slugs = %v", got.Slugs)
	}
	if got.Paths["professional-writing"] != "/vault/skills/professional-writing/SKILL.md" {
		t.Fatalf("paths = %v; the locator is what shows the canonical file is in the vault", got.Paths)
	}
	// A non-file locator is not a filesystem skill and must not be read as one.
	if got.Has("hosted-thing") {
		t.Fatalf("a non-file locator was parsed as a filesystem skill: %v", got.Slugs)
	}
}

// A machine with hooks configured emits `system`/`hook_started` events before
// the init event. Daniel's real Claude Code does; a first-line-only reader
// failed there and nowhere else, so the prelude is a regression test.
func TestDiscoverClaudeSkipsHookPrelude(t *testing.T) {
	bin := stubBin(t, "claude",
		"echo '{\"type\":\"system\",\"subtype\":\"hook_started\"}'\n"+
			"echo '{\"type\":\"system\",\"subtype\":\"hook_completed\"}'\n"+
			"echo '"+claudeInitLine+"'\n")
	got, err := (Verifier{ClaudeBin: bin}).Discover(context.Background(), ClaudeCode)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !got.Has("professional-writing") {
		t.Fatalf("slugs = %v", got.Slugs)
	}
}

func TestDiscoverRejectsUnusableHarnessOutput(t *testing.T) {
	cases := []struct {
		harness string
		bin     string
		script  string
	}{
		{ClaudeCode, "claude", "echo 'not json'\n"},
		// Structured output that never carries an init event: the probe must
		// give up with a reason rather than report an empty skill list as a pass.
		{ClaudeCode, "claude", "echo '{\"type\":\"assistant\"}'\n"},
		{ClaudeCode, "claude", "echo 'boom' >&2\nexit 1\n"},
		{Codex, "codex", "echo 'not json'\n"},
		{Codex, "codex", "echo 'boom' >&2\nexit 3\n"},
	}
	for _, tc := range cases {
		bin := stubBin(t, tc.bin, tc.script)
		v := Verifier{ClaudeBin: bin, CodexBin: bin}
		if _, err := v.Discover(context.Background(), tc.harness); err == nil {
			t.Fatalf("%s: unusable output must be an error, not an empty pass", tc.harness)
		}
	}
	if _, err := (Verifier{}).Discover(context.Background(), "cursor"); err == nil {
		t.Fatal("an unknown harness must error")
	}
}

// Verification is the proof, so a link the harness does not enumerate FAILS.
// Without this the command could report success on a directory the harness
// never read.
func TestVerifyFailsWhenTheHarnessDoesNotSeeTheSkill(t *testing.T) {
	claude := stubBin(t, "claude", "echo '"+claudeInitLine+"'\n")
	codex := stubBin(t, "codex", "cat <<'EOF'\n"+codexPromptInput+"\nEOF\n")
	v := Verifier{ClaudeBin: claude, CodexBin: codex}

	report := Report{Harnesses: []HarnessReport{
		{Harness: ClaudeCode, Results: []LinkResult{{Slug: "professional-writing", Action: ActionLinked}}},
		{Harness: Codex, Results: []LinkResult{{Slug: "karpathy-guidelines", Action: ActionLinked}}},
	}}
	err := v.Verify(context.Background(), &report)
	if err == nil {
		t.Fatal("a link the harness never enumerated must fail verification")
	}
	if !strings.Contains(err.Error(), "karpathy-guidelines") {
		t.Fatalf("err = %v, want it to name the missing skill", err)
	}
	if report.Harnesses[0].VerifyError != "" {
		t.Fatalf("claude-code verified fine but reports %q", report.Harnesses[0].VerifyError)
	}
	if len(report.Harnesses[0].Verified) == 0 {
		t.Fatal("a passing harness must record what it enumerated")
	}
	if report.Harnesses[1].VerifyError == "" {
		t.Fatal("the failing harness must record why")
	}
}

func TestVerifyPassesAndSkipsEmptyHarnesses(t *testing.T) {
	claude := stubBin(t, "claude", "echo '"+claudeInitLine+"'\n")
	v := Verifier{ClaudeBin: claude, CodexBin: "/nonexistent/codex"}

	report := Report{Harnesses: []HarnessReport{
		{Harness: ClaudeCode, Results: []LinkResult{{Slug: "professional-writing", Action: ActionUnchanged}}},
		// Nothing was linked here, so the probe must not run — and must not
		// fail on a harness this machine does not have.
		{Harness: Codex, Results: []LinkResult{{Slug: "hermes", Action: ActionSkipped}}},
	}}
	if err := v.Verify(context.Background(), &report); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Harnesses[1].Verified != nil || report.Harnesses[1].VerifyError != "" {
		t.Fatal("a harness with nothing linked must not be probed")
	}
}
