package skills

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real shape of `grok inspect`, taken from the installed grok 1.0.3 while
// the fn-3 e2e test ran it: indented section headings carrying a count, entries
// prefixed with a tree glyph, skills reporting a scope word and MCP servers
// reporting a transport and a source. The parser is tested against THAT, never
// against a shape this package would have preferred.
const grokInspectOutput = `  Environment
  └ Version: 1.0.3 [unknown]
  └ CWD: /w
  └ Project trusted: yes

  MCP Servers (2)
  └ gno (stdio)                ~/.grok/config.toml [config]
  └ homeplane (http)           ~/.grok/config.toml [config]

  Skills (3)
  └ professional-writing       user
  └ casual-writing             user
  └ frontmatter-beta-name      user

  Commands (0)
  └ (none)
`

func TestDiscoverGrokReadsTheSkillsSection(t *testing.T) {
	bin := stubBin(t, "grok", "cat <<'EOF'\n"+grokInspectOutput+"EOF\n")
	v := Verifier{GrokBin: bin}

	got, err := v.Discover(context.Background(), Grok)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, want := range []string{"professional-writing", "casual-writing", "frontmatter-beta-name"} {
		if !got.Has(want) {
			t.Errorf("slugs = %v, missing %s", got.Slugs, want)
		}
	}
	// The MCP section carries entries in the same tree shape. Reading one as a
	// skill would report a connector as provisioned.
	for _, mcp := range []string{"gno", "homeplane"} {
		if got.Has(mcp) {
			t.Errorf("an MCP server was reported as a skill: %v", got.Slugs)
		}
	}
	if got.Has("(none)") || got.Has("Version:") {
		t.Errorf("non-skill lines leaked into the enumeration: %v", got.Slugs)
	}
}

// Every invocation carries `--leader-socket <a path that does not exist>`.
//
// grok supports a resident leader process which could, in principle, answer
// from configuration it read before Homeplane wrote any. No leader exists on
// this machine today — but that is a fact about a moment, not a guarantee, and
// R3/R4's proof has to defeat a stale resident process BY CONSTRUCTION rather
// than by coincidence. A leader cannot be attached to a socket that is not
// there.
func TestTheGrokProbeCannotBeServedByAResidentLeader(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	bin := stubBin(t, "grok", "echo \"$@\" > "+argvFile+"\ncat <<'EOF'\n"+grokInspectOutput+"EOF\n")

	if _, err := (Verifier{GrokBin: bin}).Discover(context.Background(), Grok); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(argv))
	var socket string
	for i, f := range fields {
		if f == "--leader-socket" && i+1 < len(fields) {
			socket = fields[i+1]
		}
	}
	if socket == "" {
		t.Fatalf("the probe did not pass --leader-socket: %q", string(argv))
	}
	if _, err := os.Lstat(socket); err == nil {
		t.Fatalf("--leader-socket %s exists; a leader could be attached to it", socket)
	}
	// `grok leader kill` would stop Daniel's running sessions. The construction
	// above is why the proof never needs it.
	if strings.Contains(string(argv), "kill") {
		t.Fatal("the probe tried to kill a leader")
	}
}

// A probe that hangs must fail the verification, not the machine. grok's own
// docs describe a TUI; a binary that never returns is exactly what a timeout is
// for.
func TestAGrokProbeThatHangsTimesOutRatherThanBlocks(t *testing.T) {
	bin := stubBin(t, "grok", "sleep 30\n")
	v := Verifier{GrokBin: bin, Timeout: 200 * time.Millisecond}

	start := time.Now()
	_, err := v.Discover(context.Background(), Grok)
	if err == nil {
		t.Fatal("a hanging probe was reported as a successful enumeration")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the probe blocked for %s", elapsed)
	}
	if !strings.Contains(err.Error(), "grok") {
		t.Errorf("err = %v, which does not name the harness that hung", err)
	}
}

// Output this build cannot read is an ERROR, never an empty enumeration.
// "grok listed nothing" and "we could not read grok's answer" are different
// facts, and reporting the second as the first turns an upstream format change
// into a silent verification pass.
func TestGrokOutputWithoutASkillsSectionFailsLoudly(t *testing.T) {
	bin := stubBin(t, "grok", "echo '  Environment'\necho '  └ Version: 9.9.9 [unknown]'\n")

	_, err := (Verifier{GrokBin: bin}).Discover(context.Background(), Grok)
	if err == nil {
		t.Fatal("unreadable output was reported as an empty skill list")
	}
	if !strings.Contains(err.Error(), "capture-grok-contract.sh") {
		t.Errorf("err = %v, which does not tell the operator how to re-establish the contract", err)
	}
}

// A link we created that the harness does not enumerate is a FAILURE. The link
// is our claim; the fresh process is the proof, and R15 rests on the second.
func TestALinkGrokDoesNotEnumerateFailsVerification(t *testing.T) {
	bin := stubBin(t, "grok", "cat <<'EOF'\n"+grokInspectOutput+"EOF\n")
	report := &Report{Harnesses: []HarnessReport{{
		Harness: Grok,
		Results: []LinkResult{
			{Slug: "professional-writing", Action: ActionLinked},
			{Slug: "never-discovered", Action: ActionLinked},
		},
	}}}

	err := (Verifier{GrokBin: bin}).Verify(context.Background(), report)
	if err == nil {
		t.Fatal("a link grok never enumerated passed verification")
	}
	if !strings.Contains(report.Harnesses[0].VerifyError, "never-discovered") {
		t.Errorf("verify error = %q, which does not name the missing skill", report.Harnesses[0].VerifyError)
	}
}

// A harness with nothing expected is not probed at all: every skill assigned to
// it was marked unsupported, so there is no claim to prove and no reason to
// spawn a process. The stub below FAILS if it is ever run, which is what makes
// "was not probed" an assertion rather than an absence.
func TestAHarnessWithOnlyUnsupportedSkillsIsNotProbed(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	bin := stubBin(t, "grok", "touch "+marker+"\nexit 1\n")
	report := &Report{Harnesses: []HarnessReport{{
		Harness: Grok,
		Results: []LinkResult{
			{Slug: "phone-home-coordinator", Action: ActionSkipped},
		},
	}}}

	if err := (Verifier{GrokBin: bin}).Verify(context.Background(), report); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("grok was spawned to prove a claim nobody made")
	}
	if report.Harnesses[0].VerifyError != "" {
		t.Errorf("verify error = %q for a harness with nothing to verify", report.Harnesses[0].VerifyError)
	}
}
