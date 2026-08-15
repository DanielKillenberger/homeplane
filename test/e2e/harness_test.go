//go:build live_e2e

package e2e_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Driving the real harnesses.
//
// A connector call "from a harness" cannot be simulated: the whole point of R6,
// R7 and R8 is that Claude Code and Codex — configured by this machine, holding
// their own grant tokens — reach Homeplane's surfaces the way they will on any
// ordinary day. Both harnesses invoke MCP tools only inside a model turn, so the
// proof runs one: `claude -p` and `codex exec` with the tool named explicitly.
//
// What is NEVER trusted is the model's prose. A harness that claims to have
// created an event proves nothing; the server's audit log is the authority, and
// every assertion in the connector stages reads it. The harness leg proves the
// call was made from that harness with that grant — the audit proves what the
// call actually was.

type harnessOutput struct {
	ok   bool
	text string
	res  result
}

// claudeTimeout bounds a model turn generously: a first turn on a cold MCP
// server pays for the server's own startup too.
const harnessTurnTimeout = 8 * time.Minute

// claude runs one non-interactive Claude Code turn with a tool allowlist.
//
// --allowedTools pre-authorizes exactly the MCP surface under proof, so the turn
// never waits on a permission prompt no one is there to answer, and cannot
// wander into tools this proof is not about. The harness runs AS CONFIGURED —
// the user's own settings, hooks and MCP entries — because that is the thing
// being proven.
func (s *stage) claude(what, prompt string, allowPrefixes ...string) harnessOutput {
	s.t.Helper()
	args := []string{"-p", prompt, "--output-format", "json"}
	for _, p := range allowPrefixes {
		args = append(args, "--allowedTools", p)
	}
	res := s.run(what+" [claude -p]", harnessTurnTimeout, "claude", args...)
	out := harnessOutput{res: res}
	var envelope struct {
		Type    string `json:"type"`
		Subtype string `json:"subtype"`
		IsError bool   `json:"is_error"`
		Result  string `json:"result"`
	}
	if err := json.Unmarshal([]byte(res.full), &envelope); err == nil {
		out.text = envelope.Result
		out.ok = res.ExitCode == 0 && !envelope.IsError
	} else {
		out.text = res.full
		out.ok = res.ExitCode == 0
	}
	return out
}

// codex runs one non-interactive Codex turn.
//
// The approval flag is not a shortcut and was not the first choice. Codex 0.146
// routes every MCP tool call through its approval path, and in `codex exec`
// there is no human to answer it: with `approval_policy="never"` the call comes
// back `user cancelled MCP tool call` in under a second, and the same happens
// with the guardian feature flag turned off. The documented non-interactive
// escape hatch is this flag — established empirically here, and recorded as the
// boundary of Codex's non-interactive surface rather than hidden.
//
// The exposure is bounded by the prompt rather than by the sandbox, so the
// prompts this proof sends are mechanical: one named tool call with fixed
// arguments and an explicit instruction to run no shell commands.
func (s *stage) codex(what, prompt string) harnessOutput {
	s.t.Helper()
	args := []string{"exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
		"--color", "never", prompt}
	res := s.run(what+" [codex exec]", harnessTurnTimeout, "codex", args...)
	return harnessOutput{ok: res.ExitCode == 0, text: res.full, res: res}
}

// grok runs one non-interactive grok turn, from a process that is FRESH by
// construction.
//
// `--leader-socket <a path that does not exist>` is the whole fresh-process
// contract (docs/decisions/fn3-grok-surfaces.md §4): a leader cannot be attached
// to a socket that is not there, so the invocation reads its configuration from
// disk because it has no alternative — rather than because no leader happened to
// be running. `grok leader kill` is never called: it would stop Daniel's
// sessions, and the socket discipline is exactly why the proof never needs it.
//
// `--always-approve` is grok's non-interactive escape hatch, the counterpart of
// the flag the Codex turn carries and for the same reason: `grok -p` has no
// human to answer a tool-approval prompt. As with Codex, the exposure is bounded
// by the PROMPT rather than by a sandbox, so every prompt this proof sends names
// one tool call with fixed arguments and forbids shell commands outright.
func (s *stage) grok(what, prompt string) harnessOutput {
	s.t.Helper()
	socket := filepath.Join(s.t.TempDir(), "no-such-leader.sock")
	args := []string{"--leader-socket", socket, "--always-approve", "-p", prompt}
	res := s.run(what+" [grok -p]", harnessTurnTimeout, "grok", args...)
	// grok's headless mode prints the model's reply on stdout as plain text.
	// The raw text is what the assertions read, for the same reason the Codex
	// leg reads raw text: the claim is about what came back, and re-shaping it
	// first is a chance to lose the thing being proven.
	return harnessOutput{ok: res.ExitCode == 0, text: res.full, res: res}
}

// grokFreshProcess asserts the fresh-process contract's other half: that no
// leader is running at all on this machine, so the proof cannot be quietly
// passing because a resident process happened to hold the right config.
//
// A machine that DOES run a leader fails here loudly instead of proving nothing.
func (s *stage) grokFreshProcess() bool {
	s.t.Helper()
	socket := filepath.Join(s.t.TempDir(), "no-such-leader.sock")
	res := s.run("grok leader list (there must be no resident leader to defeat)", 2*time.Minute,
		"grok", "--leader-socket", socket, "leader", "list")
	out := strings.ToLower(res.full + res.Stderr)
	return s.assert("grok runs no resident leader, and every proof invocation names a socket that does not exist",
		res.ExitCode == 0 && strings.Contains(out, "no leader"),
		"`grok leader list` exit %d: %s; proof socket: %s", res.ExitCode, firstLine(res.full+res.Stderr), socket)
}

// harnessCall asks a harness to make ONE named tool call with exactly these
// arguments and to report what came back.
//
// The instruction is deliberately mechanical. A model asked to "create a test
// event" would choose its own arguments; the proof needs the arguments the
// manifest's guards are written about (send_updates above all), so they are
// spelled out and the harness is told not to improvise.
func toolPrompt(server, tool string, args map[string]any, extra string) string {
	body, _ := json.MarshalIndent(args, "", "  ")
	// The tool is named in its fully-qualified form, and the prompt says out
	// loud that the server exposes many tools. Without that, a model that
	// enumerates the surface first can decide the request is ambiguous — one run
	// answered "Refused: expected exactly one homeplane get_events tool, found
	// 24" and made no call at all, which is a proof step that neither passed nor
	// failed for any reason to do with Homeplane.
	return "Call the MCP tool `" + server + "/" + tool + "` — the tool named `" + tool +
		"` on the MCP server named `" + server + "`. That server exposes many tools; call only this one, " +
		"and do not look for another server or a differently named tool.\n\n" +
		"Use EXACTLY these arguments:\n\n```json\n" + string(body) + "\n```\n\n" +
		"Do not add, remove or change any argument. Make exactly one tool call and run no shell commands. " +
		"Then reply with the tool's raw result text and nothing else. " +
		"If the call is refused or errors, reply with that text verbatim — an error IS the answer here, " +
		"and must not be turned into a refusal to call." + extra
}

// repoRoot locates the repository from the test's own directory.
func repoRoot(s *stage) string {
	s.t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		wd, _ := os.Getwd()
		return filepath.Join(wd, "..", "..")
	}
	return strings.TrimSpace(string(out))
}
