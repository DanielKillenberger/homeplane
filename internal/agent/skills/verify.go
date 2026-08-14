package skills

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultVerifyTimeout bounds a harness probe. Both probes are local — neither
// needs the network to enumerate skills — so a probe that takes longer than
// this is stuck, not slow.
const DefaultVerifyTimeout = 90 * time.Second

// Verifier asks a FRESH harness process which skills it can see.
//
// This is the R15 proof, and it is deliberately not our own bookkeeping: the
// only thing that establishes provisioning is the harness itself enumerating
// the skill. Both probes were chosen because they are local and need no model
// turn:
//
//   - Claude Code emits a `system`/`init` event as the first line of
//     `--output-format stream-json`, carrying the `skills` array it discovered.
//     The probe reads that one line and kills the process, so no request is
//     made and no credential is required. Claude Code names a skill after the
//     DIRECTORY it found it in.
//
//   - Codex renders its model-visible prompt with `codex debug prompt-input`,
//     which includes a `<skills_instructions>` block listing each skill with its
//     resolved SKILL.md path. Codex names a skill after the SKILL.md
//     frontmatter `name`. The path is a bonus: it is the harness itself saying
//     the canonical file is in the vault.
type Verifier struct {
	// ClaudeBin and CodexBin are the executables to run. Empty means the
	// harness's own name on PATH.
	ClaudeBin string
	CodexBin  string
	// Env is the child's complete environment. Nil means inherit this
	// process's. Tests set HOME / CLAUDE_CONFIG_DIR / CODEX_HOME here so a
	// probe runs against a fixture harness rather than the operator's.
	Env []string
	// Dir is the child's working directory. Empty means inherit.
	Dir string
	// Timeout bounds one probe. Zero means DefaultVerifyTimeout.
	Timeout time.Duration
}

// Discovery is what one fresh harness process reported.
type Discovery struct {
	Harness string `json:"harness"`
	// Slugs are the skill names the harness itself listed, sorted.
	Slugs []string `json:"slugs"`
	// Paths maps a skill name to the SKILL.md path the harness resolved, for
	// harnesses that report one (Codex).
	Paths map[string]string `json:"paths,omitempty"`
}

// Has reports whether the harness enumerated this skill.
func (d Discovery) Has(slug string) bool {
	for _, s := range d.Slugs {
		if s == slug {
			return true
		}
	}
	return false
}

func (v Verifier) timeout() time.Duration {
	if v.Timeout > 0 {
		return v.Timeout
	}
	return DefaultVerifyTimeout
}

func (v Verifier) binary(harnessID string) string {
	switch harnessID {
	case ClaudeCode:
		if strings.TrimSpace(v.ClaudeBin) != "" {
			return v.ClaudeBin
		}
		return "claude"
	case Codex:
		if strings.TrimSpace(v.CodexBin) != "" {
			return v.CodexBin
		}
		return "codex"
	}
	return ""
}

// Discover spawns the harness and returns what it enumerated.
func (v Verifier) Discover(ctx context.Context, harnessID string) (Discovery, error) {
	switch harnessID {
	case ClaudeCode:
		return v.discoverClaude(ctx)
	case Codex:
		return v.discoverCodex(ctx)
	default:
		return Discovery{}, fmt.Errorf("skills: verify: unknown harness %q (known: %s)", harnessID, strings.Join(Known(), ", "))
	}
}

// claudeInit is the shape of Claude Code's first stream-json event.
type claudeInit struct {
	Type    string   `json:"type"`
	Subtype string   `json:"subtype"`
	Skills  []string `json:"skills"`
}

func (v Verifier) discoverClaude(ctx context.Context) (Discovery, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, v.binary(ClaudeCode),
		"-p", "homeplane skill provisioning probe",
		"--output-format", "stream-json",
		"--verbose",
		"--max-turns", "1",
	)
	cmd.Env = v.Env
	cmd.Dir = v.Dir
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Discovery{}, fmt.Errorf("skills: verify claude-code: %w", err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Discovery{}, fmt.Errorf("skills: verify claude-code: %w", err)
	}
	// The init event is emitted before any request is made. Reading it and
	// killing the process is what keeps this probe free of a model turn.
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	// The init event is not necessarily the FIRST line: a machine with hooks
	// configured emits `system`/`hook_started` events ahead of it. (Found by
	// running this against Daniel's real Claude Code, which has hooks; a
	// first-line-only reader failed there and nowhere else.) So the probe scans
	// for the init event, bounded by a line cap and the context timeout so a
	// harness that never emits one cannot hang the run.
	const maxPreludeLines = 200
	reader := bufio.NewReaderSize(stdout, 1<<20)
	var lastType string
	for i := 0; i < maxPreludeLines; i++ {
		line, readErr := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			var event claudeInit
			if err := json.Unmarshal([]byte(trimmed), &event); err == nil {
				if event.Type == "system" && event.Subtype == "init" {
					slugs := append([]string(nil), event.Skills...)
					sort.Strings(slugs)
					return Discovery{Harness: ClaudeCode, Slugs: slugs}, nil
				}
				lastType = event.Type + "/" + event.Subtype
			} else if lastType == "" {
				// Not JSON at all, and nothing structured seen yet: this is not
				// the stream-json protocol, and guessing is worse than saying so.
				return Discovery{}, fmt.Errorf("skills: verify claude-code: %s did not emit stream-json (first output: %q)",
					v.binary(ClaudeCode), truncate(trimmed, 200))
			}
		}
		if readErr != nil {
			break
		}
	}
	return Discovery{}, fmt.Errorf("skills: verify claude-code: no system/init event from %s (last event: %q); stderr: %s",
		v.binary(ClaudeCode), lastType, strings.TrimSpace(truncate(stderr.String(), 400)))
}

// codexSkillLine matches one entry of Codex's `<skills_instructions>` list:
// "- <name>: <description> (file: <path>)". Entries whose locator is not a
// file (an environment or orchestrator resource) are not filesystem skills and
// do not match.
var codexSkillLine = regexp.MustCompile(`^- ([^:\s]+): .*\(file: (.+)\)$`)

// codexPromptMessage is the shape of one `codex debug prompt-input` element.
type codexPromptMessage struct {
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func (v Verifier) discoverCodex(ctx context.Context) (Discovery, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, v.binary(Codex), "debug", "prompt-input")
	cmd.Env = v.Env
	cmd.Dir = v.Dir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Discovery{}, fmt.Errorf("skills: verify codex: %s debug prompt-input: %w; stderr: %s",
			v.binary(Codex), err, strings.TrimSpace(truncate(stderr.String(), 400)))
	}

	var messages []codexPromptMessage
	if err := json.Unmarshal([]byte(stdout.String()), &messages); err != nil {
		return Discovery{}, fmt.Errorf("skills: verify codex: prompt-input is not JSON: %w", err)
	}

	d := Discovery{Harness: Codex, Paths: map[string]string{}}
	for _, msg := range messages {
		for _, c := range msg.Content {
			if !strings.Contains(c.Text, "<skills_instructions>") {
				continue
			}
			for _, line := range strings.Split(c.Text, "\n") {
				m := codexSkillLine.FindStringSubmatch(strings.TrimRight(line, " \t"))
				if m == nil {
					continue
				}
				d.Slugs = append(d.Slugs, m[1])
				d.Paths[m[1]] = m[2]
			}
		}
	}
	sort.Strings(d.Slugs)
	return d, nil
}

// Verify probes every harness in the report and records what it found.
//
// A skill that was linked but is NOT enumerated by the fresh process fails
// verification for that harness: the link is our claim, the enumeration is the
// proof, and R15 rests on the second.
func (v Verifier) Verify(ctx context.Context, report *Report) error {
	var failures []string
	for i := range report.Harnesses {
		hr := &report.Harnesses[i]
		var expected []string
		for _, r := range hr.Results {
			switch r.Action {
			case ActionLinked, ActionUnchanged, ActionRepointed:
				expected = append(expected, r.Slug)
			}
		}
		if len(expected) == 0 {
			continue
		}

		found, err := v.Discover(ctx, hr.Harness)
		if err != nil {
			hr.VerifyError = err.Error()
			failures = append(failures, hr.Harness+": "+err.Error())
			continue
		}
		hr.Verified = found.Slugs

		var missing []string
		for _, slug := range expected {
			if !found.Has(slug) {
				missing = append(missing, slug)
			}
		}
		if len(missing) > 0 {
			msg := fmt.Sprintf("a fresh %s process did not enumerate: %s", hr.Harness, strings.Join(missing, ", "))
			hr.VerifyError = msg
			failures = append(failures, msg)
		}
	}
	if len(failures) > 0 {
		return errors.New("skills: verification failed — " + strings.Join(failures, "; "))
	}
	return nil
}

// LookHarness reports whether a harness CLI is on PATH, so a caller can skip a
// probe for a harness this machine does not have rather than fail it.
func (v Verifier) LookHarness(harnessID string) (string, error) {
	bin := v.binary(harnessID)
	if bin == "" {
		return "", fmt.Errorf("skills: unknown harness %q", harnessID)
	}
	if strings.ContainsRune(bin, os.PathSeparator) {
		if _, err := os.Stat(bin); err != nil {
			return "", err
		}
		return bin, nil
	}
	return exec.LookPath(bin)
}
