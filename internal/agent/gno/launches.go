package gno

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Per-launch observability for the stdio endpoint.
//
// R4 asks for two different things from two different lifecycles. The daemon has
// a pid, so its history is the restart ledger. The stdio endpoint has no pid at
// all — a harness starts its own server whenever it feels like it and reaps it
// when it is done — so the only honest report is "what happened the last few
// times one was launched".
//
// A probe taken once at activation cannot answer that: the engine can be
// upgraded, the index deleted, or Bun removed the day after, and every harness
// launch would fail while `status` kept quoting a week-old success. So the
// descriptor does not point harnesses at GNO directly. It points them at
// `homeplane-agent gno mcp`, which records the launch here and then becomes the
// engine. Every launch a harness performs lands in this ledger, including the
// ones that fail before the engine produces a single byte.
//
// The wrapper is deliberately thin: it execs the derived upstream template with
// the harness's own pipes attached. It never parses, buffers, or interprets the
// MCP stream — an observer that could corrupt the thing it observes would be a
// bad trade for the visibility it buys.

// LaunchLedgerSchemaVersion is bumped when the on-disk shape changes.
const LaunchLedgerSchemaVersion = 1

// maxRetainedLaunches bounds the file. A harness that reconnects in a loop must
// not be able to grow it without limit.
const maxRetainedLaunches = 25

// Launch is one recorded launch of the stdio endpoint.
type Launch struct {
	At         time.Time `json:"at"`
	OK         bool      `json:"ok"`
	PID        int       `json:"pid,omitempty"`
	ExitCode   int       `json:"exit_code"`
	DurationMS int64     `json:"duration_ms"`
	Client     string    `json:"client,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// LaunchLedger is the recent history of stdio endpoint launches.
type LaunchLedger struct {
	SchemaVersion int      `json:"schema_version"`
	TotalLaunches int      `json:"total_launches"`
	TotalFailures int      `json:"total_failures"`
	Launches      []Launch `json:"launches"`
}

// LaunchLedgerPath is where the stdio launch history lives.
func LaunchLedgerPath(stateDir string) string {
	return filepath.Join(DescriptorDir(stateDir), ComponentRetrievalEngine+".launches.json")
}

// LoadLaunchLedger reads the launch history. A missing file is an empty ledger,
// not an error: a machine whose harnesses have never started the endpoint is a
// normal machine.
func LoadLaunchLedger(stateDir string) (LaunchLedger, error) {
	raw, err := os.ReadFile(LaunchLedgerPath(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return LaunchLedger{SchemaVersion: LaunchLedgerSchemaVersion}, nil
		}
		return LaunchLedger{}, fmt.Errorf("gno: read launch ledger: %w", err)
	}
	var l LaunchLedger
	if err := json.Unmarshal(raw, &l); err != nil {
		return LaunchLedger{}, fmt.Errorf("gno: parse %s: %w", LaunchLedgerPath(stateDir), err)
	}
	return l, nil
}

// RecordLaunch appends one launch outcome.
func RecordLaunch(stateDir string, launch Launch) (LaunchLedger, error) {
	ledger, err := LoadLaunchLedger(stateDir)
	if err != nil {
		// A corrupt ledger must not stop a harness from starting the endpoint:
		// observability is worth less than the capability it observes.
		ledger = LaunchLedger{}
	}
	ledger.SchemaVersion = LaunchLedgerSchemaVersion
	ledger.TotalLaunches++
	if !launch.OK {
		ledger.TotalFailures++
	}
	launch.At = launch.At.UTC()
	ledger.Launches = append(ledger.Launches, launch)
	if len(ledger.Launches) > maxRetainedLaunches {
		ledger.Launches = append([]Launch(nil), ledger.Launches[len(ledger.Launches)-maxRetainedLaunches:]...)
	}

	raw, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return ledger, fmt.Errorf("gno: encode launch ledger: %w", err)
	}
	if err := os.MkdirAll(DescriptorDir(stateDir), dirPerm); err != nil {
		return ledger, fmt.Errorf("gno: create endpoint directory: %w", err)
	}
	if err := writeFileAtomic(LaunchLedgerPath(stateDir), append(raw, '\n'), filePerm); err != nil {
		return ledger, fmt.Errorf("gno: write launch ledger: %w", err)
	}
	return ledger, nil
}

// LastLaunch returns the most recent launch, if any.
func (l LaunchLedger) LastLaunch() (Launch, bool) {
	if len(l.Launches) == 0 {
		return Launch{}, false
	}
	return l.Launches[len(l.Launches)-1], true
}

// ConsecutiveFailures counts failures at the end of the history. One failed
// launch is a bad moment; several in a row is a broken endpoint.
func (l LaunchLedger) ConsecutiveFailures() int {
	n := 0
	for i := len(l.Launches) - 1; i >= 0; i-- {
		if l.Launches[i].OK {
			return n
		}
		n++
	}
	return n
}

// Summary is the one-line detail `status` prints for the stdio endpoint.
//
// It never claims a running process — there is not one — and it always carries
// the timestamp of whatever it is reporting, so a stale success reads as stale.
func (l LaunchLedger) Summary() string {
	last, ok := l.LastLaunch()
	if !ok {
		return "stdio endpoint: never launched by a harness"
	}
	when := last.At.UTC().Format(time.RFC3339)
	if last.OK {
		s := fmt.Sprintf("stdio endpoint: last launch ok at %s (%d launches", when, l.TotalLaunches)
		if l.TotalFailures > 0 {
			s += fmt.Sprintf(", %d failed", l.TotalFailures)
		}
		return s + ")"
	}
	return fmt.Sprintf("stdio endpoint: last launch FAILED at %s (%d consecutive; %s)",
		when, l.ConsecutiveFailures(), firstLine(last.Detail))
}

// StdioOptions parameterises one wrapped launch.
type StdioOptions struct {
	StateDir string
	// Command, Args, and Env are the DERIVED upstream launch template, taken
	// from the activation record so the wrapper runs exactly what upstream said
	// to run and never re-derives an argv of its own.
	Command string
	Args    []string
	Env     map[string]string
	// Stdin/Stdout/Stderr are the harness's own pipes, passed straight through.
	Stdin  *os.File
	Stdout *os.File
	Stderr *os.File
	// Client, when known, names the harness.
	Client string
	Now    func() time.Time
}

// RunStdioEndpoint launches the engine's stdio MCP server for a harness and
// records the outcome.
//
// The recording happens when the launch ENDS, not when it begins: a session a
// harness holds open for an hour is reported only once it closes. That is a
// deliberate limit rather than an oversight — the failures R4 cares about
// (missing runtime, deleted index, version drift) all exit immediately, so they
// reach `status` at once, and pretending to report a live session would put this
// component right back into claiming a pid it does not have.
func RunStdioEndpoint(ctx context.Context, opts StdioOptions) error {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	started := now()
	record := func(l Launch) {
		l.At = started
		l.DurationMS = now().Sub(started).Milliseconds()
		l.Client = opts.Client
		// A failure to record must never take down the endpoint itself.
		_, _ = RecordLaunch(opts.StateDir, l)
	}

	if strings.TrimSpace(opts.Command) == "" {
		err := errors.New("gno: the activation record has no stdio launch template — run `homeplane-agent gno activate`")
		record(Launch{OK: false, ExitCode: -1, Detail: err.Error()})
		return err
	}

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = mergeEnv(opts.Env)
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	if err := cmd.Start(); err != nil {
		record(Launch{OK: false, ExitCode: -1, Detail: "launch failed: " + err.Error()})
		return fmt.Errorf("gno: launch the stdio endpoint: %w", err)
	}
	pid := cmd.Process.Pid
	err := cmd.Wait()
	if err != nil {
		code := -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		record(Launch{OK: false, PID: pid, ExitCode: code, Detail: firstLine(err.Error())})
		return fmt.Errorf("gno: the stdio endpoint exited with an error: %w", err)
	}
	record(Launch{OK: true, PID: pid, ExitCode: 0})
	return nil
}

// Client identifies the harness that launched the endpoint, when it says so.
// MCP clients do not announce themselves before the server starts, so this is
// taken from the environment the harness passes down and is best-effort.
func ClientFromEnv(environ []string) string {
	for _, kv := range environ {
		key, value, _ := strings.Cut(kv, "=")
		switch key {
		case "HOMEPLANE_HARNESS", "CLAUDECODE", "CLAUDE_CODE", "CODEX_SANDBOX":
			if strings.TrimSpace(value) != "" {
				return key + "=" + value
			}
		}
	}
	return ""
}
