package gno

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestStdioSessionClosedByTheClientIsNotAFailure. MCP clients end a stdio
// session by signalling the server — Claude Code and Codex both SIGKILL it —
// so counting that as a failed launch made every ordinary harness session
// degrade the component. `status` then reported a working endpoint as broken,
// with a "25 consecutive failures" count made entirely of successful sessions.
func TestStdioSessionClosedByTheClientIsNotAFailure(t *testing.T) {
	state := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- RunStdioEndpoint(ctx, StdioOptions{
			StateDir: state,
			Command:  "/bin/sh",
			// A server that stays up until it is told to stop, like the real one.
			Args:   []string{"-c", "trap '' TERM; sleep 30"},
			Client: "test-harness",
		})
	}()
	// Give it a moment to start, then end the session the way a client does.
	time.Sleep(300 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("a session closed by the client reported an error: %v", err)
	}
	ledger, err := LoadLaunchLedger(state)
	if err != nil {
		t.Fatalf("LoadLaunches: %v", err)
	}
	if len(ledger.Launches) != 1 {
		t.Fatalf("ledger has %d launches, want 1", len(ledger.Launches))
	}
	l := ledger.Launches[0]
	if !l.OK {
		t.Errorf("launch recorded as a failure: %+v", l)
	}
	if !strings.Contains(l.Detail, "closed by the client") {
		t.Errorf("detail %q does not say the client closed the session", l.Detail)
	}
}

// TestStdioCrashIsStillAFailure — the other half. A server that exits non-zero
// on its own has failed, and the ledger must keep saying so.
func TestStdioCrashIsStillAFailure(t *testing.T) {
	state := t.TempDir()
	err := RunStdioEndpoint(context.Background(), StdioOptions{
		StateDir: state,
		Command:  "/bin/sh",
		Args:     []string{"-c", "exit 3"},
	})
	if err == nil {
		t.Fatal("a server that exited 3 was reported as a success")
	}
	ledger, loadErr := LoadLaunchLedger(state)
	if loadErr != nil {
		t.Fatalf("LoadLaunches: %v", loadErr)
	}
	if len(ledger.Launches) != 1 || ledger.Launches[0].OK {
		t.Fatalf("ledger = %+v, want one failed launch", ledger.Launches)
	}
}
