package gno

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A holder stranded by a killed engine blocks every later start with a message
// about the resident runtime, which on a supervised machine is a crash loop no
// restart can fix. These tests hold both halves of the narrow licence to clear
// it: a holder of OUR index's lock is reclaimed, and nothing else is touched.

func startHolder(t *testing.T, lockPath string) *exec.Cmd {
	t.Helper()
	// A stand-in for GNO's detached holder: a process whose argv names the lock,
	// which is exactly how the real one is found. The loop matters — a shell
	// given a single command execs it and the lock path leaves the argv, which
	// is a property of `sh`, not of what is being tested.
	cmd := exec.Command("/bin/sh", "-c", "while :; do sleep 0.2; done # "+lockPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start a stand-in lock holder: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// Give the process table a moment to show it.
	time.Sleep(200 * time.Millisecond)
	return cmd
}

func TestReclaimStrandedResidentHolder(t *testing.T) {
	data := t.TempDir()
	lock := ResidentLockPath(data)
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatalf("create the lock file: %v", err)
	}
	holder := startHolder(t, lock)

	res, err := ReclaimResidentRuntime(context.Background(), data, time.Second)
	if err != nil {
		t.Fatalf("ReclaimResidentRuntime: %v", err)
	}
	if !res.Cleared() {
		t.Fatalf("nothing was reclaimed: %+v (%s)", res, res.Summary())
	}
	// The holder is this test's own child, so it lingers as a zombie until it is
	// reaped — a real stranded holder is nobody's child. Reaping is how the test
	// asks what actually happened to it.
	state, waitErr := holder.Process.Wait()
	if waitErr != nil {
		t.Fatalf("wait for the holder: %v", waitErr)
	}
	if state.ExitCode() == 0 && !state.Exited() {
		t.Errorf("holder ended as %v, want a signalled or non-zero exit", state)
	}
}

// TestReclaimLeavesAnotherIndexAlone. A human running GNO on their own vault
// holds a lock in their own data directory. Matching on the full lock path is
// what keeps this narrow: their process names a different file.
func TestReclaimLeavesAnotherIndexAlone(t *testing.T) {
	ours := t.TempDir()
	theirs := filepath.Join(t.TempDir(), "someone-elses-index")
	if err := os.MkdirAll(theirs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ResidentLockPath(ours), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ResidentLockPath(theirs), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	stranger := startHolder(t, ResidentLockPath(theirs))

	res, err := ReclaimResidentRuntime(context.Background(), ours, time.Second)
	if err != nil {
		t.Fatalf("ReclaimResidentRuntime: %v", err)
	}
	if res.Cleared() {
		t.Errorf("reclaimed something while only another index had a holder: %+v", res)
	}
	if syscall.Kill(stranger.Process.Pid, 0) != nil {
		t.Error("the other index's holder was killed")
	}
}

// TestReclaimIsANoOpWithoutALock — the ordinary case on a healthy machine.
func TestReclaimIsANoOpWithoutALock(t *testing.T) {
	res, err := ReclaimResidentRuntime(context.Background(), t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("ReclaimResidentRuntime: %v", err)
	}
	if res.Cleared() || res.Detail != "" {
		t.Errorf("a directory with no lock produced %+v", res)
	}
}
