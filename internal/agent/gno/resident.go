package gno

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The resident-runtime lock, and why Homeplane is allowed to clear it.
//
// GNO serializes access to an index with a "resident runtime" lock: one holder
// per index, kept by a small detached process that holds a flock on
// `<data dir>/.resident-owner.lock`. When the engine exits cleanly it releases
// it. When the engine is KILLED — a harness closing a stdio session, a
// supervisor booting a unit out, a laptop sleeping through a restart — the
// holder can outlive it, and every later start fails with
//
//	Error: Resident runtime already active for index "default".
//	Stop the owning gno serve or gno daemon process and retry.
//
// which on a supervised machine is a crash loop that no amount of restarting
// fixes. It cost this proof two rounds of manual recovery before it was
// understood, and it would cost an operator a machine that is simply down.
//
// Clearing another process's lock is normally the wrong instinct, so the
// argument for it here is narrow and rests on ownership: the index directory is
// Homeplane's own machine-local state (R14 — outside the vault, never
// synchronized, disposable and rebuildable). Nothing but a Homeplane-launched
// engine has any business holding a lock inside it. A holder whose engine is
// gone is therefore stranded by construction, and the only question left is
// whether it is really stranded — which is why the holder is identified by the
// exact lock path in its argv and stopped politely before it is killed.
//
// A holder belonging to some OTHER index (a human running `gno` on their own
// vault, in their own data directory) has a different path in its argv and is
// never matched.

// residentLockName is the file GNO's resident-runtime holder locks.
const residentLockName = ".resident-owner.lock"

// ResidentLockPath is the resident-runtime lock for a data directory.
func ResidentLockPath(dataDir string) string { return filepath.Join(dataDir, residentLockName) }

// ReclaimResult reports what a reclaim did, so the caller can log it rather
// than kill processes quietly.
type ReclaimResult struct {
	// LockPath is the lock that was examined.
	LockPath string
	// Holders are the pids found holding it.
	Holders []int
	// Stopped are the pids that exited after being asked.
	Stopped []int
	// Killed are the pids that had to be killed after the grace period.
	Killed []int
	// Detail explains an outcome that is neither "nothing to do" nor "cleared".
	Detail string
}

// Cleared reports whether anything was actually reclaimed.
func (r ReclaimResult) Cleared() bool { return len(r.Stopped)+len(r.Killed) > 0 }

// Summary renders the result for a log line or a status detail.
func (r ReclaimResult) Summary() string {
	switch {
	case r.Detail != "":
		return r.Detail
	case !r.Cleared():
		return "no stranded resident-runtime holder"
	default:
		return fmt.Sprintf("reclaimed the resident-runtime lock from %d stranded holder(s) (%s)",
			len(r.Stopped)+len(r.Killed), pidList(append(append([]int{}, r.Stopped...), r.Killed...)))
	}
}

// ReclaimResidentRuntime clears a stranded holder of the index's resident lock.
//
// It is a no-op when the lock file does not exist, when nothing holds it, or
// when the only holder is this process's own child. `grace` bounds how long a
// holder gets to exit after SIGTERM before it is killed.
func ReclaimResidentRuntime(ctx context.Context, dataDir string, grace time.Duration) (ReclaimResult, error) {
	res := ReclaimResult{LockPath: ResidentLockPath(dataDir)}
	if strings.TrimSpace(dataDir) == "" {
		return res, errors.New("gno: no data directory to reclaim")
	}
	if _, err := os.Stat(res.LockPath); err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return res, fmt.Errorf("gno: examine the resident-runtime lock: %w", err)
	}
	if grace <= 0 {
		grace = 3 * time.Second
	}

	holders, err := lockHolders(ctx, res.LockPath)
	if err != nil {
		// Not being able to LOOK is not a licence to kill anything, and it is
		// also not a failure to start: the engine's own error is clearer than a
		// guess would be.
		res.Detail = "could not identify the resident-runtime holder: " + err.Error()
		return res, nil
	}
	res.Holders = holders
	self := os.Getpid()
	for _, pid := range holders {
		if pid == self {
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				continue // it exited between the scan and now
			}
			res.Detail = fmt.Sprintf("could not stop the resident-runtime holder %d: %v", pid, err)
			return res, nil
		}
		if waitForExit(pid, grace) {
			res.Stopped = append(res.Stopped, pid)
			continue
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			res.Detail = fmt.Sprintf("could not kill the resident-runtime holder %d: %v", pid, err)
			return res, nil
		}
		waitForExit(pid, grace)
		res.Killed = append(res.Killed, pid)
	}
	return res, nil
}

// lockHolders finds processes whose argv names this exact lock file.
//
// `pgrep -f` is used rather than lsof because the holder is a process STARTED
// with the lock path as an argument, so the path is in its command line — and
// pgrep exists on both platforms this agent supports, while lsof is not
// guaranteed. The match is the full path, so a holder for another index (a
// human's own `gno` on their own data directory) cannot match.
func lockHolders(ctx context.Context, lockPath string) ([]int, error) {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", lockPath)
	out, err := cmd.Output()
	if err != nil {
		// pgrep exits 1 when nothing matched, which is the ordinary case.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		pid, convErr := strconv.Atoi(strings.TrimSpace(line))
		if convErr != nil || pid <= 1 {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// waitForExit polls until the process is gone or the grace period ends. Signal 0
// is the portable "does this process still exist" probe.
func waitForExit(pid int, grace time.Duration) bool {
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return syscall.Kill(pid, 0) != nil
}

func pidList(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, p := range pids {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ", ")
}
