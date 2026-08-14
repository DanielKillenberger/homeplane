package supervise

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Restart tracking.
//
// launchd and systemd both restart a dead process, and both of them will do it
// forever without telling anyone. A supervised process that dies every four
// seconds looks, to `status`, exactly like a supervised process that is running
// — unless something on the machine counts the restarts. That is this ledger's
// only job, and it is why R4 and R14 can both say "crash-loop surfaced".
//
// The supervised process itself records its own start, so this works the same
// on launchd and systemd without parsing either supervisor's logs.

// LedgerSchemaVersion is bumped when the on-disk ledger shape changes.
const LedgerSchemaVersion = 1

const (
	ledgerFilePerm fs.FileMode = 0o600
	ledgerDirPerm  fs.FileMode = 0o700
)

// DefaultCrashLoopWindow and DefaultCrashLoopThreshold define "crash-looping":
// more than a handful of starts inside a few minutes is not a service being
// restarted, it is a service failing to start.
const (
	DefaultCrashLoopWindow    = 5 * time.Minute
	DefaultCrashLoopThreshold = 5
)

// Start is one recorded launch of a supervised process.
type Start struct {
	At     time.Time `json:"at"`
	PID    int       `json:"pid"`
	Reason string    `json:"reason,omitempty"`
}

// Exit is one recorded termination.
type Exit struct {
	At     time.Time `json:"at"`
	Code   int       `json:"code"`
	Detail string    `json:"detail,omitempty"`
}

// Ledger is the restart history of one supervised unit.
type Ledger struct {
	SchemaVersion int     `json:"schema_version"`
	Label         string  `json:"label"`
	TotalStarts   int     `json:"total_starts"`
	TotalExits    int     `json:"total_exits"`
	Starts        []Start `json:"starts"`
	Exits         []Exit  `json:"exits"`
}

// maxRetained bounds the ledger so a long-lived machine cannot grow it without
// limit. The totals are kept exactly; only the detailed history is trimmed.
const maxRetained = 50

// StartsWithin counts starts in the window ending at now.
func (l Ledger) StartsWithin(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	n := 0
	for _, s := range l.Starts {
		if s.At.After(cutoff) {
			n++
		}
	}
	return n
}

// CrashLooping reports whether the unit restarted more than threshold times
// inside the window.
func (l Ledger) CrashLooping(now time.Time, window time.Duration, threshold int) bool {
	if window <= 0 {
		window = DefaultCrashLoopWindow
	}
	if threshold <= 0 {
		threshold = DefaultCrashLoopThreshold
	}
	return l.StartsWithin(now, window) > threshold
}

// LastStart returns the most recent start, if any.
func (l Ledger) LastStart() (Start, bool) {
	if len(l.Starts) == 0 {
		return Start{}, false
	}
	return l.Starts[len(l.Starts)-1], true
}

// LastExit returns the most recent exit, if any.
func (l Ledger) LastExit() (Exit, bool) {
	if len(l.Exits) == 0 {
		return Exit{}, false
	}
	return l.Exits[len(l.Exits)-1], true
}

// SelfReportedRunning says only that the last recorded EVENT was a start.
//
// It is NOT liveness, and it must never be used as liveness. A process that is
// SIGKILLed never records an exit, so this stays true forever for a process
// that died months ago. Use a supervise.Probe (ProcessProbe by default) to find
// out whether anything is actually running; this exists so a probe can tell
// "believed up, and it is" from "believed up, but the pid is gone".
func (l Ledger) SelfReportedRunning() bool {
	last, ok := l.LastStart()
	if !ok {
		return false
	}
	exit, ok := l.LastExit()
	if !ok {
		return true
	}
	return last.At.After(exit.At)
}

// Summary is the one-line detail `status` prints for a supervised component.
//
// It reports HISTORY only — counts, timestamps, the last exit. It deliberately
// makes no claim about whether the process is up; that comes from a probe.
func (l Ledger) Summary(now time.Time) string {
	if l.TotalStarts == 0 {
		return "never started"
	}
	last, _ := l.LastStart()
	s := fmt.Sprintf("%d starts (last %s", l.TotalStarts, last.At.UTC().Format(time.RFC3339))
	if last.PID > 0 && l.SelfReportedRunning() {
		s += fmt.Sprintf(", pid %d", last.PID)
	}
	s += ")"
	if l.CrashLooping(now, DefaultCrashLoopWindow, DefaultCrashLoopThreshold) {
		s += fmt.Sprintf(" — CRASH-LOOPING: %d starts in the last %s",
			l.StartsWithin(now, DefaultCrashLoopWindow), DefaultCrashLoopWindow)
	}
	if exit, ok := l.LastExit(); ok && !l.SelfReportedRunning() {
		s += fmt.Sprintf("; last exit code %d", exit.Code)
	}
	return s
}

// Tracker persists a ledger for one unit.
type Tracker struct {
	// Dir is the directory holding ledger files (the agent state dir).
	Dir string
	// Label identifies the unit.
	Label string
}

// Path is the ledger's file path.
func (t Tracker) Path() string {
	return filepath.Join(t.Dir, "supervise", t.Label+".restarts.json")
}

// Load reads the ledger. A missing file is an empty ledger, not an error.
func (t Tracker) Load() (Ledger, error) {
	raw, err := os.ReadFile(t.Path())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Ledger{SchemaVersion: LedgerSchemaVersion, Label: t.Label}, nil
		}
		return Ledger{}, fmt.Errorf("supervise: read restart ledger: %w", err)
	}
	var l Ledger
	if err := json.Unmarshal(raw, &l); err != nil {
		return Ledger{}, fmt.Errorf("supervise: parse restart ledger %s: %w", t.Path(), err)
	}
	if l.Label == "" {
		l.Label = t.Label
	}
	return l, nil
}

// RecordStart appends a start and persists the ledger.
func (t Tracker) RecordStart(now time.Time, pid int, reason string) (Ledger, error) {
	return t.mutate(func(l *Ledger) {
		l.TotalStarts++
		l.Starts = append(l.Starts, Start{At: now.UTC(), PID: pid, Reason: reason})
		l.Starts = trimStarts(l.Starts)
	})
}

// RecordExit appends an exit and persists the ledger.
func (t Tracker) RecordExit(now time.Time, code int, detail string) (Ledger, error) {
	return t.mutate(func(l *Ledger) {
		l.TotalExits++
		l.Exits = append(l.Exits, Exit{At: now.UTC(), Code: code, Detail: detail})
		l.Exits = trimExits(l.Exits)
	})
}

// Reset clears the ledger, used when a unit is deliberately reinstalled.
func (t Tracker) Reset() error {
	if err := os.Remove(t.Path()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("supervise: reset restart ledger: %w", err)
	}
	return nil
}

func (t Tracker) mutate(fn func(*Ledger)) (Ledger, error) {
	if t.Dir == "" || t.Label == "" {
		return Ledger{}, errors.New("supervise: tracker needs a directory and a label")
	}
	l, err := t.Load()
	if err != nil {
		return Ledger{}, err
	}
	l.SchemaVersion = LedgerSchemaVersion
	l.Label = t.Label
	fn(&l)
	sort.SliceStable(l.Starts, func(i, j int) bool { return l.Starts[i].At.Before(l.Starts[j].At) })
	sort.SliceStable(l.Exits, func(i, j int) bool { return l.Exits[i].At.Before(l.Exits[j].At) })

	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return Ledger{}, fmt.Errorf("supervise: encode restart ledger: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(t.Path()), ledgerDirPerm); err != nil {
		return Ledger{}, fmt.Errorf("supervise: create ledger directory: %w", err)
	}
	if err := writeFileAtomic(t.Path(), append(raw, '\n'), ledgerFilePerm); err != nil {
		return Ledger{}, fmt.Errorf("supervise: write restart ledger: %w", err)
	}
	return l, nil
}

func trimStarts(s []Start) []Start {
	if len(s) <= maxRetained {
		return s
	}
	return append([]Start(nil), s[len(s)-maxRetained:]...)
}

func trimExits(s []Exit) []Exit {
	if len(s) <= maxRetained {
		return s
	}
	return append([]Exit(nil), s[len(s)-maxRetained:]...)
}

func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
