package supervise

import (
	"os"
	"testing"
	"time"
)

func TestLedgerStartsEmpty(t *testing.T) {
	tr := Tracker{Dir: t.TempDir(), Label: "com.homeplane.vault-sync"}
	l, err := tr.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if l.TotalStarts != 0 || l.Running() {
		t.Fatalf("ledger = %+v, want empty and not running", l)
	}
	if l.Summary(time.Now()) != "never started" {
		t.Fatalf("summary = %q", l.Summary(time.Now()))
	}
}

func TestRecordStartAndExit(t *testing.T) {
	dir := t.TempDir()
	tr := Tracker{Dir: dir, Label: "com.homeplane.vault-sync"}
	t0 := time.Unix(1000, 0).UTC()

	if _, err := tr.RecordStart(t0, 4242, "supervised start"); err != nil {
		t.Fatalf("RecordStart: %v", err)
	}
	l, err := tr.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !l.Running() {
		t.Fatal("ledger says not running after a start")
	}
	if start, _ := l.LastStart(); start.PID != 4242 {
		t.Fatalf("pid = %d, want 4242", start.PID)
	}

	if _, err := tr.RecordExit(t0.Add(time.Minute), 3, "killed"); err != nil {
		t.Fatalf("RecordExit: %v", err)
	}
	l, _ = tr.Load()
	if l.Running() {
		t.Fatal("ledger says running after an exit")
	}
	if exit, _ := l.LastExit(); exit.Code != 3 {
		t.Fatalf("exit code = %d, want 3", exit.Code)
	}

	// The ledger records restart counts; it must not be world-readable, since
	// it names paths and pids on the machine.
	info, err := os.Stat(tr.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("ledger mode = %o, want 0600", perm)
	}
}

// Kill → restart is the R4/R14 behaviour: each supervised launch increments the
// count, and status reports it.
func TestRestartCountSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	tr := Tracker{Dir: dir, Label: "unit"}
	base := time.Unix(5000, 0).UTC()
	for i := 0; i < 3; i++ {
		if _, err := tr.RecordStart(base.Add(time.Duration(i)*time.Hour), 100+i, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.RecordExit(base.Add(time.Duration(i)*time.Hour+time.Minute), 1, "died"); err != nil {
			t.Fatal(err)
		}
	}
	fresh := Tracker{Dir: dir, Label: "unit"}
	l, err := fresh.Load()
	if err != nil {
		t.Fatal(err)
	}
	if l.TotalStarts != 3 || l.TotalExits != 3 {
		t.Fatalf("ledger = %+v, want 3 starts and 3 exits", l)
	}
	// Spread across hours: restarts, not a crash loop.
	if l.CrashLooping(base.Add(3*time.Hour), DefaultCrashLoopWindow, DefaultCrashLoopThreshold) {
		t.Fatal("hourly restarts were misreported as a crash loop")
	}
}

func TestCrashLoopDetection(t *testing.T) {
	tr := Tracker{Dir: t.TempDir(), Label: "unit"}
	base := time.Unix(9000, 0).UTC()
	for i := 0; i < 6; i++ {
		if _, err := tr.RecordStart(base.Add(time.Duration(i)*5*time.Second), 1, ""); err != nil {
			t.Fatal(err)
		}
	}
	l, err := tr.Load()
	if err != nil {
		t.Fatal(err)
	}
	now := base.Add(time.Minute)
	if got := l.StartsWithin(now, DefaultCrashLoopWindow); got != 6 {
		t.Fatalf("starts in window = %d, want 6", got)
	}
	if !l.CrashLooping(now, DefaultCrashLoopWindow, DefaultCrashLoopThreshold) {
		t.Fatal("six starts in a minute is not a crash loop?")
	}
	// Long after the burst, the window has moved on.
	later := base.Add(time.Hour)
	if l.CrashLooping(later, DefaultCrashLoopWindow, DefaultCrashLoopThreshold) {
		t.Fatal("an old burst still reads as a crash loop")
	}
}

// A machine that has been up for months must not grow an unbounded ledger.
func TestLedgerIsBounded(t *testing.T) {
	tr := Tracker{Dir: t.TempDir(), Label: "unit"}
	base := time.Unix(1, 0).UTC()
	for i := 0; i < 120; i++ {
		if _, err := tr.RecordStart(base.Add(time.Duration(i)*time.Minute), i, ""); err != nil {
			t.Fatal(err)
		}
	}
	l, err := tr.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Starts) > maxRetained {
		t.Fatalf("retained %d starts, want at most %d", len(l.Starts), maxRetained)
	}
	// The exact total is still correct — only the detail is trimmed.
	if l.TotalStarts != 120 {
		t.Fatalf("total = %d, want 120", l.TotalStarts)
	}
}

func TestReset(t *testing.T) {
	tr := Tracker{Dir: t.TempDir(), Label: "unit"}
	if _, err := tr.RecordStart(time.Now(), 1, ""); err != nil {
		t.Fatal(err)
	}
	if err := tr.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	l, err := tr.Load()
	if err != nil {
		t.Fatal(err)
	}
	if l.TotalStarts != 0 {
		t.Fatalf("ledger survived reset: %+v", l)
	}
	// Resetting an absent ledger is not an error.
	if err := tr.Reset(); err != nil {
		t.Fatalf("second Reset: %v", err)
	}
}

func TestTrackerNeedsDirAndLabel(t *testing.T) {
	if _, err := (Tracker{Label: "x"}).RecordStart(time.Now(), 1, ""); err == nil {
		t.Fatal("a tracker without a directory was accepted")
	}
	if _, err := (Tracker{Dir: t.TempDir()}).RecordStart(time.Now(), 1, ""); err == nil {
		t.Fatal("a tracker without a label was accepted")
	}
}

func TestSummaryReportsPidAndExit(t *testing.T) {
	tr := Tracker{Dir: t.TempDir(), Label: "unit"}
	t0 := time.Unix(1000, 0).UTC()
	if _, err := tr.RecordStart(t0, 777, ""); err != nil {
		t.Fatal(err)
	}
	l, _ := tr.Load()
	if s := l.Summary(t0); !contains(s, "pid 777") {
		t.Fatalf("summary = %q, want a pid", s)
	}
	if _, err := tr.RecordExit(t0.Add(time.Second), 9, "boom"); err != nil {
		t.Fatal(err)
	}
	l, _ = tr.Load()
	if s := l.Summary(t0.Add(time.Second)); !contains(s, "last exit code 9") {
		t.Fatalf("summary = %q, want the exit code", s)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
