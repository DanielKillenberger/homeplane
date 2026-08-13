package supervise

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The bug these tests exist for: a SIGKILLed process records no exit, so the
// ledger ends on a start event forever. Anything that reads "the last event was
// a start" as liveness reports a healthy service for a process that died months
// ago and was never restarted.

func ledgerWith(t *testing.T, starts []Start, exits []Exit) Ledger {
	t.Helper()
	tr := Tracker{Dir: t.TempDir(), Label: "com.homeplane.vault-sync"}
	for _, s := range starts {
		if _, err := tr.RecordStart(s.At, s.PID, s.Reason); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range exits {
		if _, err := tr.RecordExit(e.At, e.Code, e.Detail); err != nil {
			t.Fatal(err)
		}
	}
	l, err := tr.Load()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A start with NO exit and NO restart, whose process is gone. This is the real
// SIGKILL shape — nothing simulates an exit, because a killed process cannot
// record one.
func TestProcessProbeCatchesAKilledProcessThatRecordedNoExit(t *testing.T) {
	// A genuinely dead pid: start a real process, reap it, then ask about it.
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}

	l := ledgerWith(t, []Start{{At: time.Now().Add(-90 * 24 * time.Hour), PID: pid}}, nil)
	if !l.SelfReportedRunning() {
		t.Fatal("the ledger should still BELIEVE it is running — that is the trap")
	}

	live := ProcessProbe(l)
	if !live.Known {
		t.Fatalf("probe = %+v, want a definite answer for a reaped pid", live)
	}
	if live.Alive {
		t.Fatalf("probe = %+v, want not alive", live)
	}
	if !strings.Contains(live.Detail, "recorded no exit") {
		t.Fatalf("detail = %q, want it to name the missing exit", live.Detail)
	}
}

func TestProcessProbeSeesALiveProcess(t *testing.T) {
	l := ledgerWith(t, []Start{{At: time.Now().Add(-time.Hour), PID: os.Getpid()}}, nil)
	live := ProcessProbe(l)
	if !live.Known || !live.Alive {
		t.Fatalf("probe = %+v, want alive for our own pid", live)
	}
}

func TestProcessProbeUsesARecordedExitWhenThereIsOne(t *testing.T) {
	base := time.Now().Add(-time.Hour)
	l := ledgerWith(t,
		[]Start{{At: base, PID: os.Getpid()}},
		[]Exit{{At: base.Add(time.Minute), Code: 3, Detail: "clean stop"}},
	)
	live := ProcessProbe(l)
	if !live.Known || live.Alive {
		t.Fatalf("probe = %+v, want a recorded exit to win", live)
	}
	if !strings.Contains(live.Detail, "code 3") {
		t.Fatalf("detail = %q, want the exit code", live.Detail)
	}
}

func TestProcessProbeNeverStarted(t *testing.T) {
	live := ProcessProbe(ledgerWith(t, nil, nil))
	if !live.Known || live.Alive {
		t.Fatalf("probe = %+v, want a definite not-running", live)
	}
}

// No pid means the probe cannot answer, and it says so rather than guessing.
func TestProcessProbeWithoutAPIDIsUnknown(t *testing.T) {
	live := ProcessProbe(ledgerWith(t, []Start{{At: time.Now(), PID: 0}}, nil))
	if live.Known {
		t.Fatalf("probe = %+v, want unknown", live)
	}
}

func TestSupervisorProbeLaunchd(t *testing.T) {
	l := ledgerWith(t, []Start{{At: time.Now(), PID: os.Getpid()}}, nil)

	running := SupervisorProbe(Launchd, "501", func(string, ...string) (string, error) {
		return "state = running\npid = 4242\n", nil
	})(l)
	if !running.Known || !running.Alive {
		t.Fatalf("probe = %+v, want alive", running)
	}

	loaded := SupervisorProbe(Launchd, "501", func(string, ...string) (string, error) {
		return "state = not running\n", nil
	})(l)
	if !loaded.Known || loaded.Alive {
		t.Fatalf("probe = %+v, want loaded-but-not-running", loaded)
	}

	absent := SupervisorProbe(Launchd, "501", func(string, ...string) (string, error) {
		return "", errors.New("Could not find service")
	})(l)
	if !absent.Known || absent.Alive {
		t.Fatalf("probe = %+v, want not loaded", absent)
	}
	if !strings.Contains(absent.Detail, "loaded") {
		t.Fatalf("detail = %q", absent.Detail)
	}
}

func TestSupervisorProbeSystemd(t *testing.T) {
	l := ledgerWith(t, []Start{{At: time.Now(), PID: os.Getpid()}}, nil)

	active := SupervisorProbe(Systemd, "1000", func(name string, args ...string) (string, error) {
		joined := name + " " + strings.Join(args, " ")
		if !strings.Contains(joined, "homeplane-vault-sync.service") {
			t.Fatalf("systemd probe asked about %q", joined)
		}
		return "active\n", nil
	})(l)
	if !active.Known || !active.Alive {
		t.Fatalf("probe = %+v, want active", active)
	}

	// `systemctl is-active` exits non-zero for an inactive unit but still
	// prints the state — that is an answer, not a failure.
	inactive := SupervisorProbe(Systemd, "1000", func(string, ...string) (string, error) {
		return "inactive\n", errors.New("exit status 3")
	})(l)
	if !inactive.Known || inactive.Alive {
		t.Fatalf("probe = %+v, want inactive", inactive)
	}

	unusable := SupervisorProbe(Systemd, "1000", func(string, ...string) (string, error) {
		return "", errors.New("systemctl not found")
	})(l)
	if unusable.Known {
		t.Fatalf("probe = %+v, want unknown", unusable)
	}
}

func TestSupervisorProbeNeedsARunner(t *testing.T) {
	l := ledgerWith(t, []Start{{At: time.Now(), PID: os.Getpid()}}, nil)
	live := SupervisorProbe(Launchd, "501", nil)(l)
	if live.Known {
		t.Fatalf("probe = %+v, want unknown without a runner", live)
	}
}

func TestObserveDefaultsToTheProcessProbe(t *testing.T) {
	tr := Tracker{Dir: t.TempDir(), Label: "com.homeplane.vault-sync"}
	if _, err := tr.RecordStart(time.Now(), os.Getpid(), ""); err != nil {
		t.Fatal(err)
	}
	ledger, live, err := tr.Observe(nil)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if ledger.TotalStarts != 1 {
		t.Fatalf("ledger = %+v", ledger)
	}
	if !live.Known || !live.Alive {
		t.Fatalf("liveness = %+v, want alive", live)
	}
}

// The ledger's own summary must not claim liveness — that is the probe's job.
func TestSummaryMakesNoLivenessClaim(t *testing.T) {
	l := ledgerWith(t, []Start{{At: time.Unix(1000, 0), PID: 4242}}, nil)
	s := l.Summary(time.Unix(2000, 0))
	for _, forbidden := range []string{"running", "alive", "healthy"} {
		if strings.Contains(strings.ToLower(s), forbidden) {
			t.Fatalf("summary claims liveness: %q", s)
		}
	}
}
