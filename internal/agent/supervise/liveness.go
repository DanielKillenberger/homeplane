package supervise

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// Liveness: is the supervised process ACTUALLY running?
//
// The restart ledger cannot answer that on its own, and pretending otherwise is
// a specific, dangerous bug. A process records its own start and its own exit —
// but a SIGKILLed process records nothing on the way out. The ledger then ends
// on a start event forever, and any status derived from "the last event was a
// start" reports a healthy sync for a process that died months ago and was
// never restarted.
//
// So liveness is an EXTERNAL observation, and the ledger only supplies the
// candidate pid. Two probes are offered:
//
//	ProcessProbe     signal 0 to the recorded pid — cheap, no supervisor needed,
//	                 and correct for the same-user processes Homeplane supervises.
//	SupervisorProbe  ask launchd/systemd directly, through an injected runner.
//
// Both can answer "I don't know", which is reported as unknown rather than
// guessed — the same rule the rest of status follows.

// Liveness is what a probe observed.
type Liveness struct {
	// Alive is meaningful only when Known is true.
	Alive bool
	// Known is false when the probe could not establish the fact.
	Known bool
	// Detail explains the observation for a human reading `status`.
	Detail string
}

// Probe observes whether the unit behind a ledger is running.
type Probe func(Ledger) Liveness

// ErrNoProbe is returned by helpers that need a probe and were given none.
var ErrNoProbe = errors.New("supervise: no liveness probe configured")

// ProcessProbe checks the pid the supervised process recorded at its last
// start, using signal 0 — the standard "does this process exist and may I
// signal it" test. It is the default because it needs no supervisor, no runner,
// and no privileges beyond the ones the agent already has over its own children.
//
// The pid-reuse caveat is real but bounded: a reused pid would have to belong to
// another process owned by the same user, and the answer is still strictly
// better than trusting a start event with no exit.
func ProcessProbe(l Ledger) Liveness {
	start, ok := l.LastStart()
	if !ok {
		return Liveness{Known: true, Alive: false, Detail: "never started"}
	}
	if exit, ok := l.LastExit(); ok && exit.At.After(start.At) {
		return Liveness{Known: true, Alive: false,
			Detail: fmt.Sprintf("exited with code %d at %s", exit.Code, exit.At.UTC().Format(time.RFC3339))}
	}
	if start.PID <= 0 {
		return Liveness{Known: false, Detail: "the last start recorded no pid"}
	}
	proc, err := os.FindProcess(start.PID)
	if err != nil {
		return Liveness{Known: true, Alive: false, Detail: fmt.Sprintf("pid %d is gone", start.PID)}
	}
	switch err := proc.Signal(syscall.Signal(0)); {
	case err == nil:
		return Liveness{Known: true, Alive: true, Detail: fmt.Sprintf("pid %d is alive", start.PID)}
	case errors.Is(err, os.ErrProcessDone), errors.Is(err, syscall.ESRCH):
		// The load-bearing case: a start with no recorded exit, because the
		// process was killed rather than allowed to record one.
		return Liveness{Known: true, Alive: false,
			Detail: fmt.Sprintf("pid %d is gone and recorded no exit (killed)", start.PID)}
	case errors.Is(err, syscall.EPERM):
		// It exists but belongs to someone else — almost certainly a reused pid.
		return Liveness{Known: false, Detail: fmt.Sprintf("pid %d is not ours (reused?)", start.PID)}
	default:
		return Liveness{Known: false, Detail: fmt.Sprintf("pid %d: %v", start.PID, err)}
	}
}

// SupervisorProbe asks launchd or systemd whether the unit is running.
//
// It is the authoritative answer where it is available, and it needs a runner —
// which `status` deliberately does not have by default, because a status command
// should not shell out to the supervisor on every invocation. Callers that want
// it (a diagnostic command, or a machine where pids are not trustworthy) pass it
// explicitly.
func SupervisorProbe(platform Platform, uid string, run func(name string, args ...string) (string, error)) Probe {
	return func(l Ledger) Liveness {
		if run == nil {
			return Liveness{Known: false, Detail: ErrNoProbe.Error()}
		}
		switch platform {
		case Launchd:
			out, err := run("launchctl", "print", "gui/"+uid+"/"+l.Label)
			if err != nil {
				// launchctl exits non-zero when the unit is not loaded at all.
				return Liveness{Known: true, Alive: false, Detail: "launchd does not have " + l.Label + " loaded"}
			}
			if strings.Contains(out, "state = running") {
				return Liveness{Known: true, Alive: true, Detail: "launchd reports it running"}
			}
			return Liveness{Known: true, Alive: false, Detail: "launchd has it loaded but not running"}
		case Systemd:
			out, err := run("systemctl", "--user", "is-active", serviceName(l.Label))
			state := strings.TrimSpace(out)
			if err != nil && state == "" {
				return Liveness{Known: false, Detail: "systemctl could not be queried"}
			}
			if state == "active" {
				return Liveness{Known: true, Alive: true, Detail: "systemd reports it active"}
			}
			return Liveness{Known: true, Alive: false, Detail: "systemd reports it " + state}
		default:
			return Liveness{Known: false, Detail: fmt.Sprintf("%v: %s", ErrUnsupportedPlatform, platform)}
		}
	}
}

// Observe applies a probe to a tracker's ledger, defaulting to ProcessProbe.
func (t Tracker) Observe(probe Probe) (Ledger, Liveness, error) {
	ledger, err := t.Load()
	if err != nil {
		return Ledger{}, Liveness{}, err
	}
	if probe == nil {
		probe = ProcessProbe
	}
	return ledger, probe(ledger), nil
}
