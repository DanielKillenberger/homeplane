package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// EnrolOptions describes one enrolment attempt.
type EnrolOptions struct {
	// StateDir is the agent state directory. It is created only AFTER the
	// server has answered successfully.
	StateDir string
	// ServerURL is the control plane's address. Empty reuses the URL recorded
	// by a previous enrolment.
	ServerURL string
	// MachineName defaults to the OS hostname, OS to runtime.GOOS.
	MachineName string
	OS          string
	Timeout     time.Duration
}

// EnrolOutcome is what an enrolment did.
type EnrolOutcome struct {
	MachineID         string
	MachineName       string
	ServerURL         string
	StateDir          string
	Rotated           bool
	CredentialVersion int64
}

// Enrol registers this machine with the control plane, or rotates its
// credential if it is already enrolled.
//
// Ordering is the whole design here:
//
//  1. Existing state is READ without creating anything, so an enrolment that
//     never reaches the server leaves a fresh machine exactly as it found it —
//     no state directory, no half-written credential (R2: "unreachable →
//     actionable error, no partial local state").
//  2. The server is called. A re-enrol from the same tailnet node lands on the
//     same machine record and rotates its credential (identity-preserving);
//     the previous credential is dead the moment the server answers.
//  3. Only then is the new credential persisted — atomically, and before this
//     function acknowledges success to anyone.
func Enrol(ctx context.Context, opts EnrolOptions) (EnrolOutcome, error) {
	dir := opts.StateDir
	if dir == "" {
		return EnrolOutcome{}, errors.New("agent: state directory is required")
	}

	prior, _, err := PeekState(dir)
	if err != nil {
		return EnrolOutcome{}, err
	}

	serverURL := strings.TrimSpace(opts.ServerURL)
	if serverURL == "" {
		serverURL = prior.ServerURL
	}
	if serverURL == "" {
		return EnrolOutcome{}, errors.New("agent: no server URL given and none recorded from a previous enrolment (pass -server or set " + EnvServerURL + ")")
	}

	name := strings.TrimSpace(opts.MachineName)
	if name == "" {
		name = prior.MachineName
	}
	if name == "" {
		name, err = os.Hostname()
		if err != nil || strings.TrimSpace(name) == "" {
			return EnrolOutcome{}, fmt.Errorf("agent: could not determine a machine name (pass -name): %w", err)
		}
	}
	osName := strings.TrimSpace(opts.OS)
	if osName == "" {
		osName = runtime.GOOS
	}

	client, err := NewClient(serverURL, opts.Timeout)
	if err != nil {
		return EnrolOutcome{}, err
	}

	res, err := client.Enrol(ctx, name, osName)
	if err != nil {
		if Unreachable(err) {
			return EnrolOutcome{}, fmt.Errorf("%w\nNothing was written to %s. Check that the server is running and reachable over the tailnet, then re-run `homeplane-agent enrol`.", err, dir)
		}
		return EnrolOutcome{}, err
	}

	return PersistEnrolment(dir, res, EnrolIdentity{
		ServerURL:   client.BaseURL(),
		MachineName: name,
		OS:          osName,
	})
}

// EnrolIdentity is the non-secret metadata recorded alongside an enrolment
// response.
type EnrolIdentity struct {
	ServerURL   string
	MachineName string
	OS          string
}

// ErrStaleEnrolment means the response being persisted is older than the
// credential already on disk, so writing it would leave this machine holding a
// credential the server has already superseded.
var ErrStaleEnrolment = errors.New("agent: enrolment response is older than the stored credential")

// PersistEnrolment writes an enrolment response to the state directory.
//
// It is separated from the network call, and exported, because this is the step
// that has to be safe against CONCURRENCY. Two enrolments racing (a retry and
// its predecessor, a human and a scheduled job) each rotate the server-side
// credential, and the server only honours the newest. If the loser's older
// response landed last, the machine would be left holding a dead credential and
// would only discover it at the next authenticated call.
//
// Two mechanisms, because one is not enough:
//
//   - The state directory is locked, so the read-modify-write of state.json and
//     machine.cred cannot interleave with another process's.
//   - Under that lock, a response whose credential version is not NEWER than
//     the stored one for the same machine is refused outright. This is what
//     protects the case a lock cannot: a filesystem that ignores advisory
//     locks, or two responses ordered differently than they were issued.
func PersistEnrolment(dir string, res EnrolResult, id EnrolIdentity) (EnrolOutcome, error) {
	if res.MachineID == "" || res.MachineCredential == "" {
		return EnrolOutcome{}, errors.New("agent: enrolment response is missing machine identity or credential")
	}

	store, err := Open(dir)
	if err != nil {
		return EnrolOutcome{}, err
	}
	release, err := store.Lock()
	if err != nil {
		return EnrolOutcome{}, err
	}
	defer release()

	// Load INSIDE the lock: anything read before it could already be stale, and
	// this is also what carries unrecognised keys written by later tasks across
	// the rewrite.
	state, hadState, err := store.Load()
	if err != nil {
		return EnrolOutcome{}, err
	}

	if hadState && state.MachineID == res.MachineID && state.CredentialVersion >= res.CredentialVersion {
		// Note what is NOT done here: nothing is written, and no error is raised
		// about the machine's health. The machine is fine — it holds the newer
		// credential. Only THIS response is discarded.
		return EnrolOutcome{}, fmt.Errorf(
			"%w: credential version %d is already stored, this response carries %d. The stored credential is the live one; nothing was changed",
			ErrStaleEnrolment, state.CredentialVersion, res.CredentialVersion)
	}

	now := time.Now().UTC()
	rotated := res.Rotated
	state.SchemaVersion = StateSchemaVersion
	state.ServerURL = id.ServerURL
	state.MachineID = res.MachineID
	state.MachineName = id.MachineName
	state.OS = id.OS
	state.CredentialVersion = res.CredentialVersion
	if state.EnroledAt.IsZero() {
		state.EnroledAt = now
	}
	if rotated {
		rotatedAt := now
		state.RotatedAt = &rotatedAt
	}

	if err := store.SaveEnrolment(state, res.MachineCredential); err != nil {
		return EnrolOutcome{}, err
	}

	return EnrolOutcome{
		MachineID:         res.MachineID,
		MachineName:       id.MachineName,
		ServerURL:         state.ServerURL,
		StateDir:          dir,
		Rotated:           rotated,
		CredentialVersion: res.CredentialVersion,
	}, nil
}

// PeekState reads state.json from dir WITHOUT creating the directory. It is
// how enrolment consults prior state before it has earned the right to write
// anything, and how status inspects a machine that may never have enrolled.
func PeekState(dir string) (State, bool, error) {
	probe := &Store{dir: dir}
	return probe.Load()
}
