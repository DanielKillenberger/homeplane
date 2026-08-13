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

	store, err := Open(dir)
	if err != nil {
		return EnrolOutcome{}, err
	}
	// Load through the store so unrecognised keys written by later tasks are
	// carried across the rewrite.
	state, _, err := store.Load()
	if err != nil {
		return EnrolOutcome{}, err
	}

	now := time.Now().UTC()
	state.SchemaVersion = StateSchemaVersion
	state.ServerURL = client.BaseURL()
	state.MachineID = res.MachineID
	state.MachineName = name
	state.OS = osName
	state.CredentialVersion = res.CredentialVersion
	if state.EnroledAt.IsZero() {
		state.EnroledAt = now
	}
	if res.Rotated {
		rotated := now
		state.RotatedAt = &rotated
	}

	if err := store.SaveEnrolment(state, res.MachineCredential); err != nil {
		return EnrolOutcome{}, err
	}

	return EnrolOutcome{
		MachineID:         res.MachineID,
		MachineName:       name,
		ServerURL:         state.ServerURL,
		StateDir:          dir,
		Rotated:           res.Rotated,
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
