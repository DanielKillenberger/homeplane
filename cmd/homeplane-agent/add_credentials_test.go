package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

// The flow itself is proven end to end in internal/agent/credflow. These cases
// cover what only the CLI can get wrong: telling an operator plainly what they
// mistyped, and refusing to start when the machine has no identity to broker
// with.

func TestAddCredentialsRequiresExactlyOneProvider(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	for _, args := range [][]string{
		{"add-credentials"},
		{"add-credentials", "one", "two"},
	} {
		res := invoke(t, append(args, "-state-dir", dir)...)
		if res.code != exitUsage {
			t.Errorf("%v: exit %d, want %d (stderr %q)", args, res.code, exitUsage, res.stderr)
		}
		if !strings.Contains(res.stderr, "provider") {
			t.Errorf("%v: stderr does not mention the provider argument: %q", args, res.stderr)
		}
	}
}

func TestAddCredentialsOnAnUnenrolledMachineExitsNotEnrolled(t *testing.T) {
	cp := newControlPlane(t)
	dir := filepath.Join(t.TempDir(), "state")

	res := invoke(t, "add-credentials", "some-provider", "-server", cp.URL, "-state-dir", dir)
	if res.code != agent.ExitNotEnrolled {
		t.Fatalf("exit %d, want %d (stderr %q)", res.code, agent.ExitNotEnrolled, res.stderr)
	}
	if !strings.Contains(res.stderr, "enrol") {
		t.Errorf("stderr does not point at enrolment: %q", res.stderr)
	}
}

// TestAddCredentialsAgainstAServerWithoutTheBrokerFailsClearly — the skeleton's
// control plane only routes credential flows when it has a connector manifest,
// so an operator will hit this while wiring a server up.
func TestAddCredentialsAgainstAServerWithoutTheBrokerFailsClearly(t *testing.T) {
	cp := newControlPlane(t)
	dir := filepath.Join(t.TempDir(), "state")
	if enrolled := invoke(t, "enrol", "-server", cp.URL, "-name", "cli-machine", "-state-dir", dir); enrolled.code != 0 {
		t.Fatalf("enrol: exit %d (stderr %q)", enrolled.code, enrolled.stderr)
	}

	res := invoke(t, "add-credentials", "some-provider", "-state-dir", dir, "-no-browser", "-timeout", "5s")
	if res.code != 1 {
		t.Fatalf("exit %d, want 1 (stderr %q)", res.code, res.stderr)
	}
	if !strings.Contains(res.stderr, "server refused the request") {
		t.Errorf("stderr does not report the server's refusal: %q", res.stderr)
	}
}
