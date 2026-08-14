package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"

	"github.com/DanielKillenberger/homeplane/internal/agent/credflow"
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

// TestAddCredentialsReportsStoredButUndeliverable. The credential is stored, so
// nobody should be sent back through a consent screen — and it is not usable, so
// nobody should be told this worked. The command has to say both, and exit
// non-zero, because a caller that sees success is entitled to assume the next
// connector call will work.
func TestAddCredentialsReportsStoredButUndeliverable(t *testing.T) {
	res := credflow.Result{
		Provider:  "google",
		State:     "completed",
		ErrorCode: "delivery_failed",
		Message:   "the credential is stored on the server, but the connector could not be given it",
	}
	if res.Succeeded() != true {
		t.Fatal("a stored credential must still count as stored")
	}
	if res.Ready() {
		t.Fatal("a credential the connector cannot read was reported as ready")
	}

	clean := credflow.Result{Provider: "google", State: "completed"}
	if !clean.Ready() {
		t.Fatal("an ordinary success was not reported as ready")
	}
	denied := credflow.Result{Provider: "google", State: "denied", ErrorCode: "provider_denied"}
	if denied.Succeeded() || denied.Ready() {
		t.Fatal("a denied flow was reported as stored or ready")
	}
}
