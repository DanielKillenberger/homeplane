package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

type fakeResolver struct{ id store.Identity }

func (f fakeResolver) Resolve(context.Context, string) (store.Identity, error) { return f.id, nil }

// newControlPlane runs the real control plane over loopback.
func newControlPlane(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, fakeResolver{id: store.Identity{NodeID: "node-cli", NodeName: "cli"}}, checker,
		server.Config{Policy: policy.Default()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

type result struct {
	code   int
	stdout string
	stderr string
}

func invoke(t *testing.T, args ...string) result {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(context.Background(), args, &out, &errBuf)
	return result{code: code, stdout: out.String(), stderr: errBuf.String()}
}

func TestEnrolThenStatusReportsADegradedButEnrolledMachine(t *testing.T) {
	cp := newControlPlane(t)
	dir := filepath.Join(t.TempDir(), "state")

	enrolled := invoke(t, "enrol", "-server", cp.URL, "-name", "cli-machine", "-state-dir", dir)
	if enrolled.code != 0 {
		t.Fatalf("enrol exit = %d, stderr: %s", enrolled.code, enrolled.stderr)
	}
	if !strings.Contains(enrolled.stdout, "enrolled machine") {
		t.Errorf("enrol stdout = %q", enrolled.stdout)
	}

	// The credential must never reach a terminal, a log, or a pipeline.
	credential, err := os.ReadFile(filepath.Join(dir, "machine.cred"))
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	secret := strings.TrimSpace(string(credential))
	if strings.Contains(enrolled.stdout+enrolled.stderr, secret) {
		t.Error("enrol printed the machine credential")
	}

	statusRes := invoke(t, "status", "-state-dir", dir)
	if statusRes.code != agent.ExitDegraded {
		t.Errorf("status exit = %d, want %d (no vault/GNO/harnesses yet)", statusRes.code, agent.ExitDegraded)
	}
	if !strings.Contains(statusRes.stdout, "enrolment") || !strings.Contains(statusRes.stdout, "grants") {
		t.Errorf("status output does not name its components:\n%s", statusRes.stdout)
	}
	if strings.Contains(statusRes.stdout, secret) {
		t.Error("status printed the machine credential")
	}

	jsonRes := invoke(t, "status", "-state-dir", dir, "-json")
	if jsonRes.code != agent.ExitDegraded {
		t.Errorf("status -json exit = %d, want %d", jsonRes.code, agent.ExitDegraded)
	}
	var report agent.Report
	if err := json.Unmarshal([]byte(jsonRes.stdout), &report); err != nil {
		t.Fatalf("status -json is not valid JSON: %v\n%s", err, jsonRes.stdout)
	}
	if !report.Enroled || report.Status != agent.OverallDegraded {
		t.Errorf("json report = %+v", report)
	}
}

func TestStatusOnAFreshMachineExitsNotEnrolled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	res := invoke(t, "status", "-state-dir", dir)
	if res.code != agent.ExitNotEnrolled {
		t.Errorf("exit = %d, want %d", res.code, agent.ExitNotEnrolled)
	}
	if !strings.Contains(res.stdout, "not_enrolled") {
		t.Errorf("stdout = %q, want it to say the machine is not enrolled", res.stdout)
	}
}

func TestEnrolAgainstAnUnreachableServerFails(t *testing.T) {
	cp := newControlPlane(t)
	url := cp.URL
	cp.Close()

	dir := filepath.Join(t.TempDir(), "state")
	res := invoke(t, "enrol", "-server", url, "-state-dir", dir, "-timeout", "2s")
	if res.code == 0 {
		t.Fatal("enrol against a dead server exited 0")
	}
	if !strings.Contains(res.stderr, "unreachable") {
		t.Errorf("stderr = %q, want an actionable unreachable-server message", res.stderr)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("failed enrolment created a state directory")
	}
}

func TestUsageErrors(t *testing.T) {
	if res := invoke(t); res.code != exitUsage {
		t.Errorf("no subcommand: exit = %d, want %d", res.code, exitUsage)
	}
	if res := invoke(t, "wat"); res.code != exitUsage {
		t.Errorf("unknown subcommand: exit = %d, want %d", res.code, exitUsage)
	}
	if res := invoke(t, "status", "extra-arg"); res.code != exitUsage {
		t.Errorf("stray argument: exit = %d, want %d", res.code, exitUsage)
	}
	if res := invoke(t, "help"); res.code != 0 || !strings.Contains(res.stdout, "homeplane-agent") {
		t.Errorf("help: exit = %d, stdout = %q", res.code, res.stdout)
	}
}
