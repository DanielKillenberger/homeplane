package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// noAudit provides explicit no-op audit callbacks for test SEEDING. The store
// requires a callback on every mutation, so opting out is visible here rather
// than implicit.
var noAudit = struct {
	enrol func(store.Machine, bool) []store.AuditEvent
	issue func(store.Grant, *store.Grant) []store.AuditEvent
}{
	enrol: func(store.Machine, bool) []store.AuditEvent { return nil },
	issue: func(store.Grant, *store.Grant) []store.AuditEvent { return nil },
}

// seedState builds a state directory with a database, an age key, one enrolled
// machine, and one active grant — the shape the admin CLI operates on.
func seedState(t *testing.T) (dir string, machineID string, grantID string) {
	t.Helper()
	dir = t.TempDir()
	st, err := store.Open(dbPath(dir))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()
	if _, err := secrets.GenerateKeyFile(keyFilePath(dir)); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}

	ctx := context.Background()
	m, _, err := st.Enrol(ctx, store.Identity{NodeID: "node-a", NodeName: "mac-a"}, "mac-a", "darwin", "hash-a", noAudit.enrol)
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	g, _, err := st.IssueGrant(ctx, m.ID, policy.HarnessCodex, []string{string(policy.ConnectorRead)}, "tok-a", noAudit.issue)
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	return dir, m.ID, g.ID
}

// captureStdout runs fn with stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out), runErr
}

func TestAdminAuditReadsTheLogAndRecordsTheRead(t *testing.T) {
	dir, machineID, grantID := seedState(t)

	out, err := captureStdout(t, func() error {
		return runAdmin([]string{"audit", "-state-dir", dir, "-json"})
	})
	if err != nil {
		t.Fatalf("admin audit: %v", err)
	}
	if strings.TrimSpace(out) != "" {
		// The seeded rows came from the store API directly, which does not
		// audit; the first read should therefore show nothing yet.
		t.Logf("initial audit output: %s", out)
	}
	_ = machineID

	// Revoke through the CLI, which DOES audit, then read the log back.
	if _, err := captureStdout(t, func() error {
		return runAdmin([]string{"revoke-grant", "-state-dir", dir, grantID})
	}); err != nil {
		t.Fatalf("admin revoke-grant: %v", err)
	}

	out, err = captureStdout(t, func() error {
		return runAdmin([]string{"audit", "-state-dir", dir, "-json"})
	})
	if err != nil {
		t.Fatalf("admin audit: %v", err)
	}

	var sawRevocation, sawRead bool
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var e store.AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("audit line is not JSON: %v (%s)", err, line)
		}
		switch e.Event {
		case store.EventGrantRevoked:
			sawRevocation = true
			if e.ActorKind != store.ActorOperator {
				t.Errorf("operator revocation actor = %q, want operator", e.ActorKind)
			}
			// Operator actions have no observed machine: there is no network
			// caller to observe, and inventing one would be a lie in the log.
			if e.ObservedNodeID != "" {
				t.Errorf("operator event carries an observed node %q", e.ObservedNodeID)
			}
			// The affected machine is the TARGET, not the actor: an operator
			// revocation must not read as the machine revoking its own grant.
			if e.AuthMachineID != "" {
				t.Errorf("operator event claims authenticated machine %q", e.AuthMachineID)
			}
			if e.Detail["target_machine_id"] == "" {
				t.Error("operator revocation does not record the target machine")
			}
			if e.GrantID != grantID {
				t.Errorf("revocation grant = %q, want %q", e.GrantID, grantID)
			}
		case store.EventAuditQueried:
			sawRead = true
			if e.ActorKind != store.ActorOperator {
				t.Errorf("audit-read actor = %q, want operator", e.ActorKind)
			}
		}
	}
	if !sawRevocation {
		t.Error("operator revocation was not audited")
	}
	if !sawRead {
		t.Error("operator audit read was not itself audited")
	}
}

func TestAdminRevokeGrantIsIdempotentAndRejectsUnknownIDs(t *testing.T) {
	dir, _, grantID := seedState(t)

	first, err := captureStdout(t, func() error {
		return runAdmin([]string{"revoke-grant", "-state-dir", dir, grantID})
	})
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if !strings.Contains(first, "revoked grant") {
		t.Errorf("unexpected output: %q", first)
	}

	second, err := captureStdout(t, func() error {
		return runAdmin([]string{"revoke-grant", "-state-dir", dir, grantID})
	})
	if err != nil {
		t.Fatalf("repeat revoke returned an error: %v", err)
	}
	if !strings.Contains(second, "already revoked") {
		t.Errorf("repeat revoke output = %q, want an already-revoked notice", second)
	}

	if _, err := captureStdout(t, func() error {
		return runAdmin([]string{"revoke-grant", "-state-dir", dir, "g-unknown"})
	}); err == nil {
		t.Error("revoking an unknown grant succeeded")
	}
}

// TestAdminRevokeCrossesMachineBoundaries is the counterpart to the HTTP rule:
// machines may only revoke their own grants, but the server-local operator is
// exactly who may revoke anyone's.
func TestAdminRevokeCrossesMachineBoundaries(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dbPath(dir))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ctx := context.Background()
	other, _, err := st.Enrol(ctx, store.Identity{NodeID: "node-b", NodeName: "linux-b"}, "linux-b", "linux", "hash-b", noAudit.enrol)
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	g, _, err := st.IssueGrant(ctx, other.ID, policy.HarnessClaudeCode, []string{string(policy.ConnectorRead)}, "tok-b", noAudit.issue)
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := captureStdout(t, func() error {
		return runAdmin([]string{"revoke-grant", "-state-dir", dir, g.ID})
	}); err != nil {
		t.Fatalf("operator revocation of another machine's grant failed: %v", err)
	}
}

func TestAdminSecretImportRequiresProtectedInput(t *testing.T) {
	dir, _, _ := seedState(t)

	t.Run("world-readable file refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client-secret")
		if err := os.WriteFile(path, []byte("super-secret"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := captureStdout(t, func() error {
			return runAdmin([]string{"secret", "import", "-state-dir", dir, "-file", path, "google/oauth-client"})
		})
		if err == nil {
			t.Fatal("import accepted a group/world-readable secret file")
		}
		if !strings.Contains(err.Error(), "0600") {
			t.Errorf("error %q does not explain the required permissions", err)
		}
	})

	t.Run("0600 file imported and encrypted at rest", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client-secret")
		const value = "google-oauth-client-secret-value"
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		out, err := captureStdout(t, func() error {
			return runAdmin([]string{"secret", "import", "-state-dir", dir, "-file", path, "google/oauth-client"})
		})
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		// The value must never be echoed back to the operator's terminal.
		if strings.Contains(out, value) {
			t.Errorf("import echoed the secret value: %q", out)
		}
		if !strings.Contains(out, "generation 1") {
			t.Errorf("import output = %q, want a generation", out)
		}

		st, err := store.Open(dbPath(dir))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		defer st.Close()
		sec, err := st.GetSecret(context.Background(), "google/oauth-client")
		if err != nil {
			t.Fatalf("GetSecret: %v", err)
		}
		if strings.Contains(string(sec.Ciphertext), value) {
			t.Fatal("secret is stored in plaintext")
		}
		kr, err := secrets.LoadKeyFile(keyFilePath(dir))
		if err != nil {
			t.Fatalf("LoadKeyFile: %v", err)
		}
		plaintext, err := kr.Decrypt(sec.Ciphertext)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		// The trailing newline a shell pipeline adds is not part of the secret.
		if string(plaintext) != value {
			t.Errorf("decrypted secret = %q, want %q", plaintext, value)
		}
	})

	t.Run("replacement bumps the generation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "client-secret")
		if err := os.WriteFile(path, []byte("rotated-value"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		out, err := captureStdout(t, func() error {
			return runAdmin([]string{"secret", "import", "-state-dir", dir, "-file", path, "google/oauth-client"})
		})
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		if !strings.Contains(out, "generation 2") {
			t.Errorf("replacement output = %q, want generation 2", out)
		}
	})
}

func TestAdminSecretInitKeyRefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	if _, err := captureStdout(t, func() error {
		return runAdmin([]string{"secret", "init-key", "-state-dir", dir})
	}); err != nil {
		t.Fatalf("init-key: %v", err)
	}
	if _, err := captureStdout(t, func() error {
		return runAdmin([]string{"secret", "init-key", "-state-dir", dir})
	}); err == nil {
		t.Fatal("init-key overwrote an existing key, orphaning every stored secret")
	}
}

// TestOperatorSurfaceIsNotReachableOverHTTP is the structural half of the
// operator-boundary claim: the HTTP router exposes enrolment, grants, and
// health — and nothing that reads global audit or revokes another machine's
// grants.
func TestOperatorSurfaceIsNotReachableOverHTTP(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dbPath(dir))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	srv, err := server.New(st, stubResolver{}, health.New(), server.Config{Policy: policy.Default()})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	handler := srv.Handler()

	for _, path := range []string{"/audit", "/admin", "/admin/audit", "/secrets", "/machines"} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			req := httptest.NewRequest(method, path, nil)
			req.RemoteAddr = "100.64.0.9:1000"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d; the operator surface must not exist over HTTP", method, path, rec.Code)
			}
		}
	}
}

type stubResolver struct{}

func (stubResolver) Resolve(context.Context, string) (store.Identity, error) {
	return store.Identity{NodeID: "node-x", NodeName: "x"}, nil
}
