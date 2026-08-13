//go:build live_google

// The live `add-credentials google` proof (R13, and the credential half of R7).
//
// It runs the REAL consent flow against real Google: a control plane with the
// real credential broker and the SHIPPED connector manifest, the real agent CLI,
// and a real browser window a human consents in. Nothing about the OAuth
// exchange is simulated — which is the point, because the property under test
// is custody: the machine that ran the flow must end up with no provider token
// anywhere, while the server ends up with one.
//
// It is behind the `live_google` build tag and an environment guard, so
// `go test ./...` never builds it.
//
//	HOMEPLANE_LIVE_GOOGLE=1 \
//	HOMEPLANE_LIVE_GOOGLE_STATE_DIR=/path/to/server-state \
//	HOMEPLANE_LIVE_GOOGLE_ACCOUNT=you@example.com \
//	HOMEPLANE_LIVE_GOOGLE_CRED_DIR=/path/to/workload-credentials \
//	go test ./cmd/homeplane-agent/ -tags live_google -run TestLiveGoogleAddCredentials -count=1 -v -timeout 20m
//
// The server state directory must already hold the age key and Homeplane's own
// Google OAuth client, imported off argv:
//
//	homeplane-server admin secret init-key   -state-dir "$DIR"
//	homeplane-server admin secret import google/client-id     -state-dir "$DIR" -file id.txt
//	homeplane-server admin secret import google/client-secret -state-dir "$DIR" -file secret.txt
package main

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/server/workloadcred"
	"net/http/httptest"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

const liveProvider = "google"

// TestLiveGoogleAddCredentials brokers a real Google credential and proves
// where it did — and did not — end up.
func TestLiveGoogleAddCredentials(t *testing.T) {
	if os.Getenv("HOMEPLANE_LIVE_GOOGLE") != "1" {
		t.Skip("set HOMEPLANE_LIVE_GOOGLE=1 to run the live Google credential proof")
	}
	serverState := os.Getenv("HOMEPLANE_LIVE_GOOGLE_STATE_DIR")
	account := os.Getenv("HOMEPLANE_LIVE_GOOGLE_ACCOUNT")
	credDir := os.Getenv("HOMEPLANE_LIVE_GOOGLE_CRED_DIR")
	if serverState == "" || account == "" {
		t.Fatal("HOMEPLANE_LIVE_GOOGLE_STATE_DIR and HOMEPLANE_LIVE_GOOGLE_ACCOUNT are required")
	}

	st, err := store.Open(filepath.Join(serverState, "homeplane.db"))
	if err != nil {
		t.Fatalf("open the server store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	keyring, err := secrets.LoadKeyFile(filepath.Join(serverState, "secrets.age-key"))
	if err != nil {
		t.Fatalf("load the credential key (run `admin secret init-key` first): %v", err)
	}

	manifestPath := filepath.Join("..", "..", "configs", "connectors", "google.json")
	manifest, err := connectors.LoadFile(manifestPath)
	if err != nil {
		t.Fatalf("load the shipped manifest %s: %v", manifestPath, err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register the shipped manifest: %v", err)
	}
	broker, err := credflow.New(engine, st, keyring, st, credflow.Config{
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	if err != nil {
		t.Fatalf("credflow.New: %v", err)
	}

	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, fakeResolver{id: store.Identity{NodeID: "node-live", NodeName: "live-proof"}},
		checker, server.Config{Policy: policy.Default(), Credentials: broker})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	cp := httptest.NewServer(srv.Handler())
	t.Cleanup(cp.Close)

	// A throwaway agent state directory: the custody assertion below is that
	// NOTHING provider-shaped ever lands in it.
	agentDir := filepath.Join(t.TempDir(), "agent-state")
	if res := invoke(t, "enrol", "-server", cp.URL, "-name", "live-proof", "-state-dir", agentDir); res.code != 0 {
		t.Fatalf("enrol: exit %d (stderr %q)", res.code, res.stderr)
	}

	t.Logf("a browser window is about to open — consent as %s, granting Drive (read-only) and Calendar", account)
	t.Logf("requested scopes: %s", strings.Join(scopesOf(t, engine), " "))

	res := invoke(t, "add-credentials", liveProvider, "-state-dir", agentDir,
		"-replace", "-timeout", "10m", "-poll-interval", "1s")
	t.Logf("add-credentials stdout: %s", strings.TrimSpace(res.stdout))
	if res.code != 0 {
		t.Fatalf("add-credentials exit %d; stderr:\n%s", res.code, res.stderr)
	}

	cred, generation, err := broker.Credential(context.Background(), liveProvider)
	if err != nil {
		t.Fatalf("the flow reported success but no credential is stored: %v", err)
	}
	if cred.Access == "" {
		t.Fatal("the stored credential carries no access token")
	}
	if cred.Refresh == "" {
		t.Error("the stored credential carries no refresh token; the flow did not request offline access")
	}
	t.Logf("credential stored server-side: generation %d, scope %q, expires %s",
		generation, cred.Scope, cred.ExpiresAt.UTC().Format(time.RFC3339))

	// Custody: the machine that ran the consent flow must hold nothing.
	assertNoTokenOnDisk(t, agentDir, cred.Access, cred.Refresh)

	// Deliver it to the connector workload, in the shape the manifest declares.
	if credDir == "" {
		t.Log("HOMEPLANE_LIVE_GOOGLE_CRED_DIR unset: skipping workload delivery")
		return
	}
	conn, _ := engine.Connector(liveProvider)
	if conn.Delivery == nil {
		t.Fatal("the connector declares no credential_delivery format")
	}
	clientID, clientSecret := driverSecrets(t, st, keyring, conn)
	path, err := workloadcred.Materialize(conn.Delivery.Format, credDir, account, workloadcred.Credential{
		AccessToken:  cred.Access,
		RefreshToken: cred.Refresh,
		TokenURI:     conn.Credential.Params["token_endpoint"],
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       strings.Fields(cred.Scope),
		ExpiresAt:    cred.ExpiresAt,
	})
	if err != nil {
		t.Fatalf("materialize the credential for the workload: %v", err)
	}
	t.Logf("delivered the credential to the connector workload at %s", path)
}

func scopesOf(t *testing.T, e *connectors.Engine) []string {
	t.Helper()
	c, ok := e.Connector(liveProvider)
	if !ok {
		t.Fatalf("the shipped manifest declares no %q connector", liveProvider)
	}
	return c.Credential.Scopes
}

// driverSecrets reads Homeplane's own OAuth client out of the store. The
// connector needs it to refresh the access token, and it is the only other
// secret that reaches the workload.
func driverSecrets(t *testing.T, st *store.SQLite, keyring *secrets.Keyring, conn connectors.Connector) (string, string) {
	t.Helper()
	read := func(param string) string {
		ref := conn.Credential.Params[param]
		if ref == "" {
			t.Fatalf("the connector declares no %s", param)
		}
		sec, err := st.GetSecret(context.Background(), ref)
		if err != nil {
			t.Fatalf("read %s (%s): %v", param, ref, err)
		}
		plaintext, err := keyring.Decrypt(sec.Ciphertext)
		if err != nil {
			t.Fatalf("decrypt %s: %v", param, err)
		}
		return string(plaintext)
	}
	return read("client_id_ref"), read("client_secret_ref")
}

// assertNoTokenOnDisk walks the agent's whole state directory looking for the
// provider tokens. The claim "the machine never sees a provider token" is only
// worth something if something checks the machine's disk for them.
func assertNoTokenOnDisk(t *testing.T, dir string, tokens ...string) {
	t.Helper()
	var checked int
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		checked++
		for _, tok := range tokens {
			if tok == "" {
				continue
			}
			if strings.Contains(string(body), tok) {
				t.Fatalf("CUSTODY VIOLATION: %s contains a provider token", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk the agent state dir: %v", err)
	}
	if checked == 0 {
		t.Fatal("the agent state directory is empty; the custody check inspected nothing")
	}
	t.Logf("custody: %d agent-side files inspected, no provider token on the machine", checked)
}
