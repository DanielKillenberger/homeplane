package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The connector-edge wiring is where a correct edge can still be deployed
// wrong, so the wiring itself is tested: what it refuses, and that a wired
// server serves BOTH planes on the one tailnet listener.

const serveTestManifest = `{
  "version": 1,
  "connectors": [
    {
      "provider": "stub-notes",
      "credential_ref": "stub/oauth-session",
      "credential_acquisition": {
        "driver": "oauth2-authcode",
        "params": {
          "auth_endpoint": "https://auth.stub.test/authorize",
          "token_endpoint": "https://auth.stub.test/token",
          "client_id_ref": "stub/client-id",
          "client_secret_ref": "stub/client-secret"
        },
        "scopes": ["notes.read"]
      },
      "mcp_server": { "name": "stub-notes", "transport": "streamable-http", "source": "stub://in-process" },
      "tools": [ { "tool": "list_notes", "action_class": "read" } ]
    }
  ]
}`

type serveTestResolver struct{ id store.Identity }

func (r serveTestResolver) Resolve(context.Context, string) (store.Identity, error) {
	return r.id, nil
}

func newComposeFixture(t *testing.T) (*server.Server, *store.SQLite, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	node := store.Identity{NodeID: "node-a", NodeName: "mac-a"}
	checker := health.New(health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)})
	srv, err := server.New(st, serveTestResolver{node}, checker, server.Config{
		Policy: policy.Default(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	manifestPath := filepath.Join(t.TempDir(), "connectors.json")
	if err := os.WriteFile(manifestPath, []byte(serveTestManifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return srv, st, manifestPath
}

func TestComposeHandlerRefusesUnsafeOrHalfWiring(t *testing.T) {
	srv, st, manifestPath := newComposeFixture(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	resolver := serveTestResolver{store.Identity{NodeID: "node-a"}}

	// Neither flag: control plane only, and it is a warning, not an error —
	// the server is still a useful control plane before a gateway exists.
	h, wired, err := composeHandler(srv, st, resolver, serveFlags{}, log)
	if err != nil || wired || h == nil {
		t.Fatalf("bare config: handler=%v wired=%v err=%v", h != nil, wired, err)
	}

	cases := map[string]serveFlags{
		"manifest without gateway": {manifestPath: manifestPath},
		"gateway without manifest": {gatewayMCP: "http://127.0.0.1:44022/mcp"},
		// The isolation guarantee is the reason this one is fatal: a routable
		// gateway can be reached without ever passing the edge.
		"routable gateway": {manifestPath: manifestPath, gatewayMCP: "http://100.64.0.9:44022/mcp"},
		"missing manifest": {manifestPath: filepath.Join(t.TempDir(), "nope.json"), gatewayMCP: "http://127.0.0.1:44022/mcp"},
		"bad edge path":    {manifestPath: manifestPath, gatewayMCP: "http://127.0.0.1:44022/mcp", edgePath: "mcp"},
	}
	for name, f := range cases {
		if _, _, err := composeHandler(srv, st, resolver, f, log); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestComposeHandlerServesBothPlanesOnOneListener(t *testing.T) {
	srv, st, manifestPath := newComposeFixture(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	node := store.Identity{NodeID: "node-a", NodeName: "mac-a"}

	handler, wired, err := composeHandler(srv, st, serveTestResolver{node}, serveFlags{
		manifestPath: manifestPath,
		gatewayMCP:   "http://127.0.0.1:44022/mcp",
		edgePath:     defaultEdgePath,
	}, log)
	if err != nil || !wired {
		t.Fatalf("composeHandler: wired=%v err=%v", wired, err)
	}

	// The control plane still answers on its own routes.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d: %s", rec.Code, rec.Body.String())
	}

	// The edge answers on its path — and answers as the EDGE, refusing a call
	// with no grant token rather than 404ing like an unmounted route.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, defaultEdgePath, strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s without a token = %d: %s", defaultEdgePath, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "grant token") {
		t.Errorf("edge refusal body = %s", rec.Body.String())
	}

	// The refusal is on the record, from the edge, with no attribution it did
	// not earn.
	rows, err := st.QueryAudit(context.Background(), store.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 1 || rows[0].Event != store.EventAuthDenied || rows[0].Reason != "missing_grant_token" {
		t.Fatalf("audit rows = %+v", rows)
	}
	if rows[0].ObservedNodeID != node.NodeID || rows[0].AuthMachineID != "" {
		t.Errorf("row attribution wrong: %+v", rows[0])
	}
}
