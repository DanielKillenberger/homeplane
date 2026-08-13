package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The connector-edge wiring is where a correct edge can still be deployed
// wrong, so the wiring itself is tested: what it refuses, what it derives, and
// that a wired server serves BOTH planes on the one tailnet listener without
// weakening the listener's own limits.

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

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

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
		Logger: quietLogger(),
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

// wiredFlags is a serveFlags that wires the edge, with per-test overrides.
func wiredFlags(manifestPath string) serveFlags {
	return serveFlags{
		manifestPath: manifestPath,
		gatewayMCP:   "http://127.0.0.1:44022/mcp",
		endpointURL:  "https://homeplane.example.ts.net/mcp",
		edgePath:     defaultEdgePath,
	}
}

func TestResolveEdgeWiringRefusesUnsafeOrHalfConfigurations(t *testing.T) {
	_, _, manifestPath := newComposeFixture(t)
	log := quietLogger()

	// Neither flag: control plane only, and a warning rather than an error —
	// the server is still a useful control plane before a gateway exists.
	w, err := resolveEdgeWiring(serveFlags{endpointURL: "https://elsewhere.example/mcp"}, log)
	if err != nil || w.enabled {
		t.Fatalf("bare config: enabled=%v err=%v", w.enabled, err)
	}
	if w.endpointURL != "https://elsewhere.example/mcp" {
		t.Errorf("unwired endpoint url was rewritten to %q", w.endpointURL)
	}

	with := func(mutate func(*serveFlags)) serveFlags {
		f := wiredFlags(manifestPath)
		mutate(&f)
		return f
	}
	cases := map[string]serveFlags{
		"manifest without gateway": {manifestPath: manifestPath},
		"gateway without manifest": {gatewayMCP: "http://127.0.0.1:44022/mcp"},
		// The isolation guarantee is why this one is fatal: a routable gateway
		// can be reached without ever passing the edge.
		"routable gateway": with(func(f *serveFlags) { f.gatewayMCP = "http://100.64.0.9:44022/mcp" }),
		"missing manifest": with(func(f *serveFlags) { f.manifestPath = filepath.Join(t.TempDir(), "nope.json") }),

		// A harness is handed endpoint_url with its grant; if it does not point
		// at the mounted edge, every machine gets a working grant and an
		// endpoint that 404s.
		"no endpoint url":       with(func(f *serveFlags) { f.endpointURL = "" }),
		"relative endpoint url": with(func(f *serveFlags) { f.endpointURL = "/mcp" }),
		"hostless endpoint url": with(func(f *serveFlags) { f.endpointURL = "https:///mcp" }),
		"endpoint url scheme":   with(func(f *serveFlags) { f.endpointURL = "ftp://homeplane.example.ts.net/mcp" }),
		"endpoint url query":    with(func(f *serveFlags) { f.endpointURL = "https://homeplane.example.ts.net/mcp?x=1" }),
		"endpoint path mismatch": with(func(f *serveFlags) {
			f.endpointURL, f.edgePath = "https://homeplane.example.ts.net/mcp", "/connectors"
		}),

		// A mount path that ServeMux would panic on, or that would shadow the
		// control plane.
		"root path":       with(func(f *serveFlags) { f.edgePath = "/" }),
		"relative path":   with(func(f *serveFlags) { f.edgePath = "mcp" }),
		"wildcard path":   with(func(f *serveFlags) { f.edgePath = "/mcp/{rest...}" }),
		"unclean path":    with(func(f *serveFlags) { f.edgePath = "/mcp/../mcp" }),
		"reserved path":   with(func(f *serveFlags) { f.edgePath = "/healthz" }),
		"shadowing grant": with(func(f *serveFlags) { f.edgePath = "/grants" }),
	}
	for name, f := range cases {
		if _, err := resolveEdgeWiring(f, log); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A path-less endpoint URL is the one ambiguity worth resolving rather than
// refusing: the operator's intent is exactly "the edge, on this host".
func TestEndpointURLIsDerivedFromTheMountPathWhenPathless(t *testing.T) {
	_, _, manifestPath := newComposeFixture(t)

	for _, raw := range []string{"https://homeplane.example.ts.net", "https://homeplane.example.ts.net/"} {
		f := wiredFlags(manifestPath)
		f.endpointURL = raw
		f.edgePath = "/connectors/mcp"

		w, err := resolveEdgeWiring(f, quietLogger())
		if err != nil {
			t.Fatalf("resolveEdgeWiring(%q): %v", raw, err)
		}
		if w.endpointURL != "https://homeplane.example.ts.net/connectors/mcp" {
			t.Errorf("derived endpoint url = %q", w.endpointURL)
		}
		if w.path != "/connectors/mcp" {
			t.Errorf("mount path = %q", w.path)
		}
	}

	// A trailing slash on either side is the same mount, not a mismatch.
	f := wiredFlags(manifestPath)
	f.endpointURL = "https://homeplane.example.ts.net/mcp/"
	if w, err := resolveEdgeWiring(f, quietLogger()); err != nil || w.endpointURL != "https://homeplane.example.ts.net/mcp" {
		t.Errorf("trailing-slash endpoint url: %q err=%v", w.endpointURL, err)
	}
}

// Wiring the edge lifts the write deadline and NOTHING else. A read deadline of
// zero would let an authenticated client hold a goroutine open indefinitely by
// dripping a body.
func TestServeTimeoutsKeepTheReadDeadline(t *testing.T) {
	read, write := serveTimeouts(true, defaultReadTimeout)
	if read != defaultReadTimeout {
		t.Errorf("wired read timeout = %v, want %v", read, defaultReadTimeout)
	}
	if write != 0 {
		t.Errorf("wired write timeout = %v, want 0 (SSE streams outlive it)", write)
	}

	read, write = serveTimeouts(false, defaultReadTimeout)
	if read != defaultReadTimeout || write != defaultWriteTimeout {
		t.Errorf("unwired timeouts = (%v, %v)", read, write)
	}
}

// The behavioural half of the same rule, against a real listener: a client that
// sends headers and then drips its body is cut off by the read deadline instead
// of holding the connection forever.
func TestSlowRequestBodyIsCutOffOnAWiredListener(t *testing.T) {
	const shortRead = 300 * time.Millisecond
	read, write := serveTimeouts(true, shortRead)
	if write != 0 {
		t.Fatalf("write timeout = %v, want 0", write)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	type bodyRead struct {
		err     error
		elapsed time.Duration
	}
	reads := make(chan bodyRead, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Go dispatches the handler once the HEADERS are read, so what the
			// deadline must cut is this body read.
			start := time.Now()
			_, err := io.Copy(io.Discard, r.Body)
			reads <- bodyRead{err: err, elapsed: time.Since(start)}
		}),
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       read,
		WriteTimeout:      write,
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Full headers, then one byte of a body that promises 1000.
	fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n", ln.Addr())
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("write body byte: %v", err)
	}

	select {
	case got := <-reads:
		if got.err == nil {
			t.Fatal("the body read completed even though the client never sent it")
		}
		if got.elapsed > 3*time.Second {
			t.Errorf("the slow body was tolerated for %s", got.elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a slow-drip body pinned the handler goroutine: the read deadline is not in force")
	}

	// And the connection itself ends rather than lingering.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil && os.IsTimeout(err) {
		t.Errorf("the connection was still open after the body read was cut off")
	}
}

func TestComposeHandlerServesBothPlanesOnOneListener(t *testing.T) {
	srv, st, manifestPath := newComposeFixture(t)
	node := store.Identity{NodeID: "node-a", NodeName: "mac-a"}

	wiring, err := resolveEdgeWiring(wiredFlags(manifestPath), quietLogger())
	if err != nil || !wiring.enabled {
		t.Fatalf("resolveEdgeWiring: enabled=%v err=%v", wiring.enabled, err)
	}
	handler, err := composeHandler(srv, st, serveTestResolver{node}, wiring, quietLogger())
	if err != nil {
		t.Fatalf("composeHandler: %v", err)
	}

	// The control plane still answers on its own routes.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d: %s", rec.Code, rec.Body.String())
	}

	// The edge answers on its path — and answers as the EDGE, refusing a call
	// with no grant token rather than 404ing like an unmounted route.
	for _, path := range []string{defaultEdgePath, defaultEdgePath + "/"} {
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a token = %d: %s", path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "grant token") {
			t.Errorf("%s refusal body = %s", path, rec.Body.String())
		}
	}

	// The refusals are on the record, from the edge, with no attribution they
	// did not earn.
	rows, err := st.QueryAudit(context.Background(), store.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("audit rows = %+v", rows)
	}
	for _, row := range rows {
		if row.Event != store.EventAuthDenied || row.Reason != "missing_grant_token" {
			t.Errorf("row = %+v", row)
		}
		if row.ObservedNodeID != node.NodeID || row.AuthMachineID != "" {
			t.Errorf("row attribution wrong: %+v", row)
		}
	}
}
