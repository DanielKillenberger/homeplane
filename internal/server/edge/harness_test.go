package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/cred"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// Two simulated tailnet machines. Every binding test in this file turns on the
// edge telling them apart from the network alone.
//
// BOUNDARY, stated rather than papered over: the resolver below is a stand-in
// for tsnet's in-process WhoIs, exactly as the control plane's tests use one.
// It resolves the same store.Identity the real resolver produces, so every rule
// built on observed identity is proven here — but "the tailnet really does
// report these two nodes this way" is a live-tailnet fact and is covered by the
// D6 spike's cross-node run (docs/decisions/d6-gateway.md, gate 1) and by the
// deployment task, not by this suite.
var (
	nodeA = store.Identity{NodeID: "node-aaaa", NodeName: "mac-a"}
	nodeB = store.Identity{NodeID: "node-bbbb", NodeName: "linux-b"}

	addrA = "100.64.0.1:41000"
	addrB = "100.64.0.2:41000"
	addrC = "100.64.0.3:41000" // a peer the tailnet cannot name
)

type fakeResolver struct{ byAddr map[string]store.Identity }

func (f fakeResolver) Resolve(_ context.Context, remoteAddr string) (store.Identity, error) {
	id, ok := f.byAddr[remoteAddr]
	if !ok {
		return store.Identity{}, fmt.Errorf("no tailnet identity for %s", remoteAddr)
	}
	return id, nil
}

// testManifest is the same declarative shape task .3 proves its engine against:
// a connector whose tools carry action classes, one deliberately excluded tool,
// and a complete inventory so half-registration is impossible.
const testManifest = `{
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
        "scopes": ["notes.read", "notes.write"]
      },
      "mcp_server": {
        "name": "stub-notes",
        "transport": "streamable-http",
        "source": "stub://in-process"
      },
      "tool_inventory": ["list_notes", "get_note", "create_note", "delete_note", "export_archive"],
      "tools": [
        { "tool": "list_notes", "action_class": "read" },
        { "tool": "get_note", "action_class": "read", "artifact_id": { "source": "request", "pointer": "$.note_id" } },
        { "tool": "create_note", "action_class": "write", "artifact_id": { "source": "response", "pointer": "$.note.id" } },
        { "tool": "delete_note", "action_class": "delete", "artifact_id": { "source": "request", "pointer": "$.note_id" } }
      ],
      "excluded_tools": [
        { "tool": "export_archive", "reason": "bulk export is out of scope for the skeleton" }
      ]
    }
  ]
}`

// ---------------------------------------------------------------------------
// The stub gateway: a streamable-HTTP MCP server standing in for the composed
// ToolHive workload proxy. It answers the 2025-06-18 handshake, issues a
// session id, and replies to tools/call over SSE — the shape the D6 spike
// observed from the real gateway. It records every request it receives, which
// is how the tests prove what the edge did and did NOT forward.
// ---------------------------------------------------------------------------

type gatewayRequest struct {
	Method    string
	Path      string
	Authz     string
	SessionID string
	Protocol  string
	Body      string
	RPCMethod string
	ToolName  string
}

type stubGateway struct {
	*httptest.Server

	mu        sync.Mutex
	requests  []gatewayRequest
	responses map[string]json.RawMessage
	failures  map[string]*RPCError
	// asJSON answers tools/call with a plain JSON body instead of SSE, which
	// the transport also permits.
	asJSON bool
}

const stubSessionID = "SESSION-STUB-1"

func newStubGateway(t *testing.T) *stubGateway {
	t.Helper()
	g := &stubGateway{
		responses: map[string]json.RawMessage{},
		failures:  map[string]*RPCError{},
	}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.Close)
	return g
}

func (g *stubGateway) respond(tool, body string) *stubGateway {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.responses[tool] = json.RawMessage(body)
	return g
}

func (g *stubGateway) fail(tool string, err *RPCError) *stubGateway {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failures[tool] = err
	return g
}

func (g *stubGateway) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var rpc rpcRequest
	_ = json.Unmarshal(body, &rpc)
	var params toolCallParams
	if len(rpc.Params) > 0 {
		_ = json.Unmarshal(rpc.Params, &params)
	}

	g.mu.Lock()
	g.requests = append(g.requests, gatewayRequest{
		Method:    r.Method,
		Path:      r.URL.Path,
		Authz:     r.Header.Get("Authorization"),
		SessionID: r.Header.Get(HeaderSessionID),
		Protocol:  r.Header.Get(HeaderProtocolVersion),
		Body:      string(body),
		RPCMethod: rpc.Method,
		ToolName:  params.Name,
	})
	responses, failures, asJSON := g.responses, g.failures, g.asJSON
	g.mu.Unlock()

	switch {
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
		return
	case r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set(HeaderSessionID, stubSessionID)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, ": open\n\n")
		return
	}

	switch rpc.Method {
	case "initialize":
		w.Header().Set(HeaderSessionID, stubSessionID)
		writeSSE(w, rpcResponse{JSONRPC: jsonRPCVersion, ID: rpc.ID, Result: json.RawMessage(
			`{"protocolVersion":"` + ProtocolVersion + `","serverInfo":{"name":"stub-notes","version":"0.0.1"}}`)})
	case methodToolsCall:
		resp := rpcResponse{JSONRPC: jsonRPCVersion, ID: rpc.ID}
		if err, ok := failures[params.Name]; ok {
			resp.Error = err
		} else if result, ok := responses[params.Name]; ok {
			resp.Result = result
		} else {
			resp.Result = json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
		}
		if asJSON {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		writeSSE(w, resp)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rpcResponse{
			JSONRPC: jsonRPCVersion, ID: rpc.ID, Result: json.RawMessage(`{"tools":[]}`)})
	}
}

func writeSSE(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	payload, _ := json.Marshal(resp)
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
}

func (g *stubGateway) seen() []gatewayRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]gatewayRequest(nil), g.requests...)
}

func (g *stubGateway) toolCalls() []gatewayRequest {
	var out []gatewayRequest
	for _, r := range g.seen() {
		if r.RPCMethod == methodToolsCall {
			out = append(out, r)
		}
	}
	return out
}

func (g *stubGateway) endpoint(t *testing.T) *url.URL {
	t.Helper()
	u, err := ParseUpstream(g.URL + "/mcp")
	if err != nil {
		t.Fatalf("stub gateway endpoint is not loopback: %v", err)
	}
	return u
}

// ---------------------------------------------------------------------------
// The edge under test, wired to a REAL store and the REAL policy/audit engine.
// Nothing between the request and the audit row is faked: only the tailnet
// resolver and the gateway's own contents are stand-ins.
// ---------------------------------------------------------------------------

type harness struct {
	t       *testing.T
	st      *store.SQLite
	gateway *stubGateway
	edge    *Edge
	sink    *failableSink

	machineA store.Machine
	tokenA   string
	grantA   store.Grant
}

// failableSink wraps the real store so a test can break the audit log on
// demand. A suite that never exercises a broken log proves nothing about the
// fail-closed path, which only runs when the log is broken.
type failableSink struct {
	*store.SQLite
	failFrom int // 1-based append index from which writes fail; 0 = never
	appends  int
	mu       sync.Mutex
}

var errSinkDown = fmt.Errorf("audit log is down")

func (f *failableSink) AppendAudit(ctx context.Context, e store.AuditEvent) error {
	f.mu.Lock()
	f.appends++
	failing := f.failFrom > 0 && f.appends >= f.failFrom
	f.mu.Unlock()
	if failing {
		return errSinkDown
	}
	return f.SQLite.AppendAudit(ctx, e)
}

func (f *failableSink) breakFromNow() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failFrom = f.appends + 1
}

func newHarness(t *testing.T, capabilities ...string) *harness {
	t.Helper()
	if len(capabilities) == 0 {
		capabilities = []string{
			string(policy.ConnectorRead), string(policy.ConnectorWrite), string(policy.ConnectorDelete),
		}
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sink := &failableSink{SQLite: st}

	gw := newStubGateway(t)
	upstream := gw.endpoint(t)

	manifest, err := connectors.Parse([]byte(testManifest))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register manifest: %v", err)
	}
	broker := connectors.NewBroker(engine, NewHTTPRuntime(upstream, gw.Client()), sink)

	e, err := New(Config{
		Store:    sink,
		Identity: fakeResolver{byAddr: map[string]store.Identity{addrA: nodeA, addrB: nodeB}},
		Broker:   broker,
		Upstream: upstream,
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}

	h := &harness{t: t, st: st, gateway: gw, edge: e, sink: sink}
	h.machineA, h.tokenA, h.grantA = h.enrolAndGrant(nodeA, "mac-a", policy.HarnessClaudeCode, capabilities)
	return h
}

// enrolAndGrant puts a machine and an active grant in the store the way the
// control plane does — through the same audited store API, not by hand.
func (h *harness) enrolAndGrant(id store.Identity, name, harnessName string, capabilities []string) (store.Machine, string, store.Grant) {
	h.t.Helper()
	ctx := context.Background()

	_, machineHash, err := cred.New()
	if err != nil {
		h.t.Fatalf("mint machine credential: %v", err)
	}
	m, _, err := h.st.Enrol(ctx, id, name, "linux", machineHash,
		func(m store.Machine, _ bool) []store.AuditEvent {
			return []store.AuditEvent{{
				Event: store.EventEnrolment, ActorKind: store.ActorMachine,
				ObservedNodeID: id.NodeID, ObservedNodeName: id.NodeName,
				AuthMachineID: m.ID, Outcome: store.OutcomeAllowed,
			}}
		})
	if err != nil {
		h.t.Fatalf("enrol: %v", err)
	}

	token, tokenHash, err := cred.New()
	if err != nil {
		h.t.Fatalf("mint grant token: %v", err)
	}
	g, _, err := h.st.IssueGrant(ctx, m.ID, harnessName, capabilities, tokenHash,
		func(g store.Grant, _ *store.Grant) []store.AuditEvent {
			return []store.AuditEvent{{
				Event: store.EventGrantIssued, ActorKind: store.ActorMachine,
				ObservedNodeID: id.NodeID, ObservedNodeName: id.NodeName,
				AuthMachineID: m.ID, Harness: g.Harness, GrantID: g.ID,
				Outcome: store.OutcomeAllowed,
			}}
		})
	if err != nil {
		h.t.Fatalf("issue grant: %v", err)
	}
	return m, token, g
}

func (h *harness) revoke(grantID string) {
	h.t.Helper()
	if _, _, err := h.st.RevokeGrant(context.Background(), grantID, "revoked_by_operator",
		func(g store.Grant) []store.AuditEvent {
			return []store.AuditEvent{{
				Event: store.EventGrantRevoked, ActorKind: store.ActorOperator,
				AuthMachineID: g.MachineID, Harness: g.Harness, GrantID: g.ID,
				Outcome: store.OutcomeAllowed, Reason: "revoked_by_operator",
			}}
		}); err != nil {
		h.t.Fatalf("revoke grant: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client-side helpers.
// ---------------------------------------------------------------------------

type edgeResponse struct {
	status  int
	header  http.Header
	rpc     rpcResponse
	rawBody string
}

// callTool sends a `tools/call` frame from a given tailnet address.
func (h *harness) callTool(remoteAddr, token, tool, args string) edgeResponse {
	h.t.Helper()
	params, err := json.Marshal(toolCallParams{Name: tool, Arguments: json.RawMessage(args)})
	if err != nil {
		h.t.Fatalf("marshal params: %v", err)
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: jsonRPCVersion, ID: json.RawMessage(`7`), Method: methodToolsCall, Params: params,
	})
	if err != nil {
		h.t.Fatalf("marshal request: %v", err)
	}
	return h.do(http.MethodPost, remoteAddr, token, string(body), map[string]string{
		HeaderSessionID:       stubSessionID,
		HeaderProtocolVersion: ProtocolVersion,
	})
}

// initialize sends the MCP handshake frame, which the edge forwards verbatim.
func (h *harness) initialize(remoteAddr, token string) edgeResponse {
	h.t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` +
		ProtocolVersion + `","clientInfo":{"name":"claude-code","version":"2.1.227"}}}`
	return h.do(http.MethodPost, remoteAddr, token, body, map[string]string{HeaderProtocolVersion: ProtocolVersion})
}

func (h *harness) do(method, remoteAddr, token, body string, headers map[string]string) edgeResponse {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/mcp", reader)
	r.RemoteAddr = remoteAddr
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	h.edge.ServeHTTP(rec, r)

	res := edgeResponse{status: rec.Code, header: rec.Header(), rawBody: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &res.rpc)
	return res
}

// ---------------------------------------------------------------------------
// Audit assertions.
// ---------------------------------------------------------------------------

func (h *harness) auditRows() []store.AuditEvent {
	h.t.Helper()
	rows, err := h.st.QueryAudit(context.Background(), store.AuditQuery{Limit: 500})
	if err != nil {
		h.t.Fatalf("query audit: %v", err)
	}
	return rows
}

// lastRow returns the most recent row with the given event name.
func (h *harness) lastRow(event string) (store.AuditEvent, bool) {
	h.t.Helper()
	var found store.AuditEvent
	var ok bool
	for _, r := range h.auditRows() {
		if r.Event == event {
			found, ok = r, true
		}
	}
	return found, ok
}

func (h *harness) requireRow(event string) store.AuditEvent {
	h.t.Helper()
	row, ok := h.lastRow(event)
	if !ok {
		h.t.Fatalf("no %q audit row; rows: %+v", event, h.auditRows())
	}
	return row
}

func (h *harness) countRows(event string) int {
	h.t.Helper()
	n := 0
	for _, r := range h.auditRows() {
		if r.Event == event {
			n++
		}
	}
	return n
}
