package edge

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The whole path, in one test: a harness on a tailnet node presents its grant
// token, the edge authenticates it, binds it to the observed node, authorizes
// the tool against the manifest, forwards it to the gateway over streamable
// HTTP, and records both audit rows. What the gateway must NOT see — the
// Homeplane grant token — is asserted as directly as what it must.
func TestValidGrantTraversesEdgeToGatewayAndBack(t *testing.T) {
	h := newHarness(t)
	h.gateway.respond("create_note", `{"note":{"id":"n-7"},"content":[{"type":"text","text":"created"}]}`)

	// The handshake is transport and belongs to the gateway: forwarded verbatim.
	init := h.initialize(addrA, h.tokenA)
	if init.status != http.StatusOK {
		t.Fatalf("initialize status = %d, body %s", init.status, init.rawBody)
	}
	if got := init.header.Get(HeaderSessionID); got != stubSessionID {
		t.Errorf("gateway session id was not passed back to the client: %q", got)
	}
	if !strings.Contains(init.rawBody, ProtocolVersion) {
		t.Errorf("initialize response did not carry protocol %s: %s", ProtocolVersion, init.rawBody)
	}

	res := h.callTool(addrA, h.tokenA, "create_note", `{"title":"weekly"}`)
	if res.status != http.StatusOK {
		t.Fatalf("tools/call status = %d, body %s", res.status, res.rawBody)
	}
	if res.rpc.Error != nil {
		t.Fatalf("tools/call returned an error: %+v", res.rpc.Error)
	}
	if !strings.Contains(string(res.rpc.Result), `"n-7"`) {
		t.Errorf("the gateway's result did not reach the client: %s", res.rpc.Result)
	}
	if string(res.rpc.ID) != "7" {
		t.Errorf("response id = %s, want the request's id", res.rpc.ID)
	}

	calls := h.gateway.toolCalls()
	if len(calls) != 1 {
		t.Fatalf("gateway saw %d tool calls, want 1", len(calls))
	}
	if calls[0].ToolName != "create_note" {
		t.Errorf("gateway saw tool %q", calls[0].ToolName)
	}
	if calls[0].SessionID != stubSessionID {
		t.Errorf("session id was not carried to the gateway: %q", calls[0].SessionID)
	}
	if calls[0].Protocol != ProtocolVersion {
		t.Errorf("protocol version forwarded = %q, want %q", calls[0].Protocol, ProtocolVersion)
	}
	for _, req := range h.gateway.seen() {
		if req.Authz != "" {
			t.Fatalf("the grant token reached the gateway on a %s %s: %q", req.Method, req.Path, req.Authz)
		}
	}

	// Both authoritative rows, with the authenticated identity the credential
	// proved and the observed node the network reported.
	call := h.requireRow(store.EventConnectorToolCall)
	if call.Outcome != store.OutcomeAllowed || call.Tool != "create_note" ||
		call.ActionClass != string(connectors.ActionWrite) {
		t.Errorf("call row wrong: %+v", call)
	}
	if call.AuthMachineID != h.machineA.ID || call.GrantID != h.grantA.ID ||
		call.Harness != policy.HarnessClaudeCode {
		t.Errorf("call row attribution wrong: %+v", call)
	}
	if call.ObservedNodeID != nodeA.NodeID || call.ObservedNodeName != nodeA.NodeName {
		t.Errorf("call row observed identity wrong: %+v", call)
	}
	if call.Detail["provider"] != "stub-notes" {
		t.Errorf("call row provider = %q", call.Detail["provider"])
	}
	result := h.requireRow(store.EventConnectorToolResult)
	if result.ArtifactID != "n-7" {
		t.Errorf("result row artifact id = %q, want the id the response revealed", result.ArtifactID)
	}
}

// A composed gateway may answer tools/call with a plain JSON body rather than
// an SSE frame; both are legal in the streamable-HTTP transport.
func TestGatewayJSONResponsesAreAccepted(t *testing.T) {
	h := newHarness(t)
	h.gateway.asJSON = true
	h.gateway.respond("list_notes", `{"content":[{"type":"text","text":"two notes"}]}`)

	res := h.callTool(addrA, h.tokenA, "list_notes", `{}`)
	if res.status != http.StatusOK || res.rpc.Error != nil {
		t.Fatalf("status %d, body %s", res.status, res.rawBody)
	}
	if !strings.Contains(string(res.rpc.Result), "two notes") {
		t.Errorf("result = %s", res.rpc.Result)
	}
}

// Revocation is the property this edge cannot cache its way out of: the grant
// is resolved from the store on every request, so a revoked token stops working
// on the very next call — not at a TTL boundary.
func TestRevokedGrantStopsWorkingImmediately(t *testing.T) {
	h := newHarness(t)

	if res := h.callTool(addrA, h.tokenA, "list_notes", `{}`); res.status != http.StatusOK {
		t.Fatalf("pre-revocation call failed: %d %s", res.status, res.rawBody)
	}
	before := len(h.gateway.toolCalls())

	h.revoke(h.grantA.ID)

	start := time.Now()
	res := h.callTool(addrA, h.tokenA, "list_notes", `{}`)
	elapsed := time.Since(start)

	if res.status != http.StatusUnauthorized {
		t.Fatalf("revoked token got status %d, want 401: %s", res.status, res.rawBody)
	}
	if elapsed > 2*time.Second {
		t.Errorf("revoked token took %s to be refused; the spec's bound is seconds", elapsed)
	}
	if res.header.Get("WWW-Authenticate") == "" {
		t.Errorf("401 did not challenge with WWW-Authenticate")
	}
	if got := len(h.gateway.toolCalls()); got != before {
		t.Errorf("a revoked call reached the gateway (%d -> %d)", before, got)
	}

	row := h.requireRow(store.EventAuthDenied)
	if row.Reason != "invalid_or_revoked_grant" {
		t.Errorf("denial reason = %q", row.Reason)
	}
	if row.AuthMachineID != "" || row.GrantID != "" {
		t.Errorf("a rejected token was attributed to an identity it did not prove: %+v", row)
	}
	if row.TokenFingerprint == "" {
		t.Errorf("rejected token carries no fingerprint to correlate repeat attempts: %+v", row)
	}
	if row.ObservedNodeID != nodeA.NodeID {
		t.Errorf("denial was not attributed to the observed node: %+v", row)
	}
}

// The machine-binding invariant (R7): a valid grant token replayed from a
// DIFFERENT tailnet node is refused, and the violation is recorded against the
// node that actually sent it — never against the machine that owns the token.
func TestReplayedTokenFromAnotherNodeIsRejectedAndAudited(t *testing.T) {
	h := newHarness(t)

	res := h.callTool(addrB, h.tokenA, "list_notes", `{}`)
	if res.status != http.StatusForbidden {
		t.Fatalf("replayed token got status %d, want 403: %s", res.status, res.rawBody)
	}
	if len(h.gateway.toolCalls()) != 0 {
		t.Fatalf("a replayed token reached the gateway")
	}

	row := h.requireRow(store.EventAuthDenied)
	if row.Reason != "machine_mismatch" {
		t.Fatalf("denial reason = %q, want machine_mismatch", row.Reason)
	}
	if row.ObservedNodeID != nodeB.NodeID || row.ObservedNodeName != nodeB.NodeName {
		t.Errorf("violation was not attributed to the OBSERVED node: %+v", row)
	}
	if row.AuthMachineID != "" || row.GrantID != "" || row.Harness != "" {
		t.Errorf("violation was attributed to the token's owner as if it had acted: %+v", row)
	}
	if row.Detail["bound_machine_id"] != h.machineA.ID {
		t.Errorf("the bound machine was not recorded as metadata: %+v", row.Detail)
	}
	if row.TokenFingerprint == "" {
		t.Errorf("replay carries no token fingerprint: %+v", row)
	}

	// The token still works from its own node: the binding rejects the replay,
	// not the grant.
	if res := h.callTool(addrA, h.tokenA, "list_notes", `{}`); res.status != http.StatusOK {
		t.Errorf("the legitimate node was locked out by another node's replay: %d", res.status)
	}
}

// Enrolment binds a machine to a node; a second machine on a second node gets
// its own grant, and neither can borrow the other's.
func TestEachMachineIsBoundToItsOwnGrant(t *testing.T) {
	h := newHarness(t)
	_, tokenB, _ := h.enrolAndGrant(nodeB, "linux-b", policy.HarnessCodex,
		[]string{string(policy.ConnectorRead)})

	if res := h.callTool(addrB, tokenB, "list_notes", `{}`); res.status != http.StatusOK {
		t.Fatalf("node B could not use its own grant: %d %s", res.status, res.rawBody)
	}
	if res := h.callTool(addrA, tokenB, "list_notes", `{}`); res.status != http.StatusForbidden {
		t.Errorf("node A used node B's token: %d", res.status)
	}
}

// Missing and unnameable callers are refused before any policy question is
// asked, and both refusals are on the record.
func TestUnauthenticatedCallsAreRefusedAndRecorded(t *testing.T) {
	h := newHarness(t)

	if res := h.callTool(addrA, "", "list_notes", `{}`); res.status != http.StatusUnauthorized {
		t.Errorf("missing token status = %d", res.status)
	}
	if row := h.requireRow(store.EventAuthDenied); row.Reason != "missing_grant_token" {
		t.Errorf("reason = %q", row.Reason)
	}

	if res := h.callTool(addrA, "not-a-real-token", "list_notes", `{}`); res.status != http.StatusUnauthorized {
		t.Errorf("unknown token status = %d", res.status)
	}
	if row := h.requireRow(store.EventAuthDenied); row.Reason != "invalid_or_revoked_grant" {
		t.Errorf("reason = %q", row.Reason)
	}

	// A peer the tailnet cannot name can never be authorized: there is no
	// observed identity to bind a token to.
	if res := h.callTool(addrC, h.tokenA, "list_notes", `{}`); res.status != http.StatusForbidden {
		t.Errorf("unresolvable peer status = %d", res.status)
	}
	if row := h.requireRow(store.EventAuthDenied); row.Reason != "identity_unresolvable" {
		t.Errorf("reason = %q", row.Reason)
	}
	if len(h.gateway.toolCalls()) != 0 {
		t.Errorf("an unauthenticated call reached the gateway")
	}
}

// Manifest refusals, end to end through the edge: each shape produces the
// engine's own reason on the row, and none of them reach the gateway.
func TestManifestRefusalsAreDeniedAndAudited(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		event    string
		reason   string
		provider string
	}{
		{"excluded tool", "export_archive", store.EventPolicyViolation, connectors.ReasonExcludedTool, "stub-notes"},
		{"unmapped tool", "summarize_notes", store.EventPolicyViolation, connectors.ReasonUnknownProvider, UnroutedProvider},
		{"qualified unmapped tool", "stub-notes__summarize_notes", store.EventPolicyViolation, connectors.ReasonUnmappedTool, "stub-notes"},
		{"unknown connector", "other__do_thing", store.EventPolicyViolation, connectors.ReasonUnknownProvider, UnroutedProvider},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			res := h.callTool(addrA, h.tokenA, tc.tool, `{}`)
			if res.status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", res.status, res.rawBody)
			}
			if res.rpc.Error == nil || res.rpc.Error.Code != codeForbidden {
				t.Errorf("client did not get a JSON-RPC refusal: %s", res.rawBody)
			}
			if len(h.gateway.toolCalls()) != 0 {
				t.Fatalf("a denied call reached the gateway")
			}
			row := h.requireRow(tc.event)
			if row.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", row.Reason, tc.reason)
			}
			if row.Outcome != store.OutcomeDenied {
				t.Errorf("outcome = %q", row.Outcome)
			}
			if row.Detail["provider"] != tc.provider {
				t.Errorf("provider = %q, want %q", row.Detail["provider"], tc.provider)
			}
			// Even a refused call is attributed to the grant that made it: the
			// credential DID prove an identity, and the row says plainly that
			// nothing was forwarded.
			if row.AuthMachineID != h.machineA.ID || row.GrantID != h.grantA.ID {
				t.Errorf("refusal lost its attribution: %+v", row)
			}
		})
	}
}

// A grant that never carried write authority cannot get it by calling a write
// tool: the required capability comes from the manifest's action class, and the
// refusal is an authorization denial rather than a manifest violation.
func TestCapabilityMissingIsDeniedAndAudited(t *testing.T) {
	h := newHarness(t, string(policy.ConnectorRead))

	res := h.callTool(addrA, h.tokenA, "delete_note", `{"note_id":"n-1"}`)
	if res.status != http.StatusForbidden {
		t.Fatalf("status = %d: %s", res.status, res.rawBody)
	}
	if len(h.gateway.toolCalls()) != 0 {
		t.Fatalf("an unauthorized delete reached the gateway")
	}
	row := h.requireRow(store.EventConnectorDenied)
	if row.Reason != connectors.ReasonCapabilityMissing {
		t.Errorf("reason = %q", row.Reason)
	}
	if row.Detail["required_capability"] != string(policy.ConnectorDelete) {
		t.Errorf("required capability = %q", row.Detail["required_capability"])
	}
	if row.ActionClass != string(connectors.ActionDelete) {
		t.Errorf("action class = %q", row.ActionClass)
	}
}

// A tool that fails inside the gateway is not a policy denial and must not be
// logged as one — and the provider's own error reaches the client rather than a
// synthesized substitute.
func TestGatewayToolErrorsReachTheClientAndAreAuditedAsFailures(t *testing.T) {
	h := newHarness(t)
	h.gateway.fail("get_note", &RPCError{Code: -32001, Message: "note not found"})

	res := h.callTool(addrA, h.tokenA, "get_note", `{"note_id":"n-404"}`)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a JSON-RPC-level error): %s", res.status, res.rawBody)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != -32001 ||
		!strings.Contains(res.rpc.Error.Message, "note not found") {
		t.Fatalf("the gateway's error did not reach the client: %s", res.rawBody)
	}
	call := h.requireRow(store.EventConnectorToolCall)
	if call.Outcome != store.OutcomeAllowed {
		t.Errorf("an admitted call that failed was recorded as denied: %+v", call)
	}
	result := h.requireRow(store.EventConnectorToolResult)
	if result.Reason != "tool_failed" {
		t.Errorf("result row reason = %q, want tool_failed", result.Reason)
	}
}

// An unreachable gateway is a transport failure, reported as such, never as a
// successful or denied call.
func TestUnreachableGatewayIsReportedAsGatewayFailure(t *testing.T) {
	h := newHarness(t)
	h.gateway.Close()

	res := h.callTool(addrA, h.tokenA, "list_notes", `{}`)
	if res.status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", res.status, res.rawBody)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != codeGatewayFailure {
		t.Errorf("client error body = %s", res.rawBody)
	}
	// The call was authorized and recorded before it was attempted, and the
	// result row says it did not complete.
	if h.countRows(store.EventConnectorToolCall) != 1 {
		t.Errorf("the attempted call was not recorded")
	}
	if row := h.requireRow(store.EventConnectorToolResult); row.Reason != "tool_failed" {
		t.Errorf("result row reason = %q", row.Reason)
	}
}

// Fail-closed, both halves. A call that cannot be recorded does not happen, and
// a refusal that cannot be recorded is still a refusal — reported as the
// server's own failure rather than answered quietly.
func TestCallsAreRefusedWhenTheAuditLogIsBroken(t *testing.T) {
	t.Run("admitted call", func(t *testing.T) {
		h := newHarness(t)
		h.sink.breakFromNow()

		res := h.callTool(addrA, h.tokenA, "list_notes", `{}`)
		if res.status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503: %s", res.status, res.rawBody)
		}
		if len(h.gateway.toolCalls()) != 0 {
			t.Fatalf("an unrecordable call was forwarded to the gateway")
		}
	})

	t.Run("refused call", func(t *testing.T) {
		h := newHarness(t)
		h.sink.breakFromNow()

		res := h.callTool(addrB, h.tokenA, "list_notes", `{}`) // replay: would be 403
		if res.status != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503: %s", res.status, res.rawBody)
		}
		if len(h.gateway.toolCalls()) != 0 {
			t.Fatalf("an unrecordable refusal still reached the gateway")
		}
	})
}

// Transport frames are the gateway's business and pass through untouched —
// minus the Homeplane credential, which stops at the edge.
func TestTransportFramesAreForwardedWithoutTheGrantToken(t *testing.T) {
	h := newHarness(t)

	if res := h.do(http.MethodGet, addrA, h.tokenA, "", map[string]string{HeaderSessionID: stubSessionID}); res.status != http.StatusOK {
		t.Errorf("SSE GET status = %d", res.status)
	}
	if res := h.do(http.MethodDelete, addrA, h.tokenA, "", map[string]string{HeaderSessionID: stubSessionID}); res.status != http.StatusNoContent {
		t.Errorf("session DELETE status = %d", res.status)
	}
	list := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	if res := h.do(http.MethodPost, addrA, h.tokenA, list, nil); res.status != http.StatusOK {
		t.Errorf("tools/list status = %d", res.status)
	}

	seen := h.gateway.seen()
	var methods []string
	for _, req := range seen {
		methods = append(methods, req.Method)
		if req.Authz != "" {
			t.Fatalf("the grant token reached the gateway: %+v", req)
		}
		// Both sides name the same single MCP endpoint: the edge must address
		// the gateway's endpoint, not the endpoint joined with its own path.
		if req.Path != h.gateway.endpoint(t).Path {
			t.Errorf("%s went to %q, want the gateway endpoint %q",
				req.Method, req.Path, h.gateway.endpoint(t).Path)
		}
		if req.SessionID != stubSessionID && req.Method != http.MethodPost {
			t.Errorf("session id was not forwarded on %s: %q", req.Method, req.SessionID)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("gateway saw %d requests (%v), want GET, DELETE and POST", len(seen), methods)
	}
	// None of them are tool calls, so none of them produced a connector row.
	if h.countRows(store.EventConnectorToolCall) != 0 {
		t.Errorf("a transport frame was audited as a tool call")
	}
}

// Every transport frame is authenticated, not just the tool calls: an
// unauthenticated peer cannot use the edge as an open proxy to the gateway.
func TestTransportFramesRequireAuthentication(t *testing.T) {
	h := newHarness(t)

	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPost} {
		if res := h.do(method, addrA, "", "", nil); res.status != http.StatusUnauthorized {
			t.Errorf("%s without a token got status %d", method, res.status)
		}
		if res := h.do(method, addrB, h.tokenA, "", nil); res.status != http.StatusForbidden {
			t.Errorf("%s replayed from another node got status %d", method, res.status)
		}
	}
	if len(h.gateway.seen()) != 0 {
		t.Fatalf("unauthenticated transport frames reached the gateway")
	}
}

// A batched JSON-RPC frame hides its tool calls inside an array, where a
// single-frame parse would not find them — and forwarding it would hand the
// gateway an unauthorized tools/call. It is refused, not forwarded.
func TestBatchedFramesAreRefusedRatherThanForwarded(t *testing.T) {
	h := newHarness(t)

	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"export_archive","arguments":{}}}]`
	res := h.do(http.MethodPost, addrA, h.tokenA, batch, nil)
	if res.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", res.status, res.rawBody)
	}
	if len(h.gateway.seen()) != 0 {
		t.Fatalf("a batched frame reached the gateway: %+v", h.gateway.seen())
	}
}

// The audit log is metadata only, and the edge must not become the hole in
// that: neither tool arguments nor a gateway response may appear in any row.
func TestNoPayloadReachesTheAuditLog(t *testing.T) {
	const secret = "the-quick-brown-fox-payload"
	h := newHarness(t)
	h.gateway.respond("create_note", `{"note":{"id":"n-9"},"content":[{"type":"text","text":"`+secret+`"}]}`)

	if res := h.callTool(addrA, h.tokenA, "create_note", `{"body":"`+secret+`"}`); res.status != http.StatusOK {
		t.Fatalf("call failed: %d %s", res.status, res.rawBody)
	}
	rows := h.auditRows()
	blob, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal rows: %v", err)
	}
	if strings.Contains(string(blob), secret) {
		t.Fatalf("payload content reached the audit log: %s", blob)
	}
	if len(rows) == 0 {
		t.Fatal("no audit rows at all")
	}
}

// Construction refuses anything that would weaken the boundary.
func TestNewRefusesUnsafeConfigurations(t *testing.T) {
	h := newHarness(t)
	loopback := h.gateway.endpoint(t)
	base := Config{Store: h.sink, Identity: fakeResolver{}, Broker: h.edge.cfg.Broker, Upstream: loopback}

	if _, err := New(base); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}

	routable := *loopback
	routable.Host = "100.64.0.9:9100"
	bad := base
	bad.Upstream = &routable
	if _, err := New(bad); err == nil {
		t.Error("a routable gateway upstream was accepted")
	}

	for name, mutate := range map[string]func(*Config){
		"no store":    func(c *Config) { c.Store = nil },
		"no identity": func(c *Config) { c.Identity = nil },
		"no broker":   func(c *Config) { c.Broker = nil },
		"no upstream": func(c *Config) { c.Upstream = nil },
	} {
		cfg := base
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
