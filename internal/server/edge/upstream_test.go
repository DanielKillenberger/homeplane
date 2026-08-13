package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/store"
)

func TestParseUpstreamAcceptsOnlyLoopbackGateways(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:44022/mcp",
		"http://[::1]:44022/mcp",
		"http://localhost:44022/mcp",
	} {
		if _, err := ParseUpstream(raw); err != nil {
			t.Errorf("ParseUpstream(%q) = %v, want accepted", raw, err)
		}
	}
	for _, raw := range []string{
		"http://100.64.0.9:9100/mcp",  // a tailnet address
		"http://0.0.0.0:9100/mcp",     // every interface
		"http://gateway.internal/mcp", // a name that would have to be resolved
		"https://example.com/mcp",     // the public internet
		"ftp://127.0.0.1/mcp",         // not HTTP at all
		"http:///mcp",                 // no host
	} {
		if _, err := ParseUpstream(raw); err == nil {
			t.Errorf("ParseUpstream(%q) was accepted; the gateway must be loopback-bound", raw)
		}
	}
}

// The bypass boundary, demonstrated rather than asserted: the composed gateway
// binds loopback only, so a peer arriving on the machine's routable address
// cannot reach it — while the same call through the edge, which binds that
// routable address, succeeds. This is the local, always-runnable half of the
// D6 spike's cross-node bypass evidence (docs/decisions/d6-gateway.md, gate 1),
// where the second node was a real tailnet machine.
func TestGatewayIsUnreachableOffLoopbackWhileTheEdgeIsReachable(t *testing.T) {
	routableIP := routableIPv4(t)

	h := newHarness(t)
	gatewayPort := portOf(t, h.gateway.URL)

	// 1. The gateway's own port, dialled on the machine's routable address:
	//    refused, because nothing is listening there.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(routableIP, gatewayPort), 2*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("the gateway accepted a connection on %s: it is not loopback-bound", routableIP)
	}

	// 2. The edge, bound to that same routable address, serves the same call.
	ln, err := net.Listen("tcp", net.JoinHostPort(routableIP, "0"))
	if err != nil {
		t.Skipf("cannot bind the routable address %s: %v", routableIP, err)
	}
	edgeAddr := ln.Addr().String()

	// The peer arrives over a real socket, so its source port is the kernel's
	// choice and a fixed address table cannot match it. The resolver names it
	// as node A — the node this grant is bound to.
	h.edge.cfg.Identity = anyPeerResolver{nodeA}

	srv := httptest.Server{Listener: ln, Config: &http.Server{Handler: h.edge.Handler()}}
	srv.Start()
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_notes","arguments":{}}}`
	req, err := http.NewRequest(http.MethodPost, "http://"+edgeAddr+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+h.tokenA)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("edge call over the routable address failed: %v", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edge status = %d: %s", resp.StatusCode, payload)
	}
	if len(h.gateway.toolCalls()) != 1 {
		t.Errorf("the gateway saw %d tool calls through the edge, want 1", len(h.gateway.toolCalls()))
	}
}

// anyPeerResolver names every peer as one node. It stands in for WhoIs in the
// isolation test, where the peer's source port is chosen by the kernel and a
// fixed address table cannot match it.
type anyPeerResolver struct{ id store.Identity }

func (a anyPeerResolver) Resolve(_ context.Context, _ string) (store.Identity, error) {
	return a.id, nil
}

func routableIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	t.Skip("no non-loopback IPv4 address on this host; the bypass boundary needs one")
	return ""
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	trimmed := strings.TrimPrefix(rawURL, "http://")
	_, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	return port
}

// The transport permits either an SSE stream or a plain JSON body; the runtime
// must read a response out of both, skip frames that are not responses, and
// refuse a body that carries neither a result nor an error.
func TestUpstreamResponseDecoding(t *testing.T) {
	sse := "event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n" +
		"event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
	rpc, err := decodeRPCResponse("text/event-stream; charset=utf-8", []byte(sse))
	if err != nil {
		t.Fatalf("decode SSE: %v", err)
	}
	if string(rpc.Result) != `{"ok":true}` {
		t.Errorf("SSE result = %s", rpc.Result)
	}

	rpc, err = decodeRPCResponse("application/json", []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"nope"}}`))
	if err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if rpc.Error == nil || rpc.Error.Code != -32001 {
		t.Errorf("JSON error = %+v", rpc.Error)
	}

	if _, err := decodeRPCResponse("text/event-stream", []byte(": keep-alive\n\n")); !errors.Is(err, ErrUpstreamProtocol) {
		t.Errorf("a stream with no response decoded as %v", err)
	}
	if _, err := decodeRPCResponse("application/json", []byte("not json")); !errors.Is(err, ErrUpstreamProtocol) {
		t.Errorf("a malformed body decoded as %v", err)
	}
}

// The runtime forwards the tool name the CLIENT used, not the manifest's
// unqualified name: routing decides policy, it does not rewrite the gateway's
// namespace.
func TestRuntimeForwardsTheWireToolName(t *testing.T) {
	var seen toolCallParams
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rpc rpcRequest
		_ = json.Unmarshal(body, &rpc)
		_ = json.Unmarshal(rpc.Params, &seen)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, rpc.ID)
	}))
	defer gw.Close()

	endpoint, err := ParseUpstream(gw.URL + "/mcp")
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	rt := NewHTTPRuntime(endpoint, gw.Client())

	ctx := withCallState(context.Background(), &callState{
		wireTool: "stub-notes__create_note", sessionID: stubSessionID,
	})
	if _, err := rt.CallTool(ctx, "stub-notes", "create_note", nil); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if seen.Name != "stub-notes__create_note" {
		t.Errorf("gateway saw tool %q, want the wire name", seen.Name)
	}
	if string(seen.Arguments) != `{}` {
		t.Errorf("absent arguments were forwarded as %s, want an empty object", seen.Arguments)
	}
}
