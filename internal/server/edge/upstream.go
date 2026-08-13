package edge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// ProtocolVersion is the MCP revision the edge speaks upstream when the client
// did not pin one. It is the revision the D6 spike verified end to end through
// the composed gateway with real Claude Code and Codex clients.
const ProtocolVersion = "2025-06-18"

// Streamable-HTTP transport headers. The session header is passed through in
// both directions: session state belongs to the gateway (D6 composition), and
// the edge must not invent or rewrite it.
const (
	HeaderSessionID       = "Mcp-Session-Id"
	HeaderProtocolVersion = "MCP-Protocol-Version"
)

// ErrUpstreamNotLoopback is the refusal that keeps the bypass boundary real.
//
// The whole isolation argument of D6's adopted shape is that the composed
// gateway listens on loopback only, so the ONLY route to it from another
// tailnet node is through this edge — where the grant token, the machine
// binding and the manifest apply. An edge configured against a routable
// upstream would silently make that boundary decorative, so it is refused at
// construction rather than discovered later.
var ErrUpstreamNotLoopback = errors.New("edge: gateway upstream must be loopback-bound")

// ErrUpstreamUnreachable wraps a transport failure talking to the gateway.
var ErrUpstreamUnreachable = errors.New("edge: gateway unreachable")

// ErrUpstreamProtocol means the gateway answered something that is not a
// well-formed streamable-HTTP MCP response.
var ErrUpstreamProtocol = errors.New("edge: malformed gateway response")

// ParseUpstream validates and parses the composed gateway's MCP endpoint URL.
// A non-loopback host is refused (see ErrUpstreamNotLoopback).
func ParseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("edge: bad gateway url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("edge: gateway url %q must be http or https", raw)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("edge: gateway url %q has no host", raw)
	}
	if !IsLoopbackHost(host) {
		return nil, fmt.Errorf("%w: %q", ErrUpstreamNotLoopback, raw)
	}
	return u, nil
}

// IsLoopbackHost reports whether a URL host names the local machine's loopback.
//
// Only a literal loopback IP or the name "localhost" qualifies. Any other name
// would have to be resolved to be judged, and a resolver answer is not a
// property of the configuration — it can change under the process, which is
// exactly the kind of silent boundary erosion this check exists to prevent.
func IsLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RPCError is a JSON-RPC error object returned by the gateway or the tool
// behind it. It is carried out of the runtime as a typed error so the edge can
// hand the client back the provider's own error faithfully instead of
// flattening every failure into a transport error.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// callState carries the per-request transport facts a ToolRuntime call needs
// but the connectors.ToolRuntime signature deliberately does not model: the
// gateway session the client is using, and the tool name as it appeared on the
// wire (a composed gateway may namespace tools; the manifest names them
// unqualified).
//
// It also carries the gateway's own JSON-RPC error back OUT. The broker
// deliberately flattens a tool failure into ErrToolFailed — what it audits is
// that the call failed, never the provider's message — so the structured error
// cannot travel in the error chain without changing what the audit layer sees.
// Handing it back through the request's own state keeps the client's answer
// faithful without putting provider text anywhere near an audit row.
type callState struct {
	sessionID       string
	wireTool        string
	protocolVersion string

	// toolError is set by the runtime when the gateway answered with a
	// JSON-RPC error. Only the goroutine serving the request touches it.
	toolError *RPCError
}

type callStateKey struct{}

// withCallState attaches the transport facts of the client's request.
func withCallState(ctx context.Context, cs *callState) context.Context {
	return context.WithValue(ctx, callStateKey{}, cs)
}

func callStateFrom(ctx context.Context) *callState {
	cs, _ := ctx.Value(callStateKey{}).(*callState)
	if cs == nil {
		return &callState{}
	}
	return cs
}

// HTTPRuntime is the connectors.ToolRuntime that forwards an ADMITTED tool call
// to the composed gateway over streamable HTTP.
//
// It is the only part of the edge that speaks to the gateway, and it is
// deliberately dumb: by the time a call reaches it the manifest has authorized
// it and the authoritative audit row is already committed (see
// connectors.Broker.Invoke). Nothing here can admit a call.
type HTTPRuntime struct {
	endpoint         *url.URL
	client           *http.Client
	maxResponseBytes int64
	nextID           atomic.Int64
}

// DefaultMaxUpstreamResponseBytes bounds a gateway response. A tool result is
// metadata plus content, not a bulk transfer, and an unbounded read would let a
// misbehaving upstream exhaust the server.
const DefaultMaxUpstreamResponseBytes = 8 << 20

// DefaultUpstreamTimeout bounds one gateway call.
const DefaultUpstreamTimeout = 60 * time.Second

// NewHTTPRuntime builds a runtime against an already-validated loopback
// endpoint. Pass a nil client for the default.
func NewHTTPRuntime(endpoint *url.URL, client *http.Client) *HTTPRuntime {
	if client == nil {
		client = &http.Client{Timeout: DefaultUpstreamTimeout}
	}
	return &HTTPRuntime{
		endpoint:         endpoint,
		client:           client,
		maxResponseBytes: DefaultMaxUpstreamResponseBytes,
	}
}

// CallTool implements connectors.ToolRuntime.
//
// The tool name sent upstream is the name the CLIENT used, not the manifest's
// unqualified name: routing (see toolRouter) exists to decide policy, not to
// rewrite the gateway's namespace.
func (rt *HTTPRuntime) CallTool(ctx context.Context, _ /* provider */, tool string, args json.RawMessage) (json.RawMessage, error) {
	cs := callStateFrom(ctx)
	wire := cs.wireTool
	if wire == "" {
		wire = tool
	}
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}

	id := rt.nextID.Add(1)
	body, err := json.Marshal(rpcRequest{
		JSONRPC: jsonRPCVersion,
		ID:      json.RawMessage(fmt.Sprintf("%d", id)),
		Method:  methodToolsCall,
		Params: mustMarshal(toolCallParams{
			Name:      wire,
			Arguments: args,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("edge: encode tool call: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rt.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("edge: build gateway request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	version := cs.protocolVersion
	if version == "" {
		version = ProtocolVersion
	}
	req.Header.Set(HeaderProtocolVersion, version)
	if cs.sessionID != "" {
		req.Header.Set(HeaderSessionID, cs.sessionID)
	}

	resp, err := rt.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstreamUnreachable, err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(resp.Body, rt.maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrUpstreamUnreachable, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: gateway returned HTTP %d", ErrUpstreamProtocol, resp.StatusCode)
	}

	rpc, err := decodeRPCResponse(resp.Header.Get("Content-Type"), payload)
	if err != nil {
		return nil, err
	}
	if rpc.Error != nil {
		// Kept for the response the client gets; the broker only learns that
		// the call failed.
		cs.toolError = rpc.Error
		return nil, rpc.Error
	}
	if len(rpc.Result) == 0 {
		return nil, fmt.Errorf("%w: response carried neither a result nor an error", ErrUpstreamProtocol)
	}
	return rpc.Result, nil
}

// decodeRPCResponse reads a streamable-HTTP MCP response body, which is either
// a single JSON object or an SSE stream whose `data:` frames carry the
// JSON-RPC messages (the gateway chooses; both are legal in the transport, and
// the D6 spike observed SSE).
func decodeRPCResponse(contentType string, payload []byte) (rpcResponse, error) {
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return decodeSSE(payload)
	}
	var rpc rpcResponse
	if err := json.Unmarshal(payload, &rpc); err != nil {
		return rpcResponse{}, fmt.Errorf("%w: %v", ErrUpstreamProtocol, err)
	}
	return rpc, nil
}

// decodeSSE returns the first SSE data frame that is a JSON-RPC response
// (carrying a result or an error). Frames that are neither — notifications,
// progress, keep-alives — are skipped rather than treated as the answer.
func decodeSSE(payload []byte) (rpcResponse, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 0, 64<<10), len(payload)+1)
	for scanner.Scan() {
		line := scanner.Text()
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "" {
			continue
		}
		var rpc rpcResponse
		if err := json.Unmarshal([]byte(data), &rpc); err != nil {
			continue
		}
		if rpc.Error != nil || len(rpc.Result) > 0 {
			return rpc, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return rpcResponse{}, fmt.Errorf("%w: read event stream: %v", ErrUpstreamProtocol, err)
	}
	return rpcResponse{}, fmt.Errorf("%w: event stream carried no JSON-RPC response", ErrUpstreamProtocol)
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// The only values marshalled here are this package's own structs over
		// already-valid json.RawMessage; a failure is a programming error.
		panic("edge: marshal: " + err.Error())
	}
	return b
}
