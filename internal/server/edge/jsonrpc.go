package edge

import "encoding/json"

// The JSON-RPC subset the edge understands. The edge is a policy and audit
// boundary, not an MCP implementation: it parses exactly enough of a request to
// decide whether it is a tool call and which tool it names, and forwards
// everything else untouched.

const (
	jsonRPCVersion  = "2.0"
	methodToolsCall = "tools/call"
)

// JSON-RPC error codes returned BY THE EDGE. -32000..-32099 is the
// implementation-defined server range; these three are the edge's own refusals
// and never collide with a code minted by the gateway or a provider.
const (
	// codeInvalidParams is JSON-RPC's own "invalid params" code.
	codeInvalidParams = -32602

	// codeInvalidRequest is JSON-RPC's own "invalid request" code.
	codeInvalidRequest = -32600

	codeForbidden      = -32003
	codeGatewayFailure = -32010
	codeAuditFailure   = -32011
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// toolCallParams is the `tools/call` parameter object. Arguments stay a raw
// message end to end: the edge never interprets tool arguments, and the audit
// derivation reduces them to a one-way digest or a declaratively extracted
// artifact id (task .3).
type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
