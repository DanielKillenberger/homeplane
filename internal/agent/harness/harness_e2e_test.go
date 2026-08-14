package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
)

// The end-to-end half of R5/R6/R7's machine side: a REAL harness CLI, reading
// the configuration this package wrote, reaching both endpoints.
//
// What is real here: the harness binary, its config parsing, its MCP client,
// its process launching, and the bearer header it puts on the wire. What is
// stubbed is what the two endpoints are — a stdio MCP server standing in for
// the retrieval engine, and a loopback streamable-HTTP MCP server standing in
// for the connector edge, which checks the Authorization header against the
// grant token this run minted and refuses anything else. That boundary is the
// right one for THIS task: whether the vault has content is task .11's proof
// and whether Google answers is task .12's; what has to be proven here is that
// the entries we wrote are reachable and carry the right authority.

// stdioMCPStub is a minimal newline-delimited JSON-RPC MCP server. It stands in
// for the retrieval engine's stdio endpoint so a harness can actually launch
// what the descriptor described.
const stdioMCPStub = `#!/usr/bin/env python3
import json, sys

TOOLS = [{"name": "vault_search",
          "description": "search the vault",
          "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}}]

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except json.JSONDecodeError:
        continue
    method, rid = req.get("method"), req.get("id")
    if rid is None:          # a notification
        continue
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "retrieval-engine-stub", "version": "0.0.1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": "a note from the vault"}]}})
    else:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "no " + str(method)}})
`

func writeStdioStub(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "retrieval-engine-stub")
	if err := os.WriteFile(path, []byte(stdioMCPStub), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubConnector is the loopback stand-in for task .16's edge. It authenticates
// EVERY request against the expected grant token — a harness that forgot the
// header, or carried the other harness's, gets 401 rather than a tool list.
type stubConnector struct {
	mu       sync.Mutex
	expected string
	accepted int
	refused  int
	// wrongToken counts requests that carried an Authorization header that was
	// not the grant token. It is kept apart from `refused` because an
	// UNAUTHENTICATED probe and a WRONG-TOKEN call are different facts: the
	// first is something a client may legitimately do, the second is the bug
	// this stub exists to catch.
	wrongToken int
	reached    int
}

func (s *stubConnector) authorized(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reached++
	auth := r.Header.Get("Authorization")
	if auth == "Bearer "+s.expected {
		s.accepted++
		return true
	}
	if auth != "" {
		s.wrongToken++
	}
	s.refused++
	return false
}

func (s *stubConnector) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted, s.refused
}

// stats returns (reached, accepted, wrongToken).
func (s *stubConnector) stats() (int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reached, s.accepted, s.wrongToken
}

func (s *stubConnector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="homeplane"`)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodDelete { // session teardown
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if len(req.ID) == 0 { // a notification: accepted, no body
		w.WriteHeader(http.StatusAccepted)
		return
	}

	var result any
	switch req.Method {
	case "initialize":
		version := req.Params.ProtocolVersion
		if version == "" {
			version = "2025-06-18"
		}
		result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "homeplane-connector-stub", "version": "0.0.1"},
		}
	case "tools/list":
		result = map[string]any{"tools": []any{
			map[string]any{"name": "google_drive__files_get", "description": "read a Drive file",
				"inputSchema": map[string]any{"type": "object"}},
		}}
	case "tools/call":
		result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}
	default:
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, req.ID)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", "stub-session")
	encoded, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
	w.Write(encoded)
}

// tokenIssuer hands out one fixed token per harness so the stub connector can
// be told which one to expect.
type tokenIssuer struct {
	endpoint string
	tokens   map[string]string
}

func (i tokenIssuer) IssueGrant(_ context.Context, harnessName string) (Grant, error) {
	return Grant{
		GrantID:      "grant-" + harnessName,
		Harness:      harnessName,
		Capabilities: []string{"connector.read"},
		EndpointURL:  i.endpoint,
		Token:        i.tokens[harnessName],
	}, nil
}

// configureAgainstStubs wires one harness to the two stub endpoints and returns
// the machine it was configured on.
func configureAgainstStubs(t *testing.T, harnessName string, connector *stubConnector, endpoint string) *machine {
	t.Helper()
	m := newMachine(t, false)

	stub := writeStdioStub(t, t.TempDir())
	if err := gno.SaveDescriptor(m.stateDir, gno.Descriptor{
		Component: gno.ComponentRetrievalEngine, Engine: "gno", EngineVersion: "stub",
		Transport: gno.TransportStdio, Command: stub, Args: []string{"--serve"},
		ServerName: "gno", Collection: "vault", VaultPath: filepath.Join(m.stateDir, "vault"),
		DerivedFrom: "test stub", WrittenAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	cfg := m.configurator(tokenIssuer{
		endpoint: endpoint,
		tokens:   map[string]string{ClaudeCode: connector.expected, Codex: connector.expected},
	})
	cfg.Only = []string{harnessName}
	report, err := cfg.Configure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Err(); err != nil {
		t.Fatalf("configure %s: %v", harnessName, err)
	}
	return m
}

func TestFromClaudeCodeBothConfiguredEndpointsAnswer(t *testing.T) {
	binary, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("Claude Code is not installed on this machine")
	}

	connector := &stubConnector{expected: "claude-grant-token-4b1c"}
	server := httptest.NewServer(connector)
	defer server.Close()

	m := configureAgainstStubs(t, ClaudeCode, connector, server.URL+"/mcp")

	// `claude mcp list` health-checks every configured server: it launches the
	// stdio one and opens an MCP session against the HTTP one. Its verdict per
	// server is therefore a real call, not a config dump.
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "mcp", "list")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+m.home, "CLAUDE_CONFIG_DIR="+m.home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("claude mcp list: %v\n%s", err, out)
	}
	text := string(out)

	for _, server := range []string{ConnectorServerName, "gno"} {
		line := lineFor(text, server+":")
		if line == "" {
			t.Fatalf("claude does not list %q at all:\n%s", server, text)
		}
		if !strings.Contains(line, "✓") && !strings.Contains(line, "✔") && !strings.Contains(line, "Connected") {
			t.Errorf("claude could not reach %q: %s", server, line)
		}
	}

	accepted, refused := connector.counts()
	if accepted == 0 {
		t.Error("the connector stub saw no authorized request from Claude Code")
	}
	if refused != 0 {
		t.Errorf("the connector stub refused %d request(s): the grant token did not reach the wire", refused)
	}
}

func lineFor(text, prefix string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return line
		}
	}
	return ""
}

func TestCodexReadsBothConfiguredEndpointsFromWhatWeWrote(t *testing.T) {
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("Codex is not installed on this machine")
	}

	connector := &stubConnector{expected: "codex-grant-token-7d3e"}
	server := httptest.NewServer(connector)
	defer server.Close()

	m := configureAgainstStubs(t, Codex, connector, server.URL+"/mcp")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "mcp", "list", "--json")
	cmd.Env = []string{"CODEX_HOME=" + m.codexHome}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex mcp list: %v\n%s", err, out)
	}

	var servers []struct {
		Name      string `json:"name"`
		Enabled   bool   `json:"enabled"`
		Transport struct {
			Type        string            `json:"type"`
			URL         string            `json:"url"`
			Command     string            `json:"command"`
			Args        []string          `json:"args"`
			HTTPHeaders map[string]string `json:"http_headers"`
		} `json:"transport"`
		AuthStatus string `json:"auth_status"`
	}
	if err := json.Unmarshal(out, &servers); err != nil {
		t.Fatalf("codex mcp list --json produced %q: %v", out, err)
	}

	seen := map[string]bool{}
	for _, s := range servers {
		seen[s.Name] = true
		switch s.Name {
		case ConnectorServerName:
			if s.Transport.URL != server.URL+"/mcp" {
				t.Errorf("connector url = %q, want the endpoint the server issued", s.Transport.URL)
			}
			if s.AuthStatus != "bearer_token" {
				t.Errorf("auth_status = %q", s.AuthStatus)
			}
			if s.Transport.HTTPHeaders["Authorization"] != "Bearer "+connector.expected {
				t.Errorf("Codex reads Authorization as %q", s.Transport.HTTPHeaders["Authorization"])
			}
		case "gno":
			if !strings.HasSuffix(s.Transport.Command, "retrieval-engine-stub") {
				t.Errorf("engine command = %q, want the descriptor's", s.Transport.Command)
			}
			if len(s.Transport.Args) != 1 || s.Transport.Args[0] != "--serve" {
				t.Errorf("engine args = %v, want the descriptor's", s.Transport.Args)
			}
		}
	}
	for _, want := range []string{ConnectorServerName, "gno", "RepoPrompt", "blender"} {
		if !seen[want] {
			t.Errorf("codex does not see %q — either we did not write it, or we removed it", want)
		}
	}

	// `mcp list` only parses. `doctor` performs a real reachability probe from
	// Codex's own HTTP client against the URL we wrote, so it is what turns
	// "Codex read our config" into "Codex reached the endpoint our config named".
	ctx2, cancel2 := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel2()
	doctor := exec.CommandContext(ctx2, binary, "doctor")
	doctor.Env = []string{"CODEX_HOME=" + m.codexHome, "HOME=" + m.home, "PATH=" + os.Getenv("PATH")}
	doctorOut, _ := doctor.CombinedOutput() // a missing login makes doctor exit nonzero; the MCP section is still emitted

	reached, _, wrongToken := connector.stats()
	if reached == 0 {
		t.Errorf("Codex never contacted the endpoint we wrote:\n%s", doctorOut)
	}
	// doctor's reachability probe deliberately carries no Authorization header,
	// so a refusal here is expected and says nothing. What must never happen is
	// a request carrying the WRONG token — that would mean we wrote one.
	if wrongToken != 0 {
		t.Errorf("%d request(s) from Codex carried a token that is not this harness's grant", wrongToken)
	}
	if !strings.Contains(string(doctorOut), server.URL+"/mcp") && !strings.Contains(string(doctorOut), "streamable_http") {
		t.Errorf("doctor did not report on the configured endpoint:\n%s", doctorOut)
	}
}

// What the two Codex tests above do and do NOT prove — stated rather than
// implied, because the acceptance criterion says "a call succeeds from each
// harness" and only half of that is reachable here.
//
// Proven, against the real CLI: Codex parses the config we wrote, resolves the
// inline bearer with no environment (`auth_status: bearer_token` under an empty
// env), keeps every pre-existing server, launches from the descriptor's exact
// command and argv, and opens a real connection to the endpoint URL we wrote.
//
// Not proven here: an AUTHENTICATED MCP tool call from Codex. Codex 0.146
// exposes no non-model MCP invocation — `mcp` only lists/gets/adds/removes, and
// `doctor`'s reachability probe deliberately sends no Authorization header
// (verified: the stub records the probe arriving with none). The only path that
// makes Codex call a tool is a model turn (`codex exec`), which needs
// credentials and a live model, so it belongs with task .7's live proof rather
// than in this package's always-runnable suite. The Claude Code test above does
// close that loop end-to-end — it authenticates against the stub and fails on a
// wrong token — so the authenticated-call path IS proven for one real harness,
// and the residual obligation is Codex-specific.
const codexProofBoundary = `authenticated Codex tool call: deferred to task .7 (Codex CLI has no ` +
	`non-model MCP invocation; doctor probes reachability without the auth header)`

func TestTheCodexProofBoundaryIsRecorded(t *testing.T) {
	if codexProofBoundary == "" {
		t.Fatal("the boundary must be stated, not silently assumed")
	}
}
