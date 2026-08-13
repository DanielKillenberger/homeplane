package gno

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The stdio launch-template probe.
//
// R4 distinguishes two lifecycles and forbids blurring them. The engine's
// DAEMON is supervised, has a pid, and has a restart ledger. The harness
// endpoint is stdio: a client launches its own server process on demand, and
// there is no persistent pid to report — so "is it healthy?" can only mean "did
// a launch of the template just work?".
//
// This is that probe. It runs the descriptor's own command, speaks the MCP
// handshake, and (optionally) calls a tool. It never claims a running process,
// and its result is recorded with a timestamp so `status` reports a LAST-PROBE
// result rather than a live one.

// MCPProbe is the outcome of launching the stdio template once.
type MCPProbe struct {
	OK          bool      `json:"ok"`
	At          time.Time `json:"at"`
	ServerName  string    `json:"server_name,omitempty"`
	ServerVer   string    `json:"server_version,omitempty"`
	ToolCount   int       `json:"tool_count,omitempty"`
	Tools       []string  `json:"tools,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
	CalledTool  string    `json:"called_tool,omitempty"`
	CallExcerpt string    `json:"call_excerpt,omitempty"`
}

// Summary phrases the probe for a human reading `status`.
func (p MCPProbe) Summary() string {
	if p.At.IsZero() {
		return "never probed"
	}
	when := p.At.UTC().Format(time.RFC3339)
	if !p.OK {
		return "last stdio launch FAILED at " + when + ": " + p.Detail
	}
	return fmt.Sprintf("last stdio launch ok at %s (%s %s, %d tools)", when, p.ServerName, p.ServerVer, p.ToolCount)
}

// DefaultProbeTimeout bounds one launch. A stdio server that cannot complete a
// handshake in this long is not a server a harness can use.
const DefaultProbeTimeout = 60 * time.Second

// MCPProbeOptions parameterises one probe.
type MCPProbeOptions struct {
	// Command and Args are the descriptor's launch template, so the probe
	// exercises exactly what a harness will run — not an approximation of it.
	Command string
	Args    []string
	Env     map[string]string
	// CallTool, when set, is invoked after the handshake with CallArgs. This is
	// what turns a handshake check into the R6 proof: a real tool call that must
	// return real vault content.
	CallTool string
	CallArgs map[string]any
	// Expect, when set, must appear in the tool call's text response.
	Expect  string
	Timeout time.Duration
}

// ProbeMCP launches the stdio template once and reports what happened.
func ProbeMCP(ctx context.Context, opts MCPProbeOptions) MCPProbe {
	started := time.Now()
	probe := MCPProbe{At: started.UTC()}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if strings.TrimSpace(opts.Command) == "" {
		probe.Detail = "no launch command in the endpoint descriptor"
		return probe
	}

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Env = mergeEnv(opts.Env)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		probe.Detail = "stdin pipe: " + err.Error()
		return probe
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		probe.Detail = "stdout pipe: " + err.Error()
		return probe
	}
	stderr := &tailBuffer{limit: 8 << 10}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		probe.Detail = "launch: " + err.Error()
		return probe
	}
	defer func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		probe.DurationMS = time.Since(started).Milliseconds()
	}()

	client := &stdioClient{in: stdin, out: bufio.NewReaderSize(stdout, 1<<20)}

	init, err := client.call(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "homeplane-agent", "version": "1"},
	})
	if err != nil {
		probe.Detail = "initialize: " + err.Error() + tailDetail(stderr)
		return probe
	}
	var initResult struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	_ = json.Unmarshal(init, &initResult)
	probe.ServerName = initResult.ServerInfo.Name
	probe.ServerVer = initResult.ServerInfo.Version

	if err := client.notify("notifications/initialized", map[string]any{}); err != nil {
		probe.Detail = "initialized notification: " + err.Error()
		return probe
	}

	toolsRaw, err := client.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		probe.Detail = "tools/list: " + err.Error() + tailDetail(stderr)
		return probe
	}
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		probe.Detail = "tools/list: " + err.Error()
		return probe
	}
	probe.ToolCount = len(tools.Tools)
	for _, t := range tools.Tools {
		probe.Tools = append(probe.Tools, t.Name)
	}
	if probe.ToolCount == 0 {
		probe.Detail = "the server exposed no tools"
		return probe
	}

	if strings.TrimSpace(opts.CallTool) == "" {
		probe.OK = true
		return probe
	}

	callRaw, err := client.call(ctx, "tools/call", map[string]any{
		"name":      opts.CallTool,
		"arguments": opts.CallArgs,
	})
	if err != nil {
		probe.Detail = opts.CallTool + ": " + err.Error() + tailDetail(stderr)
		return probe
	}
	probe.CalledTool = opts.CallTool
	text := extractToolText(callRaw)
	probe.CallExcerpt = excerpt(text, 400)
	if opts.Expect != "" && !strings.Contains(text, opts.Expect) {
		probe.Detail = fmt.Sprintf("%s returned no content matching %q", opts.CallTool, opts.Expect)
		return probe
	}
	probe.OK = true
	return probe
}

func tailDetail(buf *tailBuffer) string {
	s := strings.TrimSpace(buf.String())
	if s == "" {
		return ""
	}
	return " (server said: " + firstLine(s) + ")"
}

func excerpt(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// extractToolText flattens an MCP tool result's text content blocks.
func extractToolText(raw json.RawMessage) string {
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return string(raw)
	}
	var sb strings.Builder
	for _, c := range result.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
			sb.WriteString("\n")
		}
	}
	if sb.Len() == 0 {
		return string(raw)
	}
	return sb.String()
}

// stdioClient speaks the newline-delimited JSON-RPC framing MCP uses over stdio.
type stdioClient struct {
	in  io.WriteCloser
	out *bufio.Reader
	id  int
}

type rpcResponse struct {
	ID     *int            `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *stdioClient) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	c.id++
	id := c.id
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
	if err := c.write(req); err != nil {
		return nil, err
	}
	// Read until the matching id: the server interleaves notifications and log
	// lines, and a client that assumed the next line was its answer would break
	// the first time a server logged anything.
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line, err := c.out.ReadBytes('\n')
		if err != nil {
			if len(strings.TrimSpace(string(line))) == 0 {
				return nil, fmt.Errorf("the server closed its output before answering %s: %w", method, err)
			}
		}
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" || !strings.HasPrefix(trimmed, "{") {
			if err != nil {
				return nil, fmt.Errorf("no answer to %s", method)
			}
			continue
		}
		var resp rpcResponse
		if jsonErr := json.Unmarshal([]byte(trimmed), &resp); jsonErr != nil {
			if err != nil {
				return nil, fmt.Errorf("no answer to %s", method)
			}
			continue
		}
		if resp.ID == nil || *resp.ID != id {
			if err != nil {
				return nil, fmt.Errorf("no answer to %s", method)
			}
			continue
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("%s: %s (code %d)", method, resp.Error.Message, resp.Error.Code)
		}
		return resp.Result, nil
	}
}

func (c *stdioClient) notify(method string, params map[string]any) error {
	return c.write(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

func (c *stdioClient) write(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := c.in.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

// mergeEnv overlays the descriptor's environment onto the process environment,
// dropping any inherited GNO_* first so an ambient value cannot redirect the
// probe away from the machine's own index.
func mergeEnv(overlay map[string]string) []string {
	var env []string
	for _, kv := range osEnviron() {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case EnvConfigDir, EnvDataDir, EnvCacheDir:
			continue
		}
		if _, ok := overlay[key]; ok {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range overlay {
		env = append(env, k+"="+v)
	}
	return env
}

// osEnviron is a test seam.
var osEnviron = os.Environ
