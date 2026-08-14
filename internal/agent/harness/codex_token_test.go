package harness

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Codex token propagation must survive a FRESH PROCESS TREE.
//
// The failure this guards against is specific and common: a config that names
// an environment variable (`bearer_token_env_var`, `env_http_headers`) works in
// the shell where that variable was exported and fails everywhere else — from a
// launchd-started editor, from a desktop app, from any process that did not
// inherit the operator's shell. The task's plan named a launcher shim exporting
// `bearer_token_env_var` as the FALLBACK for exactly that reason.
//
// The fallback turned out not to be needed. Codex's config reference documents
// `mcp_servers.<id>.http_headers` — "static HTTP headers included with each MCP
// HTTP request" — so the bearer can live inline in the 0600 config.toml, with
// no environment involved at any point. That is verified two ways below: as a
// property of what we WRITE (no env indirection anywhere in the entry), which
// always runs; and against the real `codex` binary launched with an EMPTY
// environment, which runs wherever Codex is installed.

// codexEnvIndirectionKeys are the keys that would make the token depend on the
// launching process's environment. Writing any of them would reintroduce the
// bug this test exists for.
var codexEnvIndirectionKeys = []string{"bearer_token_env_var", "env_http_headers", "env", "env_vars"}

func TestTheCodexEntryCarriesItsTokenWithNoEnvironmentIndirection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCodexWriter(path, "").Apply(managedEntries("fresh-tree-token"), nil); err != nil {
		t.Fatal(err)
	}
	tree, err := parseTOMLTree(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	entry := entryIn(t, tree, codexContainer, ConnectorServerName)

	headers, ok := entry["http_headers"].(map[string]any)
	if !ok {
		t.Fatal("the connector entry has no static http_headers; the token would have to come from somewhere else")
	}
	if headers["Authorization"] != "Bearer fresh-tree-token" {
		t.Fatalf("Authorization = %v", headers["Authorization"])
	}
	for _, key := range codexEnvIndirectionKeys {
		if _, present := entry[key]; present {
			t.Errorf("the entry declares %q: the token would depend on the launching environment", key)
		}
	}
}

// TestCodexResolvesTheTokenInAnEmptyEnvironment is the real proof: the actual
// Codex CLI, in a process that inherited NOTHING — no PATH, no HOME, no shell
// exports — reads the config we wrote and reports that it has a bearer token
// for the Homeplane endpoint.
func TestCodexResolvesTheTokenInAnEmptyEnvironment(t *testing.T) {
	binary, err := exec.LookPath("codex")
	if err != nil {
		t.Skip("codex is not installed on this machine; the fresh-process-tree proof needs the real CLI")
	}

	codexHome := t.TempDir()
	path := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(path, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	const token = "fresh-tree-token-9f2a"
	if _, err := NewCodexWriter(path, "").Apply(managedEntries(token), nil); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "mcp", "list", "--json")
	// The whole point: an empty environment apart from where the config lives.
	// Anything the token needed from a shell would be missing here.
	cmd.Env = []string{"CODEX_HOME=" + codexHome}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex mcp list failed in an empty environment: %v\n%s", err, out)
	}

	var servers []struct {
		Name      string `json:"name"`
		Transport struct {
			Type              string            `json:"type"`
			URL               string            `json:"url"`
			BearerTokenEnvVar *string           `json:"bearer_token_env_var"`
			HTTPHeaders       map[string]string `json:"http_headers"`
		} `json:"transport"`
		AuthStatus string `json:"auth_status"`
	}
	if err := json.Unmarshal(out, &servers); err != nil {
		t.Fatalf("codex mcp list --json produced %q: %v", out, err)
	}

	var found bool
	for _, s := range servers {
		if s.Name != ConnectorServerName {
			continue
		}
		found = true
		if s.Transport.Type != "streamable_http" {
			t.Errorf("transport = %q, want streamable_http", s.Transport.Type)
		}
		if s.AuthStatus != "bearer_token" {
			t.Errorf("auth_status = %q, want bearer_token — Codex did not resolve the token", s.AuthStatus)
		}
		if got := s.Transport.HTTPHeaders["Authorization"]; got != "Bearer "+token {
			t.Errorf("Codex read Authorization as %q", got)
		}
		if s.Transport.BearerTokenEnvVar != nil {
			t.Errorf("the entry depends on env var %q", *s.Transport.BearerTokenEnvVar)
		}
	}
	if !found {
		t.Fatalf("Codex does not see the %q server at all:\n%s", ConnectorServerName, out)
	}

	// The harness's own view of the file must still show the unrelated servers
	// the fixture had — Codex parsing it is not by itself proof they survived.
	for _, name := range []string{"RepoPrompt", "blender"} {
		if !strings.Contains(string(out), name) {
			t.Errorf("Codex no longer sees the pre-existing %q server", name)
		}
	}
}
