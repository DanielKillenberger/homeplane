package harness

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every test in this file runs against a FIXTURE COPY in a temp directory. The
// fixtures are shaped like the real files on the machine this was built for —
// a ~/.claude.json with dozens of unrelated top-level keys and a pre-existing
// MCP server, a ~/.codex/config.toml with comments, quoted-path project tables,
// env sub-tables and a disabled server — because the merge discipline is only
// interesting against configuration somebody actually has. The real files are
// never opened here.

const claudeFixture = `{
  "installMethod": "native",
  "numStartups": 412,
  "mcpServers": {
    "rize": {
      "type": "http",
      "url": "https://mcp.rize.io/mcp",
      "headers": {
        "Authorization": "Bearer someone-elses-token"
      }
    }
  },
  "projects": {
    "/Users/daniel/Projects/homeplane": {
      "allowedTools": [],
      "hasTrustDialogAccepted": true
    }
  },
  "tipsHistory": {
    "shift-tab": 3
  }
}
`

const codexFixture = `# Codex configuration. Hand-edited; the comments matter.
model = "gpt-5.6-sol"
model_reasoning_effort = "xhigh"

[projects."/Users/daniel/Projects/homeplane"]
trust_level = "trusted"

[mcp_servers.RepoPrompt]
command = "/Users/daniel/RepoPrompt/repoprompt_cli"
enabled = false
tool_timeout_sec = 10000.0

[mcp_servers.blender]
command = "/Users/daniel/.local/bin/blender-mcp"

[mcp_servers.blender.env]
BLENDER_HOST = "localhost"
BLENDER_PORT = "9876"

# Keep this: the TUI nux counters are reset by hand.
[tui.model_availability_nux]
"gpt-5.6-sol" = 3
`

// grokFixture is a ~/.grok/config.toml shaped like the one the fn-3 capture
// seeded and observed: a hand-written preamble comment, an unrelated table, an
// unrelated pre-existing MCP entry with its own comment — and a [compat.claude]
// table that already carries OTHER keys, so the `mcps` edit has to be a
// key-level change rather than a table replacement. [compat.cursor] is
// deliberately ABSENT, so one compat cell exercises the edit path and the other
// the append path.
const grokFixture = `# grok configuration. Hand-written; the comments matter.
[ui]
max_thoughts_width = 120

[compat.claude]
skills = true
mcps = true   # inherited from Claude Code today
rules = true

# an unrelated pre-existing MCP entry, with its own comment
[mcp_servers.preexisting-thing]
command = "/usr/bin/true"
args = ["--keep-me"]
enabled = true
`

// managedEntries are the two entries every run writes.
func managedEntries(token string) []Entry {
	return []Entry{
		{
			Name: ConnectorServerName, Transport: TransportHTTP,
			URL:     "https://server.tail-scale.ts.net/mcp",
			Headers: map[string]string{"Authorization": "Bearer " + token},
		},
		{
			Name: "gno", Transport: TransportStdio,
			Command: "/usr/local/bin/homeplane-agent",
			Args:    []string{"gno", "mcp", "-state-dir", "/Users/daniel/.homeplane"},
		},
	}
}

type fixture struct {
	name   string
	path   string
	writer Writer
	parse  parseFn
	// container is the config key managed entries live under.
	container string
	// entryOf extracts one managed entry from a parsed tree.
	entryOf func(tree map[string]any, name string) (map[string]any, bool)
	// authOf extracts the bearer header from a parsed managed entry.
	authOf func(entry map[string]any) (string, bool)
}

func newFixtures(t *testing.T) []fixture {
	t.Helper()
	dir := t.TempDir()

	claudePath := filepath.Join(dir, ".claude.json")
	if err := os.WriteFile(claudePath, []byte(claudeFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(dir, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexPath, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	nested := func(key string) func(map[string]any, string) (map[string]any, bool) {
		return func(tree map[string]any, name string) (map[string]any, bool) {
			container, ok := tree[key].(map[string]any)
			if !ok {
				return nil, false
			}
			entry, ok := container[name].(map[string]any)
			return entry, ok
		}
	}
	authIn := func(key string) func(map[string]any) (string, bool) {
		return func(entry map[string]any) (string, bool) {
			h, ok := entry[key].(map[string]any)
			if !ok {
				return "", false
			}
			v, ok := h["Authorization"].(string)
			return v, ok
		}
	}

	return []fixture{
		{
			name: ClaudeCode, path: claudePath, writer: NewClaudeWriter(claudePath),
			parse: parseJSONTree, container: claudeContainer,
			entryOf: nested(claudeContainer), authOf: authIn("headers"),
		},
		{
			name: Codex, path: codexPath, writer: NewCodexWriter(codexPath),
			parse: parseTOMLTree, container: codexContainer,
			entryOf: nested(codexContainer), authOf: authIn("http_headers"),
		},
	}
}

func (f fixture) read(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatalf("read %s: %v", f.path, err)
	}
	return raw
}

func (f fixture) tree(t *testing.T) map[string]any {
	t.Helper()
	tree, err := f.parse(f.read(t))
	if err != nil {
		t.Fatalf("parse %s: %v", f.path, err)
	}
	return tree
}

func TestWriteAddsManagedEntriesAndPreservesEverythingElse(t *testing.T) {
	for _, f := range newFixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			before := f.read(t)
			beforeTree, err := f.parse(before)
			if err != nil {
				t.Fatal(err)
			}

			applied, err := f.writer.Apply(managedEntries("tok-a"), nil)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if !applied.Changed {
				t.Error("Apply reported no change")
			}
			if applied.BackupPath == "" {
				t.Fatal("no backup was taken")
			}
			backup, err := os.ReadFile(applied.BackupPath)
			if err != nil {
				t.Fatalf("read backup: %v", err)
			}
			if string(backup) != string(before) {
				t.Error("the backup is not a copy of the pre-write file")
			}

			afterTree := f.tree(t)

			// The contract, checked literally.
			residualBefore := stripManaged(cloneTree(beforeTree), f.container, []string{ConnectorServerName, "gno"})
			residualAfter := stripManaged(cloneTree(afterTree), f.container, []string{ConnectorServerName, "gno"})
			if !reflect.DeepEqual(residualBefore, residualAfter) {
				t.Fatalf("unrelated configuration changed: %s", describeDiff(residualBefore, residualAfter))
			}

			// And the managed entries really landed.
			connector, ok := f.entryOf(afterTree, ConnectorServerName)
			if !ok {
				t.Fatal("the connector entry is missing")
			}
			if auth, ok := f.authOf(connector); !ok || auth != "Bearer tok-a" {
				t.Errorf("Authorization = %q (present: %v)", auth, ok)
			}
			if _, ok := f.entryOf(afterTree, "gno"); !ok {
				t.Error("the retrieval-engine entry is missing")
			}

			// The specific things a careless writer loses.
			text := string(f.read(t))
			for _, keep := range preservedMarkers(f.name) {
				if !strings.Contains(text, keep) {
					t.Errorf("the write lost %q", keep)
				}
			}
		})
	}
}

func preservedMarkers(harnessName string) []string {
	if harnessName == Codex {
		return []string{
			"# Codex configuration. Hand-edited; the comments matter.",
			"# Keep this: the TUI nux counters are reset by hand.",
			`[projects."/Users/daniel/Projects/homeplane"]`,
			"tool_timeout_sec = 10000.0",
			"[mcp_servers.blender.env]",
		}
	}
	return []string{"someone-elses-token", "hasTrustDialogAccepted"}
}

func cloneTree(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if m, ok := v.(map[string]any); ok {
			out[k] = cloneTree(m)
			continue
		}
		out[k] = v
	}
	return out
}

func TestRewritingIsIdempotentDownToTheByte(t *testing.T) {
	for _, f := range newFixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			if _, err := f.writer.Apply(managedEntries("tok-a"), nil); err != nil {
				t.Fatalf("first Apply: %v", err)
			}
			first := f.read(t)

			applied, err := f.writer.Apply(managedEntries("tok-a"), nil)
			if err != nil {
				t.Fatalf("second Apply: %v", err)
			}
			if applied.Changed {
				t.Error("a re-run with the same inputs reported a change")
			}
			if got := f.read(t); string(got) != string(first) {
				t.Errorf("a re-run rewrote the file:\n--- first ---\n%s\n--- second ---\n%s", first, got)
			}
		})
	}
}

func TestANewTokenReplacesTheOldOneAndLeavesNoTrace(t *testing.T) {
	for _, f := range newFixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			if _, err := f.writer.Apply(managedEntries("tok-old"), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := f.writer.Apply(managedEntries("tok-new"), nil); err != nil {
				t.Fatal(err)
			}
			text := string(f.read(t))
			if strings.Contains(text, "tok-old") {
				t.Error("the superseded token is still in the config")
			}
			if !strings.Contains(text, "tok-new") {
				t.Error("the new token was not written")
			}
			// Exactly one managed connector entry, not two.
			if n := strings.Count(text, "tok-new"); n != 1 {
				t.Errorf("the new token appears %d times, want 1", n)
			}
		})
	}
}

func TestRetiringAnEntryRemovesItAndNothingElse(t *testing.T) {
	for _, f := range newFixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			// A first run under an older descriptor that named the engine
			// "retrieval".
			old := managedEntries("tok-a")
			old[1].Name = "retrieval"
			if _, err := f.writer.Apply(old, nil); err != nil {
				t.Fatal(err)
			}
			if _, ok := f.entryOf(f.tree(t), "retrieval"); !ok {
				t.Fatal("the first run did not write the old entry")
			}

			// The descriptor now publishes "gno"; the old name is retired.
			if _, err := f.writer.Apply(managedEntries("tok-a"), []string{"retrieval"}); err != nil {
				t.Fatal(err)
			}
			tree := f.tree(t)
			if _, ok := f.entryOf(tree, "retrieval"); ok {
				t.Error("the retired entry was left orphaned in the config")
			}
			if _, ok := f.entryOf(tree, "gno"); !ok {
				t.Error("the new entry is missing")
			}
			if _, ok := f.entryOf(tree, "blender"); f.name == Codex && !ok {
				t.Error("retiring removed an unrelated server")
			}
		})
	}
}

func TestAMalformedConfigIsSkippedWithItsOriginalIntact(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		body   string
		writer func(string) Writer
	}{
		{"claude", ".claude.json", `{"mcpServers": {"rize": {`, NewClaudeWriter},
		{"codex", "config.toml", "model = \"x\"\n[mcp_servers.broken\ncommand = 1\n", NewCodexWriter},
		{"claude not an object", ".claude.json", `["not", "an", "object"]`, NewClaudeWriter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.file)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			applied, err := c.writer(path).Apply(managedEntries("tok"), nil)
			if !errors.Is(err, ErrMalformedConfig) {
				t.Fatalf("err = %v, want ErrMalformedConfig", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != c.body {
				t.Errorf("the original was modified:\n%s", got)
			}
			if applied.BackupPath == "" {
				t.Fatal("no backup was taken of the malformed config")
			}
			backup, readErr := os.ReadFile(applied.BackupPath)
			if readErr != nil {
				t.Fatalf("the backup is not intact: %v", readErr)
			}
			if string(backup) != c.body {
				t.Error("the backup does not hold the original bytes")
			}
		})
	}
}

func TestWrittenConfigsAreOwnerOnly(t *testing.T) {
	for _, f := range newFixtures(t) {
		t.Run(f.name, func(t *testing.T) {
			// Start from a permissive file: a config that already held a token
			// world-readably must be TIGHTENED, not merely left alone.
			if err := os.Chmod(f.path, 0o644); err != nil {
				t.Fatal(err)
			}
			applied, err := f.writer.Apply(managedEntries("tok"), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{f.path, applied.BackupPath} {
				info, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if perm := info.Mode().Perm(); perm != 0o600 {
					t.Errorf("%s has mode %#o, want 0600", p, perm)
				}
			}
		})
	}
}

func TestCreatingAConfigFromNothingProducesOnlyManagedEntries(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		path   string
		writer func(string) Writer
		parse  parseFn
	}{
		"claude": {filepath.Join(dir, "fresh", ".claude.json"), NewClaudeWriter, parseJSONTree},
		"codex":  {filepath.Join(dir, "fresh-codex", "config.toml"), NewCodexWriter, parseTOMLTree},
	} {
		t.Run(name, func(t *testing.T) {
			applied, err := tc.writer(tc.path).Apply(managedEntries("tok"), nil)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if applied.BackupPath != "" {
				t.Error("a backup was invented for a file that did not exist")
			}
			raw, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			tree, err := tc.parse(raw)
			if err != nil {
				t.Fatalf("the created file does not parse: %v\n%s", err, raw)
			}
			if len(tree) != 1 {
				t.Errorf("a fresh config gained keys beyond the managed container: %v", sortedKeys(tree))
			}
			info, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("mode %#o, want 0600", perm)
			}
		})
	}
}

func TestTheWriterRefusesAProjectScopedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcp.json")
	if _, err := NewClaudeWriter(path).Apply(managedEntries("tok"), nil); !errors.Is(err, ErrProjectScope) {
		t.Fatalf("err = %v, want ErrProjectScope — a grant token must never reach a git-shared file", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the refused path was created anyway")
	}
}

func TestTheWriterRefusesAnUnsafeServerName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	bad := managedEntries("tok")
	bad[1].Name = "a.name.with dots"
	if _, err := NewCodexWriter(path).Apply(bad, nil); !errors.Is(err, ErrUnsafeServerName) {
		t.Fatalf("err = %v, want ErrUnsafeServerName", err)
	}
}

// A write that would have dropped unrelated configuration must be refused and
// leave the file exactly as it was. The failure is injected at the one place it
// could realistically originate: a rewrite that produces the wrong bytes.
func TestAWriteThatWouldLoseConfigurationIsRefusedBeforeItHappens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(codexFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	sabotaged := fileWriter{harness: Codex, path: path, format: format{
		container: codexContainer,
		parse:     parseTOMLTree,
		rewrite: func(before []byte, entries []Entry, managed []string) ([]byte, error) {
			out, err := rewriteCodex(before, entries, managed)
			if err != nil {
				return nil, err
			}
			// Drop an unrelated table, as a span-scanner bug would.
			return []byte(strings.Replace(string(out), "[mcp_servers.blender]\n", "", 1)), nil
		},
	}}

	_, err := sabotaged.Apply(managedEntries("tok"), nil)
	if !errors.Is(err, ErrPreservationFailed) {
		t.Fatalf("err = %v, want ErrPreservationFailed", err)
	}
	if got := string(mustRead(t, path)); got != codexFixture {
		t.Errorf("the file was modified despite the refusal:\n%s", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestJSONLayoutIsPreserved(t *testing.T) {
	compact := filepath.Join(t.TempDir(), ".claude.json")
	if err := os.WriteFile(compact, []byte(`{"numStartups":1,"mcpServers":{"rize":{"type":"http","url":"u"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClaudeWriter(compact).Apply(managedEntries("tok"), nil); err != nil {
		t.Fatal(err)
	}
	raw := string(mustRead(t, compact))
	if strings.Count(raw, "\n") != 1 { // just the trailing newline
		t.Errorf("a compact config was reformatted:\n%s", raw)
	}
	// Key order is preserved, so the unrelated key still comes first.
	if !strings.HasPrefix(raw, `{"numStartups":1,`) {
		t.Errorf("top-level key order changed: %s", raw)
	}
}
