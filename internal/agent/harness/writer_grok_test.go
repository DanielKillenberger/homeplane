package harness

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The grok writer, checked against the shape grok's OWN tooling was observed to
// write (testdata/grok-1.0.3-contract.txt) rather than against a shape this
// package invented.

func grokConfigAt(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func grokEntries(token string) []Entry {
	return []Entry{
		{
			Name:      ConnectorServerName,
			Transport: TransportHTTP,
			URL:       "https://server.ts.net/mcp",
			Headers:   map[string]string{"Authorization": "Bearer " + token},
		},
		{
			Name:      "gno",
			Transport: TransportStdio,
			Command:   "/usr/local/bin/homeplane-agent",
			Args:      []string{"gno", "mcp", "stdio"},
		},
	}
}

// ── The captured contract ────────────────────────────────────────────────────

// What `grok mcp add` itself wrote, read out of the pinned capture. If grok's
// entry shape ever changes, the capture is regenerated and THIS test is what
// fails — rather than a machine silently getting an entry grok ignores.
func TestGrokEntryMatchesTheCapturedContractShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "grok-1.0.3-contract.txt"))
	if err != nil {
		t.Fatal(err)
	}
	captured := sectionOf(t, string(raw), "=== config.toml after the add ===")

	// The four load-bearing facts, taken from the capture rather than restated:
	// the container table, `enabled = true` written explicitly, the headers
	// SUB-table (not `http_headers`, which is Codex's spelling), and the header
	// key.
	for _, want := range []string{
		"[mcp_servers.homeplane-edge]",
		"enabled = true",
		"[mcp_servers.homeplane-edge.headers]",
		"Authorization = ",
	} {
		if !strings.Contains(captured, want) {
			t.Fatalf("the capture no longer contains %q — re-read docs/decisions/fn3-grok-surfaces.md before trusting this writer:\n%s", want, captured)
		}
	}

	block, err := renderTOMLEntry([]string{grokContainer}, Entry{
		Name:      "homeplane-edge",
		Transport: TransportHTTP,
		URL:       "https://edge.example.invalid/mcp",
		Headers:   map[string]string{"Authorization": "Bearer x"},
	}, grokEntryStyle)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[mcp_servers.homeplane-edge]",
		`url = "https://edge.example.invalid/mcp"`,
		"enabled = true",
		"[mcp_servers.homeplane-edge.headers]",
		`Authorization = "Bearer x"`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("rendered entry is missing %q:\n%s", want, block)
		}
	}
	// Codex's spelling must not leak into grok's file: grok would not read it,
	// and the entry would silently carry no credential.
	if strings.Contains(block, "http_headers") {
		t.Errorf("the grok entry uses Codex's headers table:\n%s", block)
	}
}

// sectionOf returns the body of one `=== heading ===` section of the capture.
func sectionOf(t *testing.T, capture, heading string) string {
	t.Helper()
	idx := strings.Index(capture, heading)
	if idx < 0 {
		t.Fatalf("the capture has no %q section", heading)
	}
	rest := capture[idx+len(heading):]
	if end := strings.Index(rest, "\n==="); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// ── Preservation, against a config somebody actually has ─────────────────────

// The reason the CLI verbs are not the writer: `grok mcp add` was observed to
// drop every comment in the file. A byte-span writer must not.
func TestGrokWritePreservesCommentsAndUnrelatedConfiguration(t *testing.T) {
	path := grokConfigAt(t, grokFixture)

	if _, err := NewGrokWriter(path).Apply(grokEntries("tok"), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	after := string(mustRead(t, path))

	for _, want := range []string{
		"# grok configuration. Hand-written; the comments matter.",
		"# an unrelated pre-existing MCP entry, with its own comment",
		"max_thoughts_width = 120",
		`command = "/usr/bin/true"`,
		`args = ["--keep-me"]`,
		"skills = true",
		"rules = true",
	} {
		if !strings.Contains(after, want) {
			t.Errorf("the write lost %q:\n%s", want, after)
		}
	}

	tree, err := parseTOMLTree([]byte(after))
	if err != nil {
		t.Fatalf("the result does not parse: %v", err)
	}
	servers, _ := tree[grokContainer].(map[string]any)
	for _, name := range []string{"preexisting-thing", ConnectorServerName, "gno"} {
		if _, ok := servers[name]; !ok {
			t.Errorf("%s is missing from the merged config", name)
		}
	}
}

// D4 and D4b: both compat cells are closed, one by EDITING a table that exists
// and carries other keys, the other by APPENDING a table that does not exist —
// and neither touches anything else in its table.
func TestConfigureClosesBothCompatCellsWithoutDisturbingTheirTables(t *testing.T) {
	path := grokConfigAt(t, grokFixture)

	if _, err := NewGrokWriter(path).Apply(grokEntries("tok"), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	tree, err := parseTOMLTree(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	compat, _ := tree["compat"].(map[string]any)
	claude, _ := compat["claude"].(map[string]any)
	cursor, _ := compat["cursor"].(map[string]any)

	if claude["mcps"] != false {
		t.Errorf("[compat.claude] mcps = %v, want false", claude["mcps"])
	}
	if cursor["mcps"] != false {
		t.Errorf("[compat.cursor] mcps = %v, want false", cursor["mcps"])
	}
	// Only the mcps cell changes. grok discovering Claude's SKILLS is a feature
	// and stays on; the rest of the table is the user's.
	if claude["skills"] != true || claude["rules"] != true {
		t.Errorf("the rest of [compat.claude] was disturbed: %v", claude)
	}
	// A trailing comment on the edited line is part of the file the user wrote.
	if got := string(mustRead(t, path)); !strings.Contains(got, "# inherited from Claude Code today") {
		t.Errorf("the comment on the edited key was eaten:\n%s", got)
	}
}

// Both the compat cells and the 0600 mode are settings grok's own tooling
// undoes. "We set it once" is therefore not a guarantee, so every run
// re-establishes them — and converges.
func TestConfigureReassertsCompatAndModeOnEveryRun(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	w := NewGrokWriter(path)

	if _, err := w.Apply(grokEntries("tok"), nil); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	first := mustRead(t, path)

	// grok flips the cell back and resets the mode, exactly as `grok mcp add`
	// was observed to do.
	reopened := strings.Replace(string(first), "mcps = false   # inherited from Claude Code today",
		"mcps = true   # inherited from Claude Code today", 1)
	if reopened == string(first) {
		t.Fatal("the fixture's edited line is not where this test thought it was")
	}
	if err := os.WriteFile(path, []byte(reopened), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := w.Apply(grokEntries("tok"), nil)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if !res.Changed {
		t.Error("a re-opened compat cell was not re-closed")
	}
	tree, err := parseTOMLTree(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	compat, _ := tree["compat"].(map[string]any)
	claude, _ := compat["claude"].(map[string]any)
	if claude["mcps"] != false {
		t.Error("the compat cell was not re-asserted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != filePerm {
		t.Errorf("mode = %v, want %v: grok resets it to 0644 and the token lives in this file", info.Mode().Perm(), filePerm)
	}
}

// An identical re-run converges: same bytes, and Changed reported honestly.
func TestGrokRewriteIsIdempotent(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	w := NewGrokWriter(path)

	if _, err := w.Apply(grokEntries("tok"), nil); err != nil {
		t.Fatal(err)
	}
	first := string(mustRead(t, path))

	res, err := w.Apply(grokEntries("tok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	second := string(mustRead(t, path))
	if first != second {
		t.Errorf("an identical re-run rewrote the file:\n--- first\n%s\n--- second\n%s", first, second)
	}
	if res.Changed {
		t.Error("an unchanged file was reported as changed")
	}
}

// grok replaces an entry WHOLESALE: re-adding the same name with a different
// url deleted the headers sub-table. So a half-written entry is repaired by
// re-rendering the WHOLE entry, never by patching a field — which is exactly
// what R2's partial-state repair asks for.
func TestAPartiallyWrittenGrokEntryIsRepairedWholesale(t *testing.T) {
	// A previous run died after writing the entry but before its headers.
	partial := grokFixture + "\n[mcp_servers.homeplane]\nurl = \"https://stale.example.invalid/mcp\"\nenabled = true\n"
	path := grokConfigAt(t, partial)

	if _, err := NewGrokWriter(path).Apply(grokEntries("fresh"), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	tree, err := parseTOMLTree(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	servers, _ := tree[grokContainer].(map[string]any)
	entry, _ := servers[ConnectorServerName].(map[string]any)
	if entry["url"] != "https://server.ts.net/mcp" {
		t.Errorf("the stale url survived: %v", entry["url"])
	}
	if entry["enabled"] != true {
		t.Errorf("the repaired entry is not enabled: %v", entry["enabled"])
	}
	headers, _ := entry["headers"].(map[string]any)
	if got, _ := headers["Authorization"].(string); !strings.HasSuffix(got, "fresh") {
		t.Errorf("the missing credential was not restored: %v", headers)
	}
	if strings.Count(string(mustRead(t, path)), "[mcp_servers.homeplane]") != 1 {
		t.Error("the repair duplicated the entry instead of replacing it")
	}
}

// A compat setting written in a shape this writer cannot edit at key
// granularity is REFUSED, with the file untouched. The alternative — round-trip
// the document through a serializer — is what eats the operator's comments, and
// is the whole reason grok's own CLI was disqualified as the writer.
func TestAnUneditableCompatShapeIsRefusedRatherThanRoundTripped(t *testing.T) {
	// The `mcps` cell as a dotted key inside [compat], which setTOMLKeyLiteral
	// deliberately does not reach.
	body := "# mine\n[compat]\nclaude.mcps = true\n"
	path := grokConfigAt(t, body)

	_, err := NewGrokWriter(path).Apply(grokEntries("tok"), nil)
	if !errors.Is(err, ErrCompatEditUnrepresentable) {
		t.Fatalf("err = %v, want ErrCompatEditUnrepresentable", err)
	}
	if got := string(mustRead(t, path)); got != body {
		t.Errorf("the file was modified by a refused write:\n%s", got)
	}
}

// The preservation exemption is not a blind spot: the compat cells are
// subtracted from the comparison, and their VALUE is asserted separately. A
// rewrite that silently failed to close them must not pass.
func TestTheCompatExemptionStillProvesTheValue(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	// A writer with grok's exemption but a rewrite that never touches compat:
	// the exemption alone would let this through.
	sloppy := fileWriter{harness: Grok, path: path, format: format{
		container:   grokContainer,
		parse:       parseTOMLTree,
		rewrite:     func(before []byte, _ []Entry, _ []string) ([]byte, error) { return before, nil },
		exempt:      [][]string{{"compat", "claude", "mcps"}, {"compat", "cursor", "mcps"}},
		assertAfter: assertGrokCompatClosed,
	}}

	_, err := sloppy.Apply(grokEntries("tok"), nil)
	if !errors.Is(err, ErrCompatEditUnrepresentable) {
		t.Fatalf("err = %v, want the unclosed compat cell to be caught", err)
	}
}

// A grok that has never been launched has no config at all. The writer creates
// it — at 0600, from the first byte, because the file holds a bearer token.
func TestGrokConfigIsCreatedAtOwnerOnlyFromNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grok", "config.toml")

	if _, err := NewGrokWriter(path).Apply(grokEntries("tok"), nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != filePerm {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	tree, err := parseTOMLTree(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	compat, _ := tree["compat"].(map[string]any)
	if claude, _ := compat["claude"].(map[string]any); claude["mcps"] != false {
		t.Error("a created-from-nothing config does not close the compat cell")
	}
}

// D3: the token is written INLINE, and the entry declares no environment
// indirection. A config naming an environment variable works in the shell that
// exported it and nowhere else — and Homeplane does not launch grok, Daniel
// does, from arbitrary contexts.
func TestTheGrokEntryCarriesNoEnvironmentIndirection(t *testing.T) {
	path := grokConfigAt(t, grokFixture)
	if _, err := NewGrokWriter(path).Apply(grokEntries("secret-token"), nil); err != nil {
		t.Fatal(err)
	}
	body := string(mustRead(t, path))

	if !strings.Contains(body, "Bearer secret-token") {
		t.Error("the token was not written inline")
	}
	if strings.Contains(body, "${") {
		t.Errorf("the entry uses ${VAR} indirection:\n%s", body)
	}
	for _, name := range []string{"HOMEPLANE_TOKEN", "GROK_TOKEN", "env"} {
		if strings.Contains(body, "[mcp_servers.homeplane."+name+"]") {
			t.Errorf("the connector entry declares an %s table", name)
		}
	}
}
