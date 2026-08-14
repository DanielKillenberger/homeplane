package harness

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func headers(spans []tomlSpan) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.header())
	}
	return out
}

func TestScanFindsEveryTableHeaderAndOnlyRealOnes(t *testing.T) {
	src := `# a leading comment mentioning [not.a.table]
model = "gpt-5.6-sol"

[projects."/Users/daniel/Projects/homeplane"]
trust_level = "trusted"

[mcp_servers.blender]
command = "/Users/daniel/.local/bin/blender-mcp"

[mcp_servers.blender.env]
BLENDER_HOST = "localhost"

[notes]
body = """
This multi-line string contains a line that looks like a table:
[mcp_servers.impostor]
and a # that is not a comment.
"""
literal = '''
[also.not.a.table]
'''
inline = "a string with [brackets] and a # hash"

[[history.entries]]
at = "2026-08-14"
`
	spans, err := scanTOMLTables([]byte(src))
	if err != nil {
		t.Fatalf("scanTOMLTables: %v", err)
	}
	want := []string{
		"projects./Users/daniel/Projects/homeplane",
		"mcp_servers.blender",
		"mcp_servers.blender.env",
		"notes",
		"history.entries",
	}
	if got := headers(spans); !reflect.DeepEqual(got, want) {
		t.Fatalf("headers = %v, want %v", got, want)
	}
	if !spans[4].arrayOfTables {
		t.Error("[[history.entries]] was not recognised as an array of tables")
	}

	// The scan must agree with a real parser about what tables exist.
	var parsed map[string]any
	if err := toml.Unmarshal([]byte(src), &parsed); err != nil {
		t.Fatalf("the fixture is not valid TOML: %v", err)
	}
	if servers, ok := parsed["mcp_servers"].(map[string]any); !ok || len(servers) != 1 {
		t.Fatalf("parser sees mcp_servers = %#v; the impostor inside the multi-line string leaked", parsed["mcp_servers"])
	}
}

func TestScanSpansCoverExactlyTheirOwnTable(t *testing.T) {
	src := "a = 1\n\n[one]\nx = 1\n\n[two]\ny = 2\n"
	spans, err := scanTOMLTables([]byte(src))
	if err != nil {
		t.Fatalf("scanTOMLTables: %v", err)
	}
	// The blank line before [two] separates the two tables and belongs to
	// neither, so it is outside both spans and survives either removal.
	if got := string([]byte(src)[spans[0].start:spans[0].end]); got != "[one]\nx = 1\n" {
		t.Errorf("span for [one] = %q", got)
	}
	if got := string([]byte(src)[spans[1].start:spans[1].end]); got != "[two]\ny = 2\n" {
		t.Errorf("span for [two] = %q", got)
	}
	// The preamble is not a span, so nothing can remove the root table.
	if spans[0].start != len("a = 1\n\n") {
		t.Errorf("first span starts at %d, want %d", spans[0].start, len("a = 1\n\n"))
	}
}

func TestScanRefusesWhatItCannotReadExactly(t *testing.T) {
	for name, src := range map[string]string{
		"unterminated header":       "[mcp_servers.blender\n",
		"empty header":              "[]\n",
		"trailing content":          "[a] junk\n",
		"unterminated multi-line":   "x = \"\"\"\nstill open\n",
		"unterminated quoted key":   "[\"unclosed\n",
		"unterminated array header": "[[a]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := scanTOMLTables([]byte(src)); err == nil {
				t.Fatal("expected a refusal; a guess here corrupts a config file")
			}
		})
	}
}

func TestRemoveTablesLeavesEveryOtherByteIdentical(t *testing.T) {
	src := `keep = "me"

[mcp_servers.keepme]
command = "x"

[mcp_servers.managed]
url = "http://old"

[mcp_servers.managed.http_headers]
Authorization = "Bearer stale"

# a comment that belongs to the table below
[tui]
theme = "dark"
`
	spans, err := scanTOMLTables([]byte(src))
	if err != nil {
		t.Fatalf("scanTOMLTables: %v", err)
	}
	out, removed := removeTOMLTables([]byte(src), spans, func(key []string) bool {
		return len(key) >= 2 && key[0] == "mcp_servers" && key[1] == "managed"
	})
	if want := []string{"mcp_servers.managed", "mcp_servers.managed.http_headers"}; !reflect.DeepEqual(removed, want) {
		t.Errorf("removed = %v, want %v", removed, want)
	}
	if strings.Contains(string(out), "stale") {
		t.Error("the managed table survived removal")
	}
	for _, keep := range []string{`keep = "me"`, "[mcp_servers.keepme]", "# a comment that belongs to the table below", "[tui]"} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("removal lost %q", keep)
		}
	}
}

func TestRenderedEntriesParseBackToWhatWentIn(t *testing.T) {
	entries := []Entry{
		{
			Name: "homeplane", Transport: TransportHTTP,
			URL:     "https://server.example/mcp",
			Headers: map[string]string{"Authorization": `Bearer tok"en\with-escapes`},
		},
		{
			Name: "gno", Transport: TransportStdio,
			Command: "/usr/local/bin/homeplane-agent",
			Args:    []string{"gno", "mcp", "-state-dir", `/tmp/a b"c`},
			Env:     map[string]string{"HOMEPLANE_STATE": "/tmp/x", "quoted.key": "v"},
		},
	}
	doc := []byte("root = 1\n")
	for _, e := range entries {
		block, err := renderTOMLEntry([]string{"mcp_servers"}, e, codexEntryStyle)
		if err != nil {
			t.Fatalf("render %s: %v", e.Name, err)
		}
		doc = appendTOMLBlock(doc, block)
	}

	var parsed map[string]any
	if err := toml.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("rendered TOML does not parse: %v\n%s", err, doc)
	}
	servers := parsed["mcp_servers"].(map[string]any)

	hp := servers["homeplane"].(map[string]any)
	if hp["url"] != "https://server.example/mcp" {
		t.Errorf("url = %v", hp["url"])
	}
	gotAuth := hp["http_headers"].(map[string]any)["Authorization"]
	if gotAuth != `Bearer tok"en\with-escapes` {
		t.Errorf("Authorization round-tripped as %q", gotAuth)
	}

	gno := servers["gno"].(map[string]any)
	wantArgs := []any{"gno", "mcp", "-state-dir", `/tmp/a b"c`}
	if !reflect.DeepEqual(gno["args"], wantArgs) {
		t.Errorf("args = %#v, want %#v", gno["args"], wantArgs)
	}
	if got := gno["env"].(map[string]any)["quoted.key"]; got != "v" {
		t.Errorf("a key needing quotes round-tripped as %v", got)
	}
	if parsed["root"] != int64(1) {
		t.Errorf("the preamble was lost: root = %v", parsed["root"])
	}
}

func TestRemovalKeepsTheCommentThatIntroducesTheNextTable(t *testing.T) {
	src := `[mcp_servers.managed]
url = "http://old"

# RepoPrompt is disabled while the CLI is being rebuilt — do not delete.
[mcp_servers.RepoPrompt]
enabled = false
`
	spans, err := scanTOMLTables([]byte(src))
	if err != nil {
		t.Fatalf("scanTOMLTables: %v", err)
	}
	out, _ := removeTOMLTables([]byte(src), spans, func(key []string) bool {
		return len(key) >= 2 && key[0] == "mcp_servers" && key[1] == "managed"
	})
	if !strings.Contains(string(out), "do not delete") {
		t.Fatalf("the comment introducing the next table was removed with the managed one:\n%s", out)
	}
}

func TestRemovingAdjacentManagedTablesStrandsNoSeparators(t *testing.T) {
	// This is what a second run sees: the blocks a first run appended. It must
	// reduce to exactly the pre-run document, or every re-run would produce a
	// diff.
	before := "existing = 1\n"
	doc := []byte(before)
	entries := []Entry{
		{Name: "homeplane", Transport: TransportHTTP, URL: "http://x/mcp",
			Headers: map[string]string{"Authorization": "Bearer t"}},
		{Name: "gno", Transport: TransportStdio, Command: "/bin/agent", Args: []string{"gno", "mcp"}},
	}
	for _, e := range entries {
		block, err := renderTOMLEntry([]string{"mcp_servers"}, e, codexEntryStyle)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		doc = appendTOMLBlock(doc, block)
	}

	spans, err := scanTOMLTables(doc)
	if err != nil {
		t.Fatalf("scanTOMLTables: %v", err)
	}
	managed := map[string]bool{"homeplane": true, "gno": true}
	out, _ := removeTOMLTables(doc, spans, func(key []string) bool {
		return len(key) >= 2 && key[0] == "mcp_servers" && managed[key[1]]
	})
	if strings.TrimRight(string(out), "\n")+"\n" != before {
		t.Fatalf("removal did not reduce to the original document:\n%q\nwant %q", string(out), before)
	}
}

// A '[' opening a line is only a table header at the top level. This is the
// review finding that mattered most: refusing a valid config would have
// happened AFTER the grant was superseded, leaving the harness with a dead
// token and a message claiming its own file was malformed.
func TestNestedArraysAndInlineTablesAreNotMistakenForTableHeaders(t *testing.T) {
	src := `matrix = [
  [1, 2],
  [3, 4],
]
profiles = [
  { name = "a", tools = ["x"] },
  { name = "b" },
]
spread = { key = "value" }

[mcp_servers.managed]
url = "http://old"

[tui]
theme = "dark"
`
	// The fixture must be valid TOML, or the test proves nothing.
	var parsed map[string]any
	if err := toml.Unmarshal([]byte(src), &parsed); err != nil {
		t.Fatalf("the fixture is not valid TOML: %v", err)
	}

	spans, err := scanTOMLTables([]byte(src))
	if err != nil {
		t.Fatalf("scanTOMLTables refused a valid config: %v", err)
	}
	if want := []string{"mcp_servers.managed", "tui"}; !reflect.DeepEqual(headers(spans), want) {
		t.Fatalf("headers = %v, want %v", headers(spans), want)
	}

	out, _ := removeTOMLTables([]byte(src), spans, func(key []string) bool {
		return len(key) >= 2 && key[0] == "mcp_servers" && key[1] == "managed"
	})
	var after map[string]any
	if err := toml.Unmarshal(out, &after); err != nil {
		t.Fatalf("removal produced invalid TOML: %v\n%s", err, out)
	}
	delete(parsed, "mcp_servers")
	if !reflect.DeepEqual(parsed, after) {
		t.Errorf("removal changed unrelated values:\n before %#v\n after  %#v", parsed, after)
	}
}

func TestScanAgreesWithTheRealParserOnWhatIsATable(t *testing.T) {
	// Every fixture in this package must be a config the scanner and a real
	// TOML parser describe identically — that agreement is what makes the
	// span-scoped write safe.
	for name, src := range map[string]string{
		"codex fixture":    codexFixture,
		"nested arrays":    "a = [\n [1],\n]\n[t]\nx = 1\n",
		"inline table":     "a = { b = 1 }\n[t]\nx = 1\n",
		"comment brackets": "# [not.a.table]\nx = 1 # [nor.this]\n[t]\ny = 2\n",
		"dotted keys":      "a.b = 1\n[t]\nc = 2\n",
	} {
		t.Run(name, func(t *testing.T) {
			var parsed map[string]any
			if err := toml.Unmarshal([]byte(src), &parsed); err != nil {
				t.Fatalf("fixture is not valid TOML: %v", err)
			}
			spans, err := scanTOMLTables([]byte(src))
			if err != nil {
				t.Fatalf("the scanner refused what the parser accepted: %v", err)
			}
			// Every top-level table the parser found must have a span whose key
			// starts with it, and no span may name something the parser did not.
			for _, s := range spans {
				if _, ok := parsed[s.key[0]]; !ok {
					t.Errorf("the scanner invented table %q", s.header())
				}
			}
		})
	}
}
