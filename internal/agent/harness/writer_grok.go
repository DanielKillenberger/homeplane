package harness

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// The grok writer.
//
// grok's MCP entries live in `~/.grok/config.toml` under `[mcp_servers.<name>]`,
// with HTTP headers in a `[mcp_servers.<name>.headers]` sub-table — the same
// format Codex uses, spelled slightly differently, so this file is the grok arm
// of the SAME byte-span machinery rather than a second implementation.
//
// grok ships CLI verbs for this (`grok mcp add`) and they are deliberately NOT
// used. Three observed behaviours disqualify them (fn3-grok-surfaces.md §1):
// they drop every comment in the file, they reset an explicitly-0600 config back
// to 0644, and `-H "Authorization: Bearer <token>"` puts the grant token in
// argv. The first two are unescapable, and the third is a hard constraint. So
// Homeplane writes the file itself.
//
// Two behaviours the writer must honour, both observed rather than assumed:
//
//   - An entry is REPLACED WHOLESALE, never merged: re-adding the same name with
//     a different url deleted the headers sub-table. So the complete entry —
//     url, enabled, headers — is rendered every time. That is also the
//     partial-state repair path: a half-written entry is repaired by rendering
//     the whole entry, never by patching a field.
//   - Entries land ENABLED. `enabled = true` is written explicitly; no
//     `grok mcp enable` step exists in this package.

// grokContainer is the table grok's MCP servers live under.
const grokContainer = "mcp_servers"

// The compat cells Homeplane closes, and the key it sets in each.
//
// grok scans other vendors' configurations by default: `[compat.claude] mcps`
// reads ~/.claude.json and `[compat.cursor] mcps` reads ~/.cursor/mcp.json. Left
// on, grok reaches the Homeplane edge through CLAUDE CODE's entry — Claude
// Code's bearer token, Claude Code's grant identity — which makes revoking
// grok's grant not actually cut grok's access (R5) and attributes grok's calls
// to another harness (R3).
//
// D4 (ratified 2026-08-14) closes the Claude cell; D4b (ratified 2026-08-15)
// closes the Cursor cell, making the isolation structural rather than contingent
// on ~/.cursor/mcp.json staying empty. Only the `mcps` cell of each table
// changes: `[compat.claude] skills` stays ON, because grok discovering Claude's
// skills is a feature.
//
// The third source, a project-scope `.mcp.json`, cannot be closed from user
// config at all. It is REPORTED by detection instead (Detection.CompatSources),
// so inheritance stays visible rather than assumed absent.
var grokCompatCells = []struct {
	table []string
	// source is the machine-readable name detection reports this cell under.
	source string
}{
	{table: []string{"compat", "claude"}, source: CompatSourceClaude},
	{table: []string{"compat", "cursor"}, source: CompatSourceCursor},
}

// grokCompatKey is the single key each compat cell assigns.
const grokCompatKey = "mcps"

// Compat source identifiers reported by detection.
const (
	CompatSourceClaude = "claude"
	CompatSourceCursor = "cursor"
	// CompatSourceProject is grok's project-scope `.mcp.json`. It is always
	// listed because no user-config key can close it: honesty about a source we
	// cannot disable is the whole point of surfacing this list.
	CompatSourceProject = "project(.mcp.json)"
)

// ErrCompatEditUnrepresentable means grok's compat settings are written in a
// shape this writer cannot edit at key granularity — a dotted key in a parent
// table, or an inline table. The configure run REFUSES rather than round-trips
// the document, because round-tripping is what would eat the operator's
// comments.
var ErrCompatEditUnrepresentable = errors.New("harness: grok's [compat] settings could not be edited without rewriting the file")

// NewGrokWriter builds the grok writer for an explicit config path.
func NewGrokWriter(configPath string) Writer {
	exempt := make([][]string, 0, len(grokCompatCells))
	for _, cell := range grokCompatCells {
		exempt = append(exempt, append(append([]string{}, cell.table...), grokCompatKey))
	}
	return fileWriter{harness: Grok, path: configPath, format: format{
		container: grokContainer,
		parse:     parseTOMLTree,
		rewrite:   rewriteGrok,
		// The compat cells are Homeplane-managed even though they live outside
		// the managed container, so the preservation equation subtracts them
		// from both sides — and assertAfter then proves they hold the value we
		// meant, which is what stops the exemption from becoming a blind spot.
		exempt:      exempt,
		assertAfter: assertGrokCompatClosed,
	}}
}

// rewriteGrok edits the SOURCE TEXT: the managed `[mcp_servers.X]` tables are
// cut out by byte span and re-rendered at the end, and the two compat cells are
// set at key granularity. Every other byte — comments, blank lines, key order,
// the rest of each compat table — is untouched.
func rewriteGrok(before []byte, entries []Entry, managed []string) ([]byte, error) {
	spans, err := scanTOMLTables(before)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedConfig, err)
	}
	managedSet := make(map[string]bool, len(managed))
	for _, n := range managed {
		managedSet[n] = true
	}

	out, _ := removeTOMLTables(before, spans, func(key []string) bool {
		return len(key) >= 2 && key[0] == grokContainer && managedSet[key[1]]
	})

	// The compat cells, re-asserted on EVERY apply rather than set once. Both
	// they and the 0600 mode are settings grok's own tooling undoes — `grok mcp
	// add` resets the mode, and a user or an upgrade can flip the cells back —
	// so each run re-establishes them and converges.
	//
	// The BEFORE tree is what tells an absent setting from one written in a
	// shape the span editor cannot reach. Appending `[compat.claude]` when the
	// value already exists as `claude.mcps` under `[compat]` would produce a
	// TOML redefinition — a refusal either way, but one whose error message
	// tells the operator nothing about what to fix.
	beforeTree, parseErr := parseTOMLTree(before)
	if parseErr != nil && len(bytes.TrimSpace(before)) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrMalformedConfig, parseErr)
	}
	for _, cell := range grokCompatCells {
		path := append(append([]string{}, cell.table...), grokCompatKey)
		var appended bool
		out, appended, err = setTOMLKeyLiteral(out, cell.table, grokCompatKey, "false")
		if err != nil {
			return nil, err
		}
		if _, defined := lookupPath(beforeTree, path); defined && appended {
			return nil, fmt.Errorf("%w: [%s] %s is already set in a shape this writer cannot edit at key granularity "+
				"(a dotted key in a parent table, or an inline table). Set it to false by hand — writing it any other way "+
				"would mean round-tripping the whole file, which is what drops your comments",
				ErrCompatEditUnrepresentable, strings.Join(cell.table, "."), grokCompatKey)
		}
	}

	for _, e := range entries {
		block, err := renderTOMLEntry([]string{grokContainer}, e, grokEntryStyle)
		if err != nil {
			return nil, err
		}
		out = appendTOMLBlock(out, block)
	}

	// The edit is proven, not assumed. A compat setting written as a dotted key
	// or an inline table is not something setTOMLKeyLiteral can reach, and the
	// only honest answers are "rewrite the whole document" (which eats comments)
	// or "refuse and say so". This refuses, BEFORE anything is written.
	tree, err := parseTOMLTree(out)
	if err != nil {
		return nil, fmt.Errorf("%w: the rewritten configuration does not parse: %v", ErrPreservationFailed, err)
	}
	if err := assertGrokCompatClosed(tree); err != nil {
		return nil, err
	}

	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	return out, nil
}

// assertGrokCompatClosed proves every compat cell Homeplane manages actually
// reads false in the parsed result.
func assertGrokCompatClosed(tree map[string]any) error {
	for _, cell := range grokCompatCells {
		v, ok := lookupPath(tree, append(append([]string{}, cell.table...), grokCompatKey))
		if !ok {
			return fmt.Errorf("%w: [%s] %s is not set after the edit — it is probably written as a dotted key or an "+
				"inline table; set it to false by hand and re-run",
				ErrCompatEditUnrepresentable, strings.Join(cell.table, "."), grokCompatKey)
		}
		b, isBool := v.(bool)
		if !isBool || b {
			return fmt.Errorf("%w: [%s] %s reads %v after the edit rather than false",
				ErrCompatEditUnrepresentable, strings.Join(cell.table, "."), grokCompatKey, v)
		}
	}
	return nil
}

func lookupPath(tree map[string]any, path []string) (any, bool) {
	cur := any(tree)
	for _, seg := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// grokCompatSources reports which OTHER vendors' configurations grok would still
// inherit MCP servers from, read from grok's own config file.
//
// It reads the file rather than invoking grok: `grok mcp doctor` performs real
// network connections, and a status surface must not. An unreadable or
// unparseable config yields the DEFAULTS, which are "everything is inherited" —
// the pessimistic answer, and the correct one when we cannot prove otherwise.
func grokCompatSources(configPath string) []string {
	enabled := map[string]bool{CompatSourceClaude: true, CompatSourceCursor: true}

	if raw, err := os.ReadFile(configPath); err == nil {
		if tree, err := parseTOMLTree(raw); err == nil {
			for _, cell := range grokCompatCells {
				v, ok := lookupPath(tree, append(append([]string{}, cell.table...), grokCompatKey))
				if !ok {
					continue
				}
				if b, isBool := v.(bool); isBool {
					enabled[cell.source] = b
				}
			}
		}
	}

	out := []string{}
	for source, on := range enabled {
		if on {
			out = append(out, source)
		}
	}
	sort.Strings(out)
	// Always last, and always present: a project-scope `.mcp.json` is merged by
	// grok and cannot be disabled from user config, so claiming it absent would
	// be the one dishonest thing this list could do.
	return append(out, CompatSourceProject)
}
