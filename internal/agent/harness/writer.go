package harness

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// A Writer applies Homeplane's managed MCP entries to one harness's
// configuration file, and nothing else in that file.
type Writer interface {
	// Harness is the harness identifier (also the grant's harness label).
	Harness() string
	// ConfigPath is the file the writer owns entries inside of.
	ConfigPath() string
	// Preflight reads the existing configuration without writing anything and
	// reports ErrMalformedConfig when it cannot be parsed. It exists so a
	// harness we are going to skip is identified BEFORE a grant is minted for
	// it: authority should not be spent on a file we will not write to.
	Preflight() error
	// Apply merges entries into the config, removing any entry named in retire
	// that a previous run left behind. It returns whether the file's bytes
	// changed and the backup it took first.
	Apply(entries []Entry, retire []string) (ApplyResult, error)
}

// ApplyResult is the record of one config write.
type ApplyResult struct {
	BackupPath string
	Changed    bool
	Retired    []string
}

// format is the per-harness half of the shared write procedure.
type format struct {
	// container is the config key the managed entries live under.
	container string
	// parse turns file bytes into a comparable tree, using a real parser for
	// the format — never the editing code being checked.
	parse parseFn
	// rewrite produces the new file bytes. It must return ErrMalformedConfig
	// (wrapped) when the existing bytes cannot be read.
	rewrite func(before []byte, entries []Entry, managed []string) ([]byte, error)
}

// fileWriter is the shared, format-independent write procedure. Both harnesses
// use it, which is why "backed up first, verified before writing, verified
// again from disk, rolled back on failure, left 0600" is one behaviour rather
// than two implementations that could drift.
type fileWriter struct {
	harness string
	path    string
	format  format
}

func (w fileWriter) Harness() string    { return w.harness }
func (w fileWriter) ConfigPath() string { return w.path }

func (w fileWriter) Preflight() error {
	raw, err := os.ReadFile(w.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // nothing to be malformed yet
		}
		return fmt.Errorf("read %s: %w", w.path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if _, err := w.format.parse(raw); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMalformedConfig, w.path, err)
	}
	return nil
}

func (w fileWriter) Apply(entries []Entry, retire []string) (ApplyResult, error) {
	if err := assertUserScope(w.path); err != nil {
		return ApplyResult{}, err
	}
	managed := managedNames(entries, retire)
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return ApplyResult{}, err
		}
	}
	for _, n := range retire {
		if err := ValidateServerName(n); err != nil {
			return ApplyResult{}, err
		}
	}

	if err := os.MkdirAll(filepath.Dir(w.path), dirPerm); err != nil {
		return ApplyResult{}, fmt.Errorf("create %s: %w", filepath.Dir(w.path), err)
	}

	// The merge is optimistic, and re-tried against fresh bytes when it loses.
	//
	// The file is not ours. Claude Code rewrites ~/.claude.json on its own
	// schedule (startup counters, project state), Codex rewrites config.toml,
	// and the user may be editing either. A plain read-modify-write would take
	// a snapshot, spend milliseconds merging, and then replace the file —
	// silently discarding anything written in between, with a preservation
	// check that compares against the STALE snapshot and therefore reports
	// success. Re-reading immediately before the rename closes that window down
	// to the rename itself; losing the race is a retry, not a lost edit.
	var result ApplyResult
	for attempt := 0; ; attempt++ {
		res, retry, err := w.applyOnce(entries, retire, managed)
		if res.BackupPath != "" {
			result.BackupPath = res.BackupPath
		}
		if err != nil {
			return result, err
		}
		if !retry {
			result.Changed = res.Changed
			return result, nil
		}
		if attempt >= maxMergeAttempts {
			return result, fmt.Errorf("%s kept changing underneath this merge (%d attempts); "+
				"close the harness and re-run", w.path, maxMergeAttempts)
		}
	}
}

// maxMergeAttempts bounds the optimistic retry. A config that loses the race
// this many times is not racing — something is rewriting it in a loop, and
// saying so beats spinning.
const maxMergeAttempts = 5

// applyOnce performs one optimistic merge. retry is true when the file changed
// between the read and the write and the caller should start over.
func (w fileWriter) applyOnce(entries []Entry, retire, managed []string) (res ApplyResult, retry bool, err error) {
	before, err := readFileAllowingMissing(w.path)
	if err != nil {
		return res, false, err
	}

	// The backup precedes the parse, so a config too malformed to read still
	// leaves the operator a copy of exactly what was there (R5).
	backup, err := backupFile(w.path)
	if err != nil {
		return res, false, err
	}
	res.BackupPath = backup

	if len(bytes.TrimSpace(before)) > 0 {
		if _, err := w.format.parse(before); err != nil {
			return res, false, fmt.Errorf("%w: %s: %v", ErrMalformedConfig, w.path, err)
		}
	}

	after, err := w.format.rewrite(before, entries, managed)
	if err != nil {
		return res, false, err
	}

	check := preservationCheck{parse: w.format.parse, container: w.format.container, managed: managed}
	// Verified BEFORE the write. A failure here has touched nothing at all,
	// which is a strictly better outcome than a correct rollback.
	if err := check.verify(before, after); err != nil {
		return res, false, err
	}

	if bytes.Equal(before, after) {
		// Still tighten the mode: an already-correct config that is
		// world-readable is not an already-correct config (R5 token hygiene).
		if err := os.Chmod(w.path, filePerm); err != nil {
			return res, false, fmt.Errorf("tighten permissions on %s: %w", w.path, err)
		}
		return res, false, nil
	}

	// Last look before the rename. Anything that changed since `before` was
	// read belongs to someone else and must not be overwritten.
	current, err := readFileAllowingMissing(w.path)
	if err != nil {
		return res, false, err
	}
	if !bytes.Equal(current, before) {
		return res, true, nil
	}

	if err := writeFileAtomic(w.path, after, filePerm); err != nil {
		return res, false, fmt.Errorf("write %s: %w", w.path, err)
	}
	res.Changed = true

	// Read back what actually landed. The check above proved the bytes we
	// intended were sound; this one proves the bytes on disk are.
	landed, err := os.ReadFile(w.path)
	if err != nil {
		return res, false, fmt.Errorf("re-read %s: %w", w.path, err)
	}
	if err := check.verify(before, landed); err != nil {
		if restoreErr := restoreFromBackup(w.path, backup); restoreErr != nil {
			return res, false, fmt.Errorf("%w (and the rollback failed: %v)", err, restoreErr)
		}
		return res, false, fmt.Errorf("%w (the original was restored from %s)", err, backup)
	}
	return res, false, nil
}

// readFileAllowingMissing treats an absent file as empty, which is what a
// harness that has never been configured actually looks like.
func readFileAllowingMissing(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

// managedNames is the set of entry names this run owns: the ones being written
// plus the ones a previous run wrote and this one is retiring. Nothing outside
// this set may be removed, and nothing outside it is exempted from the
// preservation check.
func managedNames(entries []Entry, retire []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if !seen[e.Name] {
			seen[e.Name] = true
			out = append(out, e.Name)
		}
	}
	for _, n := range retire {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// ── Claude Code ──────────────────────────────────────────────────────────────

// claudeContainer is the object user-scope MCP servers live in inside
// ~/.claude.json.
const claudeContainer = "mcpServers"

// NewClaudeWriter builds the Claude Code writer for an explicit config path.
// Callers normally reach it through Locator, which only ever produces the
// user-scope path.
func NewClaudeWriter(configPath string) Writer {
	return fileWriter{harness: ClaudeCode, path: configPath, format: format{
		container: claudeContainer,
		parse:     parseJSONTree,
		rewrite:   rewriteClaude,
	}}
}

func rewriteClaude(before []byte, entries []Entry, managed []string) ([]byte, error) {
	root, err := parseJSONObject(before)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedConfig, err)
	}
	servers := newJSONObject()
	if raw, ok := root.get(claudeContainer); ok {
		servers, err = parseJSONObject(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not an object: %v", ErrMalformedConfig, claudeContainer, err)
		}
	}

	for _, n := range managed {
		servers.delete(n)
	}
	for _, e := range entries {
		encoded, err := marshalClaudeEntry(e)
		if err != nil {
			return nil, err
		}
		servers.set(e.Name, encoded)
	}

	if servers.len() == 0 {
		root.delete(claudeContainer)
	} else {
		encoded, err := servers.marshal()
		if err != nil {
			return nil, err
		}
		root.set(claudeContainer, encoded)
	}
	return root.marshalLike(before)
}

// marshalClaudeEntry renders one entry in Claude Code's user-scope shape. The
// field order is fixed rather than map-derived so a re-run that changes nothing
// produces identical bytes — which is what makes idempotence observable instead
// of merely claimed.
func marshalClaudeEntry(e Entry) (json.RawMessage, error) {
	obj := newJSONObject()
	put := func(key string, value any) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		obj.set(key, encoded)
		return nil
	}
	switch e.Transport {
	case TransportHTTP:
		if err := errs(put("type", "http"), put("url", e.URL)); err != nil {
			return nil, err
		}
		if len(e.Headers) > 0 {
			if err := put("headers", e.Headers); err != nil {
				return nil, err
			}
		}
	case TransportStdio:
		args := e.Args
		if args == nil {
			args = []string{}
		}
		if err := errs(put("type", "stdio"), put("command", e.Command), put("args", args)); err != nil {
			return nil, err
		}
		if len(e.Env) > 0 {
			if err := put("env", e.Env); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("harness: entry %q has unsupported transport %q", e.Name, e.Transport)
	}
	return obj.marshal()
}

func errs(list ...error) error {
	for _, err := range list {
		if err != nil {
			return err
		}
	}
	return nil
}

// ── Codex ────────────────────────────────────────────────────────────────────

// codexContainer is the table Codex's MCP servers live under.
const codexContainer = "mcp_servers"

// NewCodexWriter builds the Codex writer for an explicit config path.
func NewCodexWriter(configPath string) Writer {
	return fileWriter{harness: Codex, path: configPath, format: format{
		container: codexContainer,
		parse:     parseTOMLTree,
		rewrite:   rewriteCodex,
	}}
}

// rewriteCodex edits the SOURCE TEXT rather than round-tripping the document:
// the managed `[mcp_servers.X]` tables (and their sub-tables) are cut out by
// byte span and re-rendered at the end, so every other byte of the file —
// comments, blank lines, key order, inline-vs-sub-table choices — is untouched.
func rewriteCodex(before []byte, entries []Entry, managed []string) ([]byte, error) {
	spans, err := scanTOMLTables(before)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedConfig, err)
	}
	managedSet := make(map[string]bool, len(managed))
	for _, n := range managed {
		managedSet[n] = true
	}

	out, _ := removeTOMLTables(before, spans, func(key []string) bool {
		return len(key) >= 2 && key[0] == codexContainer && managedSet[key[1]]
	})

	for _, e := range entries {
		block, err := renderTOMLEntry([]string{codexContainer}, e)
		if err != nil {
			return nil, err
		}
		out = appendTOMLBlock(out, block)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	return out, nil
}
