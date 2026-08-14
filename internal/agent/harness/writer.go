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
	// Prepare performs every check that does NOT need a grant, and writes
	// nothing: containment, entry and retire-name validation, directory
	// creation, backup and write access, and a full dry-merge whose result is
	// run through the preservation check.
	//
	// It is the first half of the two-phase transaction (see configureOne). Its
	// entries carry placeholder credentials — only their NAMES and shapes matter
	// to a merge — so every local reason a write could fail is discovered before
	// the server is asked to supersede the harness's working grant.
	Prepare(entries []Entry, retire []string) (Plan, error)
	// Commit performs the second half: it re-merges with the FINAL entries (the
	// ones carrying the issued token and endpoint), backs the file up, verifies
	// preservation, and replaces the file atomically under a race check.
	Commit(plan Plan, entries []Entry) (ApplyResult, error)
	// Apply is Prepare followed by Commit against the same entries. It is the
	// single-phase form, for callers that have nothing to lose between the two.
	Apply(entries []Entry, retire []string) (ApplyResult, error)
}

// Plan is what Prepare established: the entry names this write owns. It carries
// no file bytes on purpose — Commit re-reads the file, because anything cached
// between the two phases is exactly the stale snapshot the race check exists to
// refuse.
type Plan struct {
	// Managed is the full set of entry names this write owns: the ones being
	// written plus the ones being retired.
	Managed []string
	// Retire names entries a previous run managed and this one removes.
	Retire []string
	// BackupPath is the copy Prepare took of the file as it stood. It is taken
	// BEFORE the parse, so a config too malformed to read still leaves the
	// operator a copy of exactly what was there (R5) — which is why it is
	// populated even when Prepare returns an error.
	BackupPath string
	// prepared guards against a zero Plan being passed to Commit, which would
	// silently manage nothing and therefore preserve nothing.
	prepared bool
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
	// exempt lists Homeplane-managed key paths that live OUTSIDE the container.
	// grok has two (`compat.claude.mcps`, `compat.cursor.mcps`); the other
	// harnesses have none. They are subtracted from both sides of the
	// preservation equation, and assertAfter proves what they became.
	exempt [][]string
	// assertAfter re-checks the parsed result of a write. It is where an exempt
	// key earns its exemption: subtracting a key from the comparison without
	// proving its value would let a silently-failed edit pass.
	assertAfter func(tree map[string]any) error
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
	plan, err := w.Prepare(entries, retire)
	if err != nil {
		// The backup survives the failure: the skip contract is "clear message
		// AND a copy of the original", and a caller that only gets the error
		// cannot tell the operator where their file went.
		return ApplyResult{BackupPath: plan.BackupPath}, err
	}
	return w.Commit(plan, entries)
}

// Prepare is the no-authority half of the write: everything that can fail
// locally, discovered before a grant exists.
func (w fileWriter) Prepare(entries []Entry, retire []string) (Plan, error) {
	if err := assertUserScope(w.path); err != nil {
		return Plan{}, err
	}
	managed := managedNames(entries, retire)
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return Plan{}, err
		}
	}
	for _, n := range retire {
		if err := ValidateServerName(n); err != nil {
			return Plan{}, err
		}
	}

	if err := os.MkdirAll(filepath.Dir(w.path), dirPerm); err != nil {
		return Plan{}, fmt.Errorf("create %s: %w", filepath.Dir(w.path), err)
	}
	// Write access is PROVED, not assumed. The atomic write and the backup both
	// create a file beside the target, so a directory we cannot create a file in
	// is a write that will fail — and discovering that after issuance would have
	// cost the harness its working grant for nothing.
	if err := assertDirWritable(filepath.Dir(w.path)); err != nil {
		return Plan{}, err
	}

	// The backup precedes the parse, for the same reason it does inside the
	// commit: the config most worth copying is the one we are about to refuse
	// to touch.
	backup, err := backupFile(w.path)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{BackupPath: backup}

	// The dry merge. It performs the whole rewrite and the whole preservation
	// check against the CURRENT file, and then throws the bytes away: a config
	// this writer cannot express — an unparseable file, an entry it cannot
	// render, a compat setting it cannot edit at key granularity — is a local
	// failure, and local failures must not cost authority.
	before, err := readFileAllowingMissing(w.path)
	if err != nil {
		return plan, err
	}
	if len(bytes.TrimSpace(before)) > 0 {
		if _, err := w.format.parse(before); err != nil {
			return plan, fmt.Errorf("%w: %s: %v", ErrMalformedConfig, w.path, err)
		}
	}
	after, err := w.format.rewrite(before, entries, managed)
	if err != nil {
		return plan, err
	}
	if err := w.check(managed).verify(before, after); err != nil {
		return plan, err
	}

	plan.Managed = managed
	plan.Retire = append([]string(nil), retire...)
	plan.prepared = true
	return plan, nil
}

// assertDirWritable creates and removes a probe file. Asking the filesystem
// beats reading permission bits: the answer that matters is whether THIS process
// can create a file there, which ownership, ACLs and read-only mounts all get a
// vote in.
func assertDirWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".homeplane-preflight-*")
	if err != nil {
		return fmt.Errorf("%s is not writable, so no configuration could be written there: %w", dir, err)
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		os.Remove(name)
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("could not clean up the write probe %s: %w", name, err)
	}
	return nil
}

// Commit is the authority-bearing half: the final entries, and the atomic
// replacement.
func (w fileWriter) Commit(plan Plan, entries []Entry) (ApplyResult, error) {
	if !plan.prepared {
		return ApplyResult{}, errors.New("harness: Commit was called without a prepared plan")
	}
	// The final entries carry the real token and endpoint. Their VALUES were
	// never seen by Prepare, so they are validated here, before anything is
	// written.
	for _, e := range entries {
		if err := e.Validate(); err != nil {
			return ApplyResult{}, err
		}
	}
	managed := plan.Managed
	retire := plan.Retire

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
	result.BackupPath = plan.BackupPath
	for attempt := 0; ; attempt++ {
		res, retry, err := w.applyOnce(entries, retire, managed, result.BackupPath)
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

// check builds the preservation equation for this writer and this run's managed
// set. One constructor, so the dry merge in Prepare and both verifications in
// Commit can never be checking different things.
func (w fileWriter) check(managed []string) preservationCheck {
	return preservationCheck{
		parse:       w.format.parse,
		container:   w.format.container,
		managed:     managed,
		exempt:      w.format.exempt,
		assertAfter: w.format.assertAfter,
	}
}

// maxMergeAttempts bounds the optimistic retry. A config that loses the race
// this many times is not racing — something is rewriting it in a loop, and
// saying so beats spinning.
const maxMergeAttempts = 5

// applyOnce performs one optimistic merge. retry is true when the file changed
// between the read and the write and the caller should start over.
func (w fileWriter) applyOnce(entries []Entry, retire, managed []string, existingBackup string) (res ApplyResult, retry bool, err error) {
	before, err := readFileAllowingMissing(w.path)
	if err != nil {
		return res, false, err
	}

	// The backup precedes the parse, so a config too malformed to read still
	// leaves the operator a copy of exactly what was there (R5).
	backup, err := ensureBackup(w.path, existingBackup)
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

	check := w.check(managed)
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
		block, err := renderTOMLEntry([]string{codexContainer}, e, codexEntryStyle)
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
