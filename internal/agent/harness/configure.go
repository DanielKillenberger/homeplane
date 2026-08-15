package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
)

// Grant is the server's answer to a grant request, as this package needs it.
//
// The Token field is the only secret in the package's public surface, and it
// exists to be written into exactly one file and then forgotten: nothing here
// stores it, logs it, or returns it in a result.
type Grant struct {
	GrantID           string
	Harness           string
	Capabilities      []string
	EndpointURL       string
	Token             string
	SupersededGrantID string
}

// GrantIssuer requests a grant for one harness.
//
// The interface is deliberately narrow and defined HERE rather than imported:
// the machine agent asks for a grant and is told what it carries. It cannot
// name capabilities, because it does not get to choose them — server-side
// policy does (internal/policy). A wider interface would make that invariant a
// convention instead of a type.
type GrantIssuer interface {
	IssueGrant(ctx context.Context, harness string) (Grant, error)
}

// Configurator configures the harnesses on this machine.
type Configurator struct {
	// StateDir is the agent state directory. Per-harness records live under it.
	StateDir string
	// Locator resolves config paths and installation.
	Locator Locator
	// Issuer mints one grant per harness.
	Issuer GrantIssuer

	// Only, when non-empty, restricts the run to these harnesses.
	Only []string

	// Lock serialises the whole run — grant issuance, config write, record and
	// state persistence — against another `configure-harnesses` process.
	//
	// Without it, two runs can interleave as "A issues, B issues, B writes, A
	// writes", which leaves the config holding A's token AFTER the server has
	// superseded it: both commands report success and the harness is dead. That
	// window is invisible to every check in this package, because each run's
	// own view is perfectly consistent. Nil means unserialised, which is only
	// correct for a caller that has its own mutual exclusion.
	Lock func() (func(), error)

	// now is a clock seam.
	now func() time.Time
}

// Configure requests a grant for each installed harness and writes both managed
// MCP entries into its configuration.
//
// The run is idempotent by construction rather than by bookkeeping: every call
// mints a FRESH grant, which supersedes the previous grant for the same
// (machine, harness) pair server-side, and then rewrites the managed entries
// from scratch. A run that dies between the two leaves a grant nobody uses and
// a config nobody can authenticate with — and the next run repairs both,
// because it does not try to reuse either.
//
// One harness never blocks another: a skip or a failure is recorded in that
// harness's Outcome and the run continues.
func (c Configurator) Configure(ctx context.Context) (Report, error) {
	if c.Issuer == nil {
		return Report{}, errors.New("harness: a grant issuer is required")
	}
	if strings.TrimSpace(c.StateDir) == "" {
		return Report{}, errors.New("harness: the agent state directory is required")
	}
	now := c.now
	if now == nil {
		now = time.Now
	}

	wanted, err := c.selected()
	if err != nil {
		return Report{}, err
	}

	if c.Lock != nil {
		release, err := c.Lock()
		if err != nil {
			return Report{}, err
		}
		defer release()
	}

	// The engine endpoint is read, validated AND converted ONCE, before any
	// harness is touched and before any grant is requested.
	//
	// Both halves of that matter. Reading once means every harness is wired to
	// the same endpoint, which a per-harness read would let a concurrent
	// re-activation split. CONVERTING once means a descriptor this writer
	// cannot express — a corrupt file, an unsupported transport, an unusable
	// server name — fails the run before any authority moves. Converting inside
	// the loop would supersede each harness's working grant and only then
	// discover it had nothing to write: a purely local problem would revoke
	// every harness's connector access.
	engine, engineErr := loadEngineEntry(c.StateDir)
	if engineErr != nil && !errors.Is(engineErr, gno.ErrNoDescriptor) {
		return Report{}, fmt.Errorf("harness: the retrieval engine endpoint is unusable, so no grant was requested: %w", engineErr)
	}

	report := Report{}
	for _, h := range wanted {
		report.Outcomes = append(report.Outcomes, c.configureOne(ctx, h, engine, engineErr, now()))
	}
	return report, nil
}

// loadEngineEntry reads the published endpoint descriptor and converts it into
// the entry harnesses will carry. gno.ErrNoDescriptor passes through unwrapped:
// "the engine is not activated on this machine" is a state the run continues
// from, unlike a descriptor that exists and cannot be used.
func loadEngineEntry(stateDir string) (Entry, error) {
	d, err := gno.LoadDescriptor(stateDir)
	if err != nil {
		return Entry{}, err
	}
	return EntryFromDescriptor(d)
}

func (c Configurator) selected() ([]string, error) {
	if len(c.Only) == 0 {
		return Known(), nil
	}
	known := map[string]bool{}
	for _, h := range Known() {
		known[h] = true
	}
	var out []string
	for _, h := range c.Only {
		h = strings.ToLower(strings.TrimSpace(h))
		if !known[h] {
			return nil, fmt.Errorf("harness: unknown harness %q (known: %s)", h, strings.Join(Known(), ", "))
		}
		out = append(out, h)
	}
	return out, nil
}

func (c Configurator) configureOne(ctx context.Context, h string, engine Entry, engineErr error, at time.Time) Outcome {
	out := Outcome{Harness: h, ConfiguredAt: at}

	detection, err := c.Locator.Detect(h)
	if err != nil {
		return failed(out, err.Error())
	}
	out.ConfigPath = detection.ConfigPath
	out.Installed = detection.Installed
	if !detection.Installed {
		out.Status = StatusSkipped
		out.Message = detection.Reason
		return out
	}
	// A harness whose CLI contract this build has not verified is SKIPPED before
	// any authority moves. Writing a config shape into a version nobody observed
	// is how a harness silently stops working, and doing it after issuance would
	// also have superseded the grant that was working.
	if !detection.Usable() {
		out.Status = StatusSkipped
		out.Message = detection.SupportReason
		return out
	}

	writer, err := c.writerFor(h, detection.ConfigPath)
	if err != nil {
		return failed(out, err.Error())
	}

	prior, err := loadRecord(c.StateDir, h)
	if err != nil {
		return failed(out, err.Error())
	}

	// A config we cannot read is a harness we skip (R5) — and we find that out
	// BEFORE asking the server for a grant, so a malformed config costs no
	// authority at all.
	if err := writer.Preflight(); err != nil {
		if errors.Is(err, ErrMalformedConfig) {
			// The skip contract is "message + backup intact", so a backup we
			// could not take is a FAILURE, not a quiet skip. Swallowing the
			// error here would report a clean skip on a full disk while the
			// promised copy of the operator's config did not exist.
			backup, backupErr := backupFile(detection.ConfigPath)
			if backupErr != nil {
				return failed(out, fmt.Sprintf("%s is malformed AND could not be backed up, so it was left strictly untouched: %v",
					detection.ConfigPath, backupErr))
			}
			out.BackupPath = backup
			out.Status = StatusSkipped
			out.Message = fmt.Sprintf("%s was left untouched: %v (a copy of it is at %s)", detection.ConfigPath, err, backup)
			return out
		}
		return failed(out, err.Error())
	}

	// ── Phase one: everything that can fail locally, before any authority moves.
	//
	// Issuance SUPERSEDES this harness's previous grant server-side. So every
	// local reason the write could fail — the destination being inside a git
	// checkout, an entry this writer cannot render, a config whose compat
	// settings it cannot edit, an unwritable directory, a state directory it
	// cannot record into — must be discovered HERE. Learning any of them after
	// issuance would leave a harness that WAS working holding a dead token, with
	// nothing written to replace it: a purely local problem that revoked a
	// working capability.
	//
	// The provisional entries carry a placeholder token and endpoint. Only the
	// entry NAMES and shapes matter to a merge, and the real values are
	// validated again in Commit before anything is written.
	provisional := c.entriesFor(placeholderGrant(h), engine, engineErr)
	desired := map[string]bool{}
	for _, e := range provisional {
		desired[e.Name] = true
		out.Managed = append(out.Managed, e.Name)
	}
	sort.Strings(out.Managed)
	for _, n := range prior.ManagedServers {
		if !desired[n] {
			out.Retired = append(out.Retired, n)
		}
	}
	sort.Strings(out.Retired)

	plan, err := writer.Prepare(provisional, out.Retired)
	// Assigned BEFORE the error check: Prepare takes its copy before it parses
	// anything, precisely so a file we end up refusing to touch still leaves the
	// operator a copy — and a copy nobody is told about is not a copy they have.
	out.BackupPath = plan.BackupPath
	if err != nil {
		if errors.Is(err, ErrMalformedConfig) {
			out.Status = StatusSkipped
			out.Message = fmt.Sprintf("%s was left untouched: %v", detection.ConfigPath, err)
			return out
		}
		message := err.Error()
		if out.BackupPath != "" {
			message += fmt.Sprintf(" (%s was left untouched; a copy of it is at %s)", detection.ConfigPath, out.BackupPath)
		}
		return failed(out, message)
	}
	// The record is the machine's memory of which entries a previous run
	// managed. A state directory we cannot write is a run that would configure
	// the harness and then forget it did — so it is proved before issuance too.
	if err := assertRecordWritable(c.StateDir); err != nil {
		return failed(out, err.Error())
	}

	// ── Phase two: authority moves, then only substitution and the commit.
	grant, err := c.Issuer.IssueGrant(ctx, h)
	if err != nil {
		return failed(out, "requesting a grant failed: "+err.Error())
	}
	if strings.TrimSpace(grant.Token) == "" || strings.TrimSpace(grant.EndpointURL) == "" {
		return failed(out, "the server issued a grant without a token or an endpoint URL")
	}
	out.GrantID = grant.GrantID
	out.SupersededGrantID = grant.SupersededGrantID
	out.EndpointURL = grant.EndpointURL
	out.Capabilities = grant.Capabilities

	entries := c.entriesFor(grant, engine, engineErr)
	if engineErr != nil {
		// The only error that reaches here is ErrNoDescriptor; Configure
		// refused the run before any issuance for every other kind.
		out.Message = "the local retrieval engine is not activated on this machine, so only the connector endpoint was written " +
			"(run `homeplane-agent gno activate`, then re-run this command)"
	}

	applied, err := writer.Commit(plan, entries)
	out.BackupPath = applied.BackupPath
	if err != nil {
		if errors.Is(err, ErrMalformedConfig) {
			out.Status = StatusSkipped
			out.Message = fmt.Sprintf("%s was left untouched: %v", detection.ConfigPath, err)
			return out
		}
		return failed(out, err.Error())
	}
	out.Changed = applied.Changed

	if err := saveRecord(c.StateDir, Record{
		SchemaVersion:  RecordSchemaVersion,
		Harness:        h,
		ConfigPath:     detection.ConfigPath,
		ManagedServers: out.Managed,
		GrantID:        grant.GrantID,
		EndpointURL:    grant.EndpointURL,
		Capabilities:   grant.Capabilities,
		ConfiguredAt:   at,
	}); err != nil {
		return failed(out, err.Error())
	}

	out.Status = StatusConfigured
	return out
}

// entriesFor is the entry set one harness gets: the connector edge, plus the
// retrieval engine when one is published. Both phases build it through this
// function, so the dry merge and the real one can never manage different names.
func (c Configurator) entriesFor(g Grant, engine Entry, engineErr error) []Entry {
	entries := []Entry{connectorEntry(g)}
	if engineErr == nil {
		entries = append(entries, engine)
	}
	return entries
}

// placeholderGrant is the stand-in phase one merges with.
//
// Its token and URL are structurally valid and semantically inert: they never
// reach disk, because Commit re-renders from the issued grant. The URL is under
// `.invalid`, which by RFC 6761 resolves nowhere, so a bug that DID write one
// fails loudly at connect time instead of quietly pointing a harness somewhere
// real.
func placeholderGrant(harnessName string) Grant {
	return Grant{
		Harness:     harnessName,
		EndpointURL: "https://preflight.homeplane.invalid/mcp",
		Token:       "preflight-placeholder-never-written",
	}
}

// assertRecordWritable proves the per-harness record could be written, without
// writing one.
func assertRecordWritable(stateDir string) error {
	dir := RecordDir(stateDir)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return assertDirWritable(dir)
}

func failed(out Outcome, message string) Outcome {
	out.Status = StatusFailed
	out.Message = message
	return out
}

func (c Configurator) writerFor(harness, configPath string) (Writer, error) {
	switch harness {
	case ClaudeCode:
		return NewClaudeWriter(configPath), nil
	case Codex:
		return NewCodexWriter(configPath), nil
	case Grok:
		return NewGrokWriter(configPath), nil
	default:
		return nil, fmt.Errorf("harness: no writer for %q", harness)
	}
}

// connectorEntry is the server connector plane, reached over the streamable-HTTP
// edge (task .16) with this harness's own grant token in an Authorization
// header. Tool names arriving here are qualified `provider__tool` by the
// harness when a bare name is ambiguous across connectors; the edge's router
// owns that resolution, so nothing about it is configured on this side.
func connectorEntry(g Grant) Entry {
	return Entry{
		Name:      ConnectorServerName,
		Transport: TransportHTTP,
		URL:       g.EndpointURL,
		Headers:   map[string]string{"Authorization": "Bearer " + g.Token},
	}
}

// EntryFromDescriptor turns the endpoint descriptor task .11 publishes into a
// managed entry.
//
// This is the whole of what the harness writer knows about the retrieval
// engine: a transport, a command, an argv and an environment, copied. Nothing
// branches on Engine or EngineVersion — swapping the engine means publishing a
// different descriptor, not editing this package (D16).
func EntryFromDescriptor(d gno.Descriptor) (Entry, error) {
	if err := d.Validate(); err != nil {
		return Entry{}, err
	}
	if d.Transport != gno.TransportStdio {
		return Entry{}, fmt.Errorf("harness: endpoint descriptor declares transport %q, which this writer cannot express", d.Transport)
	}
	if err := ValidateServerName(d.ServerName); err != nil {
		return Entry{}, err
	}
	e := Entry{
		Name:      d.ServerName,
		Transport: TransportStdio,
		Command:   d.Command,
		Args:      append([]string{}, d.Args...),
	}
	if len(d.Env) > 0 {
		e.Env = make(map[string]string, len(d.Env))
		for k, v := range d.Env {
			e.Env[k] = v
		}
	}
	// The descriptor already refuses to carry anything credential-shaped
	// (Descriptor.AssertNoSecrets). Validate re-checks it here because THIS is
	// the point where the value reaches a config file.
	return e, e.Validate()
}

// ── Per-harness record ───────────────────────────────────────────────────────

// RecordSchemaVersion is bumped when the record's shape changes.
const RecordSchemaVersion = 1

// Record is what this machine remembers about one configured harness.
//
// It exists for exactly one job: knowing which entry names a PREVIOUS run
// managed, so a rename (a descriptor that now publishes a different server
// name) retires the old entry instead of orphaning it. It deliberately holds no
// token — the token lives in the harness config and nowhere else — and it is
// never treated as authoritative about the grant, which `status` reconciles
// against the server on every call.
type Record struct {
	SchemaVersion  int       `json:"schema_version"`
	Harness        string    `json:"harness"`
	ConfigPath     string    `json:"config_path"`
	ManagedServers []string  `json:"managed_servers"`
	GrantID        string    `json:"grant_id"`
	EndpointURL    string    `json:"endpoint_url"`
	Capabilities   []string  `json:"capabilities,omitempty"`
	ConfiguredAt   time.Time `json:"configured_at"`
}

// RecordDir is where per-harness records live.
func RecordDir(stateDir string) string { return filepath.Join(stateDir, "harnesses") }

// RecordPath is one harness's record path.
func RecordPath(stateDir, harness string) string {
	return filepath.Join(RecordDir(stateDir), harness+".json")
}

func loadRecord(stateDir, harness string) (Record, error) {
	raw, err := os.ReadFile(RecordPath(stateDir, harness))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{Harness: harness}, nil
		}
		return Record{}, fmt.Errorf("read %s: %w", RecordPath(stateDir, harness), err)
	}
	var r Record
	if err := jsonUnmarshal(raw, &r); err != nil {
		// A corrupt record is not worth failing a run over: it only remembers
		// which names to retire, and the worst case of forgetting is an orphan
		// entry the operator can see.
		return Record{Harness: harness}, nil
	}
	return r, nil
}

func saveRecord(stateDir string, r Record) error {
	if err := os.MkdirAll(RecordDir(stateDir), dirPerm); err != nil {
		return fmt.Errorf("create %s: %w", RecordDir(stateDir), err)
	}
	raw, err := jsonMarshalIndent(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(RecordPath(stateDir, r.Harness), append(raw, '\n'), filePerm)
}

// LoadRecords reads every per-harness record, in Known() order. Absent records
// are omitted rather than faked.
func LoadRecords(stateDir string) ([]Record, error) {
	var out []Record
	for _, h := range Known() {
		if _, err := os.Stat(RecordPath(stateDir, h)); err != nil {
			continue
		}
		r, err := loadRecord(stateDir, h)
		if err != nil {
			return nil, err
		}
		if r.GrantID != "" {
			out = append(out, r)
		}
	}
	return out, nil
}
