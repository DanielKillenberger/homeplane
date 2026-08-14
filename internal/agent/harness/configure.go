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

	// The engine endpoint is read ONCE, before any harness is touched: every
	// harness must be wired to the same endpoint, and re-reading per harness
	// would let a concurrent re-activation split them.
	endpoint, endpointErr := gno.LoadDescriptor(c.StateDir)

	report := Report{}
	for _, h := range wanted {
		report.Outcomes = append(report.Outcomes, c.configureOne(ctx, h, endpoint, endpointErr, now()))
	}
	return report, nil
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

func (c Configurator) configureOne(ctx context.Context, h string, endpoint gno.Descriptor, endpointErr error, at time.Time) Outcome {
	out := Outcome{Harness: h, ConfiguredAt: at}

	detection, err := c.Locator.Detect(h)
	if err != nil {
		return failed(out, err.Error())
	}
	out.ConfigPath = detection.ConfigPath
	if !detection.Installed {
		out.Status = StatusSkipped
		out.Message = detection.Reason
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
			out.Status = StatusSkipped
			out.Message = fmt.Sprintf("%s was left untouched: %v", detection.ConfigPath, err)
			if backup, backupErr := backupFile(detection.ConfigPath); backupErr == nil {
				out.BackupPath = backup
				out.Message += fmt.Sprintf(" (a copy of it is at %s)", backup)
			}
			return out
		}
		return failed(out, err.Error())
	}

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

	entries := []Entry{connectorEntry(grant)}
	if endpointErr == nil {
		engine, err := EntryFromDescriptor(endpoint)
		if err != nil {
			return failed(out, err.Error())
		}
		entries = append(entries, engine)
	} else if errors.Is(endpointErr, gno.ErrNoDescriptor) {
		out.Message = "the local retrieval engine is not activated on this machine, so only the connector endpoint was written " +
			"(run `homeplane-agent gno activate`, then re-run this command)"
	} else {
		return failed(out, "reading the retrieval engine endpoint failed: "+endpointErr.Error())
	}

	desired := map[string]bool{}
	for _, e := range entries {
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

	applied, err := writer.Apply(entries, out.Retired)
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
