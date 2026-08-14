// Package harness configures the agent harnesses installed on this machine —
// Claude Code and Codex (D1) — to reach Homeplane's two capability surfaces
// over MCP: the locally supervised retrieval engine, and the server's connector
// edge.
//
// Three rules shape everything here.
//
//   - Merge-only, never rewrite. A harness config file belongs to its user, not
//     to Homeplane. Writes touch the Homeplane-managed MCP server entries and
//     nothing else, and every write is verified after the fact by re-parsing:
//     the parse of the file after the write, minus the managed entries, must be
//     deep-equal to the parse before, minus the managed entries (R5). A write
//     that cannot prove that is rolled back from the backup it took first.
//
//   - The endpoint is described, not assumed. The retrieval engine's transport,
//     command, argv and environment come verbatim from the endpoint descriptor
//     task .11 publishes (`internal/agent/gno`, the D16 seam). Nothing in this
//     package knows what engine is behind it, and nothing branches on which one
//     it is.
//
//   - One grant per harness, and the server decides what it carries. Each
//     harness gets its own grant token, requested fresh on every run. The
//     server supersedes the previous grant for the pair, so a run that fails
//     halfway is repaired by running again rather than by cleaning up: the
//     next run's grant invalidates whatever the failed run may have written.
//     Tokens land only in user-scoped 0600 files, and never in a project file
//     that could be committed.
package harness

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Harness identifiers. They match the server-side policy vocabulary
// (internal/policy) because they ARE the same names: a grant is issued for a
// harness, and the policy that decides its capabilities is keyed by this
// string. Duplicating the constants rather than importing the server-side
// package keeps the machine agent free of a dependency on server policy.
const (
	ClaudeCode = "claude-code"
	Codex      = "codex"
	Grok       = "grok"
)

// Known lists the harnesses this task configures, in a stable order.
//
// skills.Known() delegates to this function rather than keeping its own list:
// the two registries drifting apart is exactly how a harness ends up configured
// for MCP and invisible to skills provisioning (or the reverse), and
// TestKnownRegistriesAreInLockstep fails if the delegation is ever broken.
func Known() []string { return []string{ClaudeCode, Codex, Grok} }

// ConnectorServerName is the MCP server name the connector edge is registered
// under inside each harness. The retrieval engine's name is NOT a constant
// here: it comes from the endpoint descriptor.
const ConnectorServerName = "homeplane"

// Permissions. Every file this package writes holds — or sits beside — a grant
// token, so all of them are owner-only.
const (
	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// Transports an Entry may use.
const (
	TransportHTTP  = "http"
	TransportStdio = "stdio"
)

// Entry is one Homeplane-managed MCP server entry, in a form neither harness's
// config format is visible in. Each harness writer renders it into its own
// syntax.
type Entry struct {
	// Name is the MCP server name the harness registers the entry under.
	Name string
	// Transport is TransportHTTP or TransportStdio.
	Transport string

	// HTTP fields.
	URL string
	// Headers may carry the grant token. It is the one secret-bearing field in
	// this package, and String/Redacted exist so it cannot reach a log by
	// accident.
	Headers map[string]string

	// Stdio fields.
	Command string
	Args    []string
	Env     map[string]string
}

// serverNameRE constrains managed server names to what both formats can carry
// as a bare key. That is not cosmetic: the TOML writer locates managed tables
// by their header text, and a name needing quotes (or, worse, containing a
// bracket or a dot) would make "the span belonging to this entry" ambiguous.
// Refusing such a name is the fail-closed answer.
var serverNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// ErrUnsafeServerName means a managed server name could not be written or
// located unambiguously.
var ErrUnsafeServerName = errors.New("harness: unsafe MCP server name")

// ValidateServerName refuses a name this package cannot manage safely.
func ValidateServerName(name string) error {
	if !serverNameRE.MatchString(name) {
		return fmt.Errorf("%w: %q (allowed: letters, digits, '_' and '-', starting with a letter or digit)",
			ErrUnsafeServerName, name)
	}
	return nil
}

// Validate refuses an entry a harness could not use.
func (e Entry) Validate() error {
	if err := ValidateServerName(e.Name); err != nil {
		return err
	}
	switch e.Transport {
	case TransportHTTP:
		if strings.TrimSpace(e.URL) == "" {
			return fmt.Errorf("harness: entry %q is http but has no url", e.Name)
		}
		if len(e.Command) > 0 || len(e.Args) > 0 {
			return fmt.Errorf("harness: entry %q is http but carries a launch command", e.Name)
		}
	case TransportStdio:
		if strings.TrimSpace(e.Command) == "" {
			return fmt.Errorf("harness: entry %q is stdio but has no command", e.Name)
		}
		if strings.TrimSpace(e.URL) != "" {
			return fmt.Errorf("harness: entry %q is stdio but carries a url", e.Name)
		}
		for k := range e.Env {
			if looksSecret(k) {
				return fmt.Errorf("harness: refusing to write %q into entry %q's environment", k, e.Name)
			}
		}
	default:
		return fmt.Errorf("harness: entry %q has unsupported transport %q", e.Name, e.Transport)
	}
	return nil
}

// Redacted returns a copy safe to print: header values are replaced by their
// length, never their content.
func (e Entry) Redacted() Entry {
	if len(e.Headers) == 0 {
		return e
	}
	clone := e
	clone.Headers = make(map[string]string, len(e.Headers))
	for k, v := range e.Headers {
		clone.Headers[k] = fmt.Sprintf("<redacted %d bytes>", len(v))
	}
	return clone
}

// String never prints a header value.
func (e Entry) String() string {
	r := e.Redacted()
	if r.Transport == TransportHTTP {
		return fmt.Sprintf("%s (http %s)", r.Name, r.URL)
	}
	return fmt.Sprintf("%s (stdio %s %s)", r.Name, r.Command, strings.Join(r.Args, " "))
}

func looksSecret(key string) bool {
	upper := strings.ToUpper(key)
	for _, bad := range []string{"TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "BEARER"} {
		if strings.Contains(upper, bad) {
			return true
		}
	}
	return false
}

// ── Errors ───────────────────────────────────────────────────────────────────

// ErrMalformedConfig means the harness's existing configuration could not be
// parsed. R5 requires that harness to be SKIPPED — never repaired, never
// overwritten — with its original file untouched and its backup intact.
var ErrMalformedConfig = errors.New("harness: existing configuration is malformed")

// ErrPreservationFailed means a write changed something outside the
// Homeplane-managed entries. It is always accompanied by a restore from the
// backup: a config we cannot prove we preserved is a config we put back.
var ErrPreservationFailed = errors.New("harness: write would not have preserved unrelated configuration")

// ErrProjectScope means a config path resolved somewhere a grant token must
// never be written — a project-scoped, git-shareable file (R5, R17).
var ErrProjectScope = errors.New("harness: refusing to write a grant token to a project-scoped file")

// ── Results ──────────────────────────────────────────────────────────────────

// Outcome is what happened to one harness.
type Outcome struct {
	Harness string `json:"harness"`
	// Status is "configured", "skipped" or "failed".
	Status string `json:"status"`
	// Installed reports whether the harness is present on this machine. It
	// separates the two skips that must NOT be reported the same way: a machine
	// without Codex is healthy, a machine whose Codex config we could not read
	// is degraded.
	Installed bool `json:"installed"`
	// ConfigPath is the file that was (or would have been) written.
	ConfigPath string `json:"config_path,omitempty"`
	// BackupPath is the timestamped copy taken before the write.
	BackupPath string `json:"backup_path,omitempty"`
	// Managed names the MCP server entries Homeplane owns in that file.
	Managed []string `json:"managed_servers,omitempty"`
	// Retired names entries a previous run managed and this one removed.
	Retired []string `json:"retired_servers,omitempty"`
	// GrantID identifies the grant whose token the file now carries. The token
	// itself is deliberately absent from every result type in this package.
	GrantID string `json:"grant_id,omitempty"`
	// SupersededGrantID is the grant this run invalidated, if any.
	SupersededGrantID string `json:"superseded_grant_id,omitempty"`
	// EndpointURL is the connector edge the harness now talks to.
	EndpointURL string `json:"endpoint_url,omitempty"`
	// Capabilities is what the SERVER decided the grant carries.
	Capabilities []string `json:"capabilities,omitempty"`
	// Message explains a skip or a failure in the operator's words.
	Message string `json:"message,omitempty"`
	// Changed reports whether the file's bytes differ from before the run. A
	// re-run that converges on the same configuration still mints a new grant,
	// so this is false only when nothing at all had to move.
	Changed bool `json:"changed"`

	ConfiguredAt time.Time `json:"configured_at"`
}

// Status values.
const (
	StatusConfigured = "configured"
	StatusSkipped    = "skipped"
	StatusFailed     = "failed"
)

// Report is the result of one configure run.
type Report struct {
	Outcomes []Outcome `json:"harnesses"`
}

// Degraded returns the harnesses this run attempted, found installed, and
// failed to configure — the ones a machine must not describe as healthy.
func (r Report) Degraded() []string {
	out := []string{}
	for _, o := range r.Outcomes {
		if !o.Installed {
			continue
		}
		if o.Status == StatusFailed || o.Status == StatusSkipped {
			out = append(out, o.Harness)
		}
	}
	sort.Strings(out)
	return out
}

// Configured returns the harnesses that ended the run configured, sorted.
func (r Report) Configured() []string {
	out := []string{}
	for _, o := range r.Outcomes {
		if o.Status == StatusConfigured {
			out = append(out, o.Harness)
		}
	}
	sort.Strings(out)
	return out
}

// Err returns a combined error when any harness failed, and nil otherwise. A
// SKIPPED harness is not an error: R5 names skipping as the correct response to
// a malformed config, and a machine without Codex installed is not a fault.
func (r Report) Err() error {
	var failed []string
	for _, o := range r.Outcomes {
		if o.Status == StatusFailed {
			failed = append(failed, o.Harness+": "+o.Message)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return errors.New("harness: " + strings.Join(failed, "; "))
}
