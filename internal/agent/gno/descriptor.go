package gno

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The endpoint descriptor is the D16 seam.
//
// Homeplane supervises "the retrieval engine" as a named component. Harnesses
// are wired from THIS file, and nothing downstream of it needs to know that the
// engine is GNO: task .6 reads a transport, a command, an argv, and an
// environment, and writes them into each harness's MCP configuration under its
// own merge discipline. Swapping the engine later means writing a different
// descriptor, not editing the harness writer.
//
// The launch template is DERIVED, never invented. `gno mcp install --dry-run
// --json` prints the exact stdio server entry upstream would write into a
// client config; this package asks for that entry and records it. The review
// lesson from task .5 — never invent a third-party CLI's surface — is enforced
// here structurally rather than by discipline.

// DescriptorSchemaVersion is bumped when the descriptor's shape changes.
const DescriptorSchemaVersion = 1

// ComponentRetrievalEngine is the ROLE this descriptor describes. The role name
// is deliberately not "gno".
const ComponentRetrievalEngine = "retrieval-engine"

// TransportStdio is the transport harnesses use to reach the engine: one
// short-lived server process per client, spoken over the client's own pipes.
const TransportStdio = "stdio"

// Descriptor is everything a harness needs to reach the retrieval engine.
type Descriptor struct {
	SchemaVersion int    `json:"schema_version"`
	Component     string `json:"component"`
	// Engine and EngineVersion identify the implementation. They are recorded
	// for operators and evidence; the harness writer must not branch on them.
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version"`

	// Transport is "stdio": Command/Args/Env launch one server per client.
	Transport string            `json:"transport"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env,omitempty"`

	// ServerName is the MCP server name harnesses should register it under.
	ServerName string `json:"server_name"`

	// Collection and VaultPath say WHAT is reachable through the endpoint.
	Collection string `json:"collection"`
	VaultPath  string `json:"vault_path"`

	// DerivedFrom records the exact upstream command whose output produced
	// Command/Args/Env, so an operator can re-derive and diff it.
	DerivedFrom string `json:"derived_from"`

	// Supervision describes the LOCAL engine process, which is a different
	// lifecycle from the stdio endpoint above and must not be confused with it
	// (R4). The daemon is supervised and has a pid; the stdio endpoint is
	// launched per client and never has one.
	Supervision *SupervisionInfo `json:"supervision,omitempty"`

	WrittenAt time.Time `json:"written_at"`
}

// SupervisionInfo describes the supervised local engine process.
type SupervisionInfo struct {
	// Mode is "daemon": Homeplane supervises a long-lived indexer.
	Mode string `json:"mode"`
	// UnitLabel is the supervision unit's label.
	UnitLabel string `json:"unit_label"`
	// Host and Port are the daemon's loopback MCP gateway. They are recorded
	// for diagnostics; harnesses use the stdio transport above, NOT this port,
	// because the HTTP gateway would need a shared bearer token that the
	// skeleton has no way to revoke per harness.
	Host string `json:"host"`
	Port int    `json:"port"`
	// HealthCommand is how anything can ask the engine how it is.
	HealthCommand string   `json:"health_command"`
	HealthArgs    []string `json:"health_args"`
}

// DescriptorDir is where endpoint descriptors live, one per component role.
func DescriptorDir(stateDir string) string { return filepath.Join(stateDir, "endpoints") }

// DescriptorPath is the retrieval engine's descriptor path.
func DescriptorPath(stateDir string) string {
	return filepath.Join(DescriptorDir(stateDir), ComponentRetrievalEngine+".json")
}

// ErrNoDescriptor means no endpoint descriptor has been published on this
// machine — the honest answer for a machine where GNO was never activated.
var ErrNoDescriptor = errors.New("gno: no retrieval-engine endpoint descriptor on this machine")

// LoadDescriptor reads the published descriptor.
func LoadDescriptor(stateDir string) (Descriptor, error) {
	raw, err := os.ReadFile(DescriptorPath(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Descriptor{}, ErrNoDescriptor
		}
		return Descriptor{}, fmt.Errorf("gno: read endpoint descriptor: %w", err)
	}
	var d Descriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		return Descriptor{}, fmt.Errorf("gno: parse %s: %w", DescriptorPath(stateDir), err)
	}
	return d, nil
}

// SaveDescriptor publishes the descriptor atomically.
func SaveDescriptor(stateDir string, d Descriptor) error {
	if err := d.Validate(); err != nil {
		return err
	}
	d.SchemaVersion = DescriptorSchemaVersion
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("gno: encode endpoint descriptor: %w", err)
	}
	if err := os.MkdirAll(DescriptorDir(stateDir), dirPerm); err != nil {
		return fmt.Errorf("gno: create endpoint directory: %w", err)
	}
	return writeFileAtomic(DescriptorPath(stateDir), append(raw, '\n'), filePerm)
}

// Validate refuses a descriptor a harness could not use, or should not be
// given.
func (d Descriptor) Validate() error {
	switch {
	case d.Component != ComponentRetrievalEngine:
		return fmt.Errorf("gno: descriptor component must be %q, got %q", ComponentRetrievalEngine, d.Component)
	case d.Transport != TransportStdio:
		return fmt.Errorf("gno: unsupported endpoint transport %q", d.Transport)
	case strings.TrimSpace(d.Command) == "":
		return errors.New("gno: descriptor has no launch command")
	case !filepath.IsAbs(d.Command):
		// A bare command name would resolve differently under launchd, which
		// has almost no PATH — the exact failure mode that makes an MCP server
		// "work in the terminal and not in the app".
		return fmt.Errorf("gno: descriptor launch command %q must be an absolute path", d.Command)
	case len(d.Args) == 0:
		return errors.New("gno: descriptor has no launch arguments")
	case strings.TrimSpace(d.ServerName) == "":
		return errors.New("gno: descriptor has no server name")
	}
	return d.AssertNoSecrets()
}

// secretishEnvKeys are the environment names a descriptor must never carry. The
// descriptor is written 0600 but is copied verbatim into harness config files
// that are not, so a token reaching it would leak by design (R5 token hygiene).
var secretishEnvKeys = []string{"TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL", "AUTH"}

// AssertNoSecrets refuses a descriptor carrying anything credential-shaped.
func (d Descriptor) AssertNoSecrets() error {
	keys := make([]string, 0, len(d.Env))
	for k := range d.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		upper := strings.ToUpper(k)
		for _, bad := range secretishEnvKeys {
			if strings.Contains(upper, bad) {
				return fmt.Errorf("gno: refusing to publish an endpoint descriptor carrying %s in its environment", k)
			}
		}
	}
	for _, a := range d.Args {
		upper := strings.ToUpper(a)
		if strings.Contains(upper, "--TOKEN") || strings.Contains(upper, "--PASSWORD") {
			return errors.New("gno: refusing to publish an endpoint descriptor with a credential in argv")
		}
	}
	return nil
}

// ── Derivation from upstream ─────────────────────────────────────────────────

// serverEntry is the shape `gno mcp install --dry-run --json` prints.
type serverEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

type installDryRun struct {
	Installed struct {
		Target     string      `json:"target"`
		Scope      string      `json:"scope"`
		ConfigPath string      `json:"configPath"`
		Action     string      `json:"action"`
		Entry      serverEntry `json:"serverEntry"`
	} `json:"installed"`
}

// ErrNoLaunchTemplate means upstream did not print a usable server entry.
var ErrNoLaunchTemplate = errors.New("gno: `gno mcp install --dry-run` printed no server entry")

// DeriveLaunchTemplate asks GNO for the stdio server entry it would install.
//
// The target is only a lens: upstream emits the same entry for every stdio
// client, which is what makes one harness-agnostic descriptor legitimate. The
// live test asserts that equivalence against the real binary rather than
// assuming it.
func (c CLI) DeriveLaunchTemplate(ctx context.Context, target, scope string) (string, []string, map[string]string, error) {
	args := MCPInstallArgs(target, scope, true)
	out, err := c.Run(ctx, Invocation{Args: args})
	if err != nil {
		return "", nil, nil, err
	}
	raw, perr := extractJSONObject(out)
	if perr != nil {
		return "", nil, nil, fmt.Errorf("%w: %v", ErrNoLaunchTemplate, perr)
	}
	var parsed installDryRun
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", nil, nil, fmt.Errorf("%w: %v", ErrNoLaunchTemplate, err)
	}
	entry := parsed.Installed.Entry
	if strings.TrimSpace(entry.Command) == "" || len(entry.Args) == 0 {
		return "", nil, nil, ErrNoLaunchTemplate
	}
	if !strings.HasPrefix(parsed.Installed.Action, "dry_run") {
		// A dry run that reports a real action means upstream CHANGED a client
		// config. Refuse the result rather than accept a template we obtained
		// by mutating a harness behind task .6's back.
		return "", nil, nil, fmt.Errorf("gno: `mcp install --dry-run` reported action %q; refusing to treat it as a dry run",
			parsed.Installed.Action)
	}
	return entry.Command, entry.Args, entry.Env, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
