// Package connectors implements Homeplane's declarative connector plane: the
// connector manifest, the policy engine that authorizes tool calls against it,
// and the audit rows derived from it.
//
// The architectural claim this package has to make true (R12) is that a
// connector is DATA, not code: adding Gmail, Rize, Oura or TickTick must be a
// manifest entry plus its credentials, with no change to enrolment, identity,
// custody, authorization, audit or revocation logic. Everything here is
// therefore generic over the manifest — there is no provider name anywhere in
// the decision path.
//
// Three rules are structural rather than conventional:
//
//   - Fail closed. A tool with no mapping is denied at invocation time and the
//     denial audited as a policy violation. A connector upgrade can never
//     introduce an unclassified write/send/delete tool that inherits access.
//   - Complete registration. Where the gateway's tool inventory is known, every
//     tool in it must be classified — mapped with an action class and required
//     capability, or explicitly excluded with a reason. A half-registered
//     connector is refused at load time, not silently accepted.
//   - Metadata only. Audit rows carry the tool name, the manifest-derived action
//     class, and either a declaratively extracted artifact id or a digest of the
//     request arguments — never the arguments and never a payload body.
package connectors

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/policy"
)

// ManifestVersion is the only schema version this build understands. An
// unknown version is refused rather than best-effort parsed: a manifest is an
// authorization input, so "mostly understood" is not a safe state.
const ManifestVersion = 1

// ActionClass is the audit/authorization class a tool call belongs to. It is
// declared per tool in the manifest, never inferred from the tool's name.
type ActionClass string

const (
	ActionRead   ActionClass = "read"
	ActionWrite  ActionClass = "write"
	ActionSend   ActionClass = "send"
	ActionDelete ActionClass = "delete"

	// ActionUnknown never appears in a manifest. It is what a denied call to an
	// unclassified tool records, so that "we did not know what this was" is
	// itself a queryable fact rather than an empty column.
	ActionUnknown ActionClass = "unknown"
)

// defaultCapability is the capability an action class requires when a mapping
// does not name one explicitly. A mapping MAY require a stronger capability
// than its class implies; it can never require a weaker one (enforced below).
var defaultCapability = map[ActionClass]policy.Capability{
	ActionRead:   policy.ConnectorRead,
	ActionWrite:  policy.ConnectorWrite,
	ActionSend:   policy.ConnectorSend,
	ActionDelete: policy.ConnectorDelete,
}

// knownCapabilities is the capability vocabulary a manifest may reference. It
// is built from the policy package's constants so a manifest can never name a
// capability no grant can carry (which would be a permanently-denied tool that
// looks configured).
var knownCapabilities = map[policy.Capability]bool{
	policy.ConnectorRead:   true,
	policy.ConnectorWrite:  true,
	policy.ConnectorSend:   true,
	policy.ConnectorDelete: true,
}

// Manifest-loading errors. Callers distinguish these to report the difference
// between "this file is malformed" and "this connector is only half declared".
var (
	// ErrInvalidManifest means the manifest is malformed or internally invalid.
	ErrInvalidManifest = errors.New("connectors: invalid manifest")
	// ErrIncompleteRegistration means a connector declared its gateway tool
	// inventory but left some of those tools unclassified.
	ErrIncompleteRegistration = errors.New("connectors: incomplete registration")
	// ErrUnknownDriver means a connector referenced a credential-acquisition
	// driver this build does not ship.
	ErrUnknownDriver = errors.New("connectors: unknown credential driver")
)

// Manifest is the whole declarative connector plane.
type Manifest struct {
	Version    int         `json:"version"`
	Connectors []Connector `json:"connectors"`
}

// Connector is one provider's declaration: where its credential comes from,
// where its MCP tools come from, and what each of those tools is allowed to be.
type Connector struct {
	// Provider is the stable connector identifier used on the wire and in
	// audit rows (e.g. "google-drive").
	Provider string `json:"provider"`
	// CredentialRef names the server-side secret holding the provider
	// credential. It is a REFERENCE into the D3 secret store; a manifest never
	// carries credential material.
	CredentialRef string `json:"credential_ref"`
	// Credential describes how that credential is acquired (R13's
	// add-credentials flow) in purely declarative terms.
	Credential CredentialAcquisition `json:"credential_acquisition"`
	// Server describes where the connector's MCP tools come from.
	Server MCPServer `json:"mcp_server"`
	// ToolInventory is the gateway's known tool list, when known. When
	// non-empty, registration REFUSES any inventory tool that is neither
	// mapped nor explicitly excluded.
	ToolInventory []string `json:"tool_inventory,omitempty"`
	// Tools maps individual tools to their action class and required
	// capability. A tool absent from this list is denied.
	Tools []ToolMapping `json:"tools"`
	// Excluded records tools deliberately kept out of scope (D18 keeps Drive's
	// write tools here). Excluded tools are denied exactly like unmapped ones;
	// listing them is how an operator says "we saw this and said no".
	Excluded []ExcludedTool `json:"excluded_tools,omitempty"`
}

// CredentialAcquisition is a reference to a standard credential driver plus its
// declarative parameters. The skeleton ships one driver, `oauth2-authcode`;
// adding a second provider on that driver is parameters only (R12).
type CredentialAcquisition struct {
	Driver string            `json:"driver"`
	Params map[string]string `json:"params"`
	Scopes []string          `json:"scopes"`
}

// MCPServer is where a connector's tools come from.
type MCPServer struct {
	// Name is the gateway's workload name for this server.
	Name string `json:"name"`
	// Transport is how the gateway reaches it.
	Transport string `json:"transport"`
	// Source is the image/package reference the gateway runs.
	Source string `json:"source"`
}

// ToolMapping is the per-tool declaration the whole authorization and audit
// story is derived from.
type ToolMapping struct {
	Tool        string      `json:"tool"`
	ActionClass ActionClass `json:"action_class"`
	// Capability is the grant capability required to invoke the tool. Empty
	// means "the default for this action class".
	Capability policy.Capability `json:"capability,omitempty"`
	// ArtifactID optionally declares where the affected artifact's identity can
	// be read. Absent means the audit row records a digest of the request
	// arguments and artifact id `unknown`.
	ArtifactID *Extractor `json:"artifact_id,omitempty"`
}

// ExtractorSource says which JSON document an extractor reads.
type ExtractorSource string

const (
	// FromRequest reads the tool's request arguments.
	FromRequest ExtractorSource = "request"
	// FromResponse reads the tool's response (e.g. the id of a created event).
	FromResponse ExtractorSource = "response"
)

// Extractor is a JSONPath-style pointer at a scalar identity field.
// Supported syntax: `$.a.b`, `$.a[0].b`, `$.a` — object keys and array indices.
type Extractor struct {
	Source  ExtractorSource `json:"source"`
	Pointer string          `json:"pointer"`
}

// ExcludedTool is a known tool deliberately left unauthorized, with the reason
// recorded so the exclusion is a documented decision rather than an omission.
type ExcludedTool struct {
	Tool   string `json:"tool"`
	Reason string `json:"reason"`
}

// driverSpec describes a credential driver's declarative parameter contract.
type driverSpec struct {
	required   []string
	optional   []string
	needScopes bool
}

// DriverOAuth2AuthCode is the one credential driver the skeleton ships.
const DriverOAuth2AuthCode = "oauth2-authcode"

var driverSpecs = map[string]driverSpec{
	DriverOAuth2AuthCode: {
		required:   []string{"auth_endpoint", "token_endpoint", "client_id_ref", "client_secret_ref"},
		optional:   []string{"redirect_path", "access_type", "prompt"},
		needScopes: true,
	},
}

// KnownDrivers lists the credential drivers this build ships, sorted.
func KnownDrivers() []string {
	out := make([]string, 0, len(driverSpecs))
	for d := range driverSpecs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

var identRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._@/-]*$`)

// Parse decodes a manifest and validates it. Unknown JSON fields are REFUSED:
// a mistyped `action_class` key would otherwise decode to an empty class and
// silently change what a tool is allowed to do.
func Parse(data []byte) (Manifest, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return Manifest{}, fmt.Errorf("%w: trailing content after the manifest object", ErrInvalidManifest)
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// LoadFile reads and validates a manifest from disk.
func LoadFile(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	return Parse(data)
}

// Providers lists the declared providers, sorted.
func (m Manifest) Providers() []string {
	out := make([]string, 0, len(m.Connectors))
	for _, c := range m.Connectors {
		out = append(out, c.Provider)
	}
	sort.Strings(out)
	return out
}

// Validate checks every rule a manifest must satisfy before it can be used as
// an authorization input.
func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("%w: unsupported version %d (this build understands %d)",
			ErrInvalidManifest, m.Version, ManifestVersion)
	}
	if len(m.Connectors) == 0 {
		return fmt.Errorf("%w: no connectors declared", ErrInvalidManifest)
	}
	seen := make(map[string]bool, len(m.Connectors))
	for i, c := range m.Connectors {
		if err := c.validate(); err != nil {
			return err
		}
		if seen[c.Provider] {
			return fmt.Errorf("%w: connector %d: duplicate provider %q", ErrInvalidManifest, i, c.Provider)
		}
		seen[c.Provider] = true
	}
	return nil
}

func (c Connector) validate() error {
	if !identRe.MatchString(c.Provider) {
		return fmt.Errorf("%w: provider %q is not a valid identifier", ErrInvalidManifest, c.Provider)
	}
	if !identRe.MatchString(c.CredentialRef) {
		return fmt.Errorf("%w: connector %q: credential_ref %q is not a valid secret reference",
			ErrInvalidManifest, c.Provider, c.CredentialRef)
	}
	if err := c.Credential.validate(c.Provider); err != nil {
		return err
	}
	if err := c.Server.validate(c.Provider); err != nil {
		return err
	}
	if len(c.Tools) == 0 && len(c.Excluded) == 0 {
		return fmt.Errorf("%w: connector %q declares no tools", ErrInvalidManifest, c.Provider)
	}

	classified := make(map[string]string, len(c.Tools)+len(c.Excluded))
	for _, t := range c.Tools {
		if err := t.validate(c.Provider); err != nil {
			return err
		}
		if where, dup := classified[t.Tool]; dup {
			return fmt.Errorf("%w: connector %q: tool %q declared twice (already %s)",
				ErrInvalidManifest, c.Provider, t.Tool, where)
		}
		classified[t.Tool] = "mapped"
	}
	for _, e := range c.Excluded {
		if strings.TrimSpace(e.Tool) == "" {
			return fmt.Errorf("%w: connector %q: excluded tool with empty name", ErrInvalidManifest, c.Provider)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("%w: connector %q: excluded tool %q needs a reason",
				ErrInvalidManifest, c.Provider, e.Tool)
		}
		if where, dup := classified[e.Tool]; dup {
			return fmt.Errorf("%w: connector %q: tool %q declared twice (already %s)",
				ErrInvalidManifest, c.Provider, e.Tool, where)
		}
		classified[e.Tool] = "excluded"
	}

	if len(c.ToolInventory) == 0 {
		return nil
	}

	// The gateway's tool list is known: registration must account for all of it,
	// and must not classify tools the gateway does not expose (a stale mapping
	// hides the fact that a tool moved or was renamed).
	inventory := make(map[string]bool, len(c.ToolInventory))
	var unclassified []string
	for _, tool := range c.ToolInventory {
		if strings.TrimSpace(tool) == "" {
			return fmt.Errorf("%w: connector %q: empty tool name in tool_inventory", ErrInvalidManifest, c.Provider)
		}
		if inventory[tool] {
			return fmt.Errorf("%w: connector %q: tool %q listed twice in tool_inventory",
				ErrInvalidManifest, c.Provider, tool)
		}
		inventory[tool] = true
		if _, ok := classified[tool]; !ok {
			unclassified = append(unclassified, tool)
		}
	}
	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		return fmt.Errorf("%w: connector %q: %d tool(s) in the gateway inventory are neither mapped nor excluded: %s",
			ErrIncompleteRegistration, c.Provider, len(unclassified), strings.Join(unclassified, ", "))
	}
	var phantom []string
	for tool := range classified {
		if !inventory[tool] {
			phantom = append(phantom, tool)
		}
	}
	if len(phantom) > 0 {
		sort.Strings(phantom)
		return fmt.Errorf("%w: connector %q: %d classified tool(s) are absent from the gateway inventory: %s",
			ErrInvalidManifest, c.Provider, len(phantom), strings.Join(phantom, ", "))
	}
	return nil
}

func (t ToolMapping) validate(provider string) error {
	if strings.TrimSpace(t.Tool) == "" {
		return fmt.Errorf("%w: connector %q: tool mapping with empty name", ErrInvalidManifest, provider)
	}
	if _, ok := defaultCapability[t.ActionClass]; !ok {
		return fmt.Errorf("%w: connector %q: tool %q has action_class %q (want read, write, send or delete)",
			ErrInvalidManifest, provider, t.Tool, t.ActionClass)
	}
	if t.Capability != "" && !knownCapabilities[t.Capability] {
		return fmt.Errorf("%w: connector %q: tool %q requires unknown capability %q",
			ErrInvalidManifest, provider, t.Tool, t.Capability)
	}
	if t.ArtifactID != nil {
		if err := t.ArtifactID.validate(provider, t.Tool); err != nil {
			return err
		}
	}
	return nil
}

// RequiredCapability is the capability a grant must carry to invoke the tool.
func (t ToolMapping) RequiredCapability() policy.Capability {
	if t.Capability != "" {
		return t.Capability
	}
	return defaultCapability[t.ActionClass]
}

func (e Extractor) validate(provider, tool string) error {
	if e.Source != FromRequest && e.Source != FromResponse {
		return fmt.Errorf("%w: connector %q: tool %q artifact_id source %q (want request or response)",
			ErrInvalidManifest, provider, tool, e.Source)
	}
	if _, err := parsePointer(e.Pointer); err != nil {
		return fmt.Errorf("%w: connector %q: tool %q artifact_id pointer: %v",
			ErrInvalidManifest, provider, tool, err)
	}
	return nil
}

func (ca CredentialAcquisition) validate(provider string) error {
	spec, ok := driverSpecs[ca.Driver]
	if !ok {
		return fmt.Errorf("%w: connector %q: driver %q (this build ships: %s)",
			ErrUnknownDriver, provider, ca.Driver, strings.Join(KnownDrivers(), ", "))
	}
	allowed := make(map[string]bool, len(spec.required)+len(spec.optional))
	for _, k := range spec.required {
		allowed[k] = true
	}
	for _, k := range spec.optional {
		allowed[k] = true
	}
	for k, v := range ca.Params {
		if !allowed[k] {
			return fmt.Errorf("%w: connector %q: driver %q has no parameter %q",
				ErrInvalidManifest, provider, ca.Driver, k)
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: connector %q: driver parameter %q is empty",
				ErrInvalidManifest, provider, k)
		}
	}
	for _, k := range spec.required {
		if strings.TrimSpace(ca.Params[k]) == "" {
			return fmt.Errorf("%w: connector %q: driver %q requires parameter %q",
				ErrInvalidManifest, provider, ca.Driver, k)
		}
	}
	// Endpoints must be https URLs, and *_ref parameters must be references
	// into the secret store rather than inline credential material — the
	// manifest is a git-tracked file and must be structurally incapable of
	// holding a client secret.
	for k, v := range ca.Params {
		switch {
		case strings.HasSuffix(k, "_endpoint"):
			u, err := url.Parse(v)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("%w: connector %q: parameter %q must be an https URL, got %q",
					ErrInvalidManifest, provider, k, v)
			}
		case strings.HasSuffix(k, "_ref"):
			if !identRe.MatchString(v) {
				return fmt.Errorf("%w: connector %q: parameter %q must be a secret reference, not a literal value",
					ErrInvalidManifest, provider, k)
			}
		}
	}
	if spec.needScopes && len(ca.Scopes) == 0 {
		return fmt.Errorf("%w: connector %q: driver %q requires at least one scope",
			ErrInvalidManifest, provider, ca.Driver)
	}
	for _, s := range ca.Scopes {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%w: connector %q: empty scope", ErrInvalidManifest, provider)
		}
	}
	return nil
}

func (s MCPServer) validate(provider string) error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: connector %q: mcp_server.name is required", ErrInvalidManifest, provider)
	}
	switch s.Transport {
	case "stdio", "streamable-http", "sse":
	default:
		return fmt.Errorf("%w: connector %q: mcp_server.transport %q (want stdio, streamable-http or sse)",
			ErrInvalidManifest, provider, s.Transport)
	}
	if strings.TrimSpace(s.Source) == "" {
		return fmt.Errorf("%w: connector %q: mcp_server.source is required", ErrInvalidManifest, provider)
	}
	return nil
}
