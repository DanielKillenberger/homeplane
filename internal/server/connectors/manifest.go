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
	"bytes"
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

// classCapability is the capability each action class requires. A mapping may
// restate its capability explicitly (self-documenting manifests are welcome),
// but it may never name a DIFFERENT one: a `capability` field that could
// diverge from the action class is an authority downgrade waiting to happen —
// declare a delete tool as requiring connector.read and a read-only grant
// deletes. There is no dominance ordering between these capabilities to make
// "stronger" meaningful, so divergence is simply refused at load time.
var classCapability = map[ActionClass]policy.Capability{
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
	// Delivery declares the FORMAT the connector's MCP server expects its
	// credential in, so a stored credential can be handed to a workload without
	// any provider-specific code on the delivery path. Absent means the
	// connector is given no credential at all.
	Delivery *CredentialDelivery `json:"credential_delivery,omitempty"`
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

// CredentialDelivery names the on-disk shape a connector's MCP server reads its
// provider credential in.
//
// It is a NAMED FORMAT, not a template: the manifest says which of the formats
// this build knows how to write, and nothing about where the credential comes
// from or what is in it. Two connectors whose servers read the same shape share
// one format, so the second is a manifest entry (R12); a connector needing a
// genuinely new shape is the only case that adds code, and it adds it in one
// place instead of on the credential path.
//
// The DESTINATION is deliberately absent: which directory a workload mounts is
// a deployment fact, supplied by whoever starts the workload, not something a
// git-tracked manifest should pin.
type CredentialDelivery struct {
	Format string `json:"format"`
}

// FormatGoogleOAuthUserFile is the credential shape the pinned Google connector
// (workspace-mcp) reads: one JSON file per Google account in its credentials
// directory, carrying the OAuth tokens plus the client identity needed to
// refresh them.
const FormatGoogleOAuthUserFile = "google-oauth-user-file"

// knownDeliveryFormats is the vocabulary a manifest may name. An unknown format
// is refused at load time rather than discovered when a workload starts with no
// credential and reports something unrelated.
var knownDeliveryFormats = map[string]bool{
	FormatGoogleOAuthUserFile: true,
}

// KnownDeliveryFormats lists the credential shapes this build can write, sorted.
func KnownDeliveryFormats() []string {
	out := make([]string, 0, len(knownDeliveryFormats))
	for f := range knownDeliveryFormats {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

func (d CredentialDelivery) validate(provider string) error {
	if !knownDeliveryFormats[d.Format] {
		return fmt.Errorf("%w: connector %q: credential_delivery format %q (this build writes: %s)",
			ErrInvalidManifest, provider, d.Format, strings.Join(KnownDeliveryFormats(), ", "))
	}
	return nil
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
//
// A mapping declares its action class in exactly one of two ways: a fixed
// `action_class`, or — for a POLYMORPHIC tool, whose effect depends on an
// argument — an `action_selector` that reads that argument. Exactly one of the
// two, never both and never neither.
type ToolMapping struct {
	Tool string `json:"tool"`
	// ActionClass is the tool's fixed class. Empty only when ActionSelector is
	// declared instead.
	ActionClass ActionClass `json:"action_class,omitempty"`
	// ActionSelector declares that this tool's class is chosen per call by a
	// request argument (see ActionSelector).
	ActionSelector *ActionSelector `json:"action_selector,omitempty"`
	// Capability is the grant capability required to invoke the tool. Empty
	// means "the default for this action class". It may not be declared
	// alongside an ActionSelector, where the class — and therefore the
	// capability — is not fixed.
	Capability policy.Capability `json:"capability,omitempty"`
	// ArtifactID optionally declares where the affected artifact's identity can
	// be read. Absent means the audit row records a digest of the request
	// arguments and artifact id `unknown`.
	//
	// It accepts one extractor or an ordered list of candidates, first match
	// wins. A list is what a multi-action tool needs: `manage_event` carries the
	// event id in its REQUEST when updating or deleting one, and only in its
	// RESPONSE when it just created one — a single extractor would have to leave
	// one of those unidentified.
	ArtifactID ArtifactExtractors `json:"artifact_id,omitempty"`
	// Guards declare capabilities a call needs IN ADDITION to its action
	// class's, based on what its arguments ask the tool to do (see
	// ArgumentGuard).
	Guards []ArgumentGuard `json:"capability_guards,omitempty"`
}

// ArgumentGuard requires an EXTRA capability when a request argument shows the
// call will do something its action class does not describe.
//
// The case that forced it is real and was missed by the action class alone: the
// pinned Google connector's `manage_event` takes a `send_updates` argument that
// defaults to "all", so creating, updating or deleting an event with attendees
// emails every one of them. That is send authority — reaching third parties —
// arriving through a tool classified `write` or `delete`. Without a guard, a
// grant holding only connector.write can notify a room full of people, and the
// audit row would call it a write.
//
// Two properties make this safe to express declaratively:
//
//   - A guard can only ever ADD a requirement. There is no form that removes or
//     lowers one, so no manifest edit can weaken a call through this field.
//   - It fires on doubt. The argument being absent, non-scalar, or carrying an
//     unlisted value all mean the guard applies — which is the direction that
//     matters, because the connector's DEFAULT (send to everyone) is exactly
//     the omitted case.
type ArgumentGuard struct {
	// Pointer addresses the request argument that decides, in the same
	// JSONPath-style subset extractors use (`$.send_updates`).
	Pointer string `json:"pointer"`
	// UnlessIn lists the values that make the guard NOT apply — the safe
	// values. Anything else, including nothing at all, requires the capability.
	UnlessIn []string `json:"unless_in"`
	// Capability is what the call additionally requires when the guard fires.
	Capability policy.Capability `json:"capability"`
	// Reason explains the authority in operator terms. It is shown to a caller
	// whose call is refused, so a denial says what the call was actually asking
	// for rather than only which capability was missing.
	Reason string `json:"reason"`
}

// Applies reports whether the guard's extra capability is required for a call
// carrying these arguments. It is total: anything it cannot read safely means
// the guard applies.
func (g ArgumentGuard) Applies(args json.RawMessage) bool {
	value, ok := Extract(Extractor{Source: FromRequest, Pointer: g.Pointer}, args)
	if !ok {
		return true
	}
	for _, safe := range g.UnlessIn {
		if value == safe {
			return false
		}
	}
	return true
}

func (g ArgumentGuard) validate(provider, tool string) error {
	if _, err := parsePointer(g.Pointer); err != nil {
		return fmt.Errorf("%w: connector %q: tool %q capability_guard pointer: %v",
			ErrInvalidManifest, provider, tool, err)
	}
	if !knownCapabilities[g.Capability] {
		return fmt.Errorf("%w: connector %q: tool %q capability_guard requires unknown capability %q",
			ErrInvalidManifest, provider, tool, g.Capability)
	}
	// A guard with no safe values can never be satisfied, which is an exclusion
	// written in the wrong place: say so with `excluded_tools`, where the reason
	// is recorded and the denial is audited as the deliberate exclusion it is.
	if len(g.UnlessIn) == 0 {
		return fmt.Errorf("%w: connector %q: tool %q capability_guard lists no safe values; "+
			"exclude the tool instead", ErrInvalidManifest, provider, tool)
	}
	for _, v := range g.UnlessIn {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: connector %q: tool %q capability_guard has an empty safe value",
				ErrInvalidManifest, provider, tool)
		}
		if len(v) > MaxIdentifierLen {
			return fmt.Errorf("%w: connector %q: tool %q capability_guard safe value is %d bytes, the limit is %d",
				ErrInvalidManifest, provider, tool, len(v), MaxIdentifierLen)
		}
	}
	if strings.TrimSpace(g.Reason) == "" {
		return fmt.Errorf("%w: connector %q: tool %q capability_guard needs a reason",
			ErrInvalidManifest, provider, tool)
	}
	return nil
}

// ActionSelector classifies a POLYMORPHIC tool — one whose effect is chosen by
// an argument rather than by which tool was called.
//
// Real connectors ship them: the pinned Google connector's `manage_event`
// creates, updates, RSVPs to and DELETES events depending on its `action`
// argument. Collapsing such a tool onto one fixed class forces a choice between
// two wrong answers — classify it `delete` and a read/write grant cannot create
// an event, classify it `write` and a deletion is audited (and authorized) as
// a write. Neither is acceptable when the action class is simultaneously the
// authorization input and the audit record.
//
// Resolution is deliberately total and fail-closed: a call whose discriminator
// is missing, non-scalar, or not one of the declared cases resolves to NO class
// and is denied `unresolved_action` as a policy violation. There is no default
// case and no fallback class, because either would mean the manifest silently
// guessing what an unrecognized action does.
type ActionSelector struct {
	// Pointer addresses the discriminating REQUEST argument, in the same
	// JSONPath-style subset extractors use (`$.action`).
	Pointer string `json:"pointer"`
	// Cases maps each recognized discriminator value to its action class. Every
	// value the tool accepts must be listed; anything else is refused.
	Cases map[string]ActionClass `json:"cases"`
}

// ExtractorSource says which JSON document an extractor reads.
type ExtractorSource string

const (
	// FromRequest reads the tool's request arguments.
	FromRequest ExtractorSource = "request"
	// FromResponse reads the tool's response (e.g. the id of a created event).
	FromResponse ExtractorSource = "response"
)

// Extractor is a JSONPath-style pointer at a scalar identity field, optionally
// refined by a step pipeline.
// Supported pointer syntax: `$.a.b`, `$.a[0].b`, `$.a` — object keys and array
// indices.
type Extractor struct {
	Source  ExtractorSource `json:"source"`
	Pointer string          `json:"pointer"`
	// Steps refine the text the pointer resolved into the identity inside it.
	//
	// They exist because a real MCP tool does not always answer in fields: an
	// MCP result is `{"content":[{"type":"text","text":"..."}]}`, and a provider
	// that reports "Successfully created event ... Link: ...?eid=<base64>" has
	// put the id in prose. Steps stay DECLARATIVE (a pattern and a decoding, in
	// the manifest) so identifying an artifact never becomes connector-specific
	// code in the audit path, and stay fail-closed: a step that matches nothing
	// yields `unknown`, never a guess.
	Steps []ExtractStep `json:"steps,omitempty"`
}

// Decodings a step may apply.
const (
	// DecodeBase64 decodes the step's input (standard or URL alphabet, padded
	// or not). It is how an id embedded in a provider's link is reached.
	DecodeBase64 = "base64"
)

// ExtractStep is one refinement. Exactly one of Match and Decode is set.
type ExtractStep struct {
	// Match is an RE2 pattern with exactly one capture group; the group is the
	// step's output.
	Match string `json:"match,omitempty"`
	// Decode names a decoding applied to the whole input.
	Decode string `json:"decode,omitempty"`
}

// ArtifactExtractors is an ordered candidate list. It accepts either a single
// extractor object or an array of them in the manifest, because a tool with one
// identity source should not have to be written as a one-element list.
type ArtifactExtractors []Extractor

func (a *ArtifactExtractors) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []Extractor
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return err
		}
		*a = list
		return nil
	}
	var one Extractor
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return err
	}
	*a = ArtifactExtractors{one}
	return nil
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

// toolNameRe is the shape a tool name may take. Tool names originate OUTSIDE
// Homeplane — the gateway advertises them and a caller names one on every
// invocation — so they are bounded and character-restricted before they are
// allowed anywhere near a manifest or an audit row.
var toolNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// MaxIdentifierLen bounds every identifier this package accepts or records:
// provider names, credential refs and tool names. It exists because an audit
// row must stay a bounded metadata record even when the name in the request was
// chosen by whoever sent the request.
const MaxIdentifierLen = 128

func validateIdentifier(kind, value string) error {
	if len(value) > MaxIdentifierLen {
		return fmt.Errorf("%w: %s is %d bytes, the limit is %d",
			ErrInvalidManifest, kind, len(value), MaxIdentifierLen)
	}
	if !identRe.MatchString(value) {
		return fmt.Errorf("%w: %s %q is not a valid identifier", ErrInvalidManifest, kind, value)
	}
	return nil
}

func validateToolName(provider, tool string) error {
	if strings.TrimSpace(tool) == "" {
		return fmt.Errorf("%w: connector %q: tool with an empty name", ErrInvalidManifest, provider)
	}
	if len(tool) > MaxIdentifierLen {
		return fmt.Errorf("%w: connector %q: tool name is %d bytes, the limit is %d",
			ErrInvalidManifest, provider, len(tool), MaxIdentifierLen)
	}
	if !toolNameRe.MatchString(tool) {
		return fmt.Errorf("%w: connector %q: tool name %q contains characters that are not allowed",
			ErrInvalidManifest, provider, tool)
	}
	return nil
}

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
	if err := validateIdentifier("provider", c.Provider); err != nil {
		return err
	}
	if err := validateIdentifier("credential_ref", c.CredentialRef); err != nil {
		return fmt.Errorf("%w (connector %q)", err, c.Provider)
	}
	if err := c.Credential.validate(c.Provider); err != nil {
		return err
	}
	if err := c.Server.validate(c.Provider); err != nil {
		return err
	}
	if c.Delivery != nil {
		if err := c.Delivery.validate(c.Provider); err != nil {
			return err
		}
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
		if err := validateToolName(c.Provider, e.Tool); err != nil {
			return err
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
		if err := validateToolName(c.Provider, tool); err != nil {
			return err
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
	if err := validateToolName(provider, t.Tool); err != nil {
		return err
	}
	for _, g := range t.Guards {
		if err := g.validate(provider, t.Tool); err != nil {
			return err
		}
	}
	if t.ActionSelector != nil {
		return t.validateSelector(provider)
	}
	want, ok := classCapability[t.ActionClass]
	if !ok {
		return fmt.Errorf("%w: connector %q: tool %q has action_class %q (want read, write, send or delete)",
			ErrInvalidManifest, provider, t.Tool, t.ActionClass)
	}
	if t.Capability != "" && !knownCapabilities[t.Capability] {
		return fmt.Errorf("%w: connector %q: tool %q requires unknown capability %q",
			ErrInvalidManifest, provider, t.Tool, t.Capability)
	}
	// The capability a tool requires is a FUNCTION of its action class, never an
	// independent knob. A mapping that could name a weaker capability than its
	// class would hand a read-only grant delete authority through a manifest
	// edit — exactly the authorization bypass the manifest exists to prevent.
	if t.Capability != "" && t.Capability != want {
		return fmt.Errorf("%w: connector %q: tool %q is %s-class and must require %q, not %q",
			ErrInvalidManifest, provider, t.Tool, t.ActionClass, want, t.Capability)
	}
	for _, ex := range t.ArtifactID {
		if err := ex.validate(provider, t.Tool); err != nil {
			return err
		}
	}
	return nil
}

// validateSelector checks a polymorphic mapping. The rules mirror the fixed
// case: every declared class must be one this build authorizes, and the
// capability may not be restated independently — here it cannot be restated at
// all, because there is no single class to restate it for.
func (t ToolMapping) validateSelector(provider string) error {
	if t.ActionClass != "" {
		return fmt.Errorf("%w: connector %q: tool %q declares both action_class and action_selector",
			ErrInvalidManifest, provider, t.Tool)
	}
	if t.Capability != "" {
		return fmt.Errorf("%w: connector %q: tool %q is selector-classified, so its capability follows the "+
			"resolved action class and may not be declared", ErrInvalidManifest, provider, t.Tool)
	}
	if _, err := parsePointer(t.ActionSelector.Pointer); err != nil {
		return fmt.Errorf("%w: connector %q: tool %q action_selector pointer: %v",
			ErrInvalidManifest, provider, t.Tool, err)
	}
	if len(t.ActionSelector.Cases) == 0 {
		return fmt.Errorf("%w: connector %q: tool %q action_selector declares no cases",
			ErrInvalidManifest, provider, t.Tool)
	}
	for value, class := range t.ActionSelector.Cases {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: connector %q: tool %q action_selector has an empty case value",
				ErrInvalidManifest, provider, t.Tool)
		}
		if len(value) > MaxIdentifierLen {
			return fmt.Errorf("%w: connector %q: tool %q action_selector case %d bytes, the limit is %d",
				ErrInvalidManifest, provider, t.Tool, len(value), MaxIdentifierLen)
		}
		if _, ok := classCapability[class]; !ok {
			return fmt.Errorf("%w: connector %q: tool %q action_selector case %q has action class %q "+
				"(want read, write, send or delete)", ErrInvalidManifest, provider, t.Tool, value, class)
		}
	}
	return nil
}

// RequiredCapability is the capability a grant must carry to invoke the tool.
// It is derived from the action class; a manifest may restate it but cannot
// change it (see validate). A selector-classified tool has no single required
// capability, so this reports none — the capability follows the class resolved
// per call by ResolveActionClass.
func (t ToolMapping) RequiredCapability() policy.Capability {
	return classCapability[t.ActionClass]
}

// ResolveActionClass reports the action class one CALL of this tool belongs to,
// and whether it could be established at all.
//
// For a fixed mapping the answer is the declared class. For a selector-mapped
// tool the discriminating argument decides, and an argument that is absent,
// non-scalar or unrecognized resolves to nothing: the caller (the engine) then
// denies the call rather than assuming a class.
func (t ToolMapping) ResolveActionClass(args json.RawMessage) (ActionClass, bool) {
	if t.ActionSelector == nil {
		_, ok := classCapability[t.ActionClass]
		return t.ActionClass, ok
	}
	value, ok := Extract(Extractor{Source: FromRequest, Pointer: t.ActionSelector.Pointer}, args)
	if !ok {
		return "", false
	}
	class, ok := t.ActionSelector.Cases[value]
	if !ok {
		return "", false
	}
	return class, true
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
	// A step that does nothing, or two steps in one, would make the pipeline's
	// behaviour depend on evaluation order rather than on what the manifest
	// says. Registration refuses both rather than resolving them at call time.
	for i, st := range e.Steps {
		switch {
		case st.Match == "" && st.Decode == "":
			return fmt.Errorf("%w: connector %q: tool %q artifact_id step %d declares neither match nor decode",
				ErrInvalidManifest, provider, tool, i)
		case st.Match != "" && st.Decode != "":
			return fmt.Errorf("%w: connector %q: tool %q artifact_id step %d declares both match and decode",
				ErrInvalidManifest, provider, tool, i)
		case st.Decode != "" && st.Decode != DecodeBase64:
			return fmt.Errorf("%w: connector %q: tool %q artifact_id step %d decode %q (want %q)",
				ErrInvalidManifest, provider, tool, i, st.Decode, DecodeBase64)
		case st.Match != "":
			re, err := compilePattern(st.Match)
			if err != nil {
				return fmt.Errorf("%w: connector %q: tool %q artifact_id step %d match: %v",
					ErrInvalidManifest, provider, tool, i, err)
			}
			// Exactly one group: zero has nothing to extract, and more than one
			// means the manifest is ambiguous about which is the identity.
			if n := re.NumSubexp(); n != 1 {
				return fmt.Errorf("%w: connector %q: tool %q artifact_id step %d match has %d capture groups (want exactly 1)",
					ErrInvalidManifest, provider, tool, i, n)
			}
		}
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
