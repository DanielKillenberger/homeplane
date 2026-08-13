// Package store owns Homeplane's server-local persistence: the machine
// enrolment registry, the grant registry, the append-only audit log, and the
// encrypted-secret store (D3: Homeplane-owned SQLite, provider secrets
// encrypted at rest with age before they ever reach this layer).
//
// Two rules are enforced structurally rather than by convention:
//
//   - Custody: this package never sees plaintext credentials. Machine and grant
//     credentials arrive already hashed; provider secrets arrive already
//     age-encrypted. Audit rows are metadata only — see AuditEvent.
//   - Audit atomicity: every lifecycle mutation (enrolment, grant issuance and
//     supersession, revocation, secret replacement) takes an audit callback and
//     writes those events in the SAME transaction as the mutation. There is no
//     API through which a grant can be revoked without the record of it, and a
//     failed audit write rolls the mutation back rather than being logged and
//     shrugged off.
package store

import (
	"errors"
	"time"
)

// ErrNotFound is returned when a lookup has no matching row.
var ErrNotFound = errors.New("store: not found")

// Identity is a tailnet-observed caller identity, resolved via WhoIs. NodeID is
// the stable, rename-proof node identifier and is the authoritative binding for
// a machine record; NodeName is human-facing and MUST NOT be used for
// authorization decisions.
type Identity struct {
	NodeID   string
	NodeName string
	UserID   string
}

// Machine is an enrolled device. Exactly one record exists per tailnet NodeID:
// re-enrolment rotates CredentialHash in place (identity-preserving rotation,
// never a duplicate record).
type Machine struct {
	ID                string
	Name              string
	OS                string
	NodeID            string
	NodeName          string
	CredentialHash    string
	CredentialVersion int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// GrantState is the lifecycle state of a Grant.
type GrantState string

const (
	GrantActive  GrantState = "active"
	GrantRevoked GrantState = "revoked"
)

// Grant is a (machine, harness) capability grant carrying its own revocable
// token. At most one grant per (machine, harness) is ever in GrantActive state;
// issuing a new one supersedes the prior one atomically.
type Grant struct {
	ID            string
	MachineID     string
	Harness       string
	Capabilities  []string
	State         GrantState
	TokenHash     string
	CreatedAt     time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

// ActorKind distinguishes who caused an audited event. Network calls are
// ActorMachine, server-local admin CLI events are ActorOperator (there is no
// observed machine — no network caller), and lifecycle side effects such as
// supersession are ActorSystem.
type ActorKind string

const (
	ActorMachine  ActorKind = "machine"
	ActorOperator ActorKind = "operator"
	ActorSystem   ActorKind = "system"
)

// Outcome is whether the audited call was permitted.
type Outcome string

const (
	OutcomeAllowed Outcome = "allowed"
	OutcomeDenied  Outcome = "denied"
)

// Audit event names recorded by the control plane. Connector tool-call events
// are appended by the edge (task .16) using the same schema.
const (
	EventEnrolment          = "enrolment"
	EventCredentialRotation = "credential_rotation"
	EventGrantIssued        = "grant_issued"
	EventGrantSuperseded    = "grant_superseded"
	EventGrantRevoked       = "grant_revoked"
	EventAuthDenied         = "auth_denied"
	EventSecretImported     = "secret_imported"
	EventAuditQueried       = "audit_queried"

	// Credential-broker events (R13). A flow's whole life is on the record:
	// started, and exactly one terminal event. EventCredentialFlowCommitted is
	// written in the SAME transaction as the credential swap, so a provider
	// credential cannot appear in the store without the record of which machine
	// brokered it. Terminal failures are recorded with their safe error_code as
	// Reason — never with a provider response body, which the schema could not
	// hold anyway.
	EventCredentialFlowStarted   = "credential_flow_started"
	EventCredentialFlowCommitted = "credential_flow_committed"
	EventCredentialFlowFailed    = "credential_flow_failed"

	// Connector-plane events, written by the manifest-driven policy/audit
	// engine (task .3) and by the edge that hosts it (task .16).
	//
	// EventConnectorToolCall is the AUTHORITATIVE record of an admitted call and
	// is written BEFORE the tool runs; EventConnectorToolResult records how that
	// call ended (and the artifact id, when only the response reveals it).
	EventConnectorToolCall   = "connector_tool_call"
	EventConnectorToolResult = "connector_tool_result"
	// EventConnectorDenied records a well-formed call refused on authority —
	// the grant lacked the capability the tool's action class requires.
	EventConnectorDenied = "connector_denied"
	// EventPolicyViolation records a call refused by the manifest itself:
	// unknown connector, or a tool that is unmapped or explicitly excluded.
	EventPolicyViolation = "policy_violation"
)

// AuditEvent is an append-only record. It is deliberately METADATA ONLY: there
// is no field (and no column) capable of holding a request or response payload
// body. Attribution splits observed identity (ObservedNodeID/ObservedNodeName,
// derived from WhoIs — what the network saw) from authenticated identity
// (AuthMachineID, Harness, GrantID — what the presented credential proved).
// Rejected calls carry TokenFingerprint plus Reason INSTEAD of authenticated
// identity, so a bad token is never misattributed to its owner.
//
// Detail carries bounded, allow-listed metadata key/value pairs only; see
// ValidateDetail.
type AuditEvent struct {
	ID    int64
	TS    time.Time
	Event string

	ActorKind ActorKind

	// Observed (WhoIs-derived) identity of the network caller, if any.
	ObservedNodeID   string
	ObservedNodeName string

	// Authenticated identity, populated only once a credential verified.
	AuthMachineID string
	Harness       string
	GrantID       string

	// Connector-call attribution (unused by the control plane, written by the
	// edge for tool calls).
	ActionClass string
	Tool        string
	ArtifactID  string

	Outcome          Outcome
	Reason           string
	TokenFingerprint string

	Detail map[string]string
}

// AuditQuery bounds an audit read.
type AuditQuery struct {
	Since time.Time
	Limit int
}

// allowedDetailKeys is the closed vocabulary permitted in AuditEvent.Detail.
// The allowlist is what structurally keeps payload bodies out of the log: an
// event cannot smuggle document contents through a free-form key.
var allowedDetailKeys = map[string]bool{
	"machine_name":           true,
	"os":                     true,
	"capabilities":           true,
	"requested_capabilities": true,
	"superseded_grant_id":    true,
	"superseded_by_grant_id": true,
	"target_machine_id":      true,
	"bound_machine_id":       true,
	"secret_ref":             true,
	"secret_generation":      true,
	// Credential-broker metadata. flow_id correlates a flow's start with its
	// terminal row; note that no key here can carry a provider response.
	"flow_id": true,
	"credential_version":     true,
	"source":                 true,
	"since":                  true,
	"limit":                  true,
	"path":                   true,
	"method":                 true,
	"http_status":            true,
	"observed_addr":          true,

	// Connector-plane metadata. Note what is NOT here and cannot be added by a
	// connector: any key capable of carrying request or response content.
	// "args_digest" is a one-way hash of the request arguments precisely so the
	// arguments themselves never need a home in this vocabulary.
	"provider":            true,
	"args_digest":         true,
	"call_id":             true,
	"required_capability": true,
	"exclusion_reason":    true,
}

// MaxDetailValueLen bounds any single Detail value. Combined with the key
// allowlist this makes the log structurally incapable of holding a body.
const MaxDetailValueLen = 256

// AllowedDetailKeys returns a copy of the permitted Detail key vocabulary.
func AllowedDetailKeys() []string {
	out := make([]string, 0, len(allowedDetailKeys))
	for k := range allowedDetailKeys {
		out = append(out, k)
	}
	return out
}

// ValidateDetail rejects any Detail map that is not bounded metadata.
func ValidateDetail(detail map[string]string) error {
	for k, v := range detail {
		if !allowedDetailKeys[k] {
			return errors.New("store: audit detail key not allowed: " + k)
		}
		if len(v) > MaxDetailValueLen {
			return errors.New("store: audit detail value too long for key: " + k)
		}
	}
	return nil
}

// Secret is an age-encrypted provider credential held server-side. Ciphertext
// is opaque to this package; Generation increments on every replacement and is
// the compare-and-swap token for R13's atomic credential replacement.
type Secret struct {
	Ref        string
	Ciphertext []byte
	Generation int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// SecretMeta describes a stored secret WITHOUT carrying its ciphertext, let
// alone its value. It exists so an operator (or a deployment check) can ask
// "which credentials does this server currently hold, and are they really
// encrypted?" — a question that must be answerable without a code path capable
// of returning the secret itself.
//
// CiphertextBytes is the stored length, and Encrypted reports whether those
// bytes are an age message. A row that is somehow NOT age-encrypted is the one
// thing worth screaming about here, and it is exactly what a length alone would
// hide.
type SecretMeta struct {
	Ref             string    `json:"ref"`
	Generation      int64     `json:"generation"`
	CiphertextBytes int       `json:"ciphertext_bytes"`
	Encrypted       bool      `json:"encrypted"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
