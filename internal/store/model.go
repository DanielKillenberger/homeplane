// Package store owns Homeplane's server-local persistence: the machine
// enrolment registry, the grant registry, the append-only audit log, and the
// encrypted-secret store (D3: Homeplane-owned SQLite, provider secrets
// encrypted at rest with age before they ever reach this layer).
//
// Custody rule enforced here: this package never sees plaintext credentials.
// Machine and grant credentials arrive already hashed; provider secrets arrive
// already age-encrypted. Audit rows are metadata only — see AuditEvent.
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
	"bound_machine_id":       true,
	"secret_ref":             true,
	"secret_generation":      true,
	"credential_version":     true,
	"source":                 true,
	"since":                  true,
	"limit":                  true,
	"path":                   true,
	"method":                 true,
	"http_status":            true,
	"observed_addr":          true,
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
