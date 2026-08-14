package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/DanielKillenberger/homeplane/internal/secrets"
)

// schema is the full DDL applied at Open. All statements are idempotent
// (IF NOT EXISTS) so Open is safe on an existing database.
const schema = `
CREATE TABLE IF NOT EXISTS machines (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	os TEXT NOT NULL,
	node_id TEXT NOT NULL UNIQUE,
	node_name TEXT NOT NULL,
	credential_hash TEXT NOT NULL,
	credential_version INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
	id TEXT PRIMARY KEY,
	machine_id TEXT NOT NULL REFERENCES machines(id),
	harness TEXT NOT NULL,
	capabilities TEXT NOT NULL,
	state TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL,
	revoked_at TEXT,
	revoked_reason TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS grants_one_active
	ON grants(machine_id, harness) WHERE state = 'active';

CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts TEXT NOT NULL,
	event TEXT NOT NULL,
	actor_kind TEXT NOT NULL,
	observed_node_id TEXT NOT NULL DEFAULT '',
	observed_node_name TEXT NOT NULL DEFAULT '',
	auth_machine_id TEXT NOT NULL DEFAULT '',
	harness TEXT NOT NULL DEFAULT '',
	grant_id TEXT NOT NULL DEFAULT '',
	action_class TEXT NOT NULL DEFAULT '',
	tool TEXT NOT NULL DEFAULT '',
	artifact_id TEXT NOT NULL DEFAULT '',
	outcome TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	token_fingerprint TEXT NOT NULL DEFAULT '',
	detail TEXT
);

CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events(ts);

CREATE TABLE IF NOT EXISTS secrets (
	ref TEXT PRIMARY KEY,
	ciphertext BLOB NOT NULL,
	generation INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
`

// SQLite is the Homeplane server-local persistence backend.
type SQLite struct {
	db *sql.DB
}

// dsnPragmas are applied per CONNECTION by the driver. They must ride the DSN
// rather than a one-off `PRAGMA` Exec: `database/sql` pools connections, so an
// Exec'd pragma would configure exactly one arbitrary connection and silently
// leave the rest with defaults (no foreign keys, no busy timeout).
const dsnPragmas = "_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

// Open opens (or creates) a SQLite database at path, applies the schema
// migration, and restricts the database file mode to 0600.
//
// The pool is capped at a single connection: this is a single-operator control
// plane with negligible concurrency, and one writer removes SQLITE_BUSY as a
// failure mode entirely. The consequence to respect when extending this
// package: never start a second query while iterating an open *sql.Rows on the
// same store, or the two will deadlock on the lone connection.
func Open(path string) (*SQLite, error) {
	// Create the database file with 0600 BEFORE SQLite opens it. SQLite derives
	// the mode of its `-wal` and `-shm` sidecars from the main database file at
	// creation time, so chmodding only after the fact leaves sidecars at the
	// umask default (typically 0644) — and those sidecars hold live machine,
	// grant, audit, and encrypted-secret pages.
	if path != "" && !strings.HasPrefix(path, ":memory:") && !strings.Contains(path, "mode=memory") {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("store: create database file: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("store: create database file: %w", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("store: chmod database: %w", err)
		}
	}

	dsn := path
	if strings.ContainsRune(dsn, '?') {
		dsn += "&" + dsnPragmas
	} else {
		dsn += "?" + dsnPragmas
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &SQLite{db: db}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	// Tighten the sidecars too: an existing database opened from an earlier,
	// looser installation would otherwise keep world-readable WAL/SHM files.
	for _, sidecar := range []string{path, path + "-wal", path + "-shm"} {
		info, statErr := os.Stat(sidecar)
		if statErr != nil || info.Mode().Perm() == 0o600 {
			continue
		}
		if err := os.Chmod(sidecar, 0o600); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: chmod %s: %w", sidecar, err)
		}
	}
	return s, nil
}

// Close releases the underlying database connection.
//
// The handle is deliberately NOT set to nil: every method must keep returning
// an error after Close, not panic. A health probe running against a
// shut-down store has to report "degraded", which is exactly the moment a nil
// dereference would take the whole server down instead.
func (s *SQLite) Close() error {
	if s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// Ping verifies the database connection is alive. A closed store reports an
// error rather than panicking (see Close).
func (s *SQLite) Ping(ctx context.Context) error {
	if s.db == nil {
		return errors.New("store: not open")
	}
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	return nil
}

// Enrol performs an identity-preserving upsert keyed on id.NodeID.
// If no machine exists for NodeID a new record is inserted (rotated=false).
// If one exists its name, os, node_name, and credential_hash are updated and
// credential_version is bumped (rotated=true). Never inserts a duplicate.
//
// audit builds the events to record for this mutation; they are written INSIDE
// the same transaction (see the package's audit-atomicity rule). It must not be
// nil — a lifecycle mutation with nothing to record is not a case this control
// plane has.
func (s *SQLite) Enrol(ctx context.Context, id Identity, name, osName, credentialHash string, audit func(m Machine, rotated bool) []AuditEvent) (Machine, bool, error) {
	if audit == nil {
		return Machine{}, false, errAuditCallbackRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, false, fmt.Errorf("store: enrol begin: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	nowStr := formatTime(now)

	var m Machine
	err = scanMachine(tx.QueryRowContext(ctx, `
		SELECT id, name, os, node_id, node_name, credential_hash, credential_version, created_at, updated_at
		FROM machines WHERE node_id = ?`, id.NodeID), &m)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Machine{}, false, fmt.Errorf("store: enrol lookup: %w", err)
	}

	if errors.Is(err, ErrNotFound) {
		mid, err := newID("m")
		if err != nil {
			return Machine{}, false, err
		}
		m = Machine{
			ID:                mid,
			Name:              name,
			OS:                osName,
			NodeID:            id.NodeID,
			NodeName:          id.NodeName,
			CredentialHash:    credentialHash,
			CredentialVersion: 1,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO machines (id, name, os, node_id, node_name, credential_hash, credential_version, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			m.ID, m.Name, m.OS, m.NodeID, m.NodeName, m.CredentialHash, m.CredentialVersion, nowStr, nowStr)
		if err != nil {
			return Machine{}, false, fmt.Errorf("store: enrol insert: %w", err)
		}
		if err := appendAuditTx(ctx, tx, audit(m, false)); err != nil {
			return Machine{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Machine{}, false, fmt.Errorf("store: enrol commit: %w", err)
		}
		return m, false, nil
	}

	m.Name = name
	m.OS = osName
	m.NodeName = id.NodeName
	m.CredentialHash = credentialHash
	m.CredentialVersion++
	m.UpdatedAt = now
	_, err = tx.ExecContext(ctx, `
		UPDATE machines
		SET name = ?, os = ?, node_name = ?, credential_hash = ?, credential_version = ?, updated_at = ?
		WHERE id = ?`,
		m.Name, m.OS, m.NodeName, m.CredentialHash, m.CredentialVersion, nowStr, m.ID)
	if err != nil {
		return Machine{}, false, fmt.Errorf("store: enrol update: %w", err)
	}
	if err := appendAuditTx(ctx, tx, audit(m, true)); err != nil {
		return Machine{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Machine{}, false, fmt.Errorf("store: enrol commit: %w", err)
	}
	return m, true, nil
}

// MachineByNodeID returns the machine bound to the given tailnet NodeID.
// Returns ErrNotFound when no machine is enrolled for that node.
func (s *SQLite) MachineByNodeID(ctx context.Context, nodeID string) (Machine, error) {
	var m Machine
	err := scanMachine(s.db.QueryRowContext(ctx, `
		SELECT id, name, os, node_id, node_name, credential_hash, credential_version, created_at, updated_at
		FROM machines WHERE node_id = ?`, nodeID), &m)
	if err != nil {
		return Machine{}, err
	}
	return m, nil
}

// MachineByID returns the machine with the given primary key.
// Returns ErrNotFound when missing.
func (s *SQLite) MachineByID(ctx context.Context, id string) (Machine, error) {
	var m Machine
	err := scanMachine(s.db.QueryRowContext(ctx, `
		SELECT id, name, os, node_id, node_name, credential_hash, credential_version, created_at, updated_at
		FROM machines WHERE id = ?`, id), &m)
	if err != nil {
		return Machine{}, err
	}
	return m, nil
}

// MachineByCredentialHash returns the machine whose credential hash matches.
//
// It exists so the server can tell "this credential is garbage" (401) apart
// from "this is a real credential, presented from the wrong node" (403) — the
// exfiltrated-and-replayed case, which must be audited against the OBSERVED
// node rather than misattributed to the credential's owner.
// Returns ErrNotFound when no machine matches.
func (s *SQLite) MachineByCredentialHash(ctx context.Context, credentialHash string) (Machine, error) {
	var m Machine
	err := scanMachine(s.db.QueryRowContext(ctx, `
		SELECT id, name, os, node_id, node_name, credential_hash, credential_version, created_at, updated_at
		FROM machines WHERE credential_hash = ? LIMIT 1`, credentialHash), &m)
	if err != nil {
		return Machine{}, err
	}
	return m, nil
}

// IssueGrant revokes any existing active grant for (machineID, harness) with
// reason "superseded", then inserts a new active grant. Both steps run in one
// transaction. Capabilities are stored as a JSON array. Returns the new grant
// and the superseded grant (nil if none).
//
// audit builds the events for this issuance (and any supersession); they are
// written inside the same transaction and must not be nil.
func (s *SQLite) IssueGrant(ctx context.Context, machineID, harness string, capabilities []string, tokenHash string, audit func(g Grant, superseded *Grant) []AuditEvent) (Grant, *Grant, error) {
	if audit == nil {
		return Grant{}, nil, errAuditCallbackRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, nil, fmt.Errorf("store: issue grant begin: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	nowStr := formatTime(now)

	var superseded *Grant
	var existing Grant
	err = scanGrant(tx.QueryRowContext(ctx, `
		SELECT id, machine_id, harness, capabilities, state, token_hash, created_at, revoked_at, revoked_reason
		FROM grants WHERE machine_id = ? AND harness = ? AND state = ?`,
		machineID, harness, string(GrantActive)), &existing)
	switch {
	case err == nil:
		_, err = tx.ExecContext(ctx, `
			UPDATE grants SET state = ?, revoked_at = ?, revoked_reason = ? WHERE id = ?`,
			string(GrantRevoked), nowStr, "superseded", existing.ID)
		if err != nil {
			return Grant{}, nil, fmt.Errorf("store: issue grant revoke prior: %w", err)
		}
		existing.State = GrantRevoked
		existing.RevokedAt = &now
		existing.RevokedReason = "superseded"
		superseded = &existing
	case errors.Is(err, ErrNotFound):
		// no prior active grant
	default:
		return Grant{}, nil, fmt.Errorf("store: issue grant lookup: %w", err)
	}

	gid, err := newID("g")
	if err != nil {
		return Grant{}, nil, err
	}
	if capabilities == nil {
		capabilities = []string{}
	}
	capsJSON, err := json.Marshal(capabilities)
	if err != nil {
		return Grant{}, nil, fmt.Errorf("store: issue grant marshal capabilities: %w", err)
	}

	g := Grant{
		ID:            gid,
		MachineID:     machineID,
		Harness:       harness,
		Capabilities:  capabilities,
		State:         GrantActive,
		TokenHash:     tokenHash,
		CreatedAt:     now,
		RevokedAt:     nil,
		RevokedReason: "",
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO grants (id, machine_id, harness, capabilities, state, token_hash, created_at, revoked_at, revoked_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '')`,
		g.ID, g.MachineID, g.Harness, string(capsJSON), string(g.State), g.TokenHash, nowStr)
	if err != nil {
		return Grant{}, nil, fmt.Errorf("store: issue grant insert: %w", err)
	}
	if err := appendAuditTx(ctx, tx, audit(g, superseded)); err != nil {
		return Grant{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return Grant{}, nil, fmt.Errorf("store: issue grant commit: %w", err)
	}
	return g, superseded, nil
}

// GrantByID returns the grant with the given primary key.
// Returns ErrNotFound when missing.
func (s *SQLite) GrantByID(ctx context.Context, id string) (Grant, error) {
	var g Grant
	err := scanGrant(s.db.QueryRowContext(ctx, `
		SELECT id, machine_id, harness, capabilities, state, token_hash, created_at, revoked_at, revoked_reason
		FROM grants WHERE id = ?`, id), &g)
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

// RevokeGrant sets state=revoked, revoked_at=now, and revoked_reason=reason
// only if the grant is currently active. Returns the grant after the call and
// changed=false when it was already revoked (idempotent). Returns ErrNotFound
// when the grant does not exist.
//
// audit builds the events for an actual state transition; it is not called
// when the grant was already revoked (nothing happened, so nothing is
// recorded). It must not be nil.
func (s *SQLite) RevokeGrant(ctx context.Context, id, reason string, audit func(g Grant) []AuditEvent) (Grant, bool, error) {
	if audit == nil {
		return Grant{}, false, errAuditCallbackRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Grant{}, false, fmt.Errorf("store: revoke grant begin: %w", err)
	}
	defer tx.Rollback()

	var g Grant
	err = scanGrant(tx.QueryRowContext(ctx, `
		SELECT id, machine_id, harness, capabilities, state, token_hash, created_at, revoked_at, revoked_reason
		FROM grants WHERE id = ?`, id), &g)
	if err != nil {
		return Grant{}, false, err
	}
	if g.State != GrantActive {
		if err := tx.Commit(); err != nil {
			return Grant{}, false, fmt.Errorf("store: revoke grant commit: %w", err)
		}
		return g, false, nil
	}

	now := time.Now().UTC()
	nowStr := formatTime(now)
	_, err = tx.ExecContext(ctx, `
		UPDATE grants SET state = ?, revoked_at = ?, revoked_reason = ? WHERE id = ?`,
		string(GrantRevoked), nowStr, reason, id)
	if err != nil {
		return Grant{}, false, fmt.Errorf("store: revoke grant update: %w", err)
	}
	g.State = GrantRevoked
	g.RevokedAt = &now
	g.RevokedReason = reason
	if err := appendAuditTx(ctx, tx, audit(g)); err != nil {
		return Grant{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Grant{}, false, fmt.Errorf("store: revoke grant commit: %w", err)
	}
	return g, true, nil
}

// ListGrants returns all grants for machineID, newest first.
// Returns an empty (non-nil) slice when none exist.
func (s *SQLite) ListGrants(ctx context.Context, machineID string) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, machine_id, harness, capabilities, state, token_hash, created_at, revoked_at, revoked_reason
		FROM grants WHERE machine_id = ? ORDER BY created_at DESC, id DESC`, machineID)
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	defer rows.Close()

	out := make([]Grant, 0)
	for rows.Next() {
		var g Grant
		if err := scanGrantRows(rows, &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	return out, nil
}

// ActiveGrantByTokenHash returns the active grant whose token hash matches.
// Returns ErrNotFound when no ACTIVE grant matches.
func (s *SQLite) ActiveGrantByTokenHash(ctx context.Context, tokenHash string) (Grant, error) {
	var g Grant
	err := scanGrant(s.db.QueryRowContext(ctx, `
		SELECT id, machine_id, harness, capabilities, state, token_hash, created_at, revoked_at, revoked_reason
		FROM grants WHERE token_hash = ? AND state = ?`, tokenHash, string(GrantActive)), &g)
	if err != nil {
		return Grant{}, err
	}
	return g, nil
}

// errAuditCallbackRequired guards the audit-atomicity rule: no lifecycle
// mutation may be committed without the events that record it.
var errAuditCallbackRequired = errors.New("store: an audit callback is required for lifecycle mutations")

// execer is satisfied by both *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// AppendAudit records a standalone event — one with no accompanying mutation,
// such as a rejected call. Events that DO accompany a mutation are written by
// that mutation's transaction instead, so the two can never diverge.
func (s *SQLite) AppendAudit(ctx context.Context, e AuditEvent) error {
	return appendAudit(ctx, s.db, e)
}

// appendAuditTx writes a mutation's audit events inside its transaction. Any
// failure aborts the mutation: an unrecorded revocation is worse than a failed
// one, because the operator would have no way to learn it happened.
func appendAuditTx(ctx context.Context, tx *sql.Tx, events []AuditEvent) error {
	for _, e := range events {
		if err := appendAudit(ctx, tx, e); err != nil {
			return err
		}
	}
	return nil
}

func appendAudit(ctx context.Context, db execer, e AuditEvent) error {
	if err := ValidateDetail(e.Detail); err != nil {
		return err
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	} else {
		e.TS = e.TS.UTC()
	}

	var detailArg any
	if len(e.Detail) > 0 {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("store: append audit marshal detail: %w", err)
		}
		detailArg = string(b)
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO audit_events (
			ts, event, actor_kind,
			observed_node_id, observed_node_name,
			auth_machine_id, harness, grant_id,
			action_class, tool, artifact_id,
			outcome, reason, token_fingerprint, detail
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		formatTime(e.TS), e.Event, string(e.ActorKind),
		e.ObservedNodeID, e.ObservedNodeName,
		e.AuthMachineID, e.Harness, e.GrantID,
		e.ActionClass, e.Tool, e.ArtifactID,
		string(e.Outcome), e.Reason, e.TokenFingerprint, detailArg,
	)
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}

// QueryAudit returns audit events matching q, always in append order.
//
// A limit selects the NEWEST q.Limit events, not the oldest. An incident view
// that silently stopped at the first 200 rows ever written would hide exactly
// the recent denials and revocations an operator opens the log to find.
func (s *SQLite) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, error) {
	const columns = `id, ts, event, actor_kind,
			observed_node_id, observed_node_name,
			auth_machine_id, harness, grant_id,
			action_class, tool, artifact_id,
			outcome, reason, token_fingerprint, detail`

	where := ""
	args := make([]any, 0, 2)
	if !q.Since.IsZero() {
		where = ` WHERE ts >= ?`
		args = append(args, formatTime(q.Since.UTC()))
	}

	query := `SELECT ` + columns + ` FROM audit_events` + where + ` ORDER BY id ASC`
	if q.Limit > 0 {
		// Take the newest window, then present it oldest-first.
		query = `SELECT ` + columns + ` FROM (SELECT ` + columns +
			` FROM audit_events` + where + ` ORDER BY id DESC LIMIT ?) ORDER BY id ASC`
		args = append(args, q.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query audit: %w", err)
	}
	defer rows.Close()

	out := make([]AuditEvent, 0)
	for rows.Next() {
		var (
			e          AuditEvent
			tsStr      string
			actorKind  string
			outcome    string
			detailNull sql.NullString
		)
		err := rows.Scan(
			&e.ID, &tsStr, &e.Event, &actorKind,
			&e.ObservedNodeID, &e.ObservedNodeName,
			&e.AuthMachineID, &e.Harness, &e.GrantID,
			&e.ActionClass, &e.Tool, &e.ArtifactID,
			&outcome, &e.Reason, &e.TokenFingerprint, &detailNull,
		)
		if err != nil {
			return nil, fmt.Errorf("store: query audit scan: %w", err)
		}
		ts, err := parseTime(tsStr)
		if err != nil {
			return nil, fmt.Errorf("store: query audit parse ts: %w", err)
		}
		e.TS = ts
		e.ActorKind = ActorKind(actorKind)
		e.Outcome = Outcome(outcome)
		if detailNull.Valid && detailNull.String != "" {
			if err := json.Unmarshal([]byte(detailNull.String), &e.Detail); err != nil {
				return nil, fmt.Errorf("store: query audit unmarshal detail: %w", err)
			}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query audit: %w", err)
	}
	return out, nil
}

// PutSecret insert-or-replaces the secret at ref. Generation is previous
// generation + 1 (starting at 1). Runs in one transaction and returns the
// new generation.
//
// audit builds the events for the import/replacement; they are written inside
// the same transaction and must not be nil.
//
// This is the LAST-WRITER-WINS form, used by the operator CLI where the
// operator is by definition the only actor. Concurrent brokered writes (R13's
// add-credentials flow) must use PutSecretCAS instead.
func (s *SQLite) PutSecret(ctx context.Context, ref string, ciphertext []byte, audit func(generation int64) []AuditEvent) (int64, error) {
	return s.putSecret(ctx, ref, ciphertext, nil, audit)
}

// ErrGenerationConflict means the secret at ref did not hold the generation the
// caller observed: something else replaced it in between. It is the loser's
// signal in R13's concurrent-credential-flow race, and the reason a losing flow
// can report "retry" honestly — nothing of its own was written.
var ErrGenerationConflict = errors.New("store: secret generation conflict")

// PutSecretCAS replaces the secret at ref only if its current generation is
// still expectedGeneration, returning ErrGenerationConflict otherwise.
// expectedGeneration 0 means "no secret is stored at this ref yet".
//
// This is what makes R13's credential replacement an ATOMIC SWAP: the existing
// credential stays live and untouched through the whole flow, and the new one
// lands in a single transaction that fails outright if another flow committed
// first. There is no window in which the ref holds neither credential.
func (s *SQLite) PutSecretCAS(ctx context.Context, ref string, ciphertext []byte, expectedGeneration int64,
	audit func(generation int64) []AuditEvent) (int64, error) {
	return s.putSecret(ctx, ref, ciphertext, &expectedGeneration, audit)
}

func (s *SQLite) putSecret(ctx context.Context, ref string, ciphertext []byte, expectedGeneration *int64,
	audit func(generation int64) []AuditEvent) (int64, error) {
	if audit == nil {
		return 0, errAuditCallbackRequired
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: put secret begin: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	nowStr := formatTime(now)

	var prevGen sql.NullInt64
	var createdAt string
	err = tx.QueryRowContext(ctx, `SELECT generation, created_at FROM secrets WHERE ref = ?`, ref).
		Scan(&prevGen, &createdAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store: put secret lookup: %w", err)
	}

	// The compare happens INSIDE the transaction, against the row this
	// transaction reads — not against a value the caller re-read a moment ago.
	if expectedGeneration != nil {
		current := int64(0)
		if !errors.Is(err, sql.ErrNoRows) {
			current = prevGen.Int64
		}
		if current != *expectedGeneration {
			return 0, fmt.Errorf("%w: secret %q is at generation %d, caller observed %d",
				ErrGenerationConflict, ref, current, *expectedGeneration)
		}
	}

	var generation int64 = 1
	if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO secrets (ref, ciphertext, generation, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?)`,
			ref, ciphertext, generation, nowStr, nowStr)
		if err != nil {
			return 0, fmt.Errorf("store: put secret insert: %w", err)
		}
	} else {
		generation = prevGen.Int64 + 1
		_, err = tx.ExecContext(ctx, `
			UPDATE secrets SET ciphertext = ?, generation = ?, updated_at = ? WHERE ref = ?`,
			ciphertext, generation, nowStr, ref)
		if err != nil {
			return 0, fmt.Errorf("store: put secret update: %w", err)
		}
	}
	if err := appendAuditTx(ctx, tx, audit(generation)); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: put secret commit: %w", err)
	}
	return generation, nil
}

// GetSecret returns the secret stored at ref.
// Returns ErrNotFound when missing.
func (s *SQLite) GetSecret(ctx context.Context, ref string) (Secret, error) {
	var (
		sec                    Secret
		createdStr, updatedStr string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT ref, ciphertext, generation, created_at, updated_at
		FROM secrets WHERE ref = ?`, ref).
		Scan(&sec.Ref, &sec.Ciphertext, &sec.Generation, &createdStr, &updatedStr)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("store: get secret: %w", err)
	}
	created, err := parseTime(createdStr)
	if err != nil {
		return Secret{}, fmt.Errorf("store: get secret parse created_at: %w", err)
	}
	updated, err := parseTime(updatedStr)
	if err != nil {
		return Secret{}, fmt.Errorf("store: get secret parse updated_at: %w", err)
	}
	sec.CreatedAt = created
	sec.UpdatedAt = updated
	return sec, nil
}

// ListSecretMeta returns metadata for every stored secret, ordered by ref, and
// never the secret values.
//
// The ciphertext is read only to measure it and to check that it IS ciphertext;
// it does not leave this function. That is deliberate: the operator surface
// this feeds must be able to prove a credential is present and encrypted
// without ever being a way to read one.
func (s *SQLite) ListSecretMeta(ctx context.Context) ([]SecretMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ref, ciphertext, generation, created_at, updated_at
		FROM secrets ORDER BY ref`)
	if err != nil {
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	defer rows.Close()

	var out []SecretMeta
	for rows.Next() {
		var (
			meta                   SecretMeta
			ciphertext             []byte
			createdStr, updatedStr string
		)
		if err := rows.Scan(&meta.Ref, &ciphertext, &meta.Generation, &createdStr, &updatedStr); err != nil {
			return nil, fmt.Errorf("store: list secrets scan: %w", err)
		}
		meta.CiphertextBytes = len(ciphertext)
		meta.Encrypted = secrets.LooksEncrypted(ciphertext)
		if meta.CreatedAt, err = parseTime(createdStr); err != nil {
			return nil, fmt.Errorf("store: list secrets parse created_at: %w", err)
		}
		if meta.UpdatedAt, err = parseTime(updatedStr); err != nil {
			return nil, fmt.Errorf("store: list secrets parse updated_at: %w", err)
		}
		out = append(out, meta)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list secrets: %w", err)
	}
	return out, nil
}

// newID returns prefix + "-" + 16 lowercase hex characters from crypto/rand.
func newID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("store: new id: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(b[:]), nil
}

// storedTimeLayout is FIXED-WIDTH on purpose. Timestamps are compared and
// ordered lexicographically by SQLite, and time.RFC3339Nano trims trailing
// zeros from the fractional part: "…:00.1Z" would sort BEFORE "…:00Z" even
// though it happens later, silently corrupting `--since` filtering and audit
// ordering at precision boundaries. Nine fixed digits make text order and
// chronological order the same thing.
const storedTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string {
	return t.UTC().Format(storedTimeLayout)
}

// parseTime reads the fixed-width stored form, falling back to RFC3339Nano so
// rows written by an earlier build still load.
func parseTime(s string) (time.Time, error) {
	for _, layout := range []string{storedTimeLayout, time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("store: unparseable timestamp %q", s)
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanMachine(row rowScanner, m *Machine) error {
	var createdStr, updatedStr string
	err := row.Scan(
		&m.ID, &m.Name, &m.OS, &m.NodeID, &m.NodeName,
		&m.CredentialHash, &m.CredentialVersion, &createdStr, &updatedStr,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: scan machine: %w", err)
	}
	created, err := parseTime(createdStr)
	if err != nil {
		return fmt.Errorf("store: parse machine created_at: %w", err)
	}
	updated, err := parseTime(updatedStr)
	if err != nil {
		return fmt.Errorf("store: parse machine updated_at: %w", err)
	}
	m.CreatedAt = created
	m.UpdatedAt = updated
	return nil
}

func scanGrant(row rowScanner, g *Grant) error {
	var (
		capsJSON      string
		state         string
		createdStr    string
		revokedAtNull sql.NullString
		revokedReason string
	)
	err := row.Scan(
		&g.ID, &g.MachineID, &g.Harness, &capsJSON, &state, &g.TokenHash,
		&createdStr, &revokedAtNull, &revokedReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("store: scan grant: %w", err)
	}
	return fillGrant(g, capsJSON, state, createdStr, revokedAtNull, revokedReason)
}

func scanGrantRows(rows *sql.Rows, g *Grant) error {
	var (
		capsJSON      string
		state         string
		createdStr    string
		revokedAtNull sql.NullString
		revokedReason string
	)
	err := rows.Scan(
		&g.ID, &g.MachineID, &g.Harness, &capsJSON, &state, &g.TokenHash,
		&createdStr, &revokedAtNull, &revokedReason,
	)
	if err != nil {
		return fmt.Errorf("store: scan grant: %w", err)
	}
	return fillGrant(g, capsJSON, state, createdStr, revokedAtNull, revokedReason)
}

func fillGrant(g *Grant, capsJSON, state, createdStr string, revokedAtNull sql.NullString, revokedReason string) error {
	if err := json.Unmarshal([]byte(capsJSON), &g.Capabilities); err != nil {
		return fmt.Errorf("store: unmarshal grant capabilities: %w", err)
	}
	if g.Capabilities == nil {
		g.Capabilities = []string{}
	}
	g.State = GrantState(state)
	g.RevokedReason = revokedReason
	created, err := parseTime(createdStr)
	if err != nil {
		return fmt.Errorf("store: parse grant created_at: %w", err)
	}
	g.CreatedAt = created
	if revokedAtNull.Valid && revokedAtNull.String != "" {
		t, err := parseTime(revokedAtNull.String)
		if err != nil {
			return fmt.Errorf("store: parse grant revoked_at: %w", err)
		}
		g.RevokedAt = &t
	} else {
		g.RevokedAt = nil
	}
	return nil
}
