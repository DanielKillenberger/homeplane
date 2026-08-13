package store

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func mustEnrol(t *testing.T, st *SQLite, nodeID, name string) Machine {
	t.Helper()
	m, _, err := st.Enrol(context.Background(), Identity{NodeID: nodeID, NodeName: name}, name, "linux", "hash-"+nodeID)
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	return m
}

// TestAuditSchemaIsMetadataOnly pins the audit table's shape. It is a schema
// test on purpose: the metadata-only discipline is a PROPERTY OF THE SCHEMA,
// not of the code that writes to it. A future column named `payload`,
// `request_body`, or `content` would give some later handler a place to log a
// document — this test is what stops that column from being added quietly.
func TestAuditSchemaIsMetadataOnly(t *testing.T) {
	st := newTestStore(t)

	rows, err := st.db.Query(`SELECT name FROM pragma_table_info('audit_events')`)
	if err != nil {
		t.Fatalf("pragma_table_info: %v", err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	sort.Strings(columns)

	want := []string{
		"action_class", "actor_kind", "artifact_id", "auth_machine_id", "detail",
		"event", "grant_id", "harness", "id", "observed_node_id", "observed_node_name",
		"outcome", "reason", "token_fingerprint", "tool", "ts",
	}
	sort.Strings(want)
	if strings.Join(columns, ",") != strings.Join(want, ",") {
		t.Fatalf("audit_events columns changed.\n got: %v\nwant: %v\n"+
			"Adding a column here needs a deliberate decision: the audit log stores metadata, never payload bodies.",
			columns, want)
	}

	// Belt and braces: no column may be named like a body carrier.
	for _, c := range columns {
		for _, banned := range []string{"payload", "body", "content", "arguments", "response", "request"} {
			if strings.Contains(c, banned) {
				t.Errorf("audit column %q looks like a payload carrier", c)
			}
		}
	}
}

func TestValidateDetailRejectsUnknownKeysAndOversizedValues(t *testing.T) {
	if err := ValidateDetail(map[string]string{"machine_name": "mac-a"}); err != nil {
		t.Fatalf("allow-listed key rejected: %v", err)
	}
	if err := ValidateDetail(map[string]string{"document_body": "…"}); err == nil {
		t.Error("non-allow-listed detail key accepted")
	}
	if err := ValidateDetail(map[string]string{"machine_name": strings.Repeat("x", MaxDetailValueLen+1)}); err == nil {
		t.Error("oversized detail value accepted")
	}

	st := newTestStore(t)
	err := st.AppendAudit(context.Background(), AuditEvent{
		Event: EventEnrolment, ActorKind: ActorMachine, Outcome: OutcomeAllowed,
		Detail: map[string]string{"note_contents": "secret vault text"},
	})
	if err == nil {
		t.Fatal("AppendAudit accepted a non-allow-listed detail key")
	}
}

func TestEnrolIsIdentityPreservingRotation(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	id := Identity{NodeID: "node-1", NodeName: "mac"}

	first, rotated, err := st.Enrol(ctx, id, "mac", "darwin", "hash-1")
	if err != nil || rotated {
		t.Fatalf("first enrol: m=%+v rotated=%v err=%v", first, rotated, err)
	}
	second, rotated, err := st.Enrol(ctx, id, "mac-renamed", "darwin", "hash-2")
	if err != nil {
		t.Fatalf("second enrol: %v", err)
	}
	if !rotated {
		t.Error("re-enrol did not report rotation")
	}
	if second.ID != first.ID {
		t.Errorf("machine id changed on re-enrol: %q -> %q", first.ID, second.ID)
	}
	if second.CredentialVersion != 2 {
		t.Errorf("credential_version = %d, want 2", second.CredentialVersion)
	}
	if second.CredentialHash != "hash-2" {
		t.Errorf("credential hash not rotated: %q", second.CredentialHash)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Error("re-enrol reset created_at; the machine record must be preserved")
	}

	var count int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM machines`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("machines rows = %d, want exactly 1 (no duplicate identity)", count)
	}

	// The old credential must no longer resolve to anything.
	if _, err := st.MachineByCredentialHash(ctx, "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old credential hash still resolves: %v", err)
	}
	if m, err := st.MachineByCredentialHash(ctx, "hash-2"); err != nil || m.ID != first.ID {
		t.Errorf("new credential hash lookup: m=%+v err=%v", m, err)
	}
}

func TestOnlyOneActiveGrantPerMachineAndHarness(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	m := mustEnrol(t, st, "node-1", "mac")

	first, superseded, err := st.IssueGrant(ctx, m.ID, "codex", []string{"connector.read"}, "tok-1")
	if err != nil || superseded != nil {
		t.Fatalf("first grant: superseded=%v err=%v", superseded, err)
	}
	second, superseded, err := st.IssueGrant(ctx, m.ID, "codex", []string{"connector.read"}, "tok-2")
	if err != nil {
		t.Fatalf("second grant: %v", err)
	}
	if superseded == nil || superseded.ID != first.ID {
		t.Fatalf("second grant did not supersede the first: %+v", superseded)
	}
	if superseded.State != GrantRevoked || superseded.RevokedReason != "superseded" {
		t.Errorf("superseded grant = %s/%s, want revoked/superseded", superseded.State, superseded.RevokedReason)
	}

	// The old token must stop resolving the instant the new one exists.
	if _, err := st.ActiveGrantByTokenHash(ctx, "tok-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("superseded token still active: %v", err)
	}
	got, err := st.ActiveGrantByTokenHash(ctx, "tok-2")
	if err != nil || got.ID != second.ID {
		t.Errorf("new token lookup: %+v err=%v", got, err)
	}

	var active int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM grants WHERE machine_id = ? AND harness = ? AND state = 'active'`,
		m.ID, "codex").Scan(&active); err != nil {
		t.Fatalf("count: %v", err)
	}
	if active != 1 {
		t.Fatalf("active grants = %d, want 1", active)
	}
}

func TestRevokeGrantIsIdempotent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	m := mustEnrol(t, st, "node-1", "mac")
	g, _, err := st.IssueGrant(ctx, m.ID, "codex", []string{"connector.read"}, "tok-1")
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}

	revoked, changed, err := st.RevokeGrant(ctx, g.ID, "revoked_by_machine")
	if err != nil || !changed {
		t.Fatalf("first revoke: changed=%v err=%v", changed, err)
	}
	if revoked.RevokedAt == nil {
		t.Error("revoked grant has no revoked_at")
	}

	again, changed, err := st.RevokeGrant(ctx, g.ID, "revoked_by_operator")
	if err != nil {
		t.Fatalf("repeat revoke: %v", err)
	}
	if changed {
		t.Error("repeat revocation reported a state change")
	}
	if again.RevokedReason != "revoked_by_machine" {
		t.Errorf("repeat revocation overwrote the original reason: %q", again.RevokedReason)
	}

	if _, _, err := st.RevokeGrant(ctx, "g-nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown grant revoke err = %v, want ErrNotFound", err)
	}
}

func TestListGrantsIsPerMachine(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	a := mustEnrol(t, st, "node-a", "mac-a")
	b := mustEnrol(t, st, "node-b", "linux-b")

	if _, _, err := st.IssueGrant(ctx, a.ID, "codex", []string{"connector.read"}, "tok-a"); err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	if _, _, err := st.IssueGrant(ctx, b.ID, "codex", []string{"connector.read"}, "tok-b"); err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}

	got, err := st.ListGrants(ctx, a.ID)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(got) != 1 || got[0].MachineID != a.ID {
		t.Fatalf("ListGrants returned %d rows for machine A: %+v", len(got), got)
	}

	empty, err := st.ListGrants(ctx, "m-unknown")
	if err != nil {
		t.Fatalf("ListGrants unknown: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Errorf("ListGrants for unknown machine = %v, want empty non-nil slice", empty)
	}
}

func TestQueryAuditFiltersBySinceAndLimit(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour)

	for i := 0; i < 5; i++ {
		if err := st.AppendAudit(ctx, AuditEvent{
			TS: base.Add(time.Duration(i) * time.Minute), Event: EventEnrolment,
			ActorKind: ActorMachine, Outcome: OutcomeAllowed,
		}); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	all, err := st.QueryAudit(ctx, AuditQuery{})
	if err != nil || len(all) != 5 {
		t.Fatalf("QueryAudit all = %d rows, err=%v", len(all), err)
	}
	if !all[0].TS.Before(all[len(all)-1].TS) {
		t.Error("audit rows are not in append order")
	}

	recent, err := st.QueryAudit(ctx, AuditQuery{Since: base.Add(3 * time.Minute)})
	if err != nil || len(recent) != 2 {
		t.Fatalf("QueryAudit since = %d rows, err=%v", len(recent), err)
	}
	limited, err := st.QueryAudit(ctx, AuditQuery{Limit: 2})
	if err != nil || len(limited) != 2 {
		t.Fatalf("QueryAudit limit = %d rows, err=%v", len(limited), err)
	}
}

func TestSecretsAreVersionedOnReplacement(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	gen, err := st.PutSecret(ctx, "google/oauth-client", []byte("cipher-1"))
	if err != nil || gen != 1 {
		t.Fatalf("first PutSecret: gen=%d err=%v", gen, err)
	}
	gen, err = st.PutSecret(ctx, "google/oauth-client", []byte("cipher-2"))
	if err != nil || gen != 2 {
		t.Fatalf("second PutSecret: gen=%d err=%v", gen, err)
	}

	sec, err := st.GetSecret(ctx, "google/oauth-client")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(sec.Ciphertext) != "cipher-2" || sec.Generation != 2 {
		t.Errorf("secret = %q/gen %d, want cipher-2/gen 2", sec.Ciphertext, sec.Generation)
	}
	if !sec.CreatedAt.Before(sec.UpdatedAt) && !sec.CreatedAt.Equal(sec.UpdatedAt) {
		t.Error("updated_at precedes created_at")
	}
	if _, err := st.GetSecret(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown secret err = %v, want ErrNotFound", err)
	}
}

func TestClosedStoreReportsErrorRatherThanPanicking(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := st.Ping(context.Background()); err == nil {
		t.Error("Ping on a closed store returned nil error")
	}
}

func TestForeignKeysAreEnforcedOnEveryConnection(t *testing.T) {
	st := newTestStore(t)
	// A grant for a machine that does not exist must be refused by the schema,
	// whichever pooled connection happens to serve the request.
	for i := 0; i < 5; i++ {
		if _, _, err := st.IssueGrant(context.Background(), "m-nonexistent", "codex", []string{"connector.read"}, "tok"); err == nil {
			t.Fatal("IssueGrant accepted a grant for an unknown machine (foreign keys not enforced)")
		}
	}
}
