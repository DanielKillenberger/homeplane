//go:build live_google

// Live Google connector proof (R7/R8).
//
// This file is behind the `live_google` build tag AND an environment guard: it
// talks to real Google, with a real credential brokered by `add-credentials`,
// through a real ToolHive workload. `go test ./...` never builds it, which is
// why the deterministic half of this task (the shipped manifest, its mappings,
// the fail-closed classification) lives in ordinary tests that always run.
//
// What it proves, in one run, against the SHIPPED manifest:
//
//   - a Drive READ reaches real Drive through the edge;
//   - a Drive WRITE is refused fail-closed by the manifest and audited as a
//     policy violation — the live half of D18;
//   - the Calendar six-op sequence (create, read back, update, verify, delete,
//     verify cleanup) succeeds on an isolated, uniquely named test event;
//   - the audit log carries the right action class per call, including the
//     delete as delete-class, and no payload;
//   - a revoked grant is refused within seconds, with no token cache to wait out.
//
// The test event is namespaced and time-stamped, checked for absence before it
// is created, and deleted by a cleanup that runs on every failure path. No
// pre-existing event or file is ever touched.
//
// Run it (see docs/runbooks/live-google-proof.md for the full sequence):
//
//	HOMEPLANE_LIVE_GOOGLE=1 \
//	HOMEPLANE_LIVE_GOOGLE_GATEWAY=http://127.0.0.1:PORT/mcp \
//	HOMEPLANE_LIVE_GOOGLE_ACCOUNT=you@example.com \
//	go test ./internal/server/edge/ -tags live_google -run TestLiveGoogle -count=1 -v
package edge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/cred"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// liveEnv is the deployment the proof runs against. Everything in it is an
// operational fact (a running gateway, a granted account), never a default:
// a proof that silently invented its target would prove nothing.
type liveEnv struct {
	gateway  string
	account  string
	driveDoc string // optional: a specific Drive file id to read
	calendar string
}

func liveGuard(t *testing.T) liveEnv {
	t.Helper()
	if os.Getenv("HOMEPLANE_LIVE_GOOGLE") != "1" {
		t.Skip("set HOMEPLANE_LIVE_GOOGLE=1 (and the gateway/account vars) to run the live Google proof")
	}
	env := liveEnv{
		gateway:  os.Getenv("HOMEPLANE_LIVE_GOOGLE_GATEWAY"),
		account:  os.Getenv("HOMEPLANE_LIVE_GOOGLE_ACCOUNT"),
		driveDoc: os.Getenv("HOMEPLANE_LIVE_GOOGLE_DRIVE_FILE_ID"),
		calendar: os.Getenv("HOMEPLANE_LIVE_GOOGLE_CALENDAR_ID"),
	}
	if env.gateway == "" || env.account == "" {
		t.Fatal("HOMEPLANE_LIVE_GOOGLE_GATEWAY and HOMEPLANE_LIVE_GOOGLE_ACCOUNT are required")
	}
	if env.calendar == "" {
		env.calendar = "primary"
	}
	return env
}

// liveHarness is the real edge in front of the real gateway. Only the tailnet
// resolver is a stand-in (tsnet WhoIs is proven live in the D6 spike, gate 1,
// and by task .16); the store, the manifest, the policy engine, the audit log
// and the provider are all real.
type liveHarness struct {
	t       *testing.T
	env     liveEnv
	st      *store.SQLite
	edge    *Edge
	token   string
	grant   store.Grant
	session string
}

func newLiveHarness(t *testing.T, capabilities ...string) *liveHarness {
	t.Helper()
	env := liveGuard(t)

	if len(capabilities) == 0 {
		capabilities = []string{
			string(policy.ConnectorRead), string(policy.ConnectorWrite), string(policy.ConnectorDelete),
		}
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "homeplane.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// The SHIPPED manifest, not a fixture: the point of a live proof is that the
	// file a deployment runs is the file that was proven.
	manifestPath := filepath.Join("..", "..", "..", "configs", "connectors", "google.json")
	manifest, err := connectors.LoadFile(manifestPath)
	if err != nil {
		t.Fatalf("load shipped manifest %s: %v", manifestPath, err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register shipped manifest: %v", err)
	}

	upstream, err := ParseUpstream(env.gateway)
	if err != nil {
		t.Fatalf("gateway upstream: %v", err)
	}
	broker := connectors.NewBroker(engine, NewHTTPRuntime(upstream, nil), st)

	e, err := New(Config{
		Store:    st,
		Identity: fakeResolver{byAddr: map[string]store.Identity{addrA: nodeA}},
		Broker:   broker,
		Upstream: upstream,
	})
	if err != nil {
		t.Fatalf("edge.New: %v", err)
	}

	h := &liveHarness{t: t, env: env, st: st, edge: e}
	h.enrolAndGrant(capabilities)
	h.session = h.openSession()
	return h
}

func (h *liveHarness) enrolAndGrant(capabilities []string) {
	h.t.Helper()
	ctx := context.Background()

	_, machineHash, err := cred.New()
	if err != nil {
		h.t.Fatalf("mint machine credential: %v", err)
	}
	m, _, err := h.st.Enrol(ctx, nodeA, "live-proof", "darwin", machineHash,
		func(m store.Machine, _ bool) []store.AuditEvent {
			return []store.AuditEvent{{
				Event: store.EventEnrolment, ActorKind: store.ActorMachine,
				ObservedNodeID: nodeA.NodeID, ObservedNodeName: nodeA.NodeName,
				AuthMachineID: m.ID, Outcome: store.OutcomeAllowed,
			}}
		})
	if err != nil {
		h.t.Fatalf("enrol: %v", err)
	}
	token, tokenHash, err := cred.New()
	if err != nil {
		h.t.Fatalf("mint grant token: %v", err)
	}
	g, _, err := h.st.IssueGrant(ctx, m.ID, policy.HarnessClaudeCode, capabilities, tokenHash,
		func(g store.Grant, _ *store.Grant) []store.AuditEvent {
			return []store.AuditEvent{{
				Event: store.EventGrantIssued, ActorKind: store.ActorMachine,
				ObservedNodeID: nodeA.NodeID, ObservedNodeName: nodeA.NodeName,
				AuthMachineID: m.ID, Harness: g.Harness, GrantID: g.ID,
				Outcome: store.OutcomeAllowed,
			}}
		})
	if err != nil {
		h.t.Fatalf("issue grant: %v", err)
	}
	h.token, h.grant = token, g
}

// openSession runs the MCP handshake THROUGH the edge and keeps the gateway's
// session id, which every later tool call carries.
func (h *liveHarness) openSession() string {
	h.t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + ProtocolVersion +
		`","capabilities":{},"clientInfo":{"name":"homeplane-live-proof","version":"1"}}}`
	res := h.do(http.MethodPost, h.token, body, map[string]string{HeaderProtocolVersion: ProtocolVersion})
	if res.status != http.StatusOK {
		h.t.Fatalf("initialize through the edge: HTTP %d: %s", res.status, res.rawBody)
	}
	sid := res.header.Get(HeaderSessionID)
	if sid == "" {
		h.t.Fatalf("the gateway issued no session id: %s", res.rawBody)
	}
	// The MCP handshake is only complete once the client acknowledges it.
	h.do(http.MethodPost, h.token, `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		map[string]string{HeaderProtocolVersion: ProtocolVersion, HeaderSessionID: sid})
	return sid
}

func (h *liveHarness) do(method, token, body string, headers map[string]string) edgeResponse {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, "/mcp", reader)
	r.RemoteAddr = addrA
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.edge.ServeHTTP(rec, r)
	res := edgeResponse{status: rec.Code, header: rec.Header(), rawBody: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &res.rpc)
	return res
}

// call invokes one tool through the edge and returns the edge's answer plus the
// tool's text content (workspace-mcp's tools all return text).
func (h *liveHarness) call(tool string, args map[string]any) (edgeResponse, string) {
	h.t.Helper()
	if _, ok := args["user_google_email"]; !ok {
		args["user_google_email"] = h.env.account
	}
	raw, err := json.Marshal(args)
	if err != nil {
		h.t.Fatalf("marshal args: %v", err)
	}
	params, err := json.Marshal(toolCallParams{Name: tool, Arguments: raw})
	if err != nil {
		h.t.Fatalf("marshal params: %v", err)
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: jsonRPCVersion, ID: json.RawMessage(`7`), Method: methodToolsCall, Params: params,
	})
	if err != nil {
		h.t.Fatalf("marshal request: %v", err)
	}
	res := h.do(http.MethodPost, h.token, string(body), map[string]string{
		HeaderProtocolVersion: ProtocolVersion,
		HeaderSessionID:       h.session,
	})
	text, _ := toolText(res)
	return res, text
}

// mustCall invokes a tool and fails the test unless it genuinely SUCCEEDED.
//
// "Succeeded" is deliberately three checks, not one. An MCP tool that fails
// answers with an ordinary JSON-RPC RESULT carrying `isError: true` and the
// failure as text — so a test that only looked at the HTTP status and the
// JSON-RPC error would pass on a tool that reached nothing at all. That is not
// hypothetical: the first live run of this file reported a green Drive read
// while the connector's container could not open a socket.
func (h *liveHarness) mustCall(tool string, args map[string]any) string {
	h.t.Helper()
	res, text := h.call(tool, args)
	if res.status != http.StatusOK {
		h.t.Fatalf("%s: HTTP %d: %s", tool, res.status, res.rawBody)
	}
	if res.rpc.Error != nil {
		h.t.Fatalf("%s: JSON-RPC error %+v", tool, res.rpc.Error)
	}
	if _, isErr := toolText(res); isErr {
		h.t.Fatalf("%s: the tool reported a failure:\n%s", tool, text)
	}
	return text
}

// toolText pulls the text content out of an MCP tool result and reports whether
// the result was a tool-level FAILURE. It returns the raw body when the answer
// is not a tool result at all (a denial, a transport error).
func toolText(res edgeResponse) (string, bool) {
	if len(res.rpc.Result) == 0 {
		return res.rawBody, res.rpc.Error != nil
	}
	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res.rpc.Result, &result); err != nil {
		return string(res.rpc.Result), false
	}
	var b strings.Builder
	for _, c := range result.Content {
		b.WriteString(c.Text)
		b.WriteString("\n")
	}
	text := b.String()
	if text == "" {
		text = string(res.rpc.Result)
	}
	// Some connectors report a failure only in the text — `isError` is optional
	// in the protocol and workspace-mcp does not always set it — so the
	// connector's own error prefix counts as a failure too.
	failed := result.IsError || strings.HasPrefix(strings.TrimSpace(text), "Error calling tool")
	return text, failed
}

func (h *liveHarness) auditRows() []store.AuditEvent {
	h.t.Helper()
	rows, err := h.st.QueryAudit(context.Background(), store.AuditQuery{Limit: 500})
	if err != nil {
		h.t.Fatalf("query audit: %v", err)
	}
	return rows
}

// lastToolRow is the most recent decision row for a tool, which is the row the
// acceptance gates read: it carries the class the manifest resolved.
func (h *liveHarness) lastToolRow(tool string) store.AuditEvent {
	h.t.Helper()
	var found store.AuditEvent
	var ok bool
	for _, r := range h.auditRows() {
		if r.Tool != tool {
			continue
		}
		if r.Event == store.EventConnectorToolCall || r.Event == store.EventPolicyViolation ||
			r.Event == store.EventConnectorDenied {
			found, ok = r, true
		}
	}
	if !ok {
		h.t.Fatalf("no decision row for tool %q", tool)
	}
	return found
}

// --- the proof ---------------------------------------------------------------

// TestLiveGoogleDriveReadThroughTheEdge — R7: a real Drive read, authorized by
// the shipped manifest, reaching real Google through the edge and the gateway.
func TestLiveGoogleDriveReadThroughTheEdge(t *testing.T) {
	h := newLiveHarness(t)

	text := h.mustCall("search_drive_files", map[string]any{"query": "trashed = false", "page_size": 3})
	if strings.Contains(strings.ToLower(text), "insufficient authentication scopes") {
		t.Fatalf("Drive read was refused at scope level; the grant is missing drive.readonly: %s", text)
	}
	t.Logf("search_drive_files returned:\n%s", text)

	row := h.lastToolRow("search_drive_files")
	if row.Outcome != store.OutcomeAllowed || row.ActionClass != string(connectors.ActionRead) {
		t.Fatalf("audit row = %+v, want an allowed read", row)
	}

	// A specific file read, when one was named — this is the artifact-id path.
	if h.env.driveDoc != "" {
		text := h.mustCall("get_drive_file_content", map[string]any{"file_id": h.env.driveDoc})
		t.Logf("get_drive_file_content returned %d bytes of text", len(text))
		row := h.lastToolRow("get_drive_file_content")
		if row.ArtifactID != h.env.driveDoc {
			t.Errorf("audited artifact id %q, want the file id %q", row.ArtifactID, h.env.driveDoc)
		}
	}
}

// TestLiveGoogleDriveWriteIsRefused — D18's live half. The refusal must happen
// at the MANIFEST, before the gateway is touched at all, and be audited as a
// policy violation.
func TestLiveGoogleDriveWriteIsRefused(t *testing.T) {
	h := newLiveHarness(t)

	res, text := h.call("create_drive_file", map[string]any{
		"file_name":    "homeplane-live-proof-must-not-exist.txt",
		"content":      "this call must never reach Google",
		"mime_type":    "text/plain",
		"content_type": "text/plain",
	})
	if res.status == http.StatusOK && res.rpc.Error == nil {
		t.Fatalf("a Drive write was ADMITTED: %s", text)
	}
	t.Logf("create_drive_file refused: HTTP %d %s", res.status, strings.TrimSpace(text))

	row := h.lastToolRow("create_drive_file")
	if row.Event != store.EventPolicyViolation || row.Outcome != store.OutcomeDenied {
		t.Fatalf("audit row = %+v, want a denied policy violation", row)
	}
	if row.Reason != connectors.ReasonExcludedTool {
		t.Fatalf("denial reason %q, want %q", row.Reason, connectors.ReasonExcludedTool)
	}
	if !strings.Contains(row.Detail["exclusion_reason"], "D18") {
		t.Errorf("exclusion reason %q does not name the deciding policy", row.Detail["exclusion_reason"])
	}
}

// TestLiveGoogleCalendarSixOp — R8's reversible write, end to end on an
// isolated event: create, read back, update, verify, delete, verify cleanup.
func TestLiveGoogleCalendarSixOp(t *testing.T) {
	h := newLiveHarness(t)

	// The summary is the only handle the cleanup has if the event id cannot be
	// parsed, so it has to be unique against every OTHER run — including one
	// starting in the same second on another machine. Timestamp for a human
	// reading the calendar, machine and harness for provenance, and 64 bits of
	// CSPRNG so two runs cannot collide by construction.
	stamp := time.Now().UTC().Format("20060102T150405Z")
	summary := fmt.Sprintf("homeplane-test-%s-%s-%s-%s",
		stamp, sanitizeForSummary(nodeA.NodeName), sanitizeForSummary(policy.HarnessClaudeCode), randomSuffix(t))
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	end := start.Add(time.Hour)
	rfc := func(tm time.Time) string { return tm.Format("2006-01-02T15:04:05Z") }

	// STEP 0 — isolation: nothing by this name exists yet.
	before := h.mustCall("get_events", map[string]any{
		"calendar_id": h.env.calendar, "query": summary, "max_results": 5,
	})
	if strings.Contains(before, summary) {
		t.Fatalf("an event named %q already exists; the proof refuses to touch it:\n%s", summary, before)
	}

	// The event is deleted no matter how this test ends. A leftover event on a
	// real calendar is the one failure mode this proof must not have, so the
	// cleanup is armed the moment the CREATE is attempted — not once the id has
	// been parsed out of the connector's prose. Parsing is exactly the step that
	// can fail while the event nevertheless exists, and when it does the cleanup
	// finds the event by its unique summary instead.
	var eventID string
	cleanupNeeded := false
	t.Cleanup(func() {
		if !cleanupNeeded {
			return
		}
		id := eventID
		if id == "" {
			id = h.findEventBySummary(summary)
		}
		if id == "" {
			t.Errorf("CLEANUP FAILED — an event named %q may exist on calendar %q and could not be located; "+
				"DELETE IT BY HAND", summary, h.env.calendar)
			return
		}
		res, text := h.call("manage_event", map[string]any{
			"action": "delete", "event_id": id, "calendar_id": h.env.calendar, "send_updates": "none",
		})
		_, failed := toolText(res)
		if res.status != http.StatusOK || res.rpc.Error != nil || failed {
			t.Errorf("CLEANUP FAILED — DELETE THIS EVENT BY HAND: calendar %q event %q (%s)",
				h.env.calendar, id, strings.TrimSpace(text))
			return
		}
		// A provider that ANSWERS "deleted" has not proved the artifact is gone.
		// The cleanup re-queries and reports whatever remains, because the only
		// acceptable end state for this test is a calendar with nothing of ours
		// on it.
		if remainder := h.remainingEvent(summary, id); remainder != "" {
			t.Errorf("CLEANUP INCOMPLETE — DELETE THIS BY HAND: calendar %q still lists %s",
				h.env.calendar, remainder)
		}
	})

	// STEP 1 — create. The cleanup is armed BEFORE the call that might create the
	// event, so a failure anywhere after this point still deletes it. It is
	// disarmed only once step 5 has verifiably deleted it.
	cleanupNeeded = true
	text := h.mustCall("manage_event", map[string]any{
		"action": "create", "calendar_id": h.env.calendar, "summary": summary,
		"start_time": rfc(start), "end_time": rfc(end),
		"description": "v1 created by the Homeplane live connector proof (" + stamp + ")",
		// No attendees are involved, but the manifest guard requires this
		// explicitly: the connector's default notifies everyone, and the proof
		// must exercise the path a real caller has to take.
		"send_updates": "none",
	})
	eventID = extractEventID(text)
	if eventID == "" {
		t.Fatalf("create returned no event id:\n%s", text)
	}
	t.Logf("STEP 1 create: event %s", eventID)
	if row := h.lastToolRow("manage_event"); row.ActionClass != string(connectors.ActionWrite) {
		t.Errorf("create audited as %q, want write", row.ActionClass)
	}

	// STEP 2 — read back.
	text = h.mustCall("get_events", map[string]any{"calendar_id": h.env.calendar, "event_id": eventID})
	if !strings.Contains(text, summary) {
		t.Fatalf("read back did not return the created event:\n%s", text)
	}
	t.Logf("STEP 2 read back: ok")
	if row := h.lastToolRow("get_events"); row.ArtifactID != eventID {
		t.Errorf("read back audited artifact %q, want %q", row.ArtifactID, eventID)
	}

	// STEP 3 — update.
	text = h.mustCall("manage_event", map[string]any{
		"action": "update", "event_id": eventID, "calendar_id": h.env.calendar,
		"description":  "v2 updated by the Homeplane live connector proof (" + stamp + ")",
		"send_updates": "none",
	})
	t.Logf("STEP 3 update: ok (%s)", firstLine(text))
	if row := h.lastToolRow("manage_event"); row.ActionClass != string(connectors.ActionWrite) || row.ArtifactID != eventID {
		t.Errorf("update audited as %+v, want a write on %s", row, eventID)
	}

	// STEP 4 — verify the update landed.
	text = h.mustCall("get_events", map[string]any{
		"calendar_id": h.env.calendar, "event_id": eventID, "detailed": true,
	})
	if !strings.Contains(text, "v2 updated") {
		t.Fatalf("the update is not visible on the event:\n%s", text)
	}
	t.Logf("STEP 4 verify: v2 present")

	// STEP 5 — delete, through the SAME tool, resolved to the delete class.
	text = h.mustCall("manage_event", map[string]any{
		"action": "delete", "event_id": eventID, "calendar_id": h.env.calendar, "send_updates": "none",
	})
	t.Logf("STEP 5 delete: ok (%s)", firstLine(text))
	deleteRow := h.lastToolRow("manage_event")
	if deleteRow.ActionClass != string(connectors.ActionDelete) {
		t.Fatalf("the delete was audited as %q, want delete-class", deleteRow.ActionClass)
	}
	if deleteRow.ArtifactID != eventID {
		t.Errorf("the delete audited artifact %q, want %q", deleteRow.ArtifactID, eventID)
	}
	deleted := eventID

	// STEP 6 — verify cleanup. The delete RESPONSE is not the proof; the
	// after-listing is, and it must show neither the id nor the summary. Only
	// once that holds is the cleanup disarmed — a "deleted" answer followed by
	// an event that is still there has to leave the retry armed.
	after := h.mustCall("get_events", map[string]any{
		"calendar_id": h.env.calendar, "query": summary, "max_results": 5,
	})
	if strings.Contains(after, deleted) || strings.Contains(after, summary) {
		t.Fatalf("the deleted event %s is still listed:\n%s", deleted, after)
	}
	cleanupNeeded = false // proven absent, not merely reported deleted
	t.Logf("STEP 6 verify cleanup: %s is gone from the after-listing", deleted)

	// The whole sequence, metadata only: the event summary passed through the
	// broker on four calls and may appear in no audit row.
	for _, row := range h.auditRows() {
		for k, v := range row.Detail {
			if strings.Contains(v, summary) {
				t.Fatalf("audit row detail %s carried the event summary: %+v", k, row)
			}
		}
		if strings.Contains(row.ArtifactID, summary) {
			t.Fatalf("audit row artifact id carried the event summary: %+v", row)
		}
	}
}

// TestLiveGoogleRevokedGrantIsRefusedImmediately — the grant is resolved from
// the store on every request, so revocation takes effect on the next call
// rather than at the end of a cache TTL.
func TestLiveGoogleRevokedGrantIsRefusedImmediately(t *testing.T) {
	h := newLiveHarness(t)

	h.mustCall("search_drive_files", map[string]any{"query": "trashed = false", "page_size": 1})

	revokedAt := time.Now()
	if _, _, err := h.st.RevokeGrant(context.Background(), h.grant.ID, "revoked_by_operator",
		func(g store.Grant) []store.AuditEvent {
			return []store.AuditEvent{{
				Event: store.EventGrantRevoked, ActorKind: store.ActorOperator,
				AuthMachineID: g.MachineID, Harness: g.Harness, GrantID: g.ID,
				Outcome: store.OutcomeAllowed, Reason: "revoked_by_operator",
			}}
		}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	res, _ := h.call("search_drive_files", map[string]any{"query": "trashed = false", "page_size": 1})
	elapsed := time.Since(revokedAt)
	if res.status != http.StatusUnauthorized {
		t.Fatalf("after revocation: HTTP %d, want 401", res.status)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("revocation took %s to take effect", elapsed)
	}
	t.Logf("revoked grant refused %s after revocation (HTTP %d)", elapsed.Round(time.Millisecond), res.status)
}

// extractEventID finds an event's id in the connector's text result.
//
// The manifest's declarative extractor cannot do this: workspace-mcp answers in
// prose, and the extractor addresses JSON. That is a recorded limitation, not a
// silent one — the create call's audit row carries artifact id `unknown` plus an
// args digest, and every later operation on the event names it in the request,
// where the extractor does reach it.
//
// Two shapes appear, and the id is read from whichever is present rather than
// from a guess: the `eid=` parameter of a calendar link, which is
// base64url("<event id> <calendar id>"), and a literal `ID: <id>`.
func extractEventID(text string) string {
	if id := eventIDFromLink(text); id != "" {
		return id
	}
	for _, line := range strings.Split(text, "\n") {
		for _, marker := range []string{"Event ID:", "event_id:", "ID:"} {
			i := strings.Index(line, marker)
			if i < 0 {
				continue
			}
			candidate := strings.TrimSpace(line[i+len(marker):])
			if f := strings.Fields(candidate); len(f) > 0 {
				candidate = f[0]
			}
			if candidate = strings.Trim(candidate, "`'\"(),.;:"); isEventID(candidate) {
				return candidate
			}
		}
	}
	return ""
}

// eventIDFromLink decodes the `eid=` parameter Google puts in an event link.
func eventIDFromLink(text string) string {
	rest := text
	for {
		i := strings.Index(rest, "eid=")
		if i < 0 {
			return ""
		}
		rest = rest[i+len("eid="):]
		raw := rest
		if j := strings.IndexAny(raw, "\"'\n\t &)>"); j >= 0 {
			raw = raw[:j]
		}
		if padded := raw + strings.Repeat("=", (4-len(raw)%4)%4); padded != "" {
			if decoded, err := base64.URLEncoding.DecodeString(padded); err == nil {
				if f := strings.Fields(string(decoded)); len(f) > 0 && isEventID(f[0]) {
					return f[0]
				}
			}
		}
	}
}

// findEventBySummary is the cleanup's last resort: ask the calendar for the
// uniquely named event and read its id back out.
func (h *liveHarness) findEventBySummary(summary string) string {
	h.t.Helper()
	_, text := h.call("get_events", map[string]any{
		"calendar_id": h.env.calendar, "query": summary, "max_results": 5,
	})
	if !strings.Contains(text, summary) {
		return ""
	}
	return extractEventID(text)
}

// remainingEvent reports what the calendar still lists for this proof's event,
// or "" when nothing of ours is left. It is the cleanup's own verification: a
// provider that answers "deleted" has reported an intention, not a state.
func (h *liveHarness) remainingEvent(summary, id string) string {
	h.t.Helper()
	_, text := h.call("get_events", map[string]any{
		"calendar_id": h.env.calendar, "query": summary, "max_results": 5,
	})
	switch {
	case strings.Contains(text, id):
		return "event " + id
	case strings.Contains(text, summary):
		return "an event named " + summary
	default:
		return ""
	}
}

// randomSuffix is 64 bits of CSPRNG, so two runs cannot pick the same summary.
func randomSuffix(t *testing.T) string {
	t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("generate a unique test-event suffix: %v", err)
	}
	return hex.EncodeToString(buf[:])
}

// sanitizeForSummary keeps the provenance parts of a summary to characters that
// survive a round trip through a calendar and a text search.
func sanitizeForSummary(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + 32)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// firstLine keeps a log line readable when a connector answers with prose.
func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 120 {
		line = line[:120] + "…"
	}
	return line
}

func isEventID(s string) bool {
	if len(s) < 16 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}
