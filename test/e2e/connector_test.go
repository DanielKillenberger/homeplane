//go:build live_e2e

package e2e_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The server half: a brokered credential, real Google through the edge, the
// D18 refusals, R8's reversible write from BOTH harnesses, R9's revocation
// asymmetry, R10's truth table, and the audit review that ties them together.

const connectorServer = "homeplane"

// --- audit helpers -----------------------------------------------------------

// decisionRows keeps the rows the edge writes for a tool call: the admitted
// call, the policy violation, the denial. They are what the acceptance reads.
func decisionRows(rows []auditRow, tool string) []auditRow {
	var out []auditRow
	for _, r := range rows {
		if r.Tool != tool {
			continue
		}
		switch r.Event {
		case "connector_tool_call", "policy_violation", "connector_denied":
			out = append(out, r)
		}
	}
	return out
}

func lastRow(rows []auditRow) (auditRow, bool) {
	if len(rows) == 0 {
		return auditRow{}, false
	}
	return rows[len(rows)-1], true
}

func rowsForHarness(rows []auditRow, harness string) []auditRow {
	var out []auditRow
	for _, r := range rows {
		if r.Harness == harness {
			out = append(out, r)
		}
	}
	return out
}

// --- credentials (R13) -------------------------------------------------------

// stageCredentials brokers the real Google credential. A human consents in a
// browser on this machine; the credential lands on the server and nowhere else.
func stageCredentials(s *stage) {
	since := time.Now().UTC().Add(-24 * time.Hour)

	args := []string{"add-credentials", "google", "-timeout", "15m", "-poll-interval", "2s"}
	if os.Getenv("HOMEPLANE_E2E_REPLACE_CREDENTIAL") == "1" {
		args = append(args, "-replace")
	}
	s.t.Log("a browser window may open — consent as " + s.env.account +
		" (Drive read-only, Calendar events, Calendar read-only)")
	res := s.agent("homeplane-agent add-credentials google (real consent)", 20*time.Minute, args...)

	// Two acceptable outcomes, and they prove different halves of R13.
	//
	// A clean exit means the consent flow ran and the server stored what it
	// brokered. A refusal because the provider is ALREADY configured is the
	// other half — the flow will not silently overwrite a working credential —
	// and it is what a re-run of this stage hits, since the credential from the
	// first run is still there. Anything else is a failure.
	switch {
	case res.ExitCode == 0:
		s.assert("the consent flow completes and the server stores the credential", true,
			"consent given at %s", res.At)
	case strings.Contains(res.Stderr, "already has a credential"):
		s.assert("an already-configured provider is refused rather than silently overwritten", true,
			"exit %d: %s", res.ExitCode, firstLine(res.Stderr))
	default:
		s.assert("the consent flow completes and the server stores the credential", false,
			"exit %d%s", res.ExitCode, tail(res.Stderr))
		return
	}

	// Custody, checked on BOTH sides. The server must hold it…
	list := s.ssh("server: admin secret list", 60*time.Second,
		fmt.Sprintf("%s/bin/homeplane-server admin secret list -state-dir %s",
			serverPrefix(s.env), s.env.serverStateDir))
	s.assert("the credential is in the server's encrypted store",
		strings.Contains(list.full, "google/oauth-session") && strings.Contains(list.full, "true"),
		"%s", strings.TrimSpace(firstLine(list.full)))

	// …and this machine must hold nothing. The agent's own state is searched for
	// anything Google-token shaped, because "the machine never sees a provider
	// token" is only worth something if something looks. Harness configs are
	// searched too: they legitimately carry a Homeplane GRANT token, and a
	// provider token appearing there would be the custody failure itself.
	home, _ := os.UserHomeDir()
	leaks := scanForTokens(s, filepath.Join(home, ".homeplane"))
	leaks = append(leaks, scanForTokens(s, filepath.Join(home, ".codex", "config.toml"))...)
	leaks = append(leaks, scanForTokens(s, filepath.Join(home, ".claude.json"))...)
	s.assert("no provider token is anywhere on this machine", len(leaks) == 0,
		"searched the agent state, both harness configs; %d hit(s): %s", len(leaks), strings.Join(leaks, ", "))

	// The credential reached the connector workload, server-side only.
	delivered := s.ssh("server: the workload's credential file", 60*time.Second,
		fmt.Sprintf("ls -l %s/var/workload-creds", serverPrefix(s.env)))
	s.assert("the credential was delivered to the connector workload",
		strings.Contains(delivered.full, ".json"), "%s", firstLine(delivered.Stdout))

	rows := s.audit("server audit: the credential flow", since)
	var committed bool
	for _, r := range rows {
		if r.Event == "credential_flow_committed" && r.Outcome == "allowed" {
			committed = true
			s.assert("the credential commit is audited by ref and generation, never by value",
				r.Detail["secret_ref"] != "" && !strings.Contains(fmt.Sprint(r.Detail), "ya29."),
				"ref %s generation %s", r.Detail["secret_ref"], r.Detail["secret_generation"])
		}
	}
	s.assert("the server audited the credential commit", committed, "%d row(s) since %s", len(rows), since.Format(time.RFC3339))
}

// scanForTokens looks for Google token SHAPES in a file or tree.
//
// It cannot look for the credential's value: this machine never had it, which
// is the property under test. So it looks for the two prefixes Google's tokens
// carry — `ya29.` for an access token and `1//0` for a refresh token.
//
// The retrieval engine's index is skipped, and the reason is worth stating: it
// is a derivative of the VAULT, so it contains whatever Daniel has written in
// his own notes — including the words "refresh_token" in a note about OAuth.
// Searching it would report the vault's contents as a custody failure, which is
// how a check that cannot fail cleanly gets weakened until it stops checking.
// Nothing Homeplane brokers is ever written there.
func scanForTokens(s *stage, root string) []string {
	s.t.Helper()
	var found []string
	skip := filepath.Join(root, "gno")
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path == skip {
				return filepath.SkipDir
			}
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for _, marker := range []string{"ya29.", "1//0"} {
			if strings.Contains(string(body), marker) {
				found = append(found, path+" ("+marker+")")
				return nil
			}
		}
		return nil
	})
	return found
}

// --- connector reads and the D18 refusal (R7) --------------------------------

// stageConnector runs, from EACH harness, the Drive read the scope policy
// allows and the Drive write it does not.
func stageConnector(s *stage) {
	for _, h := range []harnessUnderProof{claudeCodeHarness, codexHarness} {
		since := time.Now().UTC().Add(-30 * time.Second)

		read := h.call(s, "Drive read via "+h.name, connectorServer, "search_drive_files", map[string]any{
			"query": "trashed = false", "page_size": 3, "user_google_email": s.env.account,
		})
		rows := s.audit("server audit after "+h.name+"'s Drive read", since)
		row, ok := lastRow(decisionRows(rowsForHarness(rows, h.grantHarness), "search_drive_files"))
		s.assert(h.name+": a Drive read reaches real Google through the edge",
			ok && row.Outcome == "allowed" && row.ActionClass == "read",
			"audit: outcome=%s class=%s grant=%s | harness said: %s",
			row.Outcome, row.ActionClass, row.GrantID, firstLine(read.text))

		since = time.Now().UTC().Add(-5 * time.Second)
		write := h.call(s, "Drive write (must be refused) via "+h.name, connectorServer, "create_drive_file", map[string]any{
			"file_name": "homeplane-e2e-must-not-exist.txt", "content": "this call must never reach Google",
			"mime_type": "text/plain", "user_google_email": s.env.account,
		})
		rows = s.audit("server audit after "+h.name+"'s Drive write attempt", since)
		row, ok = lastRow(decisionRows(rowsForHarness(rows, h.grantHarness), "create_drive_file"))
		s.assert(h.name+": a Drive write is refused fail-closed and audited as a policy violation",
			ok && row.Outcome == "denied" && row.Event == "policy_violation",
			"audit: event=%s outcome=%s reason=%s exclusion=%q | harness said: %s",
			row.Event, row.Outcome, row.Reason, row.Detail["exclusion_reason"], firstLine(write.text))
	}
}

// --- R8: the reversible write, from each harness -----------------------------

type harnessUnderProof struct {
	name         string
	grantHarness string
	call         func(s *stage, what, server, tool string, args map[string]any) harnessOutput
}

var claudeCodeHarness = harnessUnderProof{
	name: "Claude Code", grantHarness: "claude-code",
	call: func(s *stage, what, server, tool string, args map[string]any) harnessOutput {
		return s.claude(what, toolPrompt(server, tool, args, ""), "mcp__"+server)
	},
}

var codexHarness = harnessUnderProof{
	name: "Codex", grantHarness: "codex",
	call: func(s *stage, what, server, tool string, args map[string]any) harnessOutput {
		return s.codex(what, toolPrompt(server, tool, args, ""))
	},
}

// stageCalendar is R8 plus the guarded-path proof inherited from .12: six
// operations on an isolated event, every Calendar mutation carrying
// send_updates:"none", and one deliberate call WITHOUT it that must be refused
// as capability_missing.
func stageCalendar(s *stage) {
	for _, h := range []harnessUnderProof{claudeCodeHarness, codexHarness} {
		runSixOp(s, h)
	}
}

// sixOp is one harness's reversible-write proof, in the order R8 states it.
// Each step is its own method for one reason: the steps have to be able to STOP
// the sequence, and a 190-line function that "continues to be thorough" after a
// failed create is how a proof reports six green steps on an event that was
// never made.
type sixOp struct {
	s       *stage
	h       harnessUnderProof
	cal     string
	summary string
	stamp   string
	eventID string
	// armed is the cleanup's own state: set the moment a create is ATTEMPTED,
	// cleared only once the event is observed absent.
	armed bool
}

func runSixOp(s *stage, h harnessUnderProof) {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	op := &sixOp{
		s: s, h: h, cal: s.env.calendarID, stamp: stamp,
		summary: fmt.Sprintf("homeplane-e2e-%s-%s-%s", stamp, sanitize(h.grantHarness), randomSuffix(s)),
	}
	defer op.cleanup()

	if !op.isolated() {
		return
	}
	if !op.create() {
		return
	}
	if !op.readBack() {
		return
	}
	if !op.update() {
		return
	}
	if !op.verifyUpdate() {
		return
	}
	// The denial leg sits between verify and delete deliberately: it needs a
	// real event to act on, and it must not be what leaves one behind.
	op.denialLeg()
	if !op.delete() {
		return
	}
	if op.verifyCleanup() {
		op.armed = false
	}
	op.assertMetadataOnly()
}

// call makes one tool call as this harness and returns the harness's answer
// together with the SERVER's decision row for it — which is what every
// assertion below is settled on.
func (o *sixOp) call(what, tool string, args map[string]any) (harnessOutput, auditRow) {
	since := time.Now().UTC().Add(-30 * time.Second)
	args["user_google_email"] = o.s.env.account
	out := o.h.call(o.s, o.h.name+" "+what, connectorServer, tool, args)
	rows := o.s.audit("server audit after "+o.h.name+" "+what, since)
	row, _ := lastRow(decisionRows(rowsForHarness(rows, o.h.grantHarness), tool))
	return out, row
}

// isolated is STEP 0: nothing by this name exists, so nothing pre-existing can
// be touched by anything that follows. The listing must have REACHED Google —
// a harness whose model declined to call the tool has not established anything,
// and its error text satisfying "the summary is absent" would be the isolation
// check passing precisely when it did nothing.
func (o *sixOp) isolated() bool {
	out, row := o.call("step 0: the name is unused", "get_events", map[string]any{
		"calendar_id": o.cal, "query": o.summary, "max_results": 5,
	})
	return o.s.assert(o.h.name+": the test event's name is unused before the proof starts",
		row.Outcome == "allowed" && !strings.Contains(out.text, o.summary),
		"audit: outcome=%s | harness said: %s", row.Outcome, firstLine(out.text))
}

// create is STEP 1, through the GUARDED path: send_updates:"none" is what a real
// caller must pass, because the connector's default emails every attendee.
func (o *sixOp) create() bool {
	start := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Hour)
	o.armed = true // before the call, not after: the step that can fail while the event exists is the one that parses its id
	out, row := o.call("step 1: create", "manage_event", map[string]any{
		"action": "create", "calendar_id": o.cal, "summary": o.summary,
		"start_time": rfc3339(start), "end_time": rfc3339(start.Add(time.Hour)),
		"description":  "v1 — Homeplane end-to-end proof (" + o.stamp + ")",
		"send_updates": "none",
	})
	o.eventID = extractEventID(out.text)
	if !o.s.assert(o.h.name+" step 1: the guarded create is admitted and audited write-class",
		row.Outcome == "allowed" && row.ActionClass == "write",
		"audit: outcome=%s class=%s | harness said: %s", row.Outcome, row.ActionClass, firstLine(out.text)) {
		return false
	}
	return o.s.assert(o.h.name+" step 1: the created event's id is known",
		o.eventID != "", "the connector answered without an id: %s", firstLine(out.text))
}

// readBack is STEP 2.
func (o *sixOp) readBack() bool {
	out, row := o.call("step 2: read back", "get_events", map[string]any{
		"calendar_id": o.cal, "event_id": o.eventID,
	})
	return o.s.assert(o.h.name+" step 2: the read-back is audited read-class against the event",
		row.Outcome == "allowed" && row.ActionClass == "read" && row.ArtifactID == o.eventID &&
			strings.Contains(out.text, o.summary),
		"audit: class=%s artifact=%s | harness said: %s", row.ActionClass, row.ArtifactID, firstLine(out.text))
}

// update is STEP 3.
func (o *sixOp) update() bool {
	out, row := o.call("step 3: update", "manage_event", map[string]any{
		"action": "update", "event_id": o.eventID, "calendar_id": o.cal,
		"description":  "v2 — updated by the Homeplane end-to-end proof (" + o.stamp + ")",
		"send_updates": "none",
	})
	return o.s.assert(o.h.name+" step 3: the update is audited write-class against the event",
		row.Outcome == "allowed" && row.ActionClass == "write" && row.ArtifactID == o.eventID,
		"audit: class=%s artifact=%s | harness said: %s", row.ActionClass, row.ArtifactID, firstLine(out.text))
}

// verifyUpdate is STEP 4 — the update landed AT GOOGLE, not merely in an answer.
func (o *sixOp) verifyUpdate() bool {
	out, row := o.call("step 4: verify the update", "get_events", map[string]any{
		"calendar_id": o.cal, "event_id": o.eventID, "detailed": true,
	})
	return o.s.assert(o.h.name+" step 4: the update is visible on the event at Google",
		row.Outcome == "allowed" && row.ActionClass == "read" && strings.Contains(out.text, "v2"),
		"audit: class=%s artifact=%s | harness said: %s", row.ActionClass, row.ArtifactID, firstLine(out.text))
}

// denialLeg is the item inherited from .12: the same tool, the same event, one
// argument removed. Without send_updates:"none" the call asks to notify every
// attendee, which is send authority no skeleton harness holds. A guard only ever
// observed permitting is not a guard anyone has watched refuse.
func (o *sixOp) denialLeg() {
	out, row := o.call("denial leg: update WITHOUT send_updates", "manage_event", map[string]any{
		"action": "update", "event_id": o.eventID, "calendar_id": o.cal,
		"description": "this call must never reach Google",
	})
	o.s.assert(o.h.name+": an unguarded manage_event is refused as capability_missing",
		row.Outcome == "denied" && strings.Contains(row.Reason, "capability_missing"),
		"audit: event=%s outcome=%s reason=%s required=%s | harness said: %s",
		row.Event, row.Outcome, row.Reason, row.Detail["required_capability"], firstLine(out.text))
}

// delete is STEP 5, through the same tool, resolved to the delete class.
func (o *sixOp) delete() bool {
	out, row := o.call("step 5: delete", "manage_event", map[string]any{
		"action": "delete", "event_id": o.eventID, "calendar_id": o.cal, "send_updates": "none",
	})
	return o.s.assert(o.h.name+" step 5: the delete is audited delete-class against the event",
		row.Outcome == "allowed" && row.ActionClass == "delete" && row.ArtifactID == o.eventID,
		"audit: class=%s artifact=%s | harness said: %s", row.ActionClass, row.ArtifactID, firstLine(out.text))
}

// verifyCleanup is STEP 6, and it is three observations rather than one.
//
// The delete's ANSWER is not the proof, and neither is "the text does not
// mention it" — an error saying the server is unavailable contains neither the
// id nor the summary, and would disarm the cleanup on a calendar that still has
// the event. So every call here must be ADMITTED by the server (the audit says
// so), and absence is established positively:
//
//	6a  a direct get by id — Google returns a deleted event as `cancelled`, and
//	    what THIS connector renders of that is recorded rather than assumed;
//	6b  a summary-filtered listing, which excludes cancelled events, shows
//	    nothing of ours;
//	6c  a second delete answers Gone — the positive signal that the artifact is
//	    no longer there, from the provider rather than from our reading of prose.
func (o *sixOp) verifyCleanup() bool {
	direct, directRow := o.call("step 6a: get the deleted event directly", "get_events", map[string]any{
		"calendar_id": o.cal, "event_id": o.eventID,
	})
	lower := strings.ToLower(direct.text)
	saysCancelled := strings.Contains(lower, "cancelled") || strings.Contains(lower, "canceled") ||
		strings.Contains(lower, "not found") || strings.Contains(lower, "no events")
	admitted := o.s.assert(o.h.name+" step 6a: the direct get is admitted and audited against the event",
		directRow.Outcome == "allowed" && directRow.ArtifactID == o.eventID,
		"audit: outcome=%s artifact=%s | harness said: %s",
		directRow.Outcome, directRow.ArtifactID, firstLine(direct.text))
	if !saysCancelled {
		// A recorded limitation rather than a weakened assertion: Google DOES
		// return the deleted event with `status: cancelled` on a direct get, and
		// the pinned connector renders neither the status nor an error — so the
		// spec's "direct get shows cancelled/gone" cannot be read from this
		// connector's prose. 6b and 6c below carry the proof instead.
		o.s.recordLimitation(o.h.name+" step 6a: the direct get cannot express cancellation",
			"workspace-mcp 1.24.0 renders a cancelled event exactly like a live one — no status, no error — "+
				"so absence is proven by the filtered listing (6b) and by the provider answering Gone to a "+
				"second delete (6c) instead. Owner: a connector-side improvement, or a mapped tool that "+
				"surfaces event status.")
	}

	listing, listRow := o.call("step 6b: the summary-filtered listing", "get_events", map[string]any{
		"calendar_id": o.cal, "query": o.summary, "max_results": 5,
	})
	absent := o.s.assert(o.h.name+" step 6b: the after-listing shows no non-cancelled match",
		listRow.Outcome == "allowed" &&
			!strings.Contains(listing.text, o.summary) && !strings.Contains(listing.text, o.eventID),
		"audit: outcome=%s | harness said: %s", listRow.Outcome, firstLine(listing.text))

	regone, goneRow := o.call("step 6c: delete it again — the provider must say it is gone", "manage_event",
		map[string]any{
			"action": "delete", "event_id": o.eventID, "calendar_id": o.cal, "send_updates": "none",
		})
	goneLower := strings.ToLower(regone.text)
	gone := o.s.assert(o.h.name+" step 6c: the provider reports the event already gone",
		goneRow.Outcome == "allowed" &&
			(strings.Contains(goneLower, "410") || strings.Contains(goneLower, "gone") ||
				strings.Contains(goneLower, "deleted") || strings.Contains(goneLower, "not found")),
		"audit: outcome=%s class=%s | harness said: %s",
		goneRow.Outcome, goneRow.ActionClass, firstLine(regone.text))

	return admitted && absent && gone
}

// assertMetadataOnly checks THIS run's rows: the event summary passed through
// the broker on four calls and may appear in none of them.
func (o *sixOp) assertMetadataOnly() {
	rows := o.s.audit("server audit: metadata-only spot check",
		time.Now().UTC().Add(-20*time.Minute))
	leaked := ""
	for _, r := range rows {
		if strings.Contains(r.ArtifactID, o.summary) {
			leaked = "artifact_id"
		}
		for k, v := range r.Detail {
			if strings.Contains(v, o.summary) {
				leaked = "detail." + k
			}
		}
	}
	o.s.assert(o.h.name+": no audit row carries the event's summary (metadata only)",
		leaked == "", "checked %d rows from this run; leak in %q", len(rows), leaked)
}

// cleanup deletes the event no matter how the sequence ended, and refuses to
// shout about a leftover it can prove was never created.
func (o *sixOp) cleanup() {
	if !o.armed {
		return
	}
	id := o.eventID
	if id == "" {
		found, _ := o.call("CLEANUP: locate the event by its unique name", "get_events", map[string]any{
			"calendar_id": o.cal, "query": o.summary, "max_results": 5,
		})
		id = extractEventID(found.text)
	}
	if id == "" {
		// Before shouting, ask the server whether this harness ever got a create
		// THROUGH. A harness that never reached the connector cannot have left an
		// event, and "DELETE IT BY HAND" on a calendar where nothing was created
		// is a false alarm that teaches an operator to ignore the real one.
		var created bool
		for _, r := range decisionRows(rowsForHarness(o.s.audit(
			"CLEANUP: did this harness ever create anything?",
			time.Now().UTC().Add(-30*time.Minute)), o.h.grantHarness), "manage_event") {
			if r.Outcome == "allowed" && r.ActionClass == "write" {
				created = true
			}
		}
		if !created {
			o.s.assert(o.h.name+": no test event was left behind", true,
				"the server audited no admitted create for this harness; nothing to clean up")
			return
		}
		o.s.assert(o.h.name+": the test event was cleaned up", false,
			"CLEANUP FAILED — an event named %q may exist on calendar %q and could not be located; DELETE IT BY HAND",
			o.summary, o.cal)
		return
	}
	del, _ := o.call("CLEANUP: delete the leftover event", "manage_event", map[string]any{
		"action": "delete", "event_id": id, "calendar_id": o.cal, "send_updates": "none",
	})
	after, afterRow := o.call("CLEANUP: confirm the event is gone", "get_events", map[string]any{
		"calendar_id": o.cal, "query": o.summary, "max_results": 5,
	})
	gone := afterRow.Outcome == "allowed" &&
		!strings.Contains(after.text, o.summary) && !strings.Contains(after.text, id)
	o.s.assert(o.h.name+": the test event was cleaned up", gone,
		"CLEANUP %s — calendar %q event %q: %s",
		map[bool]string{true: "ok", false: "INCOMPLETE — DELETE BY HAND"}[gone], o.cal, id, firstLine(del.text))
}

func rfc3339(t time.Time) string { return t.Format("2006-01-02T15:04:05Z") }

// --- R9: revocation asymmetry ------------------------------------------------

func stageRevocation(s *stage) {
	rep, _ := s.status()
	var claudeGrant, codexGrant string
	for _, g := range rep.Grants {
		if g.State != "active" {
			continue
		}
		switch g.Harness {
		case "claude-code":
			claudeGrant = g.GrantID
		case "codex":
			codexGrant = g.GrantID
		}
	}
	if !s.assert("both harnesses hold an active grant before revocation",
		claudeGrant != "" && codexGrant != "", "claude-code %s, codex %s", claudeGrant, codexGrant) {
		return
	}

	// The OPERATOR path: server-local admin CLI, the surface the spec gives an
	// operator for a machine they cannot touch.
	since := time.Now().UTC().Add(-30 * time.Second)
	revoked := time.Now()
	rev := s.ssh("server: admin revoke-grant (Claude Code)", 60*time.Second,
		fmt.Sprintf("%s/bin/homeplane-server admin revoke-grant -state-dir %s %s",
			serverPrefix(s.env), s.env.serverStateDir, claudeGrant))
	s.assert("the operator can revoke a grant from the server", rev.ExitCode == 0,
		"exit %d: %s", rev.ExitCode, firstLine(rev.Stdout+rev.Stderr))

	// The revoked harness fails; the other keeps working. Both are checked
	// against the AUDIT, so a harness that merely says "I could not" proves
	// nothing on its own.
	failing := claudeCodeHarness.call(s, "Claude Code after revocation (must fail)", connectorServer,
		"search_drive_files", map[string]any{"query": "trashed = false", "page_size": 1,
			"user_google_email": s.env.account})
	elapsed := time.Since(revoked)
	rows := s.audit("server audit after the revoked harness called", since)
	var refused bool
	var admittedAfter int
	for _, r := range rows {
		if r.Outcome == "denied" && (strings.Contains(r.Reason, "revoked") ||
			strings.Contains(r.Reason, "invalid_token") || strings.Contains(r.Reason, "unknown_grant")) {
			refused = true
		}
		// The property that matters is not only that something was refused: it
		// is that the revoked grant admitted no CALL afterwards. Lifecycle rows
		// about the grant — the revocation itself is an allowed operator action
		// carrying that grant id — are not calls, and counting them would make
		// this assertion fail on its own success.
		if r.Event == "connector_tool_call" && r.GrantID == claudeGrant &&
			r.Outcome == "allowed" && r.TS.After(revoked.UTC()) {
			admittedAfter++
		}
	}
	s.assert("the revoked harness is refused within seconds, and its grant admits nothing after",
		refused && admittedAfter == 0 && elapsed < 90*time.Second,
		"refusal audited=%v, %d call(s) admitted on the revoked grant after revocation, %s elapsed | harness said: %s",
		refused, admittedAfter, elapsed.Round(time.Second), firstLine(failing.text))

	working := codexHarness.call(s, "Codex after the other harness was revoked (must still work)",
		connectorServer, "search_drive_files", map[string]any{"query": "trashed = false", "page_size": 1,
			"user_google_email": s.env.account})
	rows = s.audit("server audit after the surviving harness called", since)
	row, ok := lastRow(decisionRows(rowsForHarness(rows, "codex"), "search_drive_files"))
	s.assert("the other harness is unaffected", ok && row.Outcome == "allowed",
		"audit: outcome=%s grant=%s | harness said: %s", row.Outcome, row.GrantID, firstLine(working.text))

	// status reconciles LIVE — a cached "active" would be the whole point missed.
	rep, _ = s.status()
	var revokedSeen bool
	for _, g := range rep.Grants {
		if g.GrantID == claudeGrant && g.State == "revoked" {
			revokedSeen = true
		}
	}
	s.assert("agent status shows the revoked grant via live reconcile", revokedSeen,
		"grants: %+v", rep.Grants)

	// Idempotence and the unknown-grant error, both named by R9.
	again := s.ssh("server: revoke the same grant again (idempotent)", 60*time.Second,
		fmt.Sprintf("%s/bin/homeplane-server admin revoke-grant -state-dir %s %s",
			serverPrefix(s.env), s.env.serverStateDir, claudeGrant))
	s.assert("repeat revocation is idempotent", again.ExitCode == 0,
		"exit %d: %s", again.ExitCode, firstLine(again.Stdout+again.Stderr))

	unknown := s.ssh("server: revoke a grant that does not exist", 60*time.Second,
		fmt.Sprintf("%s/bin/homeplane-server admin revoke-grant -state-dir %s grant-does-not-exist",
			serverPrefix(s.env), s.env.serverStateDir))
	s.assert("revoking an unknown grant is an error, not a silent success", unknown.ExitCode != 0,
		"exit %d: %s", unknown.ExitCode, firstLine(unknown.Stderr))

	// The MACHINE-AUTHENTICATED path, which R9 names alongside the operator's.
	// It is the API a machine uses to revoke its own grant, and its error
	// contract is an HTTP status — so the proof reads the status rather than a
	// shell exit code, which cannot tell 404 from anything else.
	machineRevocation(s, codexGrant)

	// The restore: re-running configure-harnesses mints a fresh grant for BOTH
	// harnesses and rewrites their configs — which is also how the machine is
	// left working when the proof ends.
	restore := s.agent("homeplane-agent configure-harnesses (restore the revoked harness)", 5*time.Minute,
		"configure-harnesses", "-json")
	s.assert("the revoked harness recovers by re-running configure-harnesses", restore.ExitCode == 0,
		"exit %d%s", restore.ExitCode, tail(restore.Stderr))
	rep, _ = s.status()
	active := map[string]string{}
	for _, g := range rep.Grants {
		if g.State == "active" {
			active[g.Harness] = g.GrantID
		}
	}
	s.assert("both revoked harnesses hold a NEW active grant",
		active["claude-code"] != "" && active["claude-code"] != claudeGrant &&
			active["codex"] != "" && active["codex"] != codexGrant,
		"claude-code %s (was %s), codex %s (was %s)",
		active["claude-code"], claudeGrant, active["codex"], codexGrant)
}

// machineRevocation exercises `DELETE /grants/{id}` with the machine's own
// credential: the path a machine takes to drop a grant without an operator, and
// the one whose errors are HTTP statuses.
//
// The credential is read from this machine's own 0600 state file, which is where
// the agent keeps it and the only place it exists. Nothing is written back.
func machineRevocation(s *stage, grantID string) {
	home, err := os.UserHomeDir()
	if err != nil {
		s.assert("the machine credential could be located", false, "%v", err)
		return
	}
	credPath := filepath.Join(home, ".homeplane", "machine.cred")
	if info, statErr := os.Stat(credPath); statErr != nil {
		s.assert("the machine credential could be located", false, "%v", statErr)
		return
	} else if perm := info.Mode().Perm(); perm != 0o600 {
		s.assert("the machine credential is 0600", false, "%s has mode %o", credPath, perm)
	}
	raw, err := os.ReadFile(credPath)
	if err != nil {
		s.assert("the machine credential could be read", false, "%v", err)
		return
	}
	credential := strings.TrimSpace(string(raw))

	// curl writes the status code and nothing else, so the credential never
	// reaches a recorded command line: it goes in a header file curl reads.
	headerFile := filepath.Join(s.t.TempDir(), "auth")
	if err := os.WriteFile(headerFile, []byte("Authorization: Bearer "+credential+"\n"), 0o600); err != nil {
		s.assert("the machine credential could be staged for the request", false, "%v", err)
		return
	}

	del := s.run("machine: DELETE /grants/"+grantID, 60*time.Second,
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20",
		"-X", "DELETE", "-H", "@"+headerFile, s.env.serverURL+"/grants/"+grantID)
	s.assert("a machine can revoke its own grant over the API",
		strings.TrimSpace(del.full) == "204" || strings.TrimSpace(del.full) == "200",
		"HTTP %s", strings.TrimSpace(del.full))

	repeat := s.run("machine: DELETE the same grant again", 60*time.Second,
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20",
		"-X", "DELETE", "-H", "@"+headerFile, s.env.serverURL+"/grants/"+grantID)
	s.assert("repeat revocation over the API is idempotent, not an error",
		strings.HasPrefix(strings.TrimSpace(repeat.full), "2"),
		"HTTP %s", strings.TrimSpace(repeat.full))

	missing := s.run("machine: DELETE a grant that does not exist", 60*time.Second,
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20",
		"-X", "DELETE", "-H", "@"+headerFile, s.env.serverURL+"/grants/g-does-not-exist")
	s.assert("an unknown grant is 404 over the API", strings.TrimSpace(missing.full) == "404",
		"HTTP %s", strings.TrimSpace(missing.full))
}

// --- helpers -----------------------------------------------------------------

func sanitize(s string) string {
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

func randomSuffix(s *stage) string {
	s.t.Helper()
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		s.t.Fatalf("generate a unique test-event suffix: %v", err)
	}
	return hex.EncodeToString(buf[:])
}

// extractEventID finds a Calendar event id in the connector's prose answer.
// Two shapes appear and the id is read from whichever is present: the `eid=`
// parameter of a calendar link (base64url of "<event id> <calendar id>") and a
// literal id line.
func extractEventID(text string) string {
	if id := eventIDFromLink(text); id != "" {
		return id
	}
	for _, line := range strings.Split(text, "\n") {
		for _, marker := range []string{"Event ID:", "event_id:", "ID:", "id:"} {
			i := strings.Index(line, marker)
			if i < 0 {
				continue
			}
			candidate := strings.TrimSpace(line[i+len(marker):])
			if f := strings.Fields(candidate); len(f) > 0 {
				candidate = f[0]
			}
			if candidate = strings.Trim(candidate, "`'\"(),.;:*"); isEventID(candidate) {
				return candidate
			}
		}
	}
	// A bare id on its own, anywhere in the answer.
	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '`' || r == '"' || r == '\''
	}) {
		if isEventID(strings.Trim(field, "()[],.;:*")) {
			return strings.Trim(field, "()[],.;:*")
		}
	}
	return ""
}

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
		padded := raw + strings.Repeat("=", (4-len(raw)%4)%4)
		if decoded, err := base64.URLEncoding.DecodeString(padded); err == nil {
			if f := strings.Fields(string(decoded)); len(f) > 0 && isEventID(f[0]) {
				return f[0]
			}
		}
	}
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
