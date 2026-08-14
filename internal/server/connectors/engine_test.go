package connectors

import (
	"errors"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The capability matrix. Every row is decided from the manifest alone: no test
// here names a rule that lives in code rather than in the connector entry.
func TestAuthorizeEnforcesTheManifestsCapabilityRequirements(t *testing.T) {
	e := stubEngine(t)

	tests := []struct {
		name        string
		tool        string
		caller      Caller
		wantAllowed bool
		wantReason  string
		wantClass   ActionClass
	}{
		{
			name: "read grant, read tool", tool: "get_note", caller: readOnlyCaller(),
			wantAllowed: true, wantClass: ActionRead,
		},
		{
			name: "read-only grant invoking a write-class tool", tool: "create_note", caller: readOnlyCaller(),
			wantReason: ReasonCapabilityMissing, wantClass: ActionWrite,
		},
		{
			name: "matching write grant", tool: "create_note", caller: readWriteCaller(),
			wantAllowed: true, wantClass: ActionWrite,
		},
		{
			name: "write grant is not delete authority", tool: "delete_note", caller: readWriteCaller(),
			wantReason: ReasonCapabilityMissing, wantClass: ActionDelete,
		},
		{
			name: "delete grant deletes", tool: "delete_note", caller: fullCaller(),
			wantAllowed: true, wantClass: ActionDelete,
		},
		{
			name: "no harness policy grants send", tool: "share_note", caller: fullCaller(),
			wantReason: ReasonCapabilityMissing, wantClass: ActionSend,
		},
		{
			name: "unmapped tool fails closed", tool: "summarize_notes", caller: fullCaller(),
			wantReason: ReasonUnmappedTool, wantClass: ActionUnknown,
		},
		{
			name: "explicitly excluded tool fails closed", tool: "export_archive", caller: fullCaller(),
			wantReason: ReasonExcludedTool, wantClass: ActionUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Authorize(req("stub-notes", tc.tool, `{"note_id":"n-1"}`, tc.caller))
			if d.Allowed != tc.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason %q)", d.Allowed, tc.wantAllowed, d.Reason)
			}
			if d.Reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", d.Reason, tc.wantReason)
			}
			if d.ActionClass != tc.wantClass {
				t.Fatalf("action class = %q, want %q", d.ActionClass, tc.wantClass)
			}
			if !d.Allowed {
				err := d.DeniedError(req("stub-notes", tc.tool, "{}", tc.caller))
				if !errors.Is(err, ErrDenied) {
					t.Fatalf("denied error = %v, want ErrDenied", err)
				}
				if !strings.Contains(err.Error(), tc.tool) && tc.wantReason != ReasonUnknownProvider {
					t.Fatalf("denied error %q does not name the tool", err)
				}
			}
		})
	}
}

func TestAuthorizeDeniesAnUnknownConnector(t *testing.T) {
	d := stubEngine(t).Authorize(req("gmail", "send_message", `{}`, fullCaller()))
	if d.Allowed || d.Reason != ReasonUnknownProvider {
		t.Fatalf("decision = %+v, want denied/unknown_provider", d)
	}
	if !d.PolicyViolation() {
		t.Fatal("an unknown connector must be classified as a policy violation")
	}
}

// A tool call that cannot be attributed to a grant is never authorized — the
// capability set is a property of the grant, so no grant means no authority.
func TestAuthorizeRefusesAnUnattributedMachineCall(t *testing.T) {
	e := stubEngine(t)

	partial := readOnlyCaller()
	partial.GrantID = ""

	d := e.Authorize(req("stub-notes", "list_notes", `{}`, partial))
	if d.Allowed || d.Reason != ReasonUnauthenticated {
		t.Fatalf("decision = %+v, want denied/unauthenticated", d)
	}
	if d.PolicyViolation() {
		t.Fatal("an unauthenticated call is an authorization failure, not a manifest violation")
	}
}

// The operator actor is the server-local path (admin CLI): there is no observed
// node and no grant, and authority comes from being on the server itself.
func TestOperatorActorNeedsNoGrantButStillNeedsCapabilities(t *testing.T) {
	e := stubEngine(t)

	operator := Caller{Actor: store.ActorOperator, Capabilities: []string{string(policy.ConnectorRead)}}
	if d := e.Authorize(req("stub-notes", "list_notes", `{}`, operator)); !d.Allowed {
		t.Fatalf("operator read denied: %+v", d)
	}
	if d := e.Authorize(req("stub-notes", "create_note", `{}`, operator)); d.Allowed {
		t.Fatal("operator was allowed a write without the write capability")
	}
	if d := e.Authorize(req("stub-notes", "export_archive", `{}`, operator)); d.Allowed {
		t.Fatal("operator was allowed an excluded tool")
	}
}

func TestUnknownActorKindIsRefused(t *testing.T) {
	c := readOnlyCaller()
	c.Actor = store.ActorKind("robot")
	if d := stubEngine(t).Authorize(req("stub-notes", "list_notes", `{}`, c)); d.Allowed || d.Reason != ReasonInvalidActor {
		t.Fatalf("decision = %+v, want denied/invalid_actor", d)
	}
}

func TestCapabilityComparisonIgnoresCaseAndPadding(t *testing.T) {
	c := machineCaller()
	c.Capabilities = []string{"  CONNECTOR.READ  "}
	if d := stubEngine(t).Authorize(req("stub-notes", "list_notes", `{}`, c)); !d.Allowed {
		t.Fatalf("decision = %+v, want allowed", d)
	}
}

// D18: Drive is read-only in Homeplane — its read tools are mapped, its write
// tools are excluded and therefore denied fail-closed; Calendar carries read,
// write and delete (R8's reversible-write proof deletes what it created).
func TestD18ScopePolicyIsExpressedEntirelyInTheManifest(t *testing.T) {
	e := googleEngine(t)

	for _, tool := range []string{"search_files", "get_file_metadata", "read_file_content"} {
		if d := e.Authorize(req("google-drive", tool, `{"file_id":"f-1"}`, readOnlyCaller())); !d.Allowed {
			t.Errorf("drive %s denied: %+v", tool, d)
		}
	}
	for _, tool := range []string{"create_file", "update_file", "delete_file"} {
		d := e.Authorize(req("google-drive", tool, `{"file_id":"f-1"}`, fullCaller()))
		if d.Allowed {
			t.Errorf("drive %s was authorized despite D18's read-only policy", tool)
		}
		if d.Reason != ReasonExcludedTool || !d.PolicyViolation() {
			t.Errorf("drive %s: reason %q, want excluded_tool policy violation", tool, d.Reason)
		}
	}

	calendar := map[string]ActionClass{
		"list_events":  ActionRead,
		"get_event":    ActionRead,
		"create_event": ActionWrite,
		"update_event": ActionWrite,
		"delete_event": ActionDelete,
	}
	for tool, class := range calendar {
		d := e.Authorize(req("google-calendar", tool, `{"event_id":"e-1"}`, fullCaller()))
		if !d.Allowed {
			t.Errorf("calendar %s denied: %+v", tool, d)
		}
		if d.ActionClass != class {
			t.Errorf("calendar %s action class %q, want %q", tool, d.ActionClass, class)
		}
	}

	// A read-only grant reaches Drive but not Calendar's mutating half.
	for _, tool := range []string{"create_event", "delete_event"} {
		if d := e.Authorize(req("google-calendar", tool, `{}`, readOnlyCaller())); d.Allowed {
			t.Errorf("calendar %s allowed to a read-only grant", tool)
		}
	}
}

func TestUnmappedToolsReportsWhatAGatewayUpgradeAdded(t *testing.T) {
	e := stubEngine(t)
	advertised := []string{"list_notes", "create_note", "summarize_notes", "export_archive"}

	got := e.UnmappedTools("stub-notes", advertised)
	want := []string{"export_archive", "summarize_notes"}
	if len(got) != len(want) {
		t.Fatalf("unmapped = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unmapped = %v, want %v", got, want)
		}
	}
	// An unknown connector authorizes nothing at all.
	if got := e.UnmappedTools("nope", advertised); len(got) != len(advertised) {
		t.Fatalf("unmapped for an unknown connector = %v, want all %v", got, advertised)
	}
}
