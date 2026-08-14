package connectors

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The SHIPPED Google connector, not a fixture.
//
// These tests read `configs/connectors/google.json` — the file a real
// deployment passes to `-connector-manifest` — because the D18 scope policy is
// only worth anything if it holds in the manifest that actually runs. A fixture
// copy would let the shipped file drift into authorizing Drive writes while a
// green suite reported the policy intact.
//
// The tool names, the tool inventory and the argument names below are the live
// surface of the pinned connector (workspace-mcp v1.24.0, run through ToolHive
// as `uvx://workspace-mcp@1.24.0` with `--tools drive calendar`), enumerated
// from a running workload via `tools/list`.

const googleProvider = "google"

func shippedGooglePath(t *testing.T) string {
	t.Helper()
	// internal/server/connectors -> repo root
	p := filepath.Join("..", "..", "..", "configs", "connectors", "google.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the shipped Google manifest is missing at %s: %v", p, err)
	}
	return p
}

func shippedGoogleEngine(t *testing.T) *Engine {
	t.Helper()
	m, err := LoadFile(shippedGooglePath(t))
	if err != nil {
		t.Fatalf("load shipped Google manifest: %v", err)
	}
	e, err := Register(m)
	if err != nil {
		t.Fatalf("register shipped Google manifest: %v", err)
	}
	return e
}

func googleConnector(t *testing.T) Connector {
	t.Helper()
	c, ok := shippedGoogleEngine(t).Connector(googleProvider)
	if !ok {
		t.Fatalf("the shipped manifest declares no %q connector", googleProvider)
	}
	return c
}

// TestShippedGoogleManifestRegisters is the load-bearing one: registration
// REFUSES a connector that leaves any inventory tool unclassified, so a green
// result here means every tool the pinned connector advertises is either
// mapped with a class or excluded with a reason.
func TestShippedGoogleManifestRegisters(t *testing.T) {
	e := shippedGoogleEngine(t)
	if got := e.Providers(); len(got) != 1 || got[0] != googleProvider {
		t.Fatalf("providers = %v, want [%s]", got, googleProvider)
	}
	c := googleConnector(t)
	if len(c.ToolInventory) == 0 {
		t.Fatal("the connector declares no tool_inventory, so nothing forces complete registration")
	}
	if got, want := len(c.Tools)+len(c.Excluded), len(c.ToolInventory); got != want {
		t.Fatalf("%d classified tools for %d inventory tools", got, want)
	}
}

// TestShippedGoogleScopesAreTheD18Set — the consent screen Daniel sees is built
// from these strings. A widened scope here is a widened grant everywhere.
func TestShippedGoogleScopesAreTheD18Set(t *testing.T) {
	want := []string{
		"https://www.googleapis.com/auth/calendar.events",
		"https://www.googleapis.com/auth/calendar.readonly",
		"https://www.googleapis.com/auth/drive.readonly",
	}
	got := append([]string(nil), googleConnector(t).Credential.Scopes...)
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("scopes = %v, want exactly %v", got, want)
	}
}

// TestShippedGooglePinsTheConnectorVersion — an unpinned source would let a
// connector upgrade change the tool surface under a manifest that claims to
// have classified all of it.
func TestShippedGooglePinsTheConnectorVersion(t *testing.T) {
	src := googleConnector(t).Server.Source
	if !strings.HasPrefix(src, "uvx://workspace-mcp@") {
		t.Fatalf("mcp_server.source = %q, want the pinned uvx workspace-mcp spec", src)
	}
	if version := strings.TrimPrefix(src, "uvx://workspace-mcp@"); version == "" || strings.Contains(version, "latest") {
		t.Fatalf("mcp_server.source %q does not pin a version", src)
	}
}

// TestShippedGoogleDeliversItsCredentialDeclaratively — without a delivery
// format the workload gets no credential and every live call fails at the
// provider, which is a deployment mistake the manifest can catch.
func TestShippedGoogleDeliversItsCredentialDeclaratively(t *testing.T) {
	d := googleConnector(t).Delivery
	if d == nil {
		t.Fatal("the connector declares no credential_delivery")
	}
	if d.Format != FormatGoogleOAuthUserFile {
		t.Fatalf("credential_delivery format = %q, want %q", d.Format, FormatGoogleOAuthUserFile)
	}
}

// TestShippedGoogleDriveIsReadOnly is the D18 policy proof at the manifest
// level: the read surface is authorized for a read-only grant, and EVERY
// write-class Drive tool is refused as a policy violation even for a caller
// holding every capability there is.
func TestShippedGoogleDriveIsReadOnly(t *testing.T) {
	e := shippedGoogleEngine(t)

	for _, tool := range []string{"search_drive_files", "get_drive_file_content"} {
		d := e.Authorize(req(googleProvider, tool, `{"user_google_email":"u@example.test","file_id":"f-1","query":"x"}`, readOnlyCaller()))
		if !d.Allowed || d.ActionClass != ActionRead {
			t.Errorf("drive %s: %+v, want an allowed read", tool, d)
		}
	}

	// Every Drive tool that can change anything, including the two D18 names.
	writes := []string{
		"create_drive_file", "update_drive_file", "create_drive_folder", "copy_drive_file",
		"import_to_google_doc", "import_to_google_sheets", "import_to_google_slides",
		"manage_drive_access", "set_drive_file_permissions",
	}
	for _, tool := range writes {
		d := e.Authorize(req(googleProvider, tool, `{"user_google_email":"u@example.test","file_id":"f-1"}`, fullCaller()))
		if d.Allowed {
			t.Errorf("drive %s was authorized despite D18's read-only policy", tool)
		}
		if d.Reason != ReasonExcludedTool || !d.PolicyViolation() {
			t.Errorf("drive %s: reason %q, want an excluded_tool policy violation", tool, d.Reason)
		}
		if d.ExclusionReason == "" {
			t.Errorf("drive %s is excluded with no recorded reason", tool)
		}
	}
}

// TestShippedGoogleNeverLetsAHarnessStartItsOwnAuthFlow — the connector ships a
// `start_google_auth` tool that would run a provider OAuth dance inside the
// workload, putting a credential somewhere Homeplane does not own it.
func TestShippedGoogleNeverLetsAHarnessStartItsOwnAuthFlow(t *testing.T) {
	d := shippedGoogleEngine(t).Authorize(req(googleProvider, "start_google_auth", `{"user_google_email":"u@example.test"}`, fullCaller()))
	if d.Allowed || d.Reason != ReasonExcludedTool {
		t.Fatalf("start_google_auth: %+v, want an excluded_tool denial", d)
	}
}

// TestShippedGoogleCalendarActionClasses covers the polymorphic tool: one MCP
// tool, four effects, and the class — hence the capability required and the
// class audited — has to follow the effect rather than the tool name.
func TestShippedGoogleCalendarActionClasses(t *testing.T) {
	e := shippedGoogleEngine(t)

	for _, tc := range []struct {
		action string
		want   ActionClass
	}{
		{"create", ActionWrite},
		{"update", ActionWrite},
		{"delete", ActionDelete},
	} {
		args := `{"user_google_email":"u@example.test","action":"` + tc.action +
			`","event_id":"ev-1","send_updates":"none"}`
		d := e.Authorize(req(googleProvider, "manage_event", args, fullCaller()))
		if !d.Allowed {
			t.Fatalf("manage_event %s denied for a full grant: %+v", tc.action, d)
		}
		if d.ActionClass != tc.want {
			t.Errorf("manage_event %s classified %q, want %q", tc.action, d.ActionClass, tc.want)
		}
		if d.RequiredCapability != classCapability[tc.want] {
			t.Errorf("manage_event %s requires %q, want %q", tc.action, d.RequiredCapability, classCapability[tc.want])
		}
	}

	// A read grant reads, and a read+write grant creates but cannot delete:
	// the whole point of resolving the class per call.
	if d := e.Authorize(req(googleProvider, "get_events", `{"user_google_email":"u@example.test","event_id":"ev-1"}`, readOnlyCaller())); !d.Allowed || d.ActionClass != ActionRead {
		t.Errorf("get_events under a read grant: %+v, want an allowed read", d)
	}
	create := `{"user_google_email":"u@example.test","action":"create","summary":"x","send_updates":"none"}`
	if d := e.Authorize(req(googleProvider, "manage_event", create, readWriteCaller())); !d.Allowed {
		t.Errorf("manage_event create under a read+write grant: %+v, want allowed", d)
	}
	del := `{"user_google_email":"u@example.test","action":"delete","event_id":"ev-1","send_updates":"none"}`
	d := e.Authorize(req(googleProvider, "manage_event", del, readWriteCaller()))
	if d.Allowed {
		t.Fatal("a read+write grant deleted a calendar event")
	}
	if d.Reason != ReasonCapabilityMissing || d.RequiredCapability != policy.ConnectorDelete {
		t.Fatalf("manage_event delete under a read+write grant: %+v, want capability_missing on connector.delete", d)
	}
}

// TestShippedGoogleUnclassifiableCallIsRefused — a polymorphic tool asked to do
// something the manifest never classified must not be guessed at. This is the
// case a connector upgrade lands in when it adds a fifth action.
func TestShippedGoogleUnclassifiableCallIsRefused(t *testing.T) {
	e := shippedGoogleEngine(t)
	for name, args := range map[string]string{
		"unknown action": `{"user_google_email":"u@example.test","action":"purge_everything"}`,
		// RSVP is deliberately not a declared case: responding to an invitation
		// messages the organizer, and the connector gives no way to do it
		// silently. It therefore classifies as nothing and is refused.
		"rsvp":           `{"user_google_email":"u@example.test","action":"rsvp","event_id":"ev-1","response":"accepted"}`,
		"no action":      `{"user_google_email":"u@example.test","summary":"x"}`,
		"non-scalar":     `{"user_google_email":"u@example.test","action":{"nested":"delete"}}`,
		"malformed args": `not json`,
	} {
		d := e.Authorize(req(googleProvider, "manage_event", args, fullCaller()))
		if d.Allowed {
			t.Errorf("%s: manage_event was authorized without a classifiable action", name)
		}
		if d.Reason != ReasonUnresolvedAction || !d.PolicyViolation() {
			t.Errorf("%s: reason %q, want an unresolved_action policy violation", name, d.Reason)
		}
		if d.ActionClass != ActionUnknown {
			t.Errorf("%s: action class %q, want %q", name, d.ActionClass, ActionUnknown)
		}
	}
}

// TestShippedGoogleAuditRowsCarryTheResolvedClass — the audit log is the record
// the acceptance gate reads, so the resolved class and the artifact id have to
// reach it, and nothing else may.
func TestShippedGoogleAuditRowsCarryTheResolvedClass(t *testing.T) {
	e := shippedGoogleEngine(t)
	sink := &recordingSink{}
	b := NewBroker(e, newStubRuntime(), sink)
	ctx := context.Background()

	secret := "homeplane-test-20260814T000000Z-do-not-keep"
	calls := []struct {
		tool  string
		args  string
		class ActionClass
		id    string
	}{
		{"get_drive_file_content", `{"user_google_email":"u@example.test","file_id":"drive-file-1"}`, ActionRead, "drive-file-1"},
		{"manage_event", `{"user_google_email":"u@example.test","action":"create","summary":"` + secret + `","send_updates":"none"}`, ActionWrite, ArtifactUnknown},
		{"get_events", `{"user_google_email":"u@example.test","event_id":"ev-77"}`, ActionRead, "ev-77"},
		{"manage_event", `{"user_google_email":"u@example.test","action":"update","event_id":"ev-77","summary":"` + secret + `","send_updates":"none"}`, ActionWrite, "ev-77"},
		{"manage_event", `{"user_google_email":"u@example.test","action":"delete","event_id":"ev-77","send_updates":"none"}`, ActionDelete, "ev-77"},
	}
	for _, c := range calls {
		if _, err := b.Invoke(ctx, req(googleProvider, c.tool, c.args, fullCaller())); err != nil {
			t.Fatalf("%s(%s): %v", c.tool, c.args, err)
		}
	}

	// Two rows per admitted call: the decision, then the result.
	if len(sink.events) != 2*len(calls) {
		t.Fatalf("%d audit rows for %d calls, want %d", len(sink.events), len(calls), 2*len(calls))
	}
	for i, c := range calls {
		call := sink.events[2*i]
		if call.ActionClass != string(c.class) {
			t.Errorf("%s: audited action class %q, want %q", c.tool, call.ActionClass, c.class)
		}
		if call.ArtifactID != c.id {
			t.Errorf("%s: audited artifact id %q, want %q", c.tool, call.ArtifactID, c.id)
		}
		if call.Outcome != store.OutcomeAllowed {
			t.Errorf("%s: outcome %q, want allowed", c.tool, call.Outcome)
		}
		if call.Detail["provider"] != googleProvider {
			t.Errorf("%s: audited provider %q", c.tool, call.Detail["provider"])
		}
	}
	// Metadata only: the event summary went through the broker and must appear
	// in no row, in any field.
	assertNoPayload(t, sink.events, secret, "u@example.test")
}

// TestShippedGoogleDeniedDriveWriteIsAudited — the fail-closed refusal is only
// worth something if it leaves a record naming what was attempted.
func TestShippedGoogleDeniedDriveWriteIsAudited(t *testing.T) {
	sink := &recordingSink{}
	b := NewBroker(shippedGoogleEngine(t), newStubRuntime(), sink)

	_, err := b.Invoke(context.Background(), req(googleProvider, "create_drive_file",
		`{"user_google_email":"u@example.test","file_name":"nope.txt","content":"nope"}`, fullCaller()))
	if err == nil {
		t.Fatal("a Drive write was forwarded")
	}
	row := sink.only(t)
	if row.Event != store.EventPolicyViolation || row.Outcome != store.OutcomeDenied {
		t.Fatalf("row = %+v, want a denied policy violation", row)
	}
	if row.Reason != ReasonExcludedTool || row.Tool != "create_drive_file" {
		t.Fatalf("row = %+v, want excluded_tool on create_drive_file", row)
	}
	if row.ActionClass != string(ActionUnknown) {
		t.Errorf("action class %q, want %q: a refused call performed no class of action", row.ActionClass, ActionUnknown)
	}
	if !strings.Contains(row.Detail["exclusion_reason"], "D18") {
		t.Errorf("exclusion reason %q does not record the deciding policy", row.Detail["exclusion_reason"])
	}
}

// --- schema-level tests for the selector itself -----------------------------

func TestActionSelectorSchemaRefusals(t *testing.T) {
	base := func(mapping string) string {
		return `{"version":1,"connectors":[{
			"provider":"poly","credential_ref":"poly/session",
			"credential_acquisition":{"driver":"oauth2-authcode","params":{
				"auth_endpoint":"https://auth.test/authorize","token_endpoint":"https://auth.test/token",
				"client_id_ref":"poly/client-id","client_secret_ref":"poly/client-secret"},"scopes":["s"]},
			"mcp_server":{"name":"poly","transport":"stdio","source":"stub://in-process"},
			"tools":[` + mapping + `]}]}`
	}
	for name, mapping := range map[string]string{
		"both class and selector": `{"tool":"t","action_class":"write","action_selector":{"pointer":"$.a","cases":{"x":"write"}}}`,
		"neither":                 `{"tool":"t"}`,
		"no cases":                `{"tool":"t","action_selector":{"pointer":"$.a","cases":{}}}`,
		"bad pointer":             `{"tool":"t","action_selector":{"pointer":"a","cases":{"x":"write"}}}`,
		"unknown case class":      `{"tool":"t","action_selector":{"pointer":"$.a","cases":{"x":"obliterate"}}}`,
		"empty case value":        `{"tool":"t","action_selector":{"pointer":"$.a","cases":{"":"write"}}}`,
		// A selector-classified tool has no fixed class, so a capability field
		// could only ever contradict the resolved one.
		"capability restated": `{"tool":"t","capability":"connector.write","action_selector":{"pointer":"$.a","cases":{"x":"write"}}}`,
	} {
		if _, err := Parse([]byte(base(mapping))); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}

	if _, err := Parse([]byte(base(`{"tool":"t","action_selector":{"pointer":"$.a","cases":{"x":"write","y":"delete"}}}`))); err != nil {
		t.Fatalf("a well-formed selector mapping was refused: %v", err)
	}
}

// TestResolveActionClassIsTotal — resolution runs on caller-supplied bytes on
// every single call, so it must answer for anything at all rather than panic.
func TestResolveActionClassIsTotal(t *testing.T) {
	fixed := ToolMapping{Tool: "t", ActionClass: ActionWrite}
	if class, ok := fixed.ResolveActionClass(nil); !ok || class != ActionWrite {
		t.Fatalf("fixed mapping resolved (%q,%v), want (write,true)", class, ok)
	}
	sel := ToolMapping{Tool: "t", ActionSelector: &ActionSelector{
		Pointer: "$.action", Cases: map[string]ActionClass{"go": ActionWrite},
	}}
	for _, args := range []string{"", "null", "[]", `{"action":null}`, `{"action":["go"]}`, `{"action":"GO"}`, `{}`} {
		if class, ok := sel.ResolveActionClass(json.RawMessage(args)); ok {
			t.Errorf("args %q resolved to %q, want unresolved", args, class)
		}
	}
	if class, ok := sel.ResolveActionClass(json.RawMessage(`{"action":"go"}`)); !ok || class != ActionWrite {
		t.Fatalf("resolved (%q,%v), want (write,true)", class, ok)
	}
}

// TestShippedGoogleNotifyingCalendarCallsNeedSendAuthority is the guard the
// action class alone could not express.
//
// `manage_event` defaults `send_updates` to "all", so a create, update or
// delete on an event with attendees emails every one of them. That is send
// authority arriving through a write- or delete-classified tool, and no harness
// policy grants connector.send — so these calls must be refused however much
// write and delete authority the grant carries.
func TestShippedGoogleNotifyingCalendarCallsNeedSendAuthority(t *testing.T) {
	e := shippedGoogleEngine(t)

	for name, args := range map[string]string{
		// The connector's default: omitted means everyone is notified.
		"send_updates omitted": `{"user_google_email":"u@example.test","action":"create","summary":"x","attendees":["a@example.test"]}`,
		"send_updates all":     `{"user_google_email":"u@example.test","action":"update","event_id":"ev-1","send_updates":"all"}`,
		"externalOnly":         `{"user_google_email":"u@example.test","action":"delete","event_id":"ev-1","send_updates":"externalOnly"}`,
		// Anything the guard cannot read as one of its safe values applies.
		"non-scalar":  `{"user_google_email":"u@example.test","action":"create","send_updates":["none"]}`,
		"unlisted":    `{"user_google_email":"u@example.test","action":"create","send_updates":"NONE"}`,
		"null":        `{"user_google_email":"u@example.test","action":"create","send_updates":null}`,
		"empty value": `{"user_google_email":"u@example.test","action":"create","send_updates":""}`,
	} {
		d := e.Authorize(req(googleProvider, "manage_event", args, fullCaller()))
		if d.Allowed {
			t.Errorf("%s: a notifying calendar call was authorized without send authority", name)
			continue
		}
		if d.Reason != ReasonCapabilityMissing || d.RequiredCapability != policy.ConnectorSend {
			t.Errorf("%s: %+v, want capability_missing on connector.send", name, d)
		}
		if d.GuardReason == "" {
			t.Errorf("%s: the refusal records no reason, so the caller cannot tell why", name)
		}
		// The class is still the truth about what the call would have done.
		if d.ActionClass == ActionUnknown {
			t.Errorf("%s: action class %q, want the resolved class", name, d.ActionClass)
		}
	}

	// The safe value is the whole point: silent operations still work.
	for _, action := range []string{"create", "update", "delete"} {
		args := `{"user_google_email":"u@example.test","action":"` + action + `","event_id":"ev-1","send_updates":"none"}`
		if d := e.Authorize(req(googleProvider, "manage_event", args, fullCaller())); !d.Allowed {
			t.Errorf("silent %s was refused: %+v", action, d)
		}
	}
}

// TestShippedGoogleGuardIsACapabilityCheckNotABan — a grant that DID carry
// connector.send would be allowed to notify. The guard raises the bar; it does
// not hard-code a refusal, which is what keeps it a policy statement rather
// than a special case for one connector.
func TestShippedGoogleGuardIsACapabilityCheckNotABan(t *testing.T) {
	sender := machineCaller(policy.ConnectorRead, policy.ConnectorWrite,
		policy.ConnectorDelete, policy.ConnectorSend)
	args := `{"user_google_email":"u@example.test","action":"create","summary":"x","send_updates":"all"}`
	d := shippedGoogleEngine(t).Authorize(req(googleProvider, "manage_event", args, sender))
	if !d.Allowed {
		t.Fatalf("a grant holding connector.send was refused: %+v", d)
	}
	if d.ActionClass != ActionWrite {
		t.Errorf("action class %q, want write: the guard adds a requirement, it does not restate the class", d.ActionClass)
	}
}

// TestShippedGoogleNotifyingRefusalIsAudited — the refusal has to leave a
// record naming the authority the call was reaching for.
func TestShippedGoogleNotifyingRefusalIsAudited(t *testing.T) {
	sink := &recordingSink{}
	b := NewBroker(shippedGoogleEngine(t), newStubRuntime(), sink)

	_, err := b.Invoke(context.Background(), req(googleProvider, "manage_event",
		`{"user_google_email":"u@example.test","action":"delete","event_id":"ev-9"}`, fullCaller()))
	if err == nil {
		t.Fatal("a notifying delete was forwarded")
	}
	if !strings.Contains(err.Error(), "send_updates") {
		t.Errorf("the caller-facing error does not say what was wrong: %v", err)
	}
	row := sink.only(t)
	if row.Outcome != store.OutcomeDenied || row.Reason != ReasonCapabilityMissing {
		t.Fatalf("row = %+v, want a capability_missing denial", row)
	}
	if row.Detail["required_capability"] != string(policy.ConnectorSend) {
		t.Errorf("audited required_capability %q, want %q",
			row.Detail["required_capability"], policy.ConnectorSend)
	}
	if row.ActionClass != string(ActionDelete) {
		t.Errorf("audited action class %q, want delete", row.ActionClass)
	}
	if row.ArtifactID != "ev-9" {
		t.Errorf("audited artifact %q, want ev-9", row.ArtifactID)
	}
}

// TestArgumentGuardSchemaRefusals — a guard is an authorization input, so a
// malformed one is refused at load time rather than silently ignored.
func TestArgumentGuardSchemaRefusals(t *testing.T) {
	base := func(guard string) string {
		return `{"version":1,"connectors":[{
			"provider":"guarded","credential_ref":"guarded/session",
			"credential_acquisition":{"driver":"oauth2-authcode","params":{
				"auth_endpoint":"https://auth.test/authorize","token_endpoint":"https://auth.test/token",
				"client_id_ref":"guarded/client-id","client_secret_ref":"guarded/client-secret"},"scopes":["s"]},
			"mcp_server":{"name":"guarded","transport":"stdio","source":"stub://in-process"},
			"tools":[{"tool":"t","action_class":"write","capability_guards":[` + guard + `]}]}]}`
	}
	for name, guard := range map[string]string{
		"bad pointer":        `{"pointer":"notice","unless_in":["none"],"capability":"connector.send","reason":"r"}`,
		"unknown capability": `{"pointer":"$.notify","unless_in":["none"],"capability":"connector.everything","reason":"r"}`,
		"no safe values":     `{"pointer":"$.notify","unless_in":[],"capability":"connector.send","reason":"r"}`,
		"empty safe value":   `{"pointer":"$.notify","unless_in":[""],"capability":"connector.send","reason":"r"}`,
		"no reason":          `{"pointer":"$.notify","unless_in":["none"],"capability":"connector.send","reason":"  "}`,
	} {
		if _, err := Parse([]byte(base(guard))); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
	if _, err := Parse([]byte(base(`{"pointer":"$.notify","unless_in":["none"],"capability":"connector.send","reason":"notifies people"}`))); err != nil {
		t.Fatalf("a well-formed guard was refused: %v", err)
	}
}

// TestArgumentGuardAppliesIsTotal — Applies runs on caller-supplied bytes on
// every call, and every unreadable answer must land on the safe side.
func TestArgumentGuardAppliesIsTotal(t *testing.T) {
	g := ArgumentGuard{Pointer: "$.send_updates", UnlessIn: []string{"none", "quiet"},
		Capability: policy.ConnectorSend, Reason: "notifies attendees"}
	for _, args := range []string{
		"", "null", "[]", "not json", `{}`, `{"send_updates":"all"}`,
		`{"send_updates":null}`, `{"send_updates":{"mode":"none"}}`, `{"send_updates":123}`,
	} {
		if !g.Applies(json.RawMessage(args)) {
			t.Errorf("args %q did not apply the guard; doubt must fall on the safe side", args)
		}
	}
	for _, args := range []string{`{"send_updates":"none"}`, `{"send_updates":"quiet"}`} {
		if g.Applies(json.RawMessage(args)) {
			t.Errorf("args %q applied the guard despite naming a safe value", args)
		}
	}
}
