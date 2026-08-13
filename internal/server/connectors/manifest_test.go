package connectors

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/policy"
)

func TestManifestLoadsAndIndexesTheDeclaredConnectors(t *testing.T) {
	e := stubEngine(t)

	if got, want := e.Providers(), []string{"stub-notes"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("providers = %v, want %v", got, want)
	}
	c, ok := e.Connector("stub-notes")
	if !ok {
		t.Fatal("stub-notes not registered")
	}
	if c.CredentialRef != "stub/oauth-session" {
		t.Fatalf("credential_ref = %q", c.CredentialRef)
	}
	if c.Credential.Driver != DriverOAuth2AuthCode {
		t.Fatalf("driver = %q", c.Credential.Driver)
	}
	if refs := e.CredentialRefs(); refs["stub-notes"] != "stub/oauth-session" {
		t.Fatalf("credential refs = %v", refs)
	}
}

func TestRequiredCapabilityDefaultsFromActionClass(t *testing.T) {
	e := stubEngine(t)
	c, _ := e.Connector("stub-notes")

	want := map[string]policy.Capability{
		"list_notes":  policy.ConnectorRead,
		"create_note": policy.ConnectorWrite,
		"delete_note": policy.ConnectorDelete,
		"share_note":  policy.ConnectorSend,
	}
	for _, tool := range c.Tools {
		if w, ok := want[tool.Tool]; ok && tool.RequiredCapability() != w {
			t.Errorf("%s requires %q, want %q", tool.Tool, tool.RequiredCapability(), w)
		}
	}
}

func TestManifestRejectsMalformedDeclarations(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))

	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr error
		wantMsg string
	}{
		{
			name:    "unsupported version",
			mutate:  func(s string) string { return strings.Replace(s, `"version": 1`, `"version": 2`, 1) },
			wantErr: ErrInvalidManifest,
			wantMsg: "unsupported version",
		},
		{
			name: "unknown field is refused rather than ignored",
			mutate: func(s string) string {
				return strings.Replace(s, `"tool": "list_notes", "action_class": "read"`,
					`"tool": "list_notes", "action_class": "read", "actionclass": "write"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "unknown field",
		},
		{
			name: "unknown action class",
			mutate: func(s string) string {
				return strings.Replace(s, `"tool": "list_notes", "action_class": "read"`,
					`"tool": "list_notes", "action_class": "peek"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "action_class",
		},
		{
			name: "unknown capability",
			mutate: func(s string) string {
				return strings.Replace(s, `"tool": "list_notes", "action_class": "read"`,
					`"tool": "list_notes", "action_class": "read", "capability": "connector.admin"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "unknown capability",
		},
		{
			name:    "unknown credential driver",
			mutate:  func(s string) string { return strings.Replace(s, `"oauth2-authcode"`, `"magic-links"`, 1) },
			wantErr: ErrUnknownDriver,
			wantMsg: "magic-links",
		},
		{
			name:    "missing required driver parameter",
			mutate:  func(s string) string { return strings.Replace(s, `"token_endpoint"`, `"redirect_path"`, 1) },
			wantErr: ErrInvalidManifest,
			wantMsg: "requires parameter",
		},
		{
			name: "non-https endpoint",
			mutate: func(s string) string {
				return strings.Replace(s, `"https://auth.stub.test/token"`, `"http://auth.stub.test/token"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "https URL",
		},
		{
			name: "inline secret instead of a reference",
			mutate: func(s string) string {
				return strings.Replace(s, `"stub/client-secret"`, `"GOCSPX-not a reference, an actual secret"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "must be a secret reference",
		},
		{
			name: "control: narrowing the declared scopes still loads",
			mutate: func(s string) string {
				return strings.Replace(s, `"scopes": ["notes.read", "notes.write"]`,
					`"scopes": ["notes.read"]`, 1)
			},
			wantErr: nil,
		},
		{
			name: "driver parameter the driver does not define",
			mutate: func(s string) string {
				return strings.Replace(s, `"client_id_ref": "stub/client-id",`,
					`"client_id_ref": "stub/client-id", "tenant": "acme",`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "has no parameter",
		},
		{
			name: "tool declared twice",
			mutate: func(s string) string {
				return strings.Replace(s, `{ "tool": "list_notes", "action_class": "read" },`,
					`{ "tool": "list_notes", "action_class": "read" }, { "tool": "list_notes", "action_class": "write" },`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "declared twice",
		},
		{
			name: "excluded tool without a reason",
			mutate: func(s string) string {
				return strings.Replace(s, `"reason": "bulk export is out of scope for the skeleton"`, `"reason": ""`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "needs a reason",
		},
		{
			name: "extractor with an unparseable pointer",
			mutate: func(s string) string {
				return strings.Replace(s, `"pointer": "$.note_id"`, `"pointer": "note_id"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "pointer",
		},
		{
			name: "extractor reading an unknown source",
			mutate: func(s string) string {
				return strings.Replace(s, `"source": "request", "pointer": "$.note_id"`,
					`"source": "headers", "pointer": "$.note_id"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "want request or response",
		},
		{
			name: "unknown transport",
			mutate: func(s string) string {
				return strings.Replace(s, `"transport": "stdio"`, `"transport": "carrier-pigeon"`, 1)
			},
			wantErr: ErrInvalidManifest,
			wantMsg: "transport",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(base)
			if mutated == base {
				t.Fatal("mutation did not change the fixture — the test asserts nothing")
			}
			_, err := Parse([]byte(mutated))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("want the mutated manifest to load, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error %q does not mention %q", err, tc.wantMsg)
			}
		})
	}
}

// The acceptance criterion "incomplete registration refused where the tool list
// is known": a connector that declares what its gateway exposes must account
// for all of it. Otherwise a gateway upgrade quietly adds an unclassified tool.
func TestIncompleteRegistrationIsRefused(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))

	dropped := strings.Replace(base,
		`,
      "excluded_tools": [
        { "tool": "export_archive", "reason": "bulk export is out of scope for the skeleton" }
      ]`, "", 1)
	if dropped == base {
		t.Fatal("fixture mutation failed: exclusion block not found")
	}

	_, err := Parse([]byte(dropped))
	if !errors.Is(err, ErrIncompleteRegistration) {
		t.Fatalf("error = %v, want ErrIncompleteRegistration", err)
	}
	if !strings.Contains(err.Error(), "export_archive") {
		t.Fatalf("error %q does not name the unclassified tool", err)
	}
}

// The mirror image: a mapping for a tool the gateway does not expose is also
// refused. A stale mapping hides a renamed or withdrawn tool.
func TestMappingForAToolOutsideTheInventoryIsRefused(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))
	phantom := strings.Replace(base, `{ "tool": "list_notes", "action_class": "read" },`,
		`{ "tool": "list_notes", "action_class": "read" }, { "tool": "list_notebooks", "action_class": "read" },`, 1)

	_, err := Parse([]byte(phantom))
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest", err)
	}
	if !strings.Contains(err.Error(), "list_notebooks") {
		t.Fatalf("error %q does not name the phantom mapping", err)
	}
}

// A connector whose gateway tool list is NOT known is still usable — unmapped
// tools simply fail closed at invocation time.
func TestUnknownToolInventoryIsAllowedAndStillFailsClosed(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))
	start := strings.Index(base, `"tool_inventory"`)
	end := strings.Index(base, `"tools"`)
	if start < 0 || end < 0 || end < start {
		t.Fatal("fixture layout changed")
	}
	noInventory := base[:start] + base[end:]

	m, err := Parse([]byte(noInventory))
	if err != nil {
		t.Fatalf("manifest without a tool inventory must load: %v", err)
	}
	e, err := Register(m)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	d := e.Authorize(req("stub-notes", "some_new_tool", `{}`, fullCaller()))
	if d.Allowed || d.Reason != ReasonUnmappedTool {
		t.Fatalf("decision = %+v, want denied/unmapped_tool", d)
	}
}

func TestParseRejectsTrailingContent(t *testing.T) {
	base := string(mustReadFixture(t, "stub.json"))
	if _, err := Parse([]byte(base + "\n{}\n")); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest", err)
	}
}

func TestLoadFileReportsAMissingManifest(t *testing.T) {
	if _, err := LoadFile("testdata/does-not-exist.json"); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error = %v, want ErrInvalidManifest", err)
	}
}

func TestRegisterRefusesAnInvalidManifestWholesale(t *testing.T) {
	m := Manifest{Version: ManifestVersion, Connectors: []Connector{
		{Provider: "ok"}, // clearly invalid: no credential, no server, no tools
	}}
	if _, err := Register(m); err == nil {
		t.Fatal("Register accepted an invalid manifest")
	}
}

func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	m := loadManifest(t, name) // proves the fixture itself is valid
	if len(m.Connectors) == 0 {
		t.Fatalf("fixture %s has no connectors", name)
	}
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}
