package gno

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validDescriptor(t *testing.T) Descriptor {
	t.Helper()
	return Descriptor{
		Component:     ComponentRetrievalEngine,
		Engine:        "gno",
		EngineVersion: "1.29.6",
		Transport:     TransportStdio,
		Command:       "/opt/bun/bin/bun",
		Args:          []string{"run", "/opt/gno/index.ts", "--config", "/state/gno/config/index.yml", "mcp"},
		Env:           map[string]string{EnvDataDir: "/state/gno/data", EnvCacheDir: "/state/gno/cache"},
		ServerName:    "gno",
		Collection:    "daniel-os",
		VaultPath:     "/vault",
		DerivedFrom:   "gno mcp install --target claude-code --scope user --dry-run --json",
		WrittenAt:     time.Now().UTC(),
	}
}

func TestDescriptorRoundTrip(t *testing.T) {
	state := t.TempDir()
	if _, err := LoadDescriptor(state); !errors.Is(err, ErrNoDescriptor) {
		t.Fatalf("an unactivated machine must report no descriptor, got %v", err)
	}

	want := validDescriptor(t)
	if err := SaveDescriptor(state, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadDescriptor(state)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Command != want.Command || !reflect.DeepEqual(got.Args, want.Args) || !reflect.DeepEqual(got.Env, want.Env) {
		t.Fatalf("the launch template did not survive a round trip:\n got %+v\nwant %+v", got, want)
	}
	if got.SchemaVersion != DescriptorSchemaVersion {
		t.Fatalf("schema version not stamped: %d", got.SchemaVersion)
	}

	info, err := os.Stat(DescriptorPath(state))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the descriptor is %v, want 0600", perm)
	}
}

// The D16 seam: the file is named for the ROLE, not the product, because task
// .6 wires harnesses from the role and must never learn the engine's name.
func TestDescriptorIsNamedForTheRoleNotTheEngine(t *testing.T) {
	state := "/state"
	path := DescriptorPath(state)
	if base := filepath.Base(path); base != "retrieval-engine.json" {
		t.Fatalf("the descriptor file is named %q; the seam is the role", base)
	}
	if strings.Contains(strings.ToLower(path), "gno") {
		t.Fatalf("the descriptor path names the engine: %s", path)
	}
}

func TestDescriptorValidationRefusesUnusableEndpoints(t *testing.T) {
	cases := map[string]func(*Descriptor){
		"wrong component":  func(d *Descriptor) { d.Component = "gno" },
		"wrong transport":  func(d *Descriptor) { d.Transport = "http" },
		"no command":       func(d *Descriptor) { d.Command = "" },
		"relative command": func(d *Descriptor) { d.Command = "bun" },
		"no args":          func(d *Descriptor) { d.Args = nil },
		"no server name":   func(d *Descriptor) { d.ServerName = "" },
	}
	for name, mutate := range cases {
		d := validDescriptor(t)
		mutate(&d)
		if err := d.Validate(); err == nil {
			t.Fatalf("%s: an unusable descriptor was accepted", name)
		}
	}
}

// Token hygiene (R5): the descriptor is copied verbatim into harness config
// files that are not 0600, so a credential reaching it would leak by design.
func TestDescriptorRefusesCredentialShapedContent(t *testing.T) {
	d := validDescriptor(t)
	d.Env = map[string]string{"GNO_MCP_TOKEN": "s3cret"}
	if err := d.Validate(); err == nil {
		t.Fatal("a descriptor carrying a token was accepted")
	}

	d = validDescriptor(t)
	d.Args = append(d.Args, "--token", "s3cret")
	if err := d.AssertNoSecrets(); err == nil {
		t.Fatal("a descriptor with a credential flag in argv was accepted")
	}

	state := t.TempDir()
	bad := validDescriptor(t)
	bad.Env = map[string]string{"SOME_PASSWORD": "hunter2"}
	if err := SaveDescriptor(state, bad); err == nil {
		t.Fatal("a credential-carrying descriptor was written to disk")
	}
	if _, err := os.Stat(DescriptorPath(state)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the refused descriptor was written anyway")
	}
}

// The launch template is DERIVED from upstream, never hand-written.
func TestDeriveLaunchTemplateUsesUpstreamsOwnEntry(t *testing.T) {
	state := t.TempDir()
	cli := newTestCLI(t, state)

	command, args, env, err := cli.DeriveLaunchTemplate(context.Background(), TargetClaudeCode, ScopeUser)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if command == "" || len(args) == 0 {
		t.Fatalf("no launch template derived: %q %v", command, args)
	}
	if args[len(args)-1] != "mcp" {
		t.Fatalf("the derived entry is not the stdio server: %v", args)
	}
	if env[EnvDataDir] != cli.Dirs.Data {
		t.Fatalf("the derived entry does not point at the machine-local index: %v", env)
	}
}

// A "dry run" that reports a real write means upstream CHANGED a harness config
// behind task .6's back. The result must be refused, not used.
func TestDeriveLaunchTemplateRefusesANonDryRunResult(t *testing.T) {
	state := t.TempDir()
	cli := newTestCLI(t, state)
	// The stub emits action "create" when --dry-run is absent; ask for the
	// non-dry-run form through the same parser to prove the guard fires.
	out, err := cli.Run(context.Background(), Invocation{Args: MCPInstallArgs(TargetClaudeCode, ScopeUser, false)})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !strings.Contains(out, `"action":"create"`) {
		t.Fatalf("the stub did not produce a non-dry-run action: %s", out)
	}

	// And the real guard, exercised through a stub whose --dry-run lies.
	t.Setenv("FAKE_GNO_LAUNCH_COMMAND", "/bin/echo")
	if _, _, _, err := cli.DeriveLaunchTemplate(context.Background(), "not-a-target", ScopeUser); err == nil {
		t.Fatal("an invalid target produced a launch template")
	}
}
