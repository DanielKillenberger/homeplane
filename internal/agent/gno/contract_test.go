package gno

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The contract tests.
//
// This package builds argv for a CLI it does not own. A stub can only prove the
// wrapper agrees with itself, so the argv is ALSO asserted against the real
// pinned build's own parser output, captured verbatim in
// testdata/gno-<version>-contract.txt by scripts/capture-gno-contract.sh.
//
// This exists because of a specific, recorded review lesson from task .5: an
// earlier wrapper invented `ob sync --vault/--once`, flags upstream does not
// have, and it passed its own tests. Capturing the real surface is the
// structural fix.

func contractText(t *testing.T) string {
	t.Helper()
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	path := filepath.Join("testdata", "gno-"+pin.Version+"-contract.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the pinned build's captured contract is missing (%v).\n"+
			"Regenerate it with scripts/capture-gno-contract.sh <path-to-gno>.", err)
	}
	return string(raw)
}

// section returns one captured block.
func section(t *testing.T, contract, header string) string {
	t.Helper()
	marker := "=== " + header + " ==="
	i := strings.Index(contract, marker)
	if i < 0 {
		t.Fatalf("the captured contract has no %q section", marker)
	}
	rest := contract[i+len(marker):]
	if j := strings.Index(rest, "\n=== "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// TestArgvMatchesThePinnedContract asserts every argv this package emits is
// accepted by the pinned build's own parser.
func TestArgvMatchesThePinnedContract(t *testing.T) {
	contract := contractText(t)
	top := section(t, contract, "gno --help")

	// Global options are parsed BEFORE the subcommand, so they must appear in
	// the ROOT help, not a subcommand's.
	for _, global := range []string{"--offline", "--index", "--config", "--json"} {
		if !strings.Contains(top, global) {
			t.Fatalf("the pinned build has no global option %q:\n%s", global, top)
		}
	}

	emitted := map[string][]string{
		"setup":  SetupArgs("/vault", "daniel-os"),
		"doctor": DoctorArgs(),
		"status": StatusArgs(),
		"search": SearchArgs("zarquon"),
		"update": UpdateArgs(),
		"index":  IndexArgs("daniel-os"),
		"daemon": DaemonArgs("127.0.0.1", 3077),
	}
	for name, args := range emitted {
		// Skip leading global flags to find the subcommand.
		sub := args
		for len(sub) > 0 && strings.HasPrefix(sub[0], "-") {
			sub = sub[1:]
		}
		if sub[0] != name {
			t.Fatalf("%s builder emits %q as its subcommand", name, sub[0])
		}
		if !strings.Contains(top, name) {
			t.Fatalf("the pinned build's command list does not contain %q:\n%s", name, top)
		}
		help := section(t, contract, "gno "+name+" --help")
		for _, a := range sub[1:] {
			if !strings.HasPrefix(a, "--") {
				continue
			}
			if !strings.Contains(help, a) {
				t.Fatalf("`gno %s` does not accept %q:\n%s", name, a, help)
			}
		}
	}

	// The MCP command group must still expose the two children this package
	// depends on: the stdio server (the harness endpoint) and the installer
	// (the descriptor's source of truth).
	mcpHelp := section(t, contract, "gno mcp --help")
	for _, child := range []string{"serve", "install", "uninstall", "status"} {
		if !strings.Contains(mcpHelp, child) {
			t.Fatalf("`gno mcp` no longer offers %q:\n%s", child, mcpHelp)
		}
	}

	// Flags a plausible-looking invention would use must NOT be accepted. These
	// are the assertions that would have caught the task .5 divergence.
	daemonHelp := section(t, contract, "gno daemon --help")
	for _, invented := range []string{"--vault", "--collection", "--index-path"} {
		if strings.Contains(daemonHelp, invented) {
			t.Fatalf("`gno daemon` unexpectedly documents %q; re-check the wrapper", invented)
		}
	}
	for _, args := range emitted {
		for _, a := range args {
			switch a {
			case "--vault", "--once", "--index-path":
				t.Fatalf("the wrapper emits an argument the pinned build does not accept: %q", a)
			}
		}
	}

	// The setup flag that keeps a first install from downloading a model.
	if !strings.Contains(section(t, contract, "gno setup --help"), "--no-semantic") {
		t.Fatal("`gno setup` no longer documents --no-semantic")
	}
}

// TestTheLaunchTemplateIsDerivedNotInvented asserts the descriptor's launch
// template comes from upstream's own installer output — and that the entry is
// the SAME for both harnesses, which is what makes one harness-agnostic
// descriptor (D16) legitimate rather than a convenient assumption.
func TestTheLaunchTemplateIsDerivedNotInvented(t *testing.T) {
	contract := contractText(t)

	type entry struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	}
	parse := func(header string) entry {
		raw, err := extractJSONObject(section(t, contract, header))
		if err != nil {
			t.Fatalf("%s: %v", header, err)
		}
		var parsed struct {
			Installed struct {
				Action string `json:"action"`
				Entry  entry  `json:"serverEntry"`
			} `json:"installed"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("%s: %v", header, err)
		}
		if !strings.HasPrefix(parsed.Installed.Action, "dry_run") {
			t.Fatalf("%s was captured as a REAL install (%q), not a dry run",
				header, parsed.Installed.Action)
		}
		return parsed.Installed.Entry
	}

	claude := parse("gno mcp install -t claude-code -s user --dry-run --json")
	codex := parse("gno mcp install -t codex -s user --dry-run --json")

	if !reflect.DeepEqual(claude, codex) {
		t.Fatalf("upstream emits different stdio entries per harness, so a single\n"+
			"harness-agnostic descriptor would be wrong:\n  claude-code: %+v\n  codex:       %+v",
			claude, codex)
	}
	if claude.Command == "" || len(claude.Args) == 0 {
		t.Fatalf("the captured server entry has no launch command: %+v", claude)
	}
	if claude.Args[len(claude.Args)-1] != "mcp" {
		t.Fatalf("upstream's entry no longer ends in the stdio `mcp` server: %v", claude.Args)
	}
	// The entry must carry GNO's directories, or a harness-launched server would
	// index somewhere other than the machine-local location we asserted.
	for _, key := range []string{EnvDataDir, EnvCacheDir} {
		if _, ok := claude.Env[key]; !ok {
			t.Fatalf("upstream's entry no longer pins %s: %+v", key, claude.Env)
		}
	}
	if !containsString(claude.Args, "--config") {
		t.Fatalf("upstream's entry no longer pins --config: %v", claude.Args)
	}

	// And the targets this project configures must still be supported.
	refusal := section(t, contract, "gno mcp install -t <invalid> --dry-run --json")
	for _, target := range []string{TargetClaudeCode, TargetCodex} {
		if !strings.Contains(refusal, target) {
			t.Fatalf("upstream's supported-target list no longer contains %q:\n%s", target, refusal)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// TestAgainstTheRealPinnedBuild runs the argv assertions against a live binary
// when one is available, and re-derives the captured contract from it.
//
// It is skipped when HOMEPLANE_GNO_BIN is unset, because a CI machine need not
// carry a Bun runtime and a 10 MB package — but when it IS set, a drift between
// the captured contract and the installed build fails here rather than in
// production.
//
// Everything here is read-only: `--help`, `--version`, and `--dry-run`.
func TestAgainstTheRealPinnedBuild(t *testing.T) {
	bin := os.Getenv("HOMEPLANE_GNO_BIN")
	if bin == "" {
		t.Skip("HOMEPLANE_GNO_BIN not set; run scripts/fetch-gno.sh --prefix DIR to get one")
	}
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}

	dirs := DefaultPaths(t.TempDir())
	if err := dirs.Create(); err != nil {
		t.Fatal(err)
	}
	cli := CLI{Bin: bin, Pin: pin, Dirs: dirs}
	if err := cli.Verify(context.Background()); err != nil {
		t.Fatalf("the real build does not match the pin: %v", err)
	}

	for _, args := range [][]string{
		SetupArgs("/vault", "c"), DoctorArgs(), StatusArgs(), SearchArgs("q"),
		UpdateArgs(), IndexArgs("c"), DaemonArgs("127.0.0.1", 3077),
	} {
		sub := args
		for len(sub) > 0 && strings.HasPrefix(sub[0], "-") {
			sub = sub[1:]
		}
		out, err := exec.Command(bin, sub[0], "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("`gno %s --help` failed: %v\n%s", sub[0], err, out)
		}
		for _, a := range sub[1:] {
			if strings.HasPrefix(a, "--") && !strings.Contains(string(out), a) {
				t.Fatalf("the installed build's `gno %s` does not accept %q:\n%s", sub[0], a, out)
			}
		}
	}

	// The derivation itself, against the real binary and both harnesses.
	claudeCmd, claudeArgs, claudeEnv, err := cli.DeriveLaunchTemplate(context.Background(), TargetClaudeCode, ScopeUser)
	if err != nil {
		t.Fatalf("derive for claude-code: %v", err)
	}
	codexCmd, codexArgs, codexEnv, err := cli.DeriveLaunchTemplate(context.Background(), TargetCodex, ScopeUser)
	if err != nil {
		t.Fatalf("derive for codex: %v", err)
	}
	if claudeCmd != codexCmd || !reflect.DeepEqual(claudeArgs, codexArgs) || !reflect.DeepEqual(claudeEnv, codexEnv) {
		t.Fatalf("the real build emits harness-SPECIFIC stdio entries:\n  %s %v %v\n  %s %v %v",
			claudeCmd, claudeArgs, claudeEnv, codexCmd, codexArgs, codexEnv)
	}
	if claudeEnv[EnvDataDir] != dirs.Data {
		t.Fatalf("the derived entry does not point at the machine-local data dir: %v", claudeEnv)
	}
}
