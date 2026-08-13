package vault

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The contract tests.
//
// This package builds argv for a third-party CLI it does not own. A fake stub
// can only ever prove the code agrees with itself, so the argv is also asserted
// against the REAL pinned build's own parser output, captured verbatim in
// testdata/ob-<version>-contract.txt by scripts/capture-ob-contract.sh.
//
// That file is the reason an invented interface cannot survive review twice:
// `--vault` and `--once` do not appear in it, so a wrapper that emitted them
// would fail here.

func contractText(t *testing.T) string {
	t.Helper()
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	path := filepath.Join("testdata", "ob-"+pin.Version+"-contract.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the pinned build's captured contract is missing (%v).\n"+
			"Regenerate it with scripts/capture-ob-contract.sh <path-to-ob>.", err)
	}
	return string(raw)
}

// section returns the captured `ob <cmd> --help` block.
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
	top := section(t, contract, "ob --help")

	// Every subcommand must exist in the top-level command list.
	emitted := map[string][]string{
		"login":            LoginArgs("d@example.com"),
		"sync-list-remote": ListRemoteArgs(),
		"sync-list-local":  ListLocalArgs(),
		"sync-setup":       SyncSetupArgs("Daniel-OS", "/v"),
		"sync-config":      SyncConfigModeArgs("/v", SyncModePullOnly),
		"sync-status":      SyncStatusArgs("/v"),
		"sync":             SyncArgs("/v"),
	}
	for name, args := range emitted {
		if args[0] != name {
			t.Fatalf("%s builder emits %q as its subcommand", name, args[0])
		}
		if !strings.Contains(top, name) {
			t.Fatalf("the pinned build's command list does not contain %q:\n%s", name, top)
		}
		// Every flag must appear in that subcommand's own help.
		help := section(t, contract, "ob "+name+" --help")
		for _, a := range args[1:] {
			if !strings.HasPrefix(a, "--") {
				continue
			}
			if !strings.Contains(help, a) {
				t.Fatalf("`ob %s` does not accept %q:\n%s", name, a, help)
			}
		}
	}

	// The continuous flag is the one that keeps R14 alive.
	if !strings.Contains(section(t, contract, "ob sync --help"), "--continuous") {
		t.Fatal("`ob sync` no longer documents --continuous")
	}

	// Flags the previous implementation invented must NOT be present — this is
	// the assertion that would have caught the divergence.
	syncHelp := section(t, contract, "ob sync --help")
	for _, invented := range []string{"--vault", "--once"} {
		if strings.Contains(syncHelp, invented) {
			t.Fatalf("`ob sync` unexpectedly documents %q; re-check the wrapper", invented)
		}
	}
	for _, args := range emitted {
		for _, a := range args {
			if a == "--once" || (args[0] == "sync" && a == "--vault") {
				t.Fatalf("the wrapper emits an argument the pinned build does not accept: %q", a)
			}
		}
	}

	// The pull-only mode the retrieval path depends on must still exist.
	if !strings.Contains(section(t, contract, "ob sync-config --help"), "--mode") {
		t.Fatal("`ob sync-config` no longer documents --mode")
	}
}

// TestSecretsAreNeverPassedAsFlags guards the custody decision that upstream's
// own interface makes easy to get wrong: `login` and `sync-setup` both accept
// `--password`, and this agent must never use either.
func TestSecretsAreNeverPassedAsFlags(t *testing.T) {
	contract := contractText(t)
	for _, cmd := range []string{"login", "sync-setup"} {
		if !strings.Contains(section(t, contract, "ob "+cmd+" --help"), "--password") {
			t.Fatalf("`ob %s` no longer offers --password; re-check the stdin path", cmd)
		}
	}
	all := [][]string{
		LoginArgs("d@example.com"),
		SyncSetupArgs("Daniel-OS", "/v"),
		SyncArgs("/v"),
		SyncContinuousArgs("/v"),
		SyncConfigModeArgs("/v", SyncModePullOnly),
		ListRemoteArgs(),
	}
	for _, args := range all {
		for _, a := range args {
			if strings.Contains(a, "--password") || strings.Contains(a, "--mfa") {
				t.Fatalf("a secret-bearing flag reached argv: %v", args)
			}
		}
	}
}

// TestAgainstTheRealPinnedBuild runs the argv assertions against a live binary
// when one is available, and re-derives the captured contract from it.
//
// It is skipped when HOMEPLANE_OB_BIN is unset, because the binary is a
// 40-package npm install that CI need not carry — but when it IS set (release
// staging, and task .7's live proof), a drift between the captured contract and
// the installed build fails here rather than in production.
//
// Everything here is UNAUTHENTICATED: `--help` and `--version` only. The
// authenticated round-trip needs Daniel's Obsidian account and stays gated to
// task .7.
func TestAgainstTheRealPinnedBuild(t *testing.T) {
	bin := os.Getenv("HOMEPLANE_OB_BIN")
	if bin == "" {
		t.Skip("HOMEPLANE_OB_BIN not set; run scripts/fetch-obsidian-headless.sh --prefix DIR to get one")
	}
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}

	// The pin must match the binary the developer actually pointed us at.
	cli := CLI{Bin: bin, Pin: pin}
	if err := cli.Verify(context.Background()); err != nil {
		t.Fatalf("the real build does not match the pin: %v", err)
	}

	// And its parser must still accept every argv we emit.
	for _, args := range [][]string{
		ListRemoteArgs(), SyncSetupArgs("x", "/v"), SyncArgs("/v"),
		SyncContinuousArgs("/v"), SyncConfigModeArgs("/v", SyncModePullOnly), SyncStatusArgs("/v"),
	} {
		out, err := exec.Command(bin, args[0], "--help").CombinedOutput()
		if err != nil {
			t.Fatalf("`ob %s --help` failed: %v\n%s", args[0], err, out)
		}
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "--") && !strings.Contains(string(out), a) {
				t.Fatalf("the installed build's `ob %s` does not accept %q:\n%s", args[0], a, out)
			}
		}
	}
}
