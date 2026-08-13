package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
)

// These tests drive the `gno` CLI surface against temporary directories and a
// fake GNO stub. Nothing here reads Daniel's vault, his real GNO index, or the
// network.
//
// The stub deliberately mirrors only what these commands touch; the wrapper's
// agreement with the REAL build is asserted separately, against the captured
// upstream contract in internal/agent/gno.

const fakeGNOCLI = `#!/bin/sh
CONFIG_FILE="${GNO_CONFIG_DIR}/index.yml"
DB="${GNO_DATA_DIR}/index-default.sqlite"
while [ $# -gt 0 ]; do
  case "$1" in
    --offline) shift ;;
    --index|--config) shift 2 ;;
    *) break ;;
  esac
done
case "$1" in
  --version|-V) echo "${FAKE_GNO_VERSION:-1.29.6}"; exit 0 ;;
  setup)
    shift; FOLDER="$1"
    [ -d "$FOLDER" ] || { echo "error: folder not found" >&2; exit 1; }
    [ -n "$(ls -A "$FOLDER" 2>/dev/null)" ] || { echo "error: verification failed" >&2; exit 1; }
    mkdir -p "$GNO_CONFIG_DIR" "$GNO_DATA_DIR"
    printf 'version: 1\n' > "$CONFIG_FILE"
    printf 'index\n' > "$DB"
    printf '{"verified":true}\n'; exit 0 ;;
  doctor)
    [ -f "$CONFIG_FILE" ] || { printf '{"healthy":false,"checks":[{"name":"config","status":"error","message":"Config file not found"}]}\n'; exit 1; }
    printf '{"healthy":true,"checks":[{"name":"config","status":"ok","message":"ok"},{"name":"database","status":"ok","message":"ok"}]}\n'
    exit 0 ;;
  search) printf '{"results":[{"docid":"#a","uri":"gno://c/n.md","title":"n"}]}\n'; exit 0 ;;
  mcp)
    shift
    case "$1" in
      install)
        printf '{"installed":{"target":"claude-code","scope":"user","configPath":"/dev/null","action":"dry_run_create","serverEntry":{"command":"%s","args":["--config","%s","mcp"],"env":{"GNO_DATA_DIR":"%s","GNO_CACHE_DIR":"%s"}}}}\n' \
          "$0" "$CONFIG_FILE" "$GNO_DATA_DIR" "$GNO_CACHE_DIR"
        exit 0 ;;
      uninstall|status) printf '{"ok":true}\n'; exit 0 ;;
      *)
        while IFS= read -r line; do
          case "$line" in
            *'"method":"initialize"'*) printf '{"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"gno","version":"1.29.6"}},"jsonrpc":"2.0","id":1}\n' ;;
            *'"method":"tools/list"'*) printf '{"result":{"tools":[{"name":"gno_search"}]},"jsonrpc":"2.0","id":2}\n' ;;
            *'"method":"tools/call"'*) printf '{"result":{"content":[{"type":"text","text":"Found 1 results"}]},"jsonrpc":"2.0","id":3}\n' ;;
          esac
        done
        exit 0 ;;
    esac ;;
  daemon) sleep 30; exit 0 ;;
esac
echo "error: unknown command $1" >&2
exit 1
`

func writeGNOStub(t *testing.T) string {
	t.Helper()
	path := filepath.Join(tmp(t), "gno")
	if err := os.WriteFile(path, []byte(fakeGNOCLI), 0o755); err != nil {
		t.Fatalf("write fake gno: %v", err)
	}
	return path
}

// gnoEnv sets up a state directory with a recorded vault, and pins the compiled
// pin to what the stub reports.
func gnoEnv(t *testing.T) (stateDir, vaultPath, unitDir, bin string) {
	t.Helper()
	root := tmp(t)
	stateDir = filepath.Join(root, "state")
	vaultPath = filepath.Join(root, "Daniel-OS")
	unitDir = filepath.Join(root, "units")
	for _, d := range []string{stateDir, vaultPath, unitDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(vaultPath, "note.md"), []byte("# note\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := agent.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(agent.State{VaultPath: vaultPath}); err != nil {
		t.Fatal(err)
	}
	return stateDir, vaultPath, unitDir, writeGNOStub(t)
}

func TestGNOActivatePublishesADescriptorAndRecordsInstalledNotOK(t *testing.T) {
	stateDir, vaultPath, unitDir, bin := gnoEnv(t)
	var stdout, stderr bytes.Buffer

	code := runGNO(context.Background(), []string{
		"activate", "-state-dir", stateDir, "-bin", bin,
		"-unit-dir", unitDir, "-collection", "daniel-os", "-json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("activate exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}

	var out struct {
		Config     gno.Config        `json:"config"`
		Prepared   gno.PrepareResult `json:"prepared"`
		Descriptor gno.Descriptor    `json:"endpoint_descriptor"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("parse activate JSON: %v\n%s", err, stdout.String())
	}
	if out.Config.VaultPath != vaultPath {
		t.Fatalf("bound %q, want %q", out.Config.VaultPath, vaultPath)
	}
	if out.Descriptor.Transport != gno.TransportStdio {
		t.Fatalf("descriptor transport %q", out.Descriptor.Transport)
	}
	if !out.Prepared.Probe.OK {
		t.Fatalf("the stdio probe did not pass: %+v", out.Prepared.Probe)
	}

	// The descriptor is on disk where .6 will look for it.
	if _, err := gno.LoadDescriptor(stateDir); err != nil {
		t.Fatalf("no published descriptor: %v", err)
	}

	// Status records `installed`, not `ok`: nothing has been loaded into the
	// supervisor, so nothing is keeping the index current.
	state, _, err := agent.PeekState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.GNO == nil || state.GNO.State != agent.StateInstalled {
		t.Fatalf("recorded state = %+v, want installed", state.GNO)
	}
	if !strings.Contains(state.GNO.Detail, "gno apply") {
		t.Fatalf("the recorded detail does not name the next step: %q", state.GNO.Detail)
	}
}

func TestGNOActivateRefusesWithoutAVaultAndSaysWhy(t *testing.T) {
	root := tmp(t)
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := writeGNOStub(t)
	var stdout, stderr bytes.Buffer

	code := runGNO(context.Background(), []string{"activate", "-state-dir", stateDir, "-bin", bin}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("activate succeeded with no vault")
	}
	state, _, err := agent.PeekState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.GNO == nil || !strings.Contains(state.GNO.Detail, "no vault") {
		t.Fatalf("the recorded reason does not name the missing vault: %+v", state.GNO)
	}
}

func TestGNOActivateRefusesAnUnpinnedBuild(t *testing.T) {
	stateDir, _, unitDir, bin := gnoEnv(t)
	t.Setenv("FAKE_GNO_VERSION", "1.0.0")
	var stdout, stderr bytes.Buffer

	code := runGNO(context.Background(), []string{
		"activate", "-state-dir", stateDir, "-bin", bin, "-unit-dir", unitDir,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("an unpinned build was accepted:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "pinned") {
		t.Fatalf("the refusal does not name the pin:\n%s", stderr.String())
	}
	if _, err := gno.LoadDescriptor(stateDir); err == nil {
		t.Fatal("a descriptor was published for a refused activation")
	}
}

func TestGNOEndpointPrintsThePublishedDescriptor(t *testing.T) {
	stateDir, _, unitDir, bin := gnoEnv(t)
	var discard bytes.Buffer
	if code := runGNO(context.Background(), []string{
		"activate", "-state-dir", stateDir, "-bin", bin, "-unit-dir", unitDir, "-json",
	}, &discard, &discard); code != 0 {
		t.Fatalf("activate failed:\n%s", discard.String())
	}

	var stdout, stderr bytes.Buffer
	if code := runGNO(context.Background(), []string{"endpoint", "-state-dir", stateDir, "-json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("endpoint exit != 0: %s", stderr.String())
	}
	var d gno.Descriptor
	if err := json.Unmarshal(stdout.Bytes(), &d); err != nil {
		t.Fatalf("parse descriptor: %v\n%s", err, stdout.String())
	}
	if d.Component != gno.ComponentRetrievalEngine {
		t.Fatalf("wrong component: %q", d.Component)
	}
	if d.Args[len(d.Args)-1] != "mcp" {
		t.Fatalf("the published launch template is not the stdio server: %v", d.Args)
	}
}

func TestGNORebuildRecoversADeletedIndex(t *testing.T) {
	stateDir, _, unitDir, bin := gnoEnv(t)
	var discard bytes.Buffer
	if code := runGNO(context.Background(), []string{
		"activate", "-state-dir", stateDir, "-bin", bin, "-unit-dir", unitDir, "-json",
	}, &discard, &discard); code != 0 {
		t.Fatalf("activate failed:\n%s", discard.String())
	}
	cfg, err := gno.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.IndexDBPath); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runGNO(context.Background(), []string{"rebuild", "-state-dir", stateDir, "-bin", bin}, &stdout, &stderr); code != 0 {
		t.Fatalf("rebuild exit != 0: %s", stderr.String())
	}
	if !gno.IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the index did not come back")
	}
}

func TestGNODeactivateWithoutExecuteChangesNothing(t *testing.T) {
	stateDir, _, unitDir, bin := gnoEnv(t)
	var discard bytes.Buffer
	if code := runGNO(context.Background(), []string{
		"activate", "-state-dir", stateDir, "-bin", bin, "-unit-dir", unitDir, "-json",
	}, &discard, &discard); code != 0 {
		t.Fatalf("activate failed:\n%s", discard.String())
	}
	cfg, err := gno.LoadConfig(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runGNO(context.Background(), []string{"deactivate", "-state-dir", stateDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("deactivate exit != 0: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "nothing was changed") {
		t.Fatalf("a dry run did not say so:\n%s", stdout.String())
	}
	if _, err := os.Stat(cfg.UnitPath); err != nil {
		t.Fatalf("the unit was removed by a dry run: %v", err)
	}
}

func TestGNOUnknownSubcommandIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runGNO(context.Background(), []string{"frobnicate"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
}
