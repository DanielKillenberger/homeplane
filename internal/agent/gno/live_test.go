package gno

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// The live tests: the real GNO binary, a REAL temporary corpus, real indexing,
// and a real MCP tool call.
//
// They are skipped without HOMEPLANE_GNO_BIN, because a CI machine need not
// carry Bun and a 10 MB package — and that boundary is recorded honestly rather
// than papered over: without the binary, this package's guarantees rest on the
// stub PLUS the captured upstream contract, and with it they rest on the engine
// itself. The evidence artifact records which of the two ran.
//
// Nothing here touches Daniel's vault or his own GNO state: every directory is
// a t.TempDir(), and all three GNO_* directories are pinned to it.

const liveMarker = "zarquon-7742-homeplane"

func liveCLI(t *testing.T) (CLI, string, string) {
	t.Helper()
	bin := os.Getenv("HOMEPLANE_GNO_BIN")
	if bin == "" {
		t.Skip("HOMEPLANE_GNO_BIN not set; run scripts/fetch-gno.sh --prefix DIR to get one")
	}
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}

	root := t.TempDir()
	state := filepath.Join(root, "state")
	corpus := filepath.Join(root, "corpus")
	for _, d := range []string{state, corpus} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	note := "# Homeplane probe note\n\nThe marker phrase is: " + liveMarker + ".\n"
	if err := os.WriteFile(filepath.Join(corpus, "homeplane-note.md"), []byte(note), 0o600); err != nil {
		t.Fatal(err)
	}

	paths := DefaultPaths(state)
	if err := paths.Create(); err != nil {
		t.Fatal(err)
	}
	return CLI{Bin: bin, Pin: pin, Dirs: paths, Timeout: 5 * time.Minute}, state, corpus
}

// The whole activation sequence, against the real engine: bind, verify, prove
// the index is machine-local, and prove a harness-shaped stdio launch returns
// REAL corpus content (R6 groundwork).
func TestLiveActivationIndexesAndAnswersFromTheCorpus(t *testing.T) {
	cli, state, corpus := liveCLI(t)

	res, err := Prepare(context.Background(), PrepareOptions{
		StateDir:   state,
		VaultPath:  corpus,
		Collection: "homeplane-live",
		CLI:        cli,
		ProbeQuery: liveMarker,
	})
	if err != nil {
		t.Fatalf("prepare against the real engine: %v", err)
	}

	// The index is where the contract says, and nowhere else.
	if !strings.HasPrefix(res.IndexDBPath, state) {
		t.Fatalf("the real engine wrote its index outside the machine-local path: %s", res.IndexDBPath)
	}
	if res.IndexBytes == 0 {
		t.Fatalf("the real index is empty: %+v", res)
	}
	// And nothing was written into the corpus itself: a vault is synchronized,
	// so an index inside it would replicate to every other machine.
	entries, err := os.ReadDir(corpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "homeplane-note.md" {
			t.Fatalf("the engine wrote %q into the corpus", e.Name())
		}
	}

	// The stdio endpoint answered a real tool call with real corpus content.
	if !res.Probe.OK {
		t.Fatalf("the real stdio endpoint failed: %+v", res.Probe)
	}
	if !strings.Contains(res.Probe.CallExcerpt, liveMarker) {
		t.Fatalf("the tool call did not return corpus content:\n%s", res.Probe.CallExcerpt)
	}
	if res.Probe.ServerName == "" {
		t.Fatalf("no server identity from the handshake: %+v", res.Probe)
	}

	// A direct lexical retrieval agrees.
	hits, err := cli.Search(context.Background(), liveMarker)
	if err != nil {
		t.Fatalf("live search: %v", err)
	}
	if len(hits) == 0 || !strings.Contains(hits[0].URI, "homeplane-note") {
		t.Fatalf("the real index did not return the note: %+v", hits)
	}
}

// The disposable contract against the real engine: delete the index, rebuild it
// from the corpus alone, and retrieve the same content again.
func TestLiveDeletedIndexSelfHeals(t *testing.T) {
	cli, state, corpus := liveCLI(t)

	prepared, err := Prepare(context.Background(), PrepareOptions{
		StateDir: state, VaultPath: corpus, Collection: "homeplane-live",
		CLI: cli, ProbeQuery: liveMarker, SkipMCPProbe: true,
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	cfg := Config{
		Bin: cli.Bin, Version: cli.Pin.Version, Collection: prepared.Collection,
		VaultPath: prepared.VaultPath, Paths: prepared.Paths, IndexDBPath: prepared.IndexDBPath,
	}
	if err := os.Remove(cfg.IndexDBPath); err != nil {
		t.Fatalf("delete the real index: %v", err)
	}
	if IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the index was not deleted")
	}

	if _, err := Rebuild(context.Background(), cli, cfg); err != nil {
		t.Fatalf("rebuild against the real engine: %v", err)
	}
	hits, err := cli.Search(context.Background(), liveMarker)
	if err != nil {
		t.Fatalf("search after rebuild: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("the rebuilt index returned nothing")
	}
	// The corpus is untouched by the rebuild.
	if _, err := os.Stat(filepath.Join(corpus, "homeplane-note.md")); err != nil {
		t.Fatalf("the rebuild disturbed the corpus: %v", err)
	}
}

// The supervised lifecycle against the real daemon: it starts, it stays up, the
// ledger records the start, and cancelling it records a clean exit.
func TestLiveSupervisedDaemonStartsAndStops(t *testing.T) {
	cli, state, corpus := liveCLI(t)

	if _, err := Prepare(context.Background(), PrepareOptions{
		StateDir: state, VaultPath: corpus, Collection: "homeplane-live",
		CLI: cli, SkipMCPProbe: true,
	}); err != nil {
		t.Fatalf("prepare: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunDaemon(ctx, RunOptions{
			StateDir: state,
			Run: func(ctx context.Context) error {
				// Port 0 is not valid for the daemon, so a high fixed port is
				// used; the loopback host keeps it off every other interface.
				return cli.Stream(ctx, Invocation{Args: DaemonArgs("127.0.0.1", 39871)})
			},
		})
	}()

	tracker := supervise.Tracker{Dir: state, Label: UnitLabel}
	deadline := time.Now().Add(60 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		ledger, err := tracker.Load()
		if err == nil && ledger.TotalStarts > 0 {
			started = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !started {
		cancel()
		<-done
		t.Fatal("the supervised daemon never recorded a start")
	}

	// Give the real daemon a moment to bind and watch, then stop it the way the
	// supervisor would.
	time.Sleep(3 * time.Second)
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon did not stop when its context was cancelled")
	}

	ledger, err := tracker.Load()
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalStarts != 1 || ledger.TotalExits != 1 {
		t.Fatalf("the lifecycle was not recorded: %+v", ledger)
	}
	if ledger.CrashLooping(time.Now(), supervise.DefaultCrashLoopWindow, supervise.DefaultCrashLoopThreshold) {
		t.Fatalf("one start was mistaken for a crash loop: %+v", ledger)
	}
}
