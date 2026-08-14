package gno

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

	if _, err := Rebuild(context.Background(), cli, cfg, RebuildOptions{StateDir: state}); err != nil {
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

// The supervised lifecycle against the real daemon.
//
// The earlier version of this test proved almost nothing: RunDaemon records a
// start BEFORE it invokes GNO, so `TotalStarts > 0` only showed that the wrapper
// ran, and the returned error was discarded. A daemon that died instantly passed.
// So this one requires the daemon to still be running (its goroutine must NOT
// have completed), requires the gateway port to be genuinely bound, and inspects
// what came back after cancellation.
func TestLiveSupervisedDaemonStartsAndStops(t *testing.T) {
	cli, state, corpus := liveCLI(t)

	prepared, err := Prepare(context.Background(), PrepareOptions{
		StateDir: state, VaultPath: corpus, Collection: "homeplane-live",
		CLI: cli, SkipMCPProbe: true,
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	tokenFile, err := EnsureGatewayToken(prepared.Paths)
	if err != nil {
		t.Fatalf("gateway token: %v", err)
	}

	const port = 39871
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunDaemon(ctx, RunOptions{
			StateDir: state,
			Run: func(ctx context.Context) error {
				return cli.Stream(ctx, Invocation{Args: DaemonArgs("127.0.0.1", port, tokenFile)})
			},
		})
	}()
	defer cancel()

	// Bound-and-listening is the real liveness signal. A daemon that exits during
	// startup never gets here, however promptly the wrapper recorded a start.
	if err := waitForListener(port, 90*time.Second); err != nil {
		cancel()
		t.Fatalf("the real daemon never bound %d: %v (run error: %v)", port, err, drainErr(done, 20*time.Second))
	}

	// It must still be RUNNING: an immediate crash after binding would otherwise
	// look identical to a healthy daemon.
	select {
	case err := <-done:
		t.Fatalf("the daemon exited on its own before it was asked to stop: %v", err)
	case <-time.After(3 * time.Second):
	}

	ledger, err := (supervise.Tracker{Dir: state, Label: UnitLabel}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalStarts != 1 || ledger.TotalExits != 0 {
		t.Fatalf("a running daemon was not recorded as started-and-not-exited: %+v", ledger)
	}

	// Now stop it the way a supervisor would, and check what came back.
	cancel()
	runErr := drainErr(done, 30*time.Second)
	if runErr == nil {
		t.Fatal("cancellation returned no error at all; the daemon cannot have been running")
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("the daemon failed rather than stopping on request: %v", runErr)
	}

	ledger, err = (supervise.Tracker{Dir: state, Label: UnitLabel}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if ledger.TotalStarts != 1 || ledger.TotalExits != 1 {
		t.Fatalf("the lifecycle was not recorded: %+v", ledger)
	}
	// A deliberate stop must not be recorded as a crash, or every rebuild and
	// every reboot would inflate the crash-loop signal status reads.
	exit, ok := ledger.LastExit()
	if !ok || exit.Code != 0 {
		t.Fatalf("an intentional cancellation was recorded as a failure: %+v", ledger.Exits)
	}
	if ledger.CrashLooping(time.Now(), supervise.DefaultCrashLoopWindow, supervise.DefaultCrashLoopThreshold) {
		t.Fatalf("one start was mistaken for a crash loop: %+v", ledger)
	}
}

// Rebuilding while the daemon is running is the dangerous case: on Unix the
// daemon keeps writing to the unlinked database while everything else reads the
// replacement. This test rebuilds under a real running daemon and then proves
// that a NEW vault document reaches the NEW index — which cannot happen if the
// resumed daemon is still attached to the old one.
func TestLiveRebuildWhileTheDaemonIsRunning(t *testing.T) {
	cli, state, corpus := liveCLI(t)

	prepared, err := Prepare(context.Background(), PrepareOptions{
		StateDir: state, VaultPath: corpus, Collection: "homeplane-live",
		CLI: cli, SkipMCPProbe: true,
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	tokenFile, err := EnsureGatewayToken(prepared.Paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Bin: cli.Bin, Version: cli.Pin.Version, Collection: prepared.Collection,
		VaultPath: prepared.VaultPath, Paths: prepared.Paths, IndexDBPath: prepared.IndexDBPath,
		GatewayToken: tokenFile, Applied: true,
	}

	const port = 39872
	// runDaemon starts one supervised daemon and returns a stop function.
	runDaemon := func() (stop func() error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- RunDaemon(ctx, RunOptions{
				StateDir: state,
				Run: func(ctx context.Context) error {
					return cli.Stream(ctx, Invocation{Args: DaemonArgs("127.0.0.1", port, tokenFile)})
				},
			})
		}()
		return func() error {
			cancel()
			drainErr(done, 30*time.Second)
			return waitForNoListener(port, 30*time.Second)
		}
	}

	stop := runDaemon()
	if err := waitForListener(port, 90*time.Second); err != nil {
		_ = stop()
		t.Fatalf("the daemon never bound %d: %v", port, err)
	}

	// A rebuild with no way to stop the daemon must REFUSE rather than race it.
	if _, err := Rebuild(context.Background(), cli, cfg, RebuildOptions{StateDir: state}); !errors.Is(err, ErrEngineRunning) {
		_ = stop()
		t.Fatalf("rebuild raced a running daemon instead of refusing: %v", err)
	}

	// With a quiesce, it stops the daemon, rebuilds, and brings it back.
	var resumed bool
	if _, err := Rebuild(context.Background(), cli, cfg, RebuildOptions{
		StateDir: state,
		Quiesce: func(context.Context) (func() error, error) {
			if err := stop(); err != nil {
				return nil, err
			}
			return func() error {
				resumed = true
				stop = runDaemon()
				return waitForListener(port, 90*time.Second)
			}, nil
		},
	}); err != nil {
		t.Fatalf("rebuild under quiesce: %v", err)
	}
	defer func() { _ = stop() }()
	if !resumed {
		t.Fatal("the daemon was never resumed after the rebuild")
	}

	// The proof: a document written AFTER the rebuild must reach the NEW index.
	// A daemon still attached to the unlinked old database cannot deliver this.
	marker := "postrebuild-" + liveMarker
	if err := os.WriteFile(filepath.Join(corpus, "post-rebuild.md"),
		[]byte("# after the rebuild\n\n"+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		hits, err := cli.Search(context.Background(), marker)
		if err == nil && len(hits) > 0 {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("a vault change made after the rebuild never reached the new index")
}

// waitForListener reports when something is accepting connections on a loopback
// port — the only trustworthy sign that the daemon actually came up.
func waitForListener(port int, within time.Duration) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	return lastErr
}

// waitForNoListener reports when the port is free again, so a restart does not
// race the previous process's socket.
func waitForNoListener(port int, within time.Duration) error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return nil
		}
		_ = conn.Close()
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("port %d is still accepting connections", port)
}

func drainErr(done <-chan error, within time.Duration) error {
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		return fmt.Errorf("the daemon did not return within %s", within)
	}
}
