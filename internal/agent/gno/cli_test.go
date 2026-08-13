package gno

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPinIsComplete(t *testing.T) {
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	if pin.Version == "" || pin.Package == "" {
		t.Fatalf("the compiled-in pin is incomplete: %+v", pin)
	}
	if len(pin.Tarball) != 64 {
		t.Fatalf("the pinned tarball checksum is not a sha256: %q", pin.Tarball)
	}
	if pin.Package != "@gmickel/gno" {
		t.Fatalf("unexpected pinned package %q", pin.Package)
	}
}

func TestParsePinRejectsUnknownKeys(t *testing.T) {
	if _, err := parsePin("version = 1.0.0\npackage = x\nchecksum = abc\n"); err == nil {
		t.Fatal("a pin with an unknown key was accepted")
	}
	if _, err := parsePin("package = x\n"); err == nil {
		t.Fatal("a pin with no version was accepted")
	}
}

func TestVerifyAcceptsThePinnedVersionAndRejectsOthers(t *testing.T) {
	dir := t.TempDir()
	cli := newTestCLI(t, dir)
	if err := cli.Verify(context.Background()); err != nil {
		t.Fatalf("the pinned stub was rejected: %v", err)
	}

	t.Setenv("FAKE_GNO_VERSION", "1.28.0")
	err := cli.Verify(context.Background())
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("a different version was accepted: %v", err)
	}
}

func TestVerifyRefusesWithoutABinary(t *testing.T) {
	cli := CLI{Pin: testPin()}
	if err := cli.Verify(context.Background()); !errors.Is(err, ErrNoBin) {
		t.Fatalf("expected ErrNoBin, got %v", err)
	}
}

// The environment isolation test. An ambient GNO_DATA_DIR redirecting the
// agent's index is exactly how an index ends up in a place nobody asserted was
// safe — so the wrapper must drop inherited values, not merely add its own.
func TestEnvironmentIsolationDropsAmbientGNOVariables(t *testing.T) {
	dir := t.TempDir()
	cli := newTestCLI(t, dir)
	log := filepath.Join(dir, "argv.log")
	t.Setenv("FAKE_GNO_LOG", log)
	t.Setenv(EnvDataDir, "/somewhere/else")
	t.Setenv(EnvConfigDir, "/also/wrong")

	if _, err := cli.Run(context.Background(), Invocation{Args: DoctorArgs()}); err == nil {
		// doctor fails before setup; the argv log is what matters here.
		t.Log("doctor succeeded unexpectedly, continuing to the environment assertion")
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	text := string(raw)
	if strings.Contains(text, "/somewhere/else") || strings.Contains(text, "/also/wrong") {
		t.Fatalf("an ambient GNO_* variable reached the child:\n%s", text)
	}
	if !strings.Contains(text, "data:"+cli.Dirs.Data) {
		t.Fatalf("the child did not receive the pinned data directory:\n%s", text)
	}
}

func TestDaemonArgsAreOfflineAndLoopback(t *testing.T) {
	args := DaemonArgs("127.0.0.1", 3077, "/state/gno/config/gateway-token")
	if args[0] != "--offline" {
		t.Fatalf("--offline must be a GLOBAL flag before the subcommand: %v", args)
	}
	if args[1] != "daemon" {
		t.Fatalf("expected the daemon subcommand: %v", args)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--host 127.0.0.1") || !strings.Contains(joined, "--port 3077") {
		t.Fatalf("the daemon must bind an explicit loopback host and port: %v", args)
	}
}

func TestSetupArgsSkipSemanticIndexing(t *testing.T) {
	args := SetupArgs("/vault", "daniel-os")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--no-semantic") {
		t.Fatalf("setup must not trigger a model download on a fresh machine: %v", args)
	}
	if !strings.Contains(joined, "--name daniel-os") {
		t.Fatalf("setup must bind the named collection: %v", args)
	}
}

func TestDoctorParsesUpstreamJSONIncludingFailure(t *testing.T) {
	dir := t.TempDir()
	cli := newTestCLI(t, dir)
	vault := filepath.Join(dir, "vault")
	if err := os.MkdirAll(vault, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vault, "note.md"), []byte("# note\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Before setup, doctor exits non-zero AND prints a report. The report is the
	// answer we want: a failing health probe is a diagnosis, not an error.
	report, err := cli.Doctor(context.Background())
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if report.Healthy {
		t.Fatal("doctor reported healthy before setup ran")
	}
	if len(report.Errors()) == 0 {
		t.Fatalf("a missing config must be an error-level check: %+v", report)
	}

	if _, err := cli.Run(context.Background(), Invocation{Args: SetupArgs(vault, "c")}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	report, err = cli.Doctor(context.Background())
	if err != nil {
		t.Fatalf("doctor after setup: %v", err)
	}
	if !report.Healthy {
		t.Fatalf("doctor reported unhealthy after a successful setup: %+v", report)
	}
	if len(report.Errors()) != 0 {
		t.Fatalf("unexpected error-level checks: %+v", report.Errors())
	}
	// An uncached model is a `warn`: reported as a degradation, not as failure.
	if len(report.Failing()) == 0 {
		t.Fatal("a warn-level check must still be surfaced by Failing()")
	}
	if !strings.Contains(report.Summary(), "embed-model warn") {
		t.Fatalf("the summary hides the degradation: %s", report.Summary())
	}
}

func TestSearchDistinguishesNoResultsFromFailure(t *testing.T) {
	dir := t.TempDir()
	cli := newTestCLI(t, dir)
	vault := filepath.Join(dir, "vault")
	if err := os.MkdirAll(vault, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vault, "note.md"), []byte("zarquon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Run(context.Background(), Invocation{Args: SetupArgs(vault, "c")}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	hits, err := cli.Search(context.Background(), "zarquon")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("search returned no hits")
	}

	t.Setenv("FAKE_GNO_NO_RESULTS", "1")
	if _, err := cli.Search(context.Background(), "nothing"); !errors.Is(err, ErrNoResults) {
		t.Fatalf("an empty result set must be distinguishable from a failure: %v", err)
	}
}

func TestClassifyRecognisesAnUninitialisedInstall(t *testing.T) {
	err := classify("error: no config. run gno init", errors.New("exit status 1"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("a missing config must be its own error: %v", err)
	}
}

func TestExtractJSONObjectSurvivesProgressChatter(t *testing.T) {
	out := "⠋ Gathering information\n{\"healthy\":true,\"checks\":[]}\ndone\n"
	raw, err := extractJSONObject(out)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.HasPrefix(string(raw), "{\"healthy\"") {
		t.Fatalf("wrong object extracted: %s", raw)
	}
}
