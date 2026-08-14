package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShippedPinIsAttested(t *testing.T) {
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	if pin.Pending() {
		t.Fatal("the shipped pin is still PENDING; sync can never activate")
	}
	// These are the values attested for obsidian-headless 0.0.13: the npm
	// tarball and the cli.js node executes. Changing the pin must change this
	// test, which is the moment a human confirms where the bytes came from.
	if pin.Version != "0.0.13" {
		t.Fatalf("pinned version = %q", pin.Version)
	}
	if pin.Tarball != "9b8e1ad3917a65d53c5ab74d06acf5ec8d941e3b02bd9bd5d035d6800e533198" {
		t.Fatalf("pinned tarball checksum changed: %q", pin.Tarball)
	}
	if pin.Checksum != "c7a0b843cd18f1164305a569d56164723a670b9ebcb66e6a445bb9fbf9555637" {
		t.Fatalf("pinned entrypoint checksum changed: %q", pin.Checksum)
	}
}

func TestVerifyRefusesAPendingPin(t *testing.T) {
	bin, _ := writeFakeOB(t)
	cli := CLI{Bin: bin, Pin: Pin{Version: "0.0.13", Checksum: PinPending}}
	if err := cli.Verify(context.Background()); !errors.Is(err, ErrPinUnset) {
		t.Fatalf("Verify = %v, want ErrPinUnset", err)
	}
}

func TestVerifyRefusesAChecksumMismatch(t *testing.T) {
	bin, _ := writeFakeOB(t)
	cli := CLI{Bin: bin, Pin: Pin{Version: "0.0.13", Checksum: strings.Repeat("ab", 32)}}
	if err := cli.Verify(context.Background()); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("Verify = %v, want ErrPinMismatch", err)
	}
}

func TestVerifyRefusesAVersionMismatch(t *testing.T) {
	cli := pinnedFakeCLI(t)
	t.Setenv("FAKE_OB_VERSION", "0.0.12")
	if err := cli.Verify(context.Background()); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("Verify = %v, want ErrPinMismatch", err)
	}
}

func TestVerifyAcceptsThePinnedBuild(t *testing.T) {
	cli := pinnedFakeCLI(t)
	if err := cli.Verify(context.Background()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyCatchesATamperedBinary(t *testing.T) {
	cli := pinnedFakeCLI(t)
	if err := os.WriteFile(cli.Bin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := cli.Verify(context.Background()); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("Verify = %v, want ErrPinMismatch", err)
	}
}

// npm installs `ob` as a symlink to the package's cli.js. The pin covers
// cli.js, because a shim's own bytes vary per installation while cli.js does
// not — so Verify must resolve the link before checksumming.
func TestVerifyResolvesTheShimSymlink(t *testing.T) {
	bin, sum := writeFakeOB(t)
	shimDir := tempDir(t)
	shim := filepath.Join(shimDir, "ob")
	if err := os.Symlink(bin, shim); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	cli := CLI{Bin: shim, Pin: Pin{Version: "0.0.13", Checksum: sum}}
	if err := cli.Verify(context.Background()); err != nil {
		t.Fatalf("Verify through a shim symlink: %v", err)
	}
	entry, err := cli.Entrypoint()
	if err != nil {
		t.Fatal(err)
	}
	if entry != bin {
		t.Fatalf("entrypoint = %q, want %q", entry, bin)
	}
}

func TestVerifyRefusesAnEmptyPath(t *testing.T) {
	cli := CLI{Pin: Pin{Version: "0.0.13", Checksum: strings.Repeat("ab", 32)}}
	if err := cli.Verify(context.Background()); err == nil {
		t.Fatal("an unconfigured CLI path was accepted")
	}
}

// Custody: the account token reaches the CLI through the environment and never
// through argv, where `ps` would expose it to every process on the machine.
func TestAuthTokenTravelsThroughTheEnvironment(t *testing.T) {
	cli := pinnedFakeCLI(t)
	cli.ConfigDir = tempDir(t)
	log := filepath.Join(tempDir(t), "ob.log")
	t.Setenv("FAKE_OB_LOG", log)

	const token = "tok-abcdef123456"
	if _, err := cli.Run(context.Background(), Invocation{
		Args:    ListRemoteArgs(),
		Secrets: Secrets{AuthToken: token},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	lines := readLog(t, log)
	if argv := lineWithPrefix(lines, "argv:"); strings.Contains(argv, token) {
		t.Fatalf("the token appeared in argv: %s", argv)
	}
	if got := lineWithPrefix(lines, "token:"); got != "token:"+token {
		t.Fatalf("the token did not reach the environment: %q", got)
	}
}

// The E2E password answers upstream's interactive prompt on stdin — upstream
// also accepts --password, and using it would put the secret in `ps`.
func TestE2EPasswordTravelsThroughStdin(t *testing.T) {
	cli := pinnedFakeCLI(t)
	log := filepath.Join(tempDir(t), "ob.log")
	t.Setenv("FAKE_OB_LOG", log)
	dest := tempDir(t)

	const pw = "e2e-secret-phrase"
	if _, err := cli.Run(context.Background(), Invocation{
		Args:    SyncSetupArgs("Daniel-OS", dest),
		Secrets: Secrets{AuthToken: "tok", E2EPassword: pw},
		Stdin:   pw + "\n",
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	lines := readLog(t, log)
	if argv := lineWithPrefix(lines, "argv:"); strings.Contains(argv, pw) {
		t.Fatalf("the E2E password appeared in argv: %s", argv)
	}
	if got := lineWithPrefix(lines, "e2e:"); got != "e2e:"+pw {
		t.Fatalf("the E2E password did not reach stdin: %q", got)
	}
}

// An ambient OBSIDIAN_AUTH_TOKEN in the operator's shell must not silently
// authenticate the agent — the agent's own stored token is the only one it uses.
func TestAmbientAuthTokenIsNotInherited(t *testing.T) {
	cli := pinnedFakeCLI(t)
	log := filepath.Join(tempDir(t), "ob.log")
	t.Setenv("FAKE_OB_LOG", log)
	t.Setenv(AuthTokenEnvVar, "ambient-token-from-the-operators-shell")

	_, _ = cli.Run(context.Background(), Invocation{Args: ListRemoteArgs()})
	if got := lineWithPrefix(readLog(t, log), "token:"); got != "token:" {
		t.Fatalf("an ambient token leaked into the child: %q", got)
	}
}

func TestAssertNoSecretInArgs(t *testing.T) {
	if err := AssertNoSecretInArgs([]string{"sync", "--path", "/x"}, "hunter2"); err != nil {
		t.Fatalf("clean argv rejected: %v", err)
	}
	if err := AssertNoSecretInArgs([]string{"login", "--password=hunter2"}, "hunter2"); err == nil {
		t.Fatal("argv containing a credential was accepted")
	}
	if err := AssertNoSecretInArgs([]string{"sync"}, ""); err != nil {
		t.Fatalf("empty secret rejected: %v", err)
	}
}

func TestRedact(t *testing.T) {
	got := Redact("login failed for hunter2 with token tok-1", "hunter2", "tok-1")
	if strings.Contains(got, "hunter2") || strings.Contains(got, "tok-1") {
		t.Fatalf("Redact left a secret behind: %q", got)
	}
	if Redact("nothing to do") != "nothing to do" {
		t.Fatal("Redact with no secrets changed the text")
	}
}

// R14: auth failure must be distinguishable from a network failure, because one
// needs a new credential and the other just needs retrying.
func TestClassifiesAuthAndNetworkFailures(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})

	t.Run("auth", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_FAIL", "error: unauthorized - please log in")
		_, err := cli.Run(context.Background(), Invocation{Args: SyncArgs(v), Secrets: testSecrets()})
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("err = %v, want *AuthError", err)
		}
		var netErr *NetworkError
		if errors.As(err, &netErr) {
			t.Fatal("an auth failure was also classified as a network failure")
		}
	})

	t.Run("network", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_FAIL", "error: connection refused while contacting sync host")
		_, err := cli.Run(context.Background(), Invocation{Args: SyncArgs(v), Secrets: testSecrets()})
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("err = %v, want *NetworkError", err)
		}
	})

	t.Run("other", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_FAIL", "error: vault format not recognised")
		_, err := cli.Run(context.Background(), Invocation{Args: SyncArgs(v), Secrets: testSecrets()})
		var authErr *AuthError
		var netErr *NetworkError
		if errors.As(err, &authErr) || errors.As(err, &netErr) {
			t.Fatalf("unrelated failure misclassified: %v", err)
		}
		if err == nil {
			t.Fatal("a failing CLI returned no error")
		}
	})
}

func TestErrorsAreRedacted(t *testing.T) {
	cli := pinnedFakeCLI(t)
	v := makeVault(t, nil)
	const secret = "leaky-token"
	t.Setenv("FAKE_OB_FAIL", "error: unauthorized for "+secret)
	_, err := cli.Run(context.Background(), Invocation{Args: SyncArgs(v), Secrets: Secrets{AuthToken: secret}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the credential leaked into the error: %v", err)
	}
}

// A one-shot call is bounded; a hung CLI must not hang the agent.
func TestRunIsBounded(t *testing.T) {
	cli := pinnedFakeCLI(t)
	cli.Timeout = 100 * time.Millisecond
	v := makeVault(t, nil)
	t.Setenv("FAKE_OB_MODE", "noop")

	start := time.Now()
	_, err := cli.Run(context.Background(), Invocation{Args: SyncContinuousArgs(v), Secrets: testSecrets()})
	if err == nil {
		t.Fatal("a continuous run through the bounded path returned success")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("the bounded path took %s", elapsed)
	}
}

// Continuous sync must NOT be killed on a timer — it ends only when its context
// is cancelled. A two-minute default would restart a healthy sync forever.
func TestStreamIsNotKilledByTheOneShotTimeout(t *testing.T) {
	cli := pinnedFakeCLI(t)
	cli.Timeout = 150 * time.Millisecond // would kill a bounded call almost at once
	v := makeVault(t, map[string]string{"a.md": "a\n"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- cli.Stream(ctx, Invocation{Args: SyncContinuousArgs(v), Secrets: testSecrets()})
	}()

	// Well past the one-shot timeout, the stream must still be running.
	select {
	case err := <-done:
		t.Fatalf("continuous sync exited after less than a second: %v", err)
	case <-time.After(1 * time.Second):
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation produced %v, want context.Canceled", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("continuous sync did not stop after cancellation")
	}
}

// A months-long process must not accumulate its whole output in memory.
func TestCapturedOutputIsBounded(t *testing.T) {
	tail := &tailBuffer{limit: 64}
	for i := 0; i < 1000; i++ {
		if _, err := tail.Write([]byte("0123456789")); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(tail.String()); got > 64 {
		t.Fatalf("retained %d bytes, want at most 64", got)
	}
	if !strings.HasSuffix(tail.String(), "0123456789") {
		t.Fatalf("the tail was not retained: %q", tail.String())
	}
}

// The redacting writer must catch a secret even when the process emits it
// across two writes.
func TestRedactingWriterHandlesSplitWrites(t *testing.T) {
	var sink strings.Builder
	w := &redactingWriter{w: &sink, secrets: []string{"supersecret"}}
	if _, err := w.Write([]byte("token=super")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("secret ok\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sink.String(), "supersecret") {
		t.Fatalf("a split secret survived redaction: %q", sink.String())
	}
	if !strings.Contains(sink.String(), "[redacted]") {
		t.Fatalf("nothing was redacted: %q", sink.String())
	}
}

func TestParsePin(t *testing.T) {
	p, err := parsePin("# comment\nversion = 1.2.3\ntarball = aa\nchecksum = bb\n")
	if err != nil {
		t.Fatalf("parsePin: %v", err)
	}
	if p.Version != "1.2.3" || p.Checksum != "bb" || p.Tarball != "aa" {
		t.Fatalf("got %+v", p)
	}
	if p.Pending() {
		t.Fatal("a real checksum was reported as pending")
	}
	if _, err := parsePin("version = 1.0.0\n"); err == nil {
		t.Fatal("a pin without a checksum was accepted")
	}
	if _, err := parsePin("checksum = abc\n"); err == nil {
		t.Fatal("a pin without a version was accepted")
	}
	if _, err := parsePin("nonsense\n"); err == nil {
		t.Fatal("a malformed pin line was accepted")
	}
	if _, err := parsePin("bogus = 1\nversion = 1\nchecksum = 2\n"); err == nil {
		t.Fatal("an unknown pin key was accepted")
	}
}

func TestParseRemoteVaults(t *testing.T) {
	got := ParseRemoteVaults("Remote vaults:\n  Daniel-OS [abc123def]\n  Scratch\n\n")
	if len(got) != 2 {
		t.Fatalf("parsed %d vaults: %+v", len(got), got)
	}
	if got[0].Name != "Daniel-OS" || got[0].ID != "abc123def" {
		t.Fatalf("first vault = %+v", got[0])
	}
	if got[1].Name != "Scratch" || got[1].ID != "" {
		t.Fatalf("second vault = %+v", got[1])
	}
	if v := ParseRemoteVaults("No vaults found\n"); len(v) != 0 {
		t.Fatalf("an empty listing produced %+v", v)
	}
}

func readLog(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	return strings.Split(string(raw), "\n")
}

func lineWithPrefix(lines []string, prefix string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}
