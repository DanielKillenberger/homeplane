package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPinIsPendingUntilAReleaseIsStaged(t *testing.T) {
	pin, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	if pin.Version == "" {
		t.Fatal("the compiled-in pin has no version")
	}
	// This assertion is intentionally strict. If someone fills the checksum in,
	// they must also change this test — which is the moment to check that the
	// value came from a verified, smoke-tested release rather than from a local
	// download nobody attested to.
	if !pin.Pending() {
		t.Fatalf("the shipped pin is no longer PENDING (checksum %q) — confirm it came from a verified release and update this test",
			pin.Checksum)
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

// A binary whose bytes match but which reports a different version is still a
// refusal: the pin is an assertion about the build, not about the file alone.
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

// A CLI that was tampered with AFTER verification is caught on the next verify,
// which is why activation verifies rather than trusting an earlier check.
func TestVerifyCatchesATamperedBinary(t *testing.T) {
	cli := pinnedFakeCLI(t)
	if err := os.WriteFile(cli.Bin, []byte("#!/bin/sh\nrm -rf \"$3\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := cli.Verify(context.Background()); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("Verify = %v, want ErrPinMismatch", err)
	}
}

// Custody: the credential reaches the CLI through the environment and never
// through argv, where `ps` would expose it to every process on the machine.
func TestSyncPassesCredentialThroughEnvNotArgv(t *testing.T) {
	cli := pinnedFakeCLI(t)
	v := makeVault(t, map[string]string{"a.md": "a\n"})
	log := filepath.Join(tempDir(t), "ob.log")
	t.Setenv("FAKE_OB_LOG", log)

	const secret = "s3cret-sync-password"
	if err := cli.SyncOnce(context.Background(), v, secret); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	text := string(raw)
	argvLine, credLine := "", ""
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "argv:") {
			argvLine = line
		}
		if strings.HasPrefix(line, "cred:") {
			credLine = line
		}
	}
	if strings.Contains(argvLine, secret) {
		t.Fatalf("the credential appeared in argv: %s", argvLine)
	}
	if credLine != "cred:"+secret {
		t.Fatalf("the credential did not reach the CLI environment: %q", credLine)
	}
}

func TestAssertNoSecretInArgs(t *testing.T) {
	if err := AssertNoSecretInArgs([]string{"sync", "--vault", "/x"}, "hunter2"); err != nil {
		t.Fatalf("clean argv rejected: %v", err)
	}
	if err := AssertNoSecretInArgs([]string{"sync", "--password=hunter2"}, "hunter2"); err == nil {
		t.Fatal("argv containing the credential was accepted")
	}
	if err := AssertNoSecretInArgs([]string{"sync"}, ""); err != nil {
		t.Fatalf("empty secret rejected: %v", err)
	}
}

func TestRedact(t *testing.T) {
	got := Redact("login failed for hunter2 (hunter2)", "hunter2")
	if strings.Contains(got, "hunter2") {
		t.Fatalf("Redact left the secret behind: %q", got)
	}
	if Redact("nothing to do", "") != "nothing to do" {
		t.Fatal("Redact with an empty secret changed the text")
	}
}

// R14: auth failure must be distinguishable from a network failure, because one
// needs a new credential and the other just needs retrying.
func TestSyncClassifiesAuthAndNetworkFailures(t *testing.T) {
	v := makeVault(t, map[string]string{"a.md": "a\n"})

	t.Run("auth", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_FAIL", "error: unauthorized — invalid credentials")
		err := cli.SyncOnce(context.Background(), v, "pw")
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
		err := cli.SyncOnce(context.Background(), v, "pw")
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("err = %v, want *NetworkError", err)
		}
	})

	t.Run("other", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_FAIL", "error: vault format not recognised")
		err := cli.SyncOnce(context.Background(), v, "pw")
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

// An error message that echoed the credential back would leak it into logs and
// into `status` detail.
func TestSyncErrorsAreRedacted(t *testing.T) {
	cli := pinnedFakeCLI(t)
	v := makeVault(t, nil)
	const secret = "leaky-password"
	t.Setenv("FAKE_OB_FAIL", "error: unauthorized for "+secret)
	err := cli.SyncOnce(context.Background(), v, secret)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the credential leaked into the error: %v", err)
	}
}

func TestSyncArgsShape(t *testing.T) {
	once := SyncOnceArgs("/vaults/Daniel-OS")
	cont := SyncContinuousArgs("/vaults/Daniel-OS")
	if once[len(once)-1] != "--once" || cont[len(cont)-1] != "--continuous" {
		t.Fatalf("unexpected argv: %v / %v", once, cont)
	}
	for _, args := range [][]string{once, cont} {
		if args[0] != "sync" || args[1] != "--vault" || args[2] != "/vaults/Daniel-OS" {
			t.Fatalf("unexpected argv: %v", args)
		}
	}
}

func TestParsePin(t *testing.T) {
	p, err := parsePin("# comment\nversion = 1.2.3\nchecksum = abc\n")
	if err != nil {
		t.Fatalf("parsePin: %v", err)
	}
	if p.Version != "1.2.3" || p.Checksum != "abc" {
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
