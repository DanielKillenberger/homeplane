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

func retrieveOpts(t *testing.T, cli CLI, dest string) RetrieveOptions {
	t.Helper()
	return RetrieveOptions{
		StateDir:  tempDir(t),
		CLI:       cli,
		Secrets:   testSecrets(),
		LocalPath: dest,
	}
}

func TestRetrievePullsAnAbsentVault(t *testing.T) {
	cli := pinnedFakeCLI(t)
	dest := filepath.Join(tempDir(t), "Daniel-OS")
	log := filepath.Join(tempDir(t), "ob.log")
	t.Setenv("FAKE_OB_LOG", log)
	t.Setenv("FAKE_OB_MODE", "pull")
	t.Setenv("FAKE_OB_REMOTES", "Daniel-OS")

	res, err := Retrieve(context.Background(), retrieveOpts(t, cli, dest))
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if res.RemoteName != "Daniel-OS" {
		t.Fatalf("remote = %q", res.RemoteName)
	}
	if !IsVault(res.VaultPath) {
		t.Fatalf("%s is not a vault after retrieval", res.VaultPath)
	}
	if res.FileCount == 0 {
		t.Fatal("retrieval reported no files")
	}
	if res.UsedFallba {
		t.Fatal("the headless path reported using the fallback")
	}

	// The first pass MUST be pull-only: a bidirectional first pass against a
	// freshly created empty directory is how an empty local side gets
	// propagated to the remote.
	lines := readLog(t, log)
	if mode := lineWithPrefix(lines, "mode:"); mode != "mode:"+SyncModePullOnly {
		t.Fatalf("first-pass sync mode = %q, want pull-only", mode)
	}
	var sawSetup, sawSync bool
	for _, l := range lines {
		if strings.HasPrefix(l, "argv:sync-setup") {
			sawSetup = true
		}
		if strings.HasPrefix(l, "argv:sync --path") {
			sawSync = true
		}
	}
	if !sawSetup || !sawSync {
		t.Fatalf("the upstream lifecycle was not followed:\n%s", strings.Join(lines, "\n"))
	}
}

// The branch that was previously unreachable: an auth failure during retrieval
// is reported as an auth failure, not as "no vault". They need different fixes.
func TestRetrieveDistinguishesAuthFailureFromNoVault(t *testing.T) {
	t.Run("auth failure", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_AUTH_FAIL", "1")
		_, err := Retrieve(context.Background(), retrieveOpts(t, cli, filepath.Join(tempDir(t), "v")))
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("err = %v, want *AuthError", err)
		}
		if errors.Is(err, ErrNoRemoteVault) {
			t.Fatal("an auth failure was reported as a missing vault")
		}
	})

	t.Run("no remote vault", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_REMOTES", "Someone-Elses-Vault")
		opts := retrieveOpts(t, cli, filepath.Join(tempDir(t), "v"))
		opts.RemoteName = "Daniel-OS"
		_, err := Retrieve(context.Background(), opts)
		if !errors.Is(err, ErrNoRemoteVault) {
			t.Fatalf("err = %v, want ErrNoRemoteVault", err)
		}
		var authErr *AuthError
		if errors.As(err, &authErr) {
			t.Fatal("a missing vault was reported as an auth failure")
		}
	})

	t.Run("no auth token at all", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		opts := retrieveOpts(t, cli, filepath.Join(tempDir(t), "v"))
		opts.Secrets = Secrets{}
		if _, err := Retrieve(context.Background(), opts); !errors.Is(err, ErrNoAuthToken) {
			t.Fatalf("err = %v, want ErrNoAuthToken", err)
		}
	})

	t.Run("network failure", func(t *testing.T) {
		cli := pinnedFakeCLI(t)
		t.Setenv("FAKE_OB_NET_FAIL", "1")
		_, err := Retrieve(context.Background(), retrieveOpts(t, cli, filepath.Join(tempDir(t), "v")))
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("err = %v, want *NetworkError", err)
		}
	})
}

// Setting up sync against the WRONG remote vault reconciles it into the local
// directory, and that has no undo — so two matches is a refusal.
func TestRetrieveRefusesToGuessBetweenRemoteVaults(t *testing.T) {
	cli := pinnedFakeCLI(t)
	t.Setenv("FAKE_OB_REMOTES", "Daniel-OS Daniel-OS-archive")

	_, err := Retrieve(context.Background(), retrieveOpts(t, cli, filepath.Join(tempDir(t), "v")))
	var ambiguous *ErrAmbiguousRemote
	if !errors.As(err, &ambiguous) {
		t.Fatalf("err = %v, want *ErrAmbiguousRemote", err)
	}
	if len(ambiguous.Candidates) != 2 {
		t.Fatalf("candidates = %+v", ambiguous.Candidates)
	}
	if !strings.Contains(err.Error(), "-remote") {
		t.Fatalf("the error does not say how to choose: %v", err)
	}
}

func TestRetrieveSelectsANamedRemote(t *testing.T) {
	cli := pinnedFakeCLI(t)
	t.Setenv("FAKE_OB_REMOTES", "Scratch Daniel-OS")
	t.Setenv("FAKE_OB_MODE", "pull")
	opts := retrieveOpts(t, cli, filepath.Join(tempDir(t), "v"))
	opts.RemoteName = "Daniel-OS"

	res, err := Retrieve(context.Background(), opts)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if res.RemoteName != "Daniel-OS" {
		t.Fatalf("remote = %q, want Daniel-OS", res.RemoteName)
	}
}

// Retrieval is for an ABSENT vault. Running it over an existing one would
// reconcile an unrelated vault into it.
func TestRetrieveRefusesAnExistingVault(t *testing.T) {
	cli := pinnedFakeCLI(t)
	existing := makeVault(t, map[string]string{"mine.md": "do not touch\n"})

	_, err := Retrieve(context.Background(), retrieveOpts(t, cli, existing))
	if err == nil {
		t.Fatal("retrieval ran over an existing vault")
	}
	if !strings.Contains(err.Error(), "already a vault") {
		t.Fatalf("err = %v, want a refusal naming the existing vault", err)
	}
	if body, err := os.ReadFile(filepath.Join(existing, "mine.md")); err != nil || string(body) != "do not touch\n" {
		t.Fatalf("the existing vault was modified (%v, %q)", err, body)
	}
}

// The documented fallback: when the headless path cannot work, launch Obsidian
// once and wait. Enrolment is never blocked by a failed retrieval (R3).
func TestRetrieveFallsBackToTheObsidianApp(t *testing.T) {
	cli := pinnedFakeCLI(t)
	t.Setenv("FAKE_OB_SETUP_FAIL", "error: vault format not recognised")
	dest := filepath.Join(tempDir(t), "v")

	opts := retrieveOpts(t, cli, dest)
	var launched bool
	opts.Fallback = func(ctx context.Context, local string) error {
		launched = true
		// Stand in for the desktop app populating the directory.
		if err := os.MkdirAll(filepath.Join(local, ConfigDirName), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(local, "from-app.md"), []byte("hello\n"), 0o600)
	}

	res, err := Retrieve(context.Background(), opts)
	if err != nil {
		t.Fatalf("Retrieve with fallback: %v", err)
	}
	if !launched || !res.UsedFallba {
		t.Fatalf("the fallback did not run: launched=%v result=%+v", launched, res)
	}
	if !IsVault(res.VaultPath) {
		t.Fatal("the fallback reported success without a vault")
	}
}

// The fallback cannot fix a bad credential, so it is not attempted for one:
// launching an app that will also fail to authenticate just hides the reason.
func TestFallbackIsNotUsedForAuthFailures(t *testing.T) {
	cli := pinnedFakeCLI(t)
	t.Setenv("FAKE_OB_AUTH_FAIL", "1")
	opts := retrieveOpts(t, cli, filepath.Join(tempDir(t), "v"))
	var launched bool
	opts.Fallback = func(context.Context, string) error { launched = true; return nil }

	_, err := Retrieve(context.Background(), opts)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want *AuthError", err)
	}
	if launched {
		t.Fatal("the app fallback was launched for an auth failure")
	}
}

func TestFallbackFailureNamesBothCauses(t *testing.T) {
	cli := pinnedFakeCLI(t)
	t.Setenv("FAKE_OB_SETUP_FAIL", "error: vault format not recognised")
	opts := retrieveOpts(t, cli, filepath.Join(tempDir(t), "v"))
	opts.Fallback = func(context.Context, string) error { return errors.New("Obsidian is not installed") }

	_, err := Retrieve(context.Background(), opts)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "not recognised") || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("err = %v, want both causes named", err)
	}
}

func TestWaitForVault(t *testing.T) {
	dir := filepath.Join(tempDir(t), "v")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = os.MkdirAll(filepath.Join(dir, ConfigDirName), 0o700)
	}()
	if err := WaitForVault(context.Background(), dir, 5*time.Second, 10*time.Millisecond); err != nil {
		t.Fatalf("WaitForVault: %v", err)
	}

	// Bounded on purpose: an unbounded wait in an installer is a hang.
	other := filepath.Join(tempDir(t), "never")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WaitForVault(context.Background(), other, 50*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("WaitForVault waited forever")
	}
}

// Login captures the CLI's own token into the agent's 0600 custody, and does it
// without ever putting the password in argv.
func TestLoginCapturesTheTokenWithoutArgvExposure(t *testing.T) {
	cli := pinnedFakeCLI(t)
	stateDir := tempDir(t)
	log := filepath.Join(tempDir(t), "ob.log")
	t.Setenv("FAKE_OB_LOG", log)
	t.Setenv("FAKE_OB_TOKEN", "tok-from-login")

	const password = "account-password"
	if err := Login(context.Background(), LoginOptions{
		StateDir: stateDir, CLI: cli, Email: "d@example.com", Password: password,
	}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	token, err := LoadAuthToken(stateDir)
	if err != nil {
		t.Fatalf("LoadAuthToken: %v", err)
	}
	if token != "tok-from-login" {
		t.Fatalf("stored token = %q", token)
	}
	lines := readLog(t, log)
	if argv := lineWithPrefix(lines, "argv:"); strings.Contains(argv, password) {
		t.Fatalf("the password appeared in argv: %s", argv)
	}
	if got := lineWithPrefix(lines, "password:"); got != "password:"+password {
		t.Fatalf("the password did not reach stdin: %q", got)
	}
	info, err := os.Stat(AuthTokenPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("stored token mode = %o, want 0600", perm)
	}
}

func TestLoginSurfacesAuthFailure(t *testing.T) {
	cli := pinnedFakeCLI(t)
	stateDir := tempDir(t)
	t.Setenv("FAKE_OB_AUTH_FAIL", "1")

	err := Login(context.Background(), LoginOptions{
		StateDir: stateDir, CLI: cli, Email: "d@example.com", Password: "wrong",
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %v, want *AuthError", err)
	}
	if _, err := LoadAuthToken(stateDir); !errors.Is(err, ErrNoAuthToken) {
		t.Fatal("a failed login stored a token anyway")
	}
}

func TestLoginRequiresEmailAndPassword(t *testing.T) {
	cli := pinnedFakeCLI(t)
	if err := Login(context.Background(), LoginOptions{StateDir: tempDir(t), CLI: cli, Password: "p"}); err == nil {
		t.Fatal("login without an email was accepted")
	}
	if err := Login(context.Background(), LoginOptions{StateDir: tempDir(t), CLI: cli, Email: "d@example.com"}); err == nil {
		t.Fatal("login without a password was accepted")
	}
}
