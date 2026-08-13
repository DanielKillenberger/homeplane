package vault

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Retrieval: what happens on a machine that has no vault yet (R3).
//
// The lifecycle is upstream's, not one this agent invented:
//
//	login            once, to obtain an account token (stored 0600, env-passed)
//	sync-list-remote to see what the account actually has
//	sync-setup       to bind an empty local directory to one chosen remote vault
//	sync-config      to force the FIRST pass to pull-only
//	sync             to pull the content down
//
// Two refusals matter more than the happy path:
//
//   - An auth failure is reported as an auth failure, never as "no vault". They
//     need different fixes, and R3 requires `status` to say which happened.
//   - Multiple matching remote vaults are an explicit-selection error. Setting
//     up sync against the wrong remote vault would then reconcile it INTO the
//     local directory, and that is not an error anyone can undo by rerunning.
//
// The first pass is forced to `pull-only`. A bidirectional first pass against a
// freshly created empty directory is precisely the shape that propagates an
// empty local side to the remote — the deletion hazard this whole package is
// built around.

// ErrAmbiguousRemote reports multiple matching remote vaults.
type ErrAmbiguousRemote struct {
	Candidates []RemoteVault
}

func (e *ErrAmbiguousRemote) Error() string {
	names := make([]string, 0, len(e.Candidates))
	for _, c := range e.Candidates {
		names = append(names, c.Name)
	}
	return fmt.Sprintf("vault: %d remote vaults match (%s) — re-run with -remote to choose one",
		len(e.Candidates), strings.Join(names, ", "))
}

// LoginOptions describes an interactive account login.
type LoginOptions struct {
	StateDir string
	CLI      CLI
	Email    string
	// Password and MFACode answer upstream's prompts on stdin. Upstream also
	// accepts them as flags; this agent never uses those, because argv is
	// world-readable in `ps`.
	Password string
	MFACode  string
}

// Login authenticates the account and captures the resulting token into the
// agent's own 0600 store.
//
// obsidian-headless writes its token into its own config directory; the agent
// confines that directory under the state dir so a human's interactive session
// is never read or clobbered, then lifts the token into its own custody.
func Login(ctx context.Context, opts LoginOptions) error {
	if strings.TrimSpace(opts.Email) == "" {
		return errors.New("vault: an email address is required to log in")
	}
	if strings.TrimSpace(opts.Password) == "" {
		return errors.New("vault: a password is required to log in")
	}
	cli := opts.CLI
	if cli.ConfigDir == "" {
		cli.ConfigDir = CLIConfigDir(opts.StateDir)
	}
	if err := os.MkdirAll(cli.ConfigDir, credDirPerm); err != nil {
		return fmt.Errorf("vault: create CLI config dir: %w", err)
	}
	if err := cli.Verify(ctx); err != nil {
		return err
	}
	secrets := Secrets{AccountPassword: opts.Password, MFACode: opts.MFACode}
	stdin := opts.Password + "\n"
	if opts.MFACode != "" {
		stdin += opts.MFACode + "\n"
	}
	if _, err := cli.Run(ctx, Invocation{
		Args:    LoginArgs(opts.Email),
		Secrets: secrets,
		Stdin:   stdin,
	}); err != nil {
		return err
	}
	token, err := readCLIToken(cli.ConfigDir)
	if err != nil {
		return err
	}
	return SaveAuthToken(opts.StateDir, token)
}

// cliTokenPaths are the two places obsidian-headless keeps its token, depending
// on platform: `$XDG_CONFIG_HOME/obsidian-headless/auth_token` on Linux and
// `$HOME/.obsidian-headless/auth_token` elsewhere. The agent pins BOTH env vars
// to its own directory, so it checks both layouts.
func cliTokenPaths(configDir string) []string {
	return []string{
		filepath.Join(configDir, "obsidian-headless", "auth_token"),
		filepath.Join(configDir, ".obsidian-headless", "auth_token"),
	}
}

func readCLIToken(configDir string) (string, error) {
	for _, p := range cliTokenPaths(configDir) {
		raw, err := os.ReadFile(p)
		if err == nil {
			token := strings.TrimSpace(string(raw))
			if token != "" {
				return token, nil
			}
		}
	}
	return "", &AuthError{Detail: "login reported success but wrote no auth token"}
}

// RetrieveOptions describes fetching a vault onto a machine that has none.
type RetrieveOptions struct {
	StateDir string
	CLI      CLI
	Secrets  Secrets
	// RemoteName selects the remote vault. Empty means "there had better be
	// exactly one", which is checked rather than assumed.
	RemoteName string
	// LocalPath is where the vault will live.
	LocalPath string
	// DeviceName identifies this machine in the sync version history.
	DeviceName string
	// Fallback, when set, is invoked if headless retrieval fails — the
	// documented "launch Obsidian once and wait for the vault" path.
	Fallback func(ctx context.Context, localPath string) error
	// Now overrides the clock.
	Now func() time.Time
}

// RetrieveResult records what retrieval did.
type RetrieveResult struct {
	VaultPath  string `json:"vault_path"`
	RemoteName string `json:"remote_name"`
	FileCount  int    `json:"file_count"`
	UsedFallba bool   `json:"used_fallback"`
}

// Retrieve fetches the vault via obsidian-headless, falling back to the
// desktop-app path when configured.
func Retrieve(ctx context.Context, opts RetrieveOptions) (RetrieveResult, error) {
	var res RetrieveResult
	if strings.TrimSpace(opts.LocalPath) == "" {
		return res, errors.New("vault: a local path is required to retrieve into")
	}
	if strings.TrimSpace(opts.Secrets.AuthToken) == "" {
		return res, ErrNoAuthToken
	}
	if err := opts.CLI.Verify(ctx); err != nil {
		return res, err
	}

	// Refuse to retrieve on top of an existing vault: `sync-setup` against a
	// populated directory reconciles, and reconciling an unrelated vault is a
	// destructive operation with no undo.
	if IsVault(opts.LocalPath) {
		return res, fmt.Errorf("vault: %s is already a vault — retrieval is only for an absent vault", opts.LocalPath)
	}
	if err := os.MkdirAll(opts.LocalPath, credDirPerm); err != nil {
		return res, fmt.Errorf("vault: create %s: %w", opts.LocalPath, err)
	}
	local, err := Canonicalize(opts.LocalPath)
	if err != nil {
		return res, err
	}

	remote, err := selectRemote(ctx, opts, local)
	if err != nil {
		if opts.Fallback == nil {
			return res, err
		}
		// An auth failure is not something the desktop app can fix either — it
		// needs a new credential — so the fallback is reserved for the cases it
		// can actually help with.
		var authErr *AuthError
		if errors.As(err, &authErr) {
			return res, err
		}
		return retrieveViaFallback(ctx, opts, local, err)
	}
	res.RemoteName = remote.Name

	setupArgs := SyncSetupArgs(remote.Name, local)
	if strings.TrimSpace(opts.DeviceName) != "" {
		setupArgs = append(setupArgs, "--device-name", opts.DeviceName)
	}
	if _, err := opts.CLI.Run(ctx, Invocation{
		Args:       setupArgs,
		Secrets:    opts.Secrets,
		Stdin:      promptAnswers(opts.Secrets),
		WorkingDir: local,
	}); err != nil {
		if opts.Fallback != nil {
			var authErr *AuthError
			if !errors.As(err, &authErr) {
				return retrieveViaFallback(ctx, opts, local, err)
			}
		}
		return res, err
	}

	// Force the FIRST pass to pull-only. A bidirectional pass against an empty
	// directory is how an empty local side gets propagated to the remote.
	if _, err := opts.CLI.Run(ctx, Invocation{
		Args:       SyncConfigModeArgs(local, SyncModePullOnly),
		Secrets:    opts.Secrets,
		WorkingDir: local,
	}); err != nil {
		return res, fmt.Errorf("vault: could not force a pull-only first sync (refusing to run a bidirectional first pass): %w", err)
	}

	if _, err := opts.CLI.Run(ctx, Invocation{
		Args:       SyncArgs(local),
		Secrets:    opts.Secrets,
		Stdin:      promptAnswers(opts.Secrets),
		WorkingDir: local,
	}); err != nil {
		if opts.Fallback != nil {
			var authErr *AuthError
			if !errors.As(err, &authErr) {
				return retrieveViaFallback(ctx, opts, local, err)
			}
		}
		return res, err
	}

	if !IsVault(local) {
		return res, fmt.Errorf("vault: retrieval completed but %s is still not a vault (no %s directory)", local, ConfigDirName)
	}
	m, err := Scan(local)
	if err != nil {
		return res, err
	}
	res.VaultPath = local
	res.FileCount = len(m.Files)
	return res, nil
}

// selectRemote lists the account's remote vaults and picks one, or refuses.
func selectRemote(ctx context.Context, opts RetrieveOptions, local string) (RemoteVault, error) {
	out, err := opts.CLI.Run(ctx, Invocation{
		Args:       ListRemoteArgs(),
		Secrets:    opts.Secrets,
		WorkingDir: local,
	})
	if err != nil {
		return RemoteVault{}, err
	}
	all := ParseRemoteVaults(out)
	var matches []RemoteVault
	if name := strings.TrimSpace(opts.RemoteName); name != "" {
		for _, v := range all {
			if strings.EqualFold(v.Name, name) || (v.ID != "" && strings.EqualFold(v.ID, name)) {
				matches = append(matches, v)
			}
		}
	} else {
		matches = all
	}
	switch len(matches) {
	case 0:
		return RemoteVault{}, ErrNoRemoteVault
	case 1:
		return matches[0], nil
	default:
		return RemoteVault{}, &ErrAmbiguousRemote{Candidates: matches}
	}
}

// retrieveViaFallback runs the documented client fallback: launch Obsidian once
// and wait for the vault to appear. It exists because a machine that cannot use
// the headless path is still a machine Daniel can fix by opening the app — and
// enrolment must not be blocked either way (R3).
func retrieveViaFallback(ctx context.Context, opts RetrieveOptions, local string, cause error) (RetrieveResult, error) {
	res := RetrieveResult{UsedFallba: true}
	if err := opts.Fallback(ctx, local); err != nil {
		return res, fmt.Errorf("vault: headless retrieval failed (%v) and the Obsidian-app fallback also failed: %w", cause, err)
	}
	if !IsVault(local) {
		return res, fmt.Errorf("vault: headless retrieval failed (%v) and no vault appeared at %s after the Obsidian-app fallback", cause, local)
	}
	canonical, err := Canonicalize(local)
	if err != nil {
		return res, err
	}
	m, err := Scan(canonical)
	if err != nil {
		return res, err
	}
	res.VaultPath = canonical
	res.FileCount = len(m.Files)
	return res, nil
}

// WaitForVault is the waiting half of the desktop-app fallback: poll until the
// directory becomes a vault, or give up. Bounded on purpose — an unbounded wait
// in an installer is indistinguishable from a hang.
func WaitForVault(ctx context.Context, path string, timeout, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if IsVault(path) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("vault: no vault appeared at %s within %s", path, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
