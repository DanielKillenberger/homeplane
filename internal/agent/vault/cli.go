package vault

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed obsidian-headless-pinned.sha256
var pinnedCLIFile string

// PinPending is the placeholder that means "no verified release has been staged
// for this repository yet". A pending pin is a refusal, never a warning.
const PinPending = "PENDING"

// ErrPinUnset means the pinned checksum is still PENDING.
var ErrPinUnset = errors.New("vault: obsidian-headless checksum pin is PENDING — stage and verify a release before activating sync")

// ErrPinMismatch means the CLI on disk is not the pinned build.
var ErrPinMismatch = errors.New("vault: obsidian-headless CLI does not match the pin")

// Pin is the exact obsidian-headless build this agent is allowed to run.
//
// Tarball is verified when a release is staged (scripts/fetch-obsidian-headless.sh);
// Checksum is the package's cli.js — the file node actually executes — and is
// verified on every run, because an install-time check says nothing about a
// binary swapped afterwards.
type Pin struct {
	Version  string `json:"version"`
	Tarball  string `json:"tarball,omitempty"`
	Checksum string `json:"checksum"`
}

// Pending reports whether the pin still has no verified checksum.
func (p Pin) Pending() bool {
	return strings.TrimSpace(p.Checksum) == "" || strings.EqualFold(strings.TrimSpace(p.Checksum), PinPending)
}

// LoadPin reads the pin compiled into the binary.
func LoadPin() (Pin, error) { return parsePin(pinnedCLIFile) }

func parsePin(text string) (Pin, error) {
	var p Pin
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Pin{}, fmt.Errorf("vault: malformed pin line %q", line)
		}
		switch strings.TrimSpace(key) {
		case "version":
			p.Version = strings.TrimSpace(value)
		case "tarball":
			p.Tarball = strings.TrimSpace(value)
		case "checksum":
			p.Checksum = strings.TrimSpace(value)
		default:
			return Pin{}, fmt.Errorf("vault: unknown pin key %q", strings.TrimSpace(key))
		}
	}
	if p.Version == "" {
		return Pin{}, errors.New("vault: pin is missing a version")
	}
	if p.Checksum == "" {
		return Pin{}, errors.New("vault: pin is missing a checksum")
	}
	return p, nil
}

// ── The upstream contract ────────────────────────────────────────────────────
//
// These argv builders mirror obsidian-headless 0.0.13's own parser, captured in
// testdata/ob-0.0.13-contract.txt and asserted by TestArgvMatchesThePinnedContract.
// The lifecycle is: `login` → `sync-list-remote` → `sync-setup` → `sync`.
//
// Upstream accepts both secrets as FLAGS (`login --password`, `sync-setup
// --password`). This agent never uses those flags: argv is world-readable in
// `ps`, and upstream prompts for either secret when the flag is omitted — so
// secrets go in on stdin, and the account token goes in through
// OBSIDIAN_AUTH_TOKEN, which upstream reads in preference to its own token file.

// AuthTokenEnvVar is the environment variable obsidian-headless reads its
// account token from, ahead of its own on-disk token file.
const AuthTokenEnvVar = "OBSIDIAN_AUTH_TOKEN"

// ConfigHomeEnvVar is where obsidian-headless keeps its own state on Linux.
// Overriding it (and HOME elsewhere) is how this agent guarantees it never
// reads or writes a human's interactive `ob login` session.
const ConfigHomeEnvVar = "XDG_CONFIG_HOME"

// LoginArgs starts an interactive login. The password and any MFA code are
// written to the process's stdin, never passed as flags.
func LoginArgs(email string) []string { return []string{"login", "--email", email} }

// LoginStatusArgs asks whether the stored token is still good. `ob login` with
// no arguments prints the account when already authenticated.
func LoginStatusArgs() []string { return []string{"login"} }

// ListRemoteArgs lists the account's remote vaults.
func ListRemoteArgs() []string { return []string{"sync-list-remote"} }

// ListLocalArgs lists locally configured vaults.
func ListLocalArgs() []string { return []string{"sync-list-local"} }

// SyncSetupArgs configures a local directory against a remote vault. The E2E
// encryption password is prompted for, and this agent answers on stdin.
func SyncSetupArgs(remoteVault, localPath string) []string {
	return []string{"sync-setup", "--vault", remoteVault, "--path", localPath}
}

// SyncArgs is one reconciling sync pass.
func SyncArgs(localPath string) []string { return []string{"sync", "--path", localPath} }

// SyncContinuousArgs is the long-lived watching sync (R14).
func SyncContinuousArgs(localPath string) []string {
	return []string{"sync", "--path", localPath, "--continuous"}
}

// SyncStatusArgs reports a configured vault's sync state.
func SyncStatusArgs(localPath string) []string {
	return []string{"sync-status", "--path", localPath}
}

// Sync modes. `pull-only` is the safe mode for the FIRST pass of a retrieval
// into an empty directory; `bidirectional` is upstream's default and the ONLY
// mode in which local edits ever reach the remote — a vault left in pull-only
// silently discards everything Daniel writes on that machine.
const (
	SyncModePullOnly      = "pull-only"
	SyncModeBidirectional = "bidirectional"
)

// SyncCreateRemoteArgs creates a remote vault. Used to stand up a DISPOSABLE
// remote for the authenticated pre-activation rehearsal (task .7).
func SyncCreateRemoteArgs(name string) []string {
	return []string{"sync-create-remote", "--name", name}
}

// SyncConfigModeArgs sets a configured vault's sync mode.
func SyncConfigModeArgs(localPath, mode string) []string {
	return []string{"sync-config", "--path", localPath, "--mode", mode}
}

// ── Execution ────────────────────────────────────────────────────────────────

// CLI is a verified obsidian-headless executable.
type CLI struct {
	// Bin is the path to the `ob` executable (npm's shim is a symlink to the
	// package's cli.js; Verify resolves it before checksumming).
	Bin string
	// Pin is the build this CLI must be.
	Pin Pin
	// ConfigDir isolates obsidian-headless's own state (token file, vault
	// registry). Empty means the process default.
	ConfigDir string
	// Timeout bounds a ONE-SHOT invocation. It never applies to continuous
	// sync, which lives until its context is cancelled.
	Timeout time.Duration
	// Log, when set, receives the CLI's output with secrets redacted.
	Log io.Writer
}

// DefaultTimeout bounds a single one-shot CLI call.
const DefaultTimeout = 2 * time.Minute

// maxCapturedOutput bounds what is retained from a CLI's output. A continuous
// sync can run for months; retaining all of its chatter to build an error
// message would be an unbounded allocation on a long-lived process.
const maxCapturedOutput = 64 << 10

var versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Entrypoint resolves the `ob` shim to the JavaScript file node executes. This
// is what the pin's checksum covers: npm's shim is a symlink whose own bytes
// vary per installation, while cli.js is byte-identical for a given version.
func (c CLI) Entrypoint() (string, error) {
	if strings.TrimSpace(c.Bin) == "" {
		return "", errors.New("vault: no obsidian-headless CLI path configured")
	}
	resolved, err := filepath.EvalSymlinks(c.Bin)
	if err != nil {
		return "", fmt.Errorf("vault: resolve %s: %w", c.Bin, err)
	}
	return resolved, nil
}

// Verify checks the executable is exactly the pinned build: the SHA-256 of the
// entrypoint node will run, then the version the binary reports about itself.
func (c CLI) Verify(ctx context.Context) error {
	if strings.TrimSpace(c.Bin) == "" {
		return errors.New("vault: no obsidian-headless CLI path configured")
	}
	if c.Pin.Pending() {
		return ErrPinUnset
	}
	entrypoint, err := c.Entrypoint()
	if err != nil {
		return err
	}
	sum, err := fileSHA256(entrypoint)
	if err != nil {
		return fmt.Errorf("vault: checksum %s: %w", entrypoint, err)
	}
	if !strings.EqualFold(sum, c.Pin.Checksum) {
		return fmt.Errorf("%w: %s has sha256 %s, pinned %s", ErrPinMismatch, entrypoint, sum, c.Pin.Checksum)
	}
	out, err := c.Run(ctx, Invocation{Args: []string{"--version"}})
	if err != nil {
		return fmt.Errorf("vault: probe obsidian-headless version: %w", err)
	}
	reported := versionPattern.FindString(out)
	if reported == "" {
		return fmt.Errorf("%w: %s reported no parseable version (%q)", ErrPinMismatch, c.Bin, strings.TrimSpace(out))
	}
	if reported != c.Pin.Version {
		return fmt.Errorf("%w: %s reports %s, pinned %s", ErrPinMismatch, c.Bin, reported, c.Pin.Version)
	}
	return nil
}

// Secrets are the two DISTINCT credentials obsidian-headless uses. Conflating
// them is a real hazard: the account token authenticates the machine to
// Obsidian, while the E2E password decrypts vault content and is not recoverable
// from the account.
type Secrets struct {
	// AuthToken authenticates the account (OBSIDIAN_AUTH_TOKEN).
	AuthToken string
	// E2EPassword decrypts an end-to-end encrypted vault. Answered at the
	// interactive prompt on stdin, never passed as a flag.
	E2EPassword string
	// AccountPassword is only used by `login`; it is never stored.
	AccountPassword string
	// MFACode is only used by `login`.
	MFACode string
}

// all returns every non-empty secret, for redaction and argv assertions.
func (s Secrets) all() []string {
	var out []string
	for _, v := range []string{s.AuthToken, s.E2EPassword, s.AccountPassword, s.MFACode} {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

// Invocation is one CLI call.
type Invocation struct {
	Args    []string
	Secrets Secrets
	// Stdin answers upstream's interactive prompts (E2E password, MFA code).
	Stdin string
	// WorkingDir runs the CLI somewhere specific. Upstream defaults several
	// commands to the current directory, so this is load-bearing.
	WorkingDir string
}

// Run performs a BOUNDED, one-shot invocation and returns its captured output.
//
// Bounded is the operative word: it is for `--version`, `sync-list-remote`,
// `sync-setup`, and a single `sync` pass — calls that must finish. Continuous
// sync must never come through here (see Stream).
func (c CLI) Run(ctx context.Context, inv Invocation) (string, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.exec(ctx, inv, false)
}

// Stream performs an UNBOUNDED invocation for continuous sync.
//
// It returns only when the process exits or ctx is cancelled — a healthy
// continuous sync must not be killed on a timer. Output is streamed through a
// redacting writer and only a bounded tail is retained, so a process that runs
// for months cannot grow an error buffer without limit.
func (c CLI) Stream(ctx context.Context, inv Invocation) error {
	_, err := c.exec(ctx, inv, true)
	return err
}

func (c CLI) exec(ctx context.Context, inv Invocation, streaming bool) (string, error) {
	secrets := inv.Secrets.all()
	if err := AssertNoSecretInArgs(inv.Args, secrets...); err != nil {
		return "", err
	}
	if strings.TrimSpace(c.Bin) == "" {
		return "", errors.New("vault: no obsidian-headless CLI path configured")
	}

	cmd := exec.CommandContext(ctx, c.Bin, inv.Args...)
	cmd.Dir = inv.WorkingDir
	cmd.Env = c.environ(inv.Secrets)
	if inv.Stdin != "" {
		cmd.Stdin = strings.NewReader(inv.Stdin)
	}

	tail := &tailBuffer{limit: maxCapturedOutput}
	var sink io.Writer = tail
	if c.Log != nil {
		sink = io.MultiWriter(tail, c.Log)
	}
	redactor := &redactingWriter{w: sink, secrets: secrets}
	cmd.Stdout = redactor
	cmd.Stderr = redactor

	err := cmd.Run()
	output := tail.String()
	if err != nil {
		if streaming && ctx.Err() != nil {
			// Cancellation is how a supervised sync is asked to stop; that is a
			// clean shutdown, not a sync failure.
			return output, ctx.Err()
		}
		return output, classify(output, err)
	}
	return output, nil
}

// environ builds the child environment: the account token goes in here (never
// argv), and obsidian-headless's own state directory is isolated so the agent
// can never clobber a human's interactive login.
func (c CLI) environ(secrets Secrets) []string {
	env := os.Environ()
	filtered := env[:0]
	for _, kv := range env {
		key, _, _ := strings.Cut(kv, "=")
		if key == AuthTokenEnvVar {
			continue // never inherit an ambient token
		}
		if c.ConfigDir != "" && (key == ConfigHomeEnvVar || key == "HOME") {
			continue
		}
		filtered = append(filtered, kv)
	}
	env = filtered
	if strings.TrimSpace(secrets.AuthToken) != "" {
		env = append(env, AuthTokenEnvVar+"="+secrets.AuthToken)
	}
	if c.ConfigDir != "" {
		// Linux: XDG_CONFIG_HOME/obsidian-headless. macOS: ~/.obsidian-headless.
		// Setting both pins the state directory on either platform.
		env = append(env, ConfigHomeEnvVar+"="+c.ConfigDir, "HOME="+c.ConfigDir)
	}
	return env
}

// tailBuffer keeps at most limit bytes, discarding from the front. It is what
// makes a months-long continuous sync safe to capture output from.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}

// redactingWriter removes secrets before they can reach a log file or an error.
// It buffers a partial line so a secret split across two writes is still caught.
type redactingWriter struct {
	w       io.Writer
	secrets []string
	pending bytes.Buffer
}

func (r *redactingWriter) Write(p []byte) (int, error) {
	n := len(p)
	r.pending.Write(p)
	for {
		line, err := r.pending.ReadString('\n')
		if err != nil {
			// No complete line yet; keep it for the next write. Flush anyway if
			// the partial line has grown past a sane bound.
			r.pending.Reset()
			r.pending.WriteString(line)
			if r.pending.Len() > 8<<10 {
				if _, err := io.WriteString(r.w, Redact(r.pending.String(), r.secrets...)); err != nil {
					return n, err
				}
				r.pending.Reset()
			}
			return n, nil
		}
		if _, err := io.WriteString(r.w, Redact(line, r.secrets...)); err != nil {
			return n, err
		}
	}
}

// ── Failure classification ───────────────────────────────────────────────────

// AuthError means the account token was rejected or absent: a NEW credential is
// needed, and no amount of retrying will help.
type AuthError struct{ Detail string }

func (e *AuthError) Error() string { return "vault: Obsidian authentication failed: " + e.Detail }

// NetworkError is a transport failure: retryable, and NOT an auth problem.
type NetworkError struct{ Detail string }

func (e *NetworkError) Error() string { return "vault: Obsidian Sync network failure: " + e.Detail }

// ErrNoRemoteVault means the account has no remote vault matching the request —
// distinct from an auth failure, which is what R3 requires status to tell apart.
var ErrNoRemoteVault = errors.New("vault: no matching remote vault on this account")

// ErrNotConfigured means the CLI was pointed at a directory that has never been
// bound to a remote vault by `sync-setup`.
//
// This has its own error because it is the difference between "sync is broken"
// and "this directory was never set up" — and because the pre-activation
// rehearsal deliberately provokes it to prove the build runs without touching
// anything.
var ErrNotConfigured = errors.New("vault: this directory is not configured for sync (run `sync-setup`)")

func classify(output string, err error) error {
	lower := strings.ToLower(output)
	switch {
	case containsAny(lower,
		"unauthorized", "authentication failed", "invalid credentials", "401",
		"not logged in", "login required", "please log in", "invalid token", "bad password"):
		return &AuthError{Detail: firstLine(output)}
	case containsAny(lower,
		"not configured", "no sync configuration", "run sync-setup", "sync-setup first",
		"vault is not set up", "no vault configuration"):
		return fmt.Errorf("%w: %s", ErrNotConfigured, firstLine(output))
	case containsAny(lower,
		"network", "timeout", "timed out", "connection refused", "econnrefused",
		"enotfound", "dns", "unreachable", "socket hang up", "temporary failure"):
		return &NetworkError{Detail: firstLine(output)}
	default:
		return fmt.Errorf("vault: obsidian-headless failed: %s: %w", firstLine(output), err)
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// AssertNoSecretInArgs is a belt-and-braces check that no credential reaches
// argv. It runs on every exec rather than being trusted to review, because
// upstream's own interface offers `--password` flags that this agent must never
// use.
func AssertNoSecretInArgs(args []string, secrets ...string) error {
	for _, secret := range secrets {
		if strings.TrimSpace(secret) == "" {
			continue
		}
		for _, a := range args {
			if strings.Contains(a, secret) {
				return errors.New("vault: refusing to exec — a credential appeared in argv")
			}
		}
	}
	return nil
}

// Redact removes every secret from text destined for a log or an error.
func Redact(text string, secrets ...string) string {
	for _, s := range secrets {
		if strings.TrimSpace(s) == "" {
			continue
		}
		text = strings.ReplaceAll(text, s, "[redacted]")
	}
	return text
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ── Output parsing ───────────────────────────────────────────────────────────

// RemoteVault is one entry from `ob sync-list-remote`.
type RemoteVault struct {
	Name string `json:"name"`
	ID   string `json:"id,omitempty"`
}

// remoteVaultLine matches the listing's rendered rows. Upstream prints a human
// table, so this is tolerant: it takes the first bracketed id when present and
// otherwise treats the row as a bare name.
var remoteVaultLine = regexp.MustCompile(`^\s*(?:[-*]\s*)?(.+?)(?:\s+[\[(]([0-9a-fA-F-]{6,})[\])])?\s*$`)

// ParseRemoteVaults reads `sync-list-remote` output.
//
// It is deliberately conservative: anything that looks like a header, a blank
// line, or a message rather than a row is skipped, and an unparseable listing
// yields no vaults rather than a guess. A wrong vault name here would set up
// sync against somebody else's vault.
func ParseRemoteVaults(output string) []RemoteVault {
	var out []RemoteVault
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasSuffix(trimmed, ":") ||
			containsAny(lower, "no vaults", "available remote", "remote vaults", "logged in as", "usage:") {
			continue
		}
		m := remoteVaultLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m[1])
		if name == "" {
			continue
		}
		out = append(out, RemoteVault{Name: name, ID: m[2]})
	}
	return out
}
