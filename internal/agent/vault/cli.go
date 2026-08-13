package vault

import (
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
	"regexp"
	"strings"
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
type Pin struct {
	Version  string `json:"version"`
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

// CLI is a verified obsidian-headless executable.
//
// Nothing here ever puts the sync credential on the command line. It is handed
// over through the environment exactly once, at exec time, and `Command` is
// available so a supervision unit can be rendered from the SAME argv the agent
// would run itself — with the credential supplied by the unit's own environment
// file, not baked into the unit.
type CLI struct {
	// Bin is the path to the obsidian-headless executable.
	Bin string
	// Pin is the build this CLI must be.
	Pin Pin
	// VersionArgs probes the version. Overridable for tests.
	VersionArgs []string
	// Timeout bounds each CLI invocation.
	Timeout time.Duration
	// Stderr, when set, receives the CLI's stderr (already redacted).
	Stderr io.Writer
}

// CredentialEnvVar carries the Obsidian Sync credential into the CLI process.
// Environment, never argv: argv is world-readable in `ps` on both platforms.
const CredentialEnvVar = "OBSIDIAN_SYNC_PASSWORD"

// DefaultTimeout bounds a single CLI call.
const DefaultTimeout = 2 * time.Minute

var versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

// Verify checks the executable is exactly the pinned build: first the SHA-256
// of the bytes on disk, then the version the binary reports about itself. Both
// must agree before any sync command is allowed to run.
func (c CLI) Verify(ctx context.Context) error {
	if strings.TrimSpace(c.Bin) == "" {
		return errors.New("vault: no obsidian-headless CLI path configured")
	}
	if c.Pin.Pending() {
		return ErrPinUnset
	}
	sum, err := fileSHA256(c.Bin)
	if err != nil {
		return fmt.Errorf("vault: checksum %s: %w", c.Bin, err)
	}
	if !strings.EqualFold(sum, c.Pin.Checksum) {
		return fmt.Errorf("%w: %s has sha256 %s, pinned %s", ErrPinMismatch, c.Bin, sum, c.Pin.Checksum)
	}
	out, err := c.run(ctx, "", c.versionArgs()...)
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

func (c CLI) versionArgs() []string {
	if len(c.VersionArgs) > 0 {
		return c.VersionArgs
	}
	return []string{"--version"}
}

// SyncOnceArgs is the argv for a single reconciling sync pass.
func SyncOnceArgs(vaultDir string) []string {
	return []string{"sync", "--vault", vaultDir, "--once"}
}

// SyncContinuousArgs is the argv a supervision unit runs to keep the vault
// synchronized (R14).
func SyncContinuousArgs(vaultDir string) []string {
	return []string{"sync", "--vault", vaultDir, "--continuous"}
}

// SyncOnce runs one sync pass against vaultDir.
func (c CLI) SyncOnce(ctx context.Context, vaultDir, credential string) error {
	if _, err := c.run(ctx, credential, SyncOnceArgs(vaultDir)...); err != nil {
		return err
	}
	return nil
}

// SyncContinuous runs the long-lived sync process. It returns when the process
// exits — which, under supervision, is what a restart is made of.
func (c CLI) SyncContinuous(ctx context.Context, vaultDir, credential string) error {
	if _, err := c.run(ctx, credential, SyncContinuousArgs(vaultDir)...); err != nil {
		return err
	}
	return nil
}

// AuthError distinguishes "the credential was rejected" from "no vault" and
// from "the network was down" — a distinction R14 requires `status` to make.
type AuthError struct{ Detail string }

func (e *AuthError) Error() string { return "vault: Obsidian Sync authentication failed: " + e.Detail }

// NetworkError is a transport failure: retryable, and NOT an auth problem.
type NetworkError struct{ Detail string }

func (e *NetworkError) Error() string { return "vault: Obsidian Sync network failure: " + e.Detail }

// classify turns a CLI failure into the category `status` reports. The CLI's
// exit codes are not a stable contract, so the message is inspected — but the
// classification is explicit and testable rather than implied by a bare error.
func classify(output string, err error) error {
	lower := strings.ToLower(output)
	switch {
	case containsAny(lower, "unauthorized", "authentication failed", "invalid credentials", "401", "login required", "bad password"):
		return &AuthError{Detail: firstLine(output)}
	case containsAny(lower, "network", "timeout", "connection refused", "dns", "unreachable", "temporary failure"):
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

// run executes the CLI. The credential goes in through the environment; the
// command's output is redacted before it can reach a log or an error string.
func (c CLI) run(ctx context.Context, credential string, args ...string) (string, error) {
	if err := AssertNoSecretInArgs(args, credential); err != nil {
		return "", err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.Bin, args...)
	cmd.Env = append(os.Environ(), CredentialEnvVar+"="+credential)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	output := Redact(buf.String(), credential)
	if c.Stderr != nil {
		fmt.Fprint(c.Stderr, output)
	}
	if err != nil {
		return output, classify(output, err)
	}
	return output, nil
}

// AssertNoSecretInArgs is a belt-and-braces check that the credential never
// reaches argv. It is called on every exec rather than trusted to review.
func AssertNoSecretInArgs(args []string, secret string) error {
	if strings.TrimSpace(secret) == "" {
		return nil
	}
	for _, a := range args {
		if strings.Contains(a, secret) {
			return errors.New("vault: refusing to exec — the sync credential appeared in argv")
		}
	}
	return nil
}

// Redact removes the credential from text destined for a log or an error.
func Redact(text, secret string) string {
	if strings.TrimSpace(secret) == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "[redacted]")
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
