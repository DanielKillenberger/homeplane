// Package workloadcred materializes a stored provider credential into the shape
// a connector's MCP server reads it in.
//
// It is the last step of the custody chain: `add-credentials` brokers the
// credential (the machine never sees it), the server stores it encrypted, and
// this package writes it — decrypted, briefly, and only ever server-side — into
// a directory the connector workload mounts. Nothing here reaches the machine,
// the harness or an audit row.
//
// The shape is chosen by NAME, from the manifest's `credential_delivery.format`
// (connectors.KnownDeliveryFormats). That indirection is what keeps R12 true on
// this path: a second provider whose server reads the same shape is a manifest
// entry, and only a genuinely new shape adds code — here, in one function,
// rather than on the credential path itself.
//
// Two properties are structural rather than conventional:
//
//   - The written file is 0600 inside a 0700 directory, created with those
//     modes rather than chmodded afterwards, so the credential is never briefly
//     world-readable (the same trap the store hit with SQLite's WAL sidecars).
//   - The write is atomic: a temp file in the destination directory, then a
//     rename. A workload reading the directory concurrently sees either the old
//     credential or the new one, never a half-written one — which matters
//     because a re-auth (R13's atomic replacement) happens while the workload
//     is running.
package workloadcred

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
)

// ErrUnsupportedFormat means the manifest named a delivery format this build
// cannot write. It is distinct from a write failure: one is a configuration
// mistake, the other is an operational one.
var ErrUnsupportedFormat = errors.New("workloadcred: unsupported credential delivery format")

// ErrInvalidAccount means the account name could not be used to name a file.
var ErrInvalidAccount = errors.New("workloadcred: invalid account")

// Credential is the provider credential to deliver. It is deliberately a plain
// value with no store or crypto in it: whatever produced it (the credential
// broker) has already done the decryption, and this package only re-shapes it.
type Credential struct {
	// AccessToken and RefreshToken are the provider's OAuth tokens.
	AccessToken  string
	RefreshToken string
	// TokenURI is where the connector refreshes the access token. It comes from
	// the manifest's driver parameters, never from the connector's own defaults.
	TokenURI string
	// ClientID and ClientSecret are Homeplane's own OAuth client, which the
	// connector needs to perform that refresh.
	ClientID     string
	ClientSecret string
	// Scopes is the granted scope set. It is written truthfully: the connector
	// refuses tools whose scope it does not hold, and that check is worth
	// keeping honest even though the provider enforces the same thing.
	Scopes []string
	// ExpiresAt is when the access token expires; the zero value means unknown.
	ExpiresAt time.Time
}

// DirMode and FileMode are the modes a credential directory and file are
// created with.
const (
	DirMode  os.FileMode = 0o700
	FileMode os.FileMode = 0o600
)

// Materialize writes the credential in the named format and returns the path it
// wrote. `dir` is the destination the workload mounts and `account` identifies
// whose credential this is (for a Google connector, the Google account address).
//
// Both are DEPLOYMENT inputs, not manifest fields: which directory a workload
// mounts and which account was granted are facts about a running system, and a
// git-tracked manifest should carry neither.
func Materialize(format, dir, account string, c Credential) (string, error) {
	switch format {
	case connectors.FormatGoogleOAuthUserFile:
		return writeGoogleOAuthUserFile(dir, account, c)
	default:
		return "", fmt.Errorf("%w: %q (this build writes: %s)",
			ErrUnsupportedFormat, format, strings.Join(connectors.KnownDeliveryFormats(), ", "))
	}
}

// googleOAuthUserFile is workspace-mcp's per-account credential file
// (auth/credential_store.py: LocalDirectoryCredentialStore). The field names are
// the connector's, not ours.
type googleOAuthUserFile struct {
	Token        string   `json:"token"`
	RefreshToken string   `json:"refresh_token"`
	TokenURI     string   `json:"token_uri"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	// Expiry is the connector's timezone-NAIVE ISO-8601 form. Google's Python
	// auth library compares it against a naive UTC now, so an offset-carrying
	// timestamp is either rejected or (worse) read as local time and treated as
	// hours-stale, forcing a refresh on every call.
	Expiry *string `json:"expiry"`
}

func writeGoogleOAuthUserFile(dir, account string, c Credential) (string, error) {
	name, err := googleAccountFilename(account)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("workloadcred: no destination directory")
	}
	if c.RefreshToken == "" && c.AccessToken == "" {
		return "", fmt.Errorf("workloadcred: credential for %q carries neither token", account)
	}

	file := googleOAuthUserFile{
		Token:        c.AccessToken,
		RefreshToken: c.RefreshToken,
		TokenURI:     c.TokenURI,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       c.Scopes,
	}
	if !c.ExpiresAt.IsZero() {
		expiry := c.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000")
		file.Expiry = &expiry
	}
	body, err := json.Marshal(file)
	if err != nil {
		return "", fmt.Errorf("workloadcred: encode credential: %w", err)
	}
	path := filepath.Join(dir, name)
	if err := writeSecretFile(dir, path, body); err != nil {
		return "", err
	}
	return path, nil
}

// googleAccountFilename is workspace-mcp's filename encoding: the account,
// percent-encoded with `@._-` kept literal, plus `.json`.
//
// The encoding is reproduced rather than approximated because the connector
// looks the file up by computing the same name — a file it cannot find is a
// credential that silently does not exist. Anything that would escape the
// directory after encoding is refused outright.
func googleAccountFilename(account string) (string, error) {
	account = strings.TrimSpace(account)
	switch {
	case account == "":
		return "", fmt.Errorf("%w: empty", ErrInvalidAccount)
	case len(account) > 320: // RFC 3696 practical maximum for an address
		return "", fmt.Errorf("%w: %d bytes is too long for an account", ErrInvalidAccount, len(account))
	case strings.ContainsAny(account, "/\\\x00"):
		return "", fmt.Errorf("%w: %q contains a path separator", ErrInvalidAccount, account)
	}
	name := url.QueryEscape(account)
	// QueryEscape renders a space as '+', which the connector's quote() renders
	// as %20. An account with a space would therefore be written where the
	// connector never looks, so it is refused instead of silently misfiled.
	if strings.Contains(name, "+") {
		return "", fmt.Errorf("%w: %q contains a space", ErrInvalidAccount, account)
	}
	name = strings.NewReplacer("%40", "@", "%2E", ".", "%2D", "-", "%5F", "_").Replace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("%w: %q does not name a file", ErrInvalidAccount, account)
	}
	return name + ".json", nil
}

// writeSecretFile creates the directory and replaces the file atomically, with
// both created at their final modes.
func writeSecretFile(dir, path string, body []byte) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("workloadcred: create credential dir: %w", err)
	}
	// MkdirAll respects the umask and skips existing directories, so the mode is
	// asserted rather than assumed.
	if err := os.Chmod(dir, DirMode); err != nil {
		return fmt.Errorf("workloadcred: tighten credential dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".credential-*.tmp")
	if err != nil {
		return fmt.Errorf("workloadcred: create temp credential: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeded

	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("workloadcred: tighten temp credential: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("workloadcred: write temp credential: %w", err)
	}
	// The credential has to be on disk before the rename publishes it: a rename
	// of an unsynced file can survive a crash with the name in place and the
	// contents empty, which reads as a corrupt credential rather than a missing
	// one.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("workloadcred: sync temp credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("workloadcred: close temp credential: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("workloadcred: publish credential: %w", err)
	}
	return nil
}
