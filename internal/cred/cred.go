// Package cred mints and verifies Homeplane's bearer credentials: machine
// credentials (issued by /enrol) and grant tokens (issued by POST /grants).
//
// Custody rule: the server returns a plaintext credential exactly once, at
// issuance, and persists only its hash. That is why re-enrolment is explicit
// rotation rather than a silent no-op — the server is structurally incapable of
// re-returning a credential it already issued.
package cred

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// TokenBytes is the entropy of every issued credential (256 bits).
const TokenBytes = 32

// New mints a fresh credential, returning the plaintext (shown to the caller
// exactly once) and the hash to persist.
func New() (plaintext, hash string, err error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("cred: generate: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, Hash(plaintext), nil
}

// Hash returns the stored form of a credential.
//
// A plain SHA-256 is deliberate and sufficient here, unlike for user passwords:
// these credentials are 256 bits of CSPRNG output, so there is no guessable
// keyspace for a stolen hash to be brute-forced against, and a slow KDF would
// only tax the per-request verification path.
func Hash(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Verify reports whether plaintext matches a stored hash, in constant time.
func Verify(plaintext, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(Hash(plaintext)), []byte(storedHash)) == 1
}

// fingerprintDomain separates fingerprints from stored hashes so that an audit
// reader (or anyone who exfiltrates the log) cannot match a logged fingerprint
// against the credential table to identify which grant a rejected token
// belonged to. Denials stay attributable to each other without becoming
// attributable to a machine.
const fingerprintDomain = "homeplane/audit-token-fingerprint\x00"

// FingerprintLen is the number of hex characters in a token fingerprint.
const FingerprintLen = 12

// Fingerprint returns a short, non-reversible label for a REJECTED credential,
// suitable for audit rows. It lets an operator correlate repeated bad-token
// attempts without ever misattributing them to a legitimate machine.
func Fingerprint(plaintext string) string {
	sum := sha256.Sum256(append([]byte(fingerprintDomain), []byte(plaintext)...))
	return hex.EncodeToString(sum[:])[:FingerprintLen]
}
