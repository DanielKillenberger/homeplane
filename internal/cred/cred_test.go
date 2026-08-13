package cred

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewMintsDistinctHighEntropyCredentials(t *testing.T) {
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		plaintext, hash, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(plaintext)
		if err != nil {
			t.Fatalf("credential is not base64url: %v", err)
		}
		if len(raw) != TokenBytes {
			t.Fatalf("credential entropy = %d bytes, want %d", len(raw), TokenBytes)
		}
		if seen[plaintext] {
			t.Fatal("New returned a duplicate credential")
		}
		seen[plaintext] = true
		if !Verify(plaintext, hash) {
			t.Fatal("freshly minted credential does not verify against its own hash")
		}
	}
}

func TestVerifyRejectsWrongCredential(t *testing.T) {
	_, hash, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	other, _, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if Verify(other, hash) {
		t.Error("a different credential verified")
	}
	if Verify("", hash) {
		t.Error("an empty credential verified")
	}
	if Verify(other, "") {
		t.Error("verification succeeded against an empty hash")
	}
}

func TestHashDoesNotContainThePlaintext(t *testing.T) {
	plaintext, hash, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if strings.Contains(hash, plaintext) {
		t.Error("stored hash contains the plaintext credential")
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64 hex characters", len(hash))
	}
}

// TestFingerprintIsDomainSeparatedFromTheStoredHash guards a subtle
// attribution property: an audit log full of fingerprints must not let a reader
// join those rows against the credential table and work out which machine a
// rejected token belonged to.
func TestFingerprintIsDomainSeparatedFromTheStoredHash(t *testing.T) {
	plaintext, hash, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp := Fingerprint(plaintext)
	if len(fp) != FingerprintLen {
		t.Errorf("fingerprint length = %d, want %d", len(fp), FingerprintLen)
	}
	if strings.HasPrefix(hash, fp) {
		t.Error("fingerprint is a prefix of the stored hash; it must be domain-separated")
	}
	if strings.Contains(fp, plaintext) {
		t.Error("fingerprint contains the plaintext")
	}
	if Fingerprint(plaintext) != fp {
		t.Error("fingerprint is not stable for the same input")
	}
	other, _, _ := New()
	if Fingerprint(other) == fp {
		t.Error("two credentials share a fingerprint")
	}
}
