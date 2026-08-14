package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// The delivery step is the difference between a credential that is stored and a
// connector that can use it, and it runs unattended on a server nobody watches.
// These tests hold what a live run cannot re-check on every commit: the file
// lands where the connector looks for it, in the shape the manifest names, with
// the modes custody depends on — and a half-configured deployment is refused at
// startup rather than discovered when the first tool call fails.

type fakeCredentialSource struct {
	cred credflow.Credential
	gen  int64
	err  error
}

func (f fakeCredentialSource) Credential(context.Context, string) (credflow.Credential, int64, error) {
	return f.cred, f.gen, f.err
}

type fakeSecretReader struct {
	byRef map[string][]byte
	err   error
}

func (f fakeSecretReader) GetSecret(_ context.Context, ref string) (store.Secret, error) {
	if f.err != nil {
		return store.Secret{}, f.err
	}
	ciphertext, ok := f.byRef[ref]
	if !ok {
		return store.Secret{}, store.ErrNotFound
	}
	return store.Secret{Ref: ref, Ciphertext: ciphertext, Generation: 1}, nil
}

func deliveryFixture(t *testing.T, cred credflow.Credential) (*secrets.Keyring, fakeSecretReader, *connectors.Engine) {
	t.Helper()
	keyring, err := secrets.GenerateKeyFile(filepath.Join(t.TempDir(), "secrets.age-key"))
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	seal := func(v string) []byte {
		ciphertext, err := keyring.Encrypt([]byte(v))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		return ciphertext
	}
	reader := fakeSecretReader{byRef: map[string][]byte{
		"google/client-id":     seal("client-id-value"),
		"google/client-secret": seal("client-secret-value"),
	}}

	manifest, err := connectors.LoadFile(filepath.Join("..", "..", "configs", "connectors", "google.json"))
	if err != nil {
		t.Fatalf("load the shipped manifest: %v", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		t.Fatalf("register the shipped manifest: %v", err)
	}
	return keyring, reader, engine
}

// TestWorkloadDeliveryWritesTheConnectorsCredentialFile is the whole point of
// the step: the connector finds its credential by computing a filename, so a
// file written anywhere else is a credential that silently does not exist.
func TestWorkloadDeliveryWritesTheConnectorsCredentialFile(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	cred := credflow.Credential{
		Provider: "google", Access: "access-token", Refresh: "refresh-token",
		Scope: "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/calendar.events",
		ExpiresAt: expires,
	}
	keyring, reader, engine := deliveryFixture(t, cred)
	dir := filepath.Join(t.TempDir(), "workload-creds")

	d, err := newWorkloadDelivery(fakeCredentialSource{cred: cred, gen: 3}, reader, keyring, engine,
		dir, "person@example.com", false, nil)
	if err != nil {
		t.Fatalf("newWorkloadDelivery: %v", err)
	}
	if err := d.deliver(context.Background(), "google"); err != nil {
		t.Fatalf("deliver: %v", err)
	}

	path := filepath.Join(dir, "person@example.com.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the connector's credential file is not where it looks for it: %v", err)
	}
	var file struct {
		Token        string   `json:"token"`
		RefreshToken string   `json:"refresh_token"`
		TokenURI     string   `json:"token_uri"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		Scopes       []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode the delivered credential: %v", err)
	}
	if file.Token != "access-token" || file.RefreshToken != "refresh-token" {
		t.Errorf("delivered tokens = %q/%q, want the stored ones", file.Token, file.RefreshToken)
	}
	// The driver secrets are Homeplane's own OAuth client, decrypted here and
	// nowhere else: without them the connector cannot refresh at all.
	if file.ClientID != "client-id-value" || file.ClientSecret != "client-secret-value" {
		t.Errorf("delivered client = %q/%q, want the values from the store", file.ClientID, file.ClientSecret)
	}
	if file.TokenURI != "https://oauth2.googleapis.com/token" {
		t.Errorf("token_uri = %q, want the manifest's token endpoint", file.TokenURI)
	}
	if len(file.Scopes) != 2 {
		t.Errorf("scopes = %v, want the two granted scopes", file.Scopes)
	}

	assertMode(t, path, 0o600)
	assertMode(t, dir, 0o700)
}

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s has mode %o, want %o", path, got, want)
	}
}

// TestWorkloadDeliveryRefusesHalfAConfiguration: a deployment that names a
// directory but no account cannot write a file the connector will ever find, and
// the symptom would be a tool call failing on a server that started cleanly.
func TestWorkloadDeliveryRefusesHalfAConfiguration(t *testing.T) {
	keyring, reader, engine := deliveryFixture(t, credflow.Credential{})
	src := fakeCredentialSource{}

	if _, err := newWorkloadDelivery(src, reader, keyring, engine, t.TempDir(), "", false, nil); err == nil {
		t.Error("a credential directory with no account was accepted")
	}
	if _, err := newWorkloadDelivery(src, reader, keyring, engine, "", "person@example.com", false, nil); err == nil {
		t.Error("an account with no credential directory was accepted")
	}
	// Neither is the ordinary case of a deployment that does not deliver.
	d, err := newWorkloadDelivery(src, reader, keyring, engine, "", "", false, nil)
	if err != nil {
		t.Fatalf("an unconfigured delivery is not an error: %v", err)
	}
	if d != nil {
		t.Error("delivery was built without any configuration")
	}
	// And the nil delivery is safe to call, because the broker calls it
	// unconditionally on every commit.
	if err := d.deliver(context.Background(), "google"); err != nil {
		t.Errorf("an unconfigured delivery must be a no-op, got %v", err)
	}
	d.deliverStored(context.Background())
}

// TestWorkloadDeliveryReportsAnAbsentCredential: the ordinary state of a fresh
// deployment is "no credential yet", and a restart must say so rather than fail.
func TestWorkloadDeliveryReportsAnAbsentCredential(t *testing.T) {
	keyring, reader, engine := deliveryFixture(t, credflow.Credential{})
	d, err := newWorkloadDelivery(fakeCredentialSource{err: store.ErrNotFound}, reader, keyring, engine,
		t.TempDir(), "person@example.com", false, nil)
	if err != nil {
		t.Fatalf("newWorkloadDelivery: %v", err)
	}
	err = d.deliver(context.Background(), "google")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deliver with no stored credential = %v, want a not-found the caller can recognize", err)
	}
	// deliverStored turns exactly that into an informational skip.
	d.deliverStored(context.Background())
}

// TestWorkloadDeliveryFailsLoudlyOnAnUnreadableDriverSecret. The credential
// would otherwise be written WITHOUT the client id and secret — a file the
// connector accepts and cannot refresh with, failing an hour later.
func TestWorkloadDeliveryFailsLoudlyOnAnUnreadableDriverSecret(t *testing.T) {
	cred := credflow.Credential{Provider: "google", Access: "access-token", Refresh: "refresh-token"}
	keyring, reader, engine := deliveryFixture(t, cred)
	delete(reader.byRef, "google/client-secret")
	dir := filepath.Join(t.TempDir(), "workload-creds")

	d, err := newWorkloadDelivery(fakeCredentialSource{cred: cred}, reader, keyring, engine,
		dir, "person@example.com", false, nil)
	if err != nil {
		t.Fatalf("newWorkloadDelivery: %v", err)
	}
	err = d.deliver(context.Background(), "google")
	if err == nil {
		t.Fatal("delivery succeeded without the connector's client secret")
	}
	if !strings.Contains(err.Error(), "client_secret_ref") {
		t.Errorf("error %q does not name the missing driver secret", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "person@example.com.json")); statErr == nil {
		t.Error("a credential file was written despite the failure")
	}
}

// TestWorkloadDeliveryGroupReadableStaysClosedToOther. The one deployment shape
// that needs a wider file — a containerized connector reading through its own
// group — must widen by exactly one bit. `other` is what would put a personal
// Google credential in reach of every account on a shared host.
func TestWorkloadDeliveryGroupReadableStaysClosedToOther(t *testing.T) {
	cred := credflow.Credential{Provider: "google", Access: "a", Refresh: "r"}
	keyring, reader, engine := deliveryFixture(t, cred)
	dir := filepath.Join(t.TempDir(), "workload-creds")

	d, err := newWorkloadDelivery(fakeCredentialSource{cred: cred}, reader, keyring, engine,
		dir, "person@example.com", true, nil)
	if err != nil {
		t.Fatalf("newWorkloadDelivery: %v", err)
	}
	if err := d.deliver(context.Background(), "google"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	assertMode(t, filepath.Join(dir, "person@example.com.json"), 0o640)
}

// TestWorkloadDeliveryKeepsTheDeploymentsDirectoryMode. The deployment makes the
// credential directory setgid to the workload's group so the connector can read
// through it; a delivery that reset the directory to 0700 would undo that on the
// next consent and leave a workload that cannot read the credential it was just
// handed.
func TestWorkloadDeliveryKeepsTheDeploymentsDirectoryMode(t *testing.T) {
	cred := credflow.Credential{Provider: "google", Access: "a", Refresh: "r"}
	keyring, reader, engine := deliveryFixture(t, cred)
	dir := filepath.Join(t.TempDir(), "workload-creds")
	if err := os.Mkdir(dir, 0o770); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, os.ModeSetgid|0o770); err != nil {
		t.Fatalf("chmod setgid: %v", err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	d, err := newWorkloadDelivery(fakeCredentialSource{cred: cred}, reader, keyring, engine,
		dir, "person@example.com", true, nil)
	if err != nil {
		t.Fatalf("newWorkloadDelivery: %v", err)
	}
	if err := d.deliver(context.Background(), "google"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if after.Mode() != before.Mode() {
		t.Errorf("the credential directory's mode changed from %v to %v", before.Mode(), after.Mode())
	}
}

// TestWorkloadDeliveryTightensAWorldAccessibleDirectory. Whatever the deployment
// does with the group, a directory `other` can enter is not one a personal
// credential may sit in — so it is closed before the credential lands, not after.
func TestWorkloadDeliveryTightensAWorldAccessibleDirectory(t *testing.T) {
	cred := credflow.Credential{Provider: "google", Access: "a", Refresh: "r"}
	keyring, reader, engine := deliveryFixture(t, cred)
	dir := filepath.Join(t.TempDir(), "workload-creds")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	d, err := newWorkloadDelivery(fakeCredentialSource{cred: cred}, reader, keyring, engine,
		dir, "person@example.com", false, nil)
	if err != nil {
		t.Fatalf("newWorkloadDelivery: %v", err)
	}
	if err := d.deliver(context.Background(), "google"); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	assertMode(t, dir, 0o700)
}
