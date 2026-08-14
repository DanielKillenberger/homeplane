package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/server/workloadcred"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// credentialSource is the brokered credential, read back out of the store. The
// broker owns decryption of its own record, so delivery asks it rather than
// re-implementing the shape.
type credentialSource interface {
	Credential(ctx context.Context, provider string) (credflow.Credential, int64, error)
}

// secretReader reads the driver secrets (Homeplane's own OAuth client) the
// connector needs in order to refresh the access token it is given.
type secretReader interface {
	GetSecret(ctx context.Context, ref string) (store.Secret, error)
}

// workloadDelivery materializes a stored provider credential into the directory
// the composed gateway's workload mounts.
//
// This is the last link of the custody chain and it is entirely server-side:
// the credential is decrypted here, written 0600 into a 0700 directory on the
// server, and never travels to a machine, a harness or an audit row. Without it
// a brokered credential is stored and unusable — the connector workload reads
// its credential from a directory, not from Homeplane's database.
type workloadDelivery struct {
	source  credentialSource
	secrets secretReader
	keyring *secrets.Keyring
	engine  *connectors.Engine
	dir     string
	// account identifies whose credential this is. It is a DEPLOYMENT fact —
	// the account the operator consents as, and the same one callers name in
	// their tool arguments — because the credential file is looked up by that
	// name and a git-tracked manifest has no business carrying it.
	account string
	// groupReadable delivers the credential 0660 so the connector's own
	// containerized identity can read it — and rewrite it on every token
	// refresh — through the directory's group.
	groupReadable bool
	log           *slog.Logger

	// mu guards the last delivery outcome, which the health probe reads from
	// another goroutine than the commit hook that writes it.
	mu      sync.Mutex
	lastErr error
}

// newWorkloadDelivery validates the deployment inputs. Both are required
// together: a directory without an account cannot name a file, and an account
// without a directory has nowhere to write.
func newWorkloadDelivery(source credentialSource, sec secretReader, keyring *secrets.Keyring,
	engine *connectors.Engine, dir, account string, groupReadable bool, log *slog.Logger) (*workloadDelivery, error) {
	dir, account = strings.TrimSpace(dir), strings.TrimSpace(account)
	switch {
	case dir == "" && account == "":
		return nil, nil
	case dir == "":
		return nil, errors.New("-workload-credential-account was given without -workload-credential-dir")
	case account == "":
		return nil, errors.New("-workload-credential-dir was given without -workload-credential-account " +
			"(the connector looks its credential up by account name)")
	case source == nil || sec == nil || keyring == nil || engine == nil:
		return nil, errors.New("workload credential delivery needs a broker, a secret store, a keyring and a manifest")
	}
	if log == nil {
		log = slog.Default()
	}
	return &workloadDelivery{source: source, secrets: sec, keyring: keyring,
		engine: engine, dir: dir, account: account, groupReadable: groupReadable, log: log}, nil
}

// deliver writes the provider's stored credential into the workload directory.
//
// A provider whose manifest entry declares no `credential_delivery` is not an
// error: it is a connector whose workload takes its credential some other way,
// and delivery has nothing to do for it.
func (d *workloadDelivery) deliver(ctx context.Context, provider string) error {
	if d == nil {
		return nil
	}
	conn, ok := d.engine.Connector(provider)
	if !ok {
		return fmt.Errorf("workload credential delivery: unknown provider %q", provider)
	}
	if conn.Delivery == nil {
		d.log.Debug("connector declares no credential_delivery; nothing to deliver", "provider", provider)
		return nil
	}

	cred, generation, err := d.source.Credential(ctx, provider)
	if err != nil {
		return fmt.Errorf("workload credential delivery: read the stored credential for %q: %w", provider, err)
	}
	clientID, err := d.driverSecret(ctx, conn, "client_id_ref")
	if err != nil {
		return err
	}
	clientSecret, err := d.driverSecret(ctx, conn, "client_secret_ref")
	if err != nil {
		return err
	}

	var opts []workloadcred.Option
	if d.groupReadable {
		opts = append(opts, workloadcred.WithGroupAccess())
	}
	path, err := workloadcred.Materialize(conn.Delivery.Format, d.dir, d.account, workloadcred.Credential{
		AccessToken:  cred.Access,
		RefreshToken: cred.Refresh,
		TokenURI:     conn.Credential.Params["token_endpoint"],
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       strings.Fields(cred.Scope),
		AuthURI:      conn.Credential.Params["auth_endpoint"],
		ExpiresAt:    cred.ExpiresAt,
	}, opts...)
	if err != nil {
		return fmt.Errorf("workload credential delivery: %w", err)
	}

	// The connector resolves its OAuth CLIENT separately from the user
	// credential, and refuses to refresh without it — a failure that only
	// appears once the first access token expires.
	clientPath, err := workloadcred.MaterializeClient(conn.Delivery.Format, d.dir, workloadcred.Credential{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURI:     conn.Credential.Params["token_endpoint"],
		AuthURI:      conn.Credential.Params["auth_endpoint"],
	}, opts...)
	if err != nil {
		return fmt.Errorf("workload credential delivery: %w", err)
	}
	// The path is logged; nothing about the credential's contents is.
	d.log.Info("delivered the provider credential to the connector workload",
		"provider", provider, "generation", generation, "path", path, "account", d.account,
		"client_config", clientPath)
	return nil
}

// deliverStored delivers every provider that already HAS a credential, which is
// what makes a restart converge: the workload's directory is recreated from the
// store rather than depending on someone re-running consent.
//
// A provider with no credential yet is skipped silently — that is the ordinary
// state of a deployment waiting for its first `add-credentials`.
func (d *workloadDelivery) deliverStored(ctx context.Context) {
	if d == nil {
		return
	}
	for _, provider := range d.engine.Providers() {
		err := d.deliver(ctx, provider)
		// A provider with no credential yet is not a delivery fault: it is the
		// ordinary state of a deployment waiting for its first consent, and
		// recording it as degraded would make /healthz red on a fresh install.
		if !errors.Is(err, store.ErrNotFound) {
			d.record(provider, err)
		}
		switch {
		case err == nil:
		case errors.Is(err, store.ErrNotFound):
			d.log.Info("no credential stored yet for this provider; run `homeplane-agent add-credentials`",
				"provider", provider)
		default:
			d.log.Error("could not deliver a stored credential to the connector workload",
				"provider", provider, "error", err)
		}
	}
}

// workloadDeliveryRef breaks the construction cycle between the broker and
// delivery: the broker needs the callback at New time, and delivery needs the
// broker to read the credential it just stored. The reference is set once,
// before the server listens, so no request can observe it half-built.
type workloadDeliveryRef struct{ d *workloadDelivery }

func (r *workloadDeliveryRef) set(d *workloadDelivery) { r.d = d }

func (r *workloadDeliveryRef) deliver(ctx context.Context, provider string, _ int64) error {
	err := r.d.deliver(ctx, provider)
	r.d.record(provider, err)
	return err
}

func (d *workloadDelivery) driverSecret(ctx context.Context, conn connectors.Connector, param string) (string, error) {
	ref := conn.Credential.Params[param]
	if ref == "" {
		return "", fmt.Errorf("workload credential delivery: connector %q declares no %s", conn.Provider, param)
	}
	sec, err := d.secrets.GetSecret(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("workload credential delivery: read %s (%s): %w", param, ref, err)
	}
	plaintext, err := d.keyring.Decrypt(sec.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("workload credential delivery: decrypt %s (%s): %w", param, ref, err)
	}
	return string(plaintext), nil
}

// health reports the last delivery outcome.
//
// A delivery that failed cannot be allowed to stay a log line. The credential
// IS stored — so the flow correctly reports success and the store correctly
// says it holds one — but the connector cannot read it, and every call fails
// with something that looks like an authorization problem. Without a component
// saying so, the only signal an operator gets is a connector that stopped
// working for no visible reason.
func (d *workloadDelivery) health() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastErr
}

// record stores the outcome of a delivery attempt for the health probe.
func (d *workloadDelivery) record(provider string, err error) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil {
		d.lastErr = fmt.Errorf("the credential for %q is stored but was not delivered to the connector workload: %w",
			provider, err)
		return
	}
	d.lastErr = nil
}
