// Package credflow is Homeplane's credential broker: the server half of R13's
// `homeplane-agent add-credentials` flow.
//
// The shape of the problem is that the human who can authorize a provider sits
// at a MACHINE, while the credential must end up ONLY on the server. So the
// flow is deliberately an asynchronous state machine rather than one request:
// the machine binds a loopback listener and asks the server to start a flow,
// the human consents in a browser, the machine relays the resulting
// authorization code back over the tailnet exactly once, and the server — never
// the machine — exchanges that code for provider tokens and stores them
// encrypted.
//
// Three properties are structural rather than conventional:
//
//   - Custody. The machine sees an authorization URL and an authorization code;
//     it never sees a provider token. Nothing in this package returns token
//     material to a caller, and the terminal diagnostic is a fixed vocabulary of
//     error codes, incapable of carrying a provider response body.
//   - Atomic replacement. An existing credential stays live and untouched for
//     the entire flow. The new one lands via compare-and-swap against the
//     generation observed when the flow started, so every unsuccessful terminal
//     state — denied, expired, failed, abandoned — leaves the old credential
//     exactly as it was, and two racing flows produce one commit and one honest
//     "retry", never a silent overwrite.
//   - Connector-agnosticism (R12). Everything provider-specific — endpoints,
//     scopes, client-credential refs — is read from the connector manifest's
//     `oauth2-authcode` driver parameters. Onboarding another OAuth provider is
//     a manifest entry; there is no per-provider code in this package.
//
// Flows themselves are in-memory and short-lived. A flow holds no credential
// material worth persisting — only a pending intent plus PKCE state — so a
// server restart abandons pending flows, which is the same outcome as the human
// walking away: nothing partial is stored, and the machine re-runs the command.
package credflow

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

// State is a flow's lifecycle state. Exactly one of the four terminal states is
// ever reached, and reaching one is irreversible.
type State string

const (
	// StatePending means the flow is waiting on the human.
	StatePending State = "pending"
	// StateCompleted means the provider credential is durably stored.
	StateCompleted State = "completed"
	// StateDenied means the provider (or the human) refused consent.
	StateDenied State = "denied"
	// StateExpired means the flow's window elapsed before a code arrived.
	StateExpired State = "expired"
	// StateFailed means a valid code was relayed but the credential could not be
	// obtained or stored. Nothing partial is stored; a new flow retries cleanly.
	StateFailed State = "failed"
)

// Terminal reports whether s is a final state.
func (s State) Terminal() bool { return s != StatePending }

// Error codes carried by a terminal diagnostic. This is a CLOSED vocabulary:
// the diagnostic exists to tell a human which class of failure happened and
// whether retrying can help, and it is deliberately incapable of relaying
// anything the provider said.
const (
	// CodeProviderDenied — the provider reported that consent was refused.
	CodeProviderDenied = "provider_denied"
	// CodeFlowExpired — no code arrived before the flow's window closed.
	CodeFlowExpired = "flow_expired"
	// CodeExchangeFailed — the code could not be exchanged for tokens.
	CodeExchangeFailed = "exchange_failed"
	// CodeStoreFailed — tokens were obtained but could not be stored.
	CodeStoreFailed = "store_failed"
	// CodeConcurrentReplacement — another flow committed this provider's
	// credential first; this one wrote nothing.
	CodeConcurrentReplacement = "concurrent_replacement"
)

// Diagnostic is the safe terminal explanation returned on a failed flow.
//
// Every field is server-authored. There is no field for a provider payload
// because there must be no way to leak one: a provider error body can contain
// tokens, account identifiers, or an HTML login page, none of which belong in a
// CLI on a machine that is not allowed to hold credentials.
type Diagnostic struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Flow is the non-secret projection of a flow, as polled by the agent.
type Flow struct {
	FlowID     string      `json:"flow_id"`
	Provider   string      `json:"provider"`
	State      State       `json:"state"`
	CreatedAt  time.Time   `json:"created_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Diagnostic *Diagnostic `json:"diagnostic,omitempty"`
}

// flow is the server-side record. The PKCE verifier and the OAuth state
// parameter live here and are never returned to any caller.
type flow struct {
	id          string
	provider    string
	machineID   string
	redirectURI string
	connector   connectors.Connector

	oauthState string
	verifier   string

	state     State
	diag      *Diagnostic
	createdAt time.Time
	expiresAt time.Time

	// observedGeneration is the credential generation at flow start — 0 when no
	// credential existed. It is the compare-and-swap token that makes
	// replacement atomic and makes a lost race detectable.
	observedGeneration int64

	// relayed records that the one-shot code relay has been used. It is set
	// before the exchange begins, so a replay cannot start a second exchange
	// even while the first is still running.
	relayed bool
}

// SecretStore is the credential-store surface the broker needs. *store.SQLite
// satisfies it.
type SecretStore interface {
	GetSecret(ctx context.Context, ref string) (store.Secret, error)
	PutSecretCAS(ctx context.Context, ref string, ciphertext []byte, expectedGeneration int64,
		audit func(generation int64) []store.AuditEvent) (int64, error)
}

// Sealer is D3's at-rest protection. *secrets.Keyring satisfies it.
type Sealer interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AuditSink is the append-only audit log. *store.SQLite satisfies it.
type AuditSink interface {
	AppendAudit(ctx context.Context, e store.AuditEvent) error
}

// Registry is the registered connector manifest. *connectors.Engine satisfies
// it. It is the ONLY source of provider knowledge in this package.
type Registry interface {
	Connector(provider string) (connectors.Connector, bool)
	Providers() []string
}

// Config carries the broker's settings. Every field has a working default.
type Config struct {
	// TTL is how long a pending flow stays open. Long enough for a human to
	// find the right account, short enough that an abandoned flow's authorization
	// URL stops being useful.
	TTL time.Duration
	// ExchangeTimeout bounds the provider token-exchange call.
	ExchangeTimeout time.Duration
	// HTTPClient performs the token exchange. Tests substitute a client that
	// trusts the fake provider's certificate.
	HTTPClient *http.Client
	// Now is the clock, injectable so expiry is testable without sleeping.
	Now func() time.Time
	// Logger receives operational logs. It never receives credential material.
	Logger *slog.Logger
}

// DefaultTTL is the lifetime of a pending flow.
const DefaultTTL = 10 * time.Minute

// DefaultExchangeTimeout bounds the provider token exchange.
const DefaultExchangeTimeout = 20 * time.Second

// Service is the credential broker.
type Service struct {
	registry Registry
	secrets  SecretStore
	sealer   Sealer
	audit    AuditSink
	cfg      Config
	log      *slog.Logger

	mu    sync.Mutex
	flows map[string]*flow
	// commit serializes the commit phase per provider. The CAS in the store is
	// what makes the race SAFE; this makes the common case orderly, so two
	// flows that finish together produce one commit and one clear conflict
	// rather than two conflicting transactions.
	commit map[string]*sync.Mutex
}

// New builds a broker.
func New(registry Registry, secrets SecretStore, sealer Sealer, audit AuditSink, cfg Config) (*Service, error) {
	if registry == nil || secrets == nil || sealer == nil || audit == nil {
		return nil, errors.New("credflow: registry, secret store, sealer and audit sink are all required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.ExchangeTimeout <= 0 {
		cfg.ExchangeTimeout = DefaultExchangeTimeout
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.ExchangeTimeout}
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{
		registry: registry,
		secrets:  secrets,
		sealer:   sealer,
		audit:    audit,
		cfg:      cfg,
		log:      cfg.Logger,
		flows:    make(map[string]*flow),
		commit:   make(map[string]*sync.Mutex),
	}, nil
}

// Providers lists the known providers, for the 404 body an unknown provider
// gets.
func (s *Service) Providers() []string { return s.registry.Providers() }

// startResult is what a successful flow start hands back to the transport.
type startResult struct {
	FlowID           string    `json:"flow_id"`
	AuthorizationURL string    `json:"authorization_url"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// start creates a pending flow for the calling machine.
func (s *Service) start(ctx context.Context, machineID, provider, redirectURI string, replace bool) (startResult, error) {
	conn, ok := s.registry.Connector(provider)
	if !ok {
		return startResult{}, &flowError{status: http.StatusNotFound, code: "not_found",
			message: "unknown provider", unknownProvider: true}
	}
	if conn.Credential.Driver != connectors.DriverOAuth2AuthCode {
		return startResult{}, &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: fmt.Sprintf("provider %q uses credential driver %q, which add-credentials cannot run",
				provider, conn.Credential.Driver)}
	}
	if err := validateLoopbackRedirect(redirectURI); err != nil {
		return startResult{}, &flowError{status: http.StatusBadRequest, code: "invalid_request", message: err.Error()}
	}

	// The generation observed here is the compare-and-swap token for the commit
	// at the far end of the flow. Reading it now — not at commit time — is what
	// makes a concurrent replacement DETECTABLE rather than a last-writer-wins
	// overwrite of a credential this flow never knew about.
	var observed int64
	existing, err := s.secrets.GetSecret(ctx, conn.CredentialRef)
	switch {
	case err == nil:
		observed = existing.Generation
	case errors.Is(err, store.ErrNotFound):
		observed = 0
	default:
		return startResult{}, fmt.Errorf("credflow: read current credential: %w", err)
	}
	if observed > 0 && !replace {
		return startResult{}, &flowError{status: http.StatusConflict, code: "conflict",
			message: fmt.Sprintf("provider %q already has a credential; re-run with replace to authorize a new one "+
				"(the existing credential stays active until the replacement is stored)", provider)}
	}

	client, err := s.resolveDriverSecret(ctx, conn, "client_id_ref")
	if err != nil {
		return startResult{}, err
	}

	oauthState, err := randomToken()
	if err != nil {
		return startResult{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return startResult{}, err
	}
	id, err := randomID()
	if err != nil {
		return startResult{}, err
	}

	now := s.cfg.Now().UTC()
	f := &flow{
		id:                 id,
		provider:           provider,
		machineID:          machineID,
		redirectURI:        redirectURI,
		connector:          conn,
		oauthState:         oauthState,
		verifier:           verifier,
		state:              StatePending,
		createdAt:          now,
		expiresAt:          now.Add(s.cfg.TTL),
		observedGeneration: observed,
	}

	authURL, err := authorizationURL(conn, client, redirectURI, oauthState, verifier)
	if err != nil {
		return startResult{}, err
	}

	// The start is on the record before the URL is handed out: a credential
	// flow that a machine could begin without the log showing it began would
	// leave the eventual credential unattributable.
	if err := s.audit.AppendAudit(ctx, store.AuditEvent{
		Event:         store.EventCredentialFlowStarted,
		ActorKind:     store.ActorMachine,
		AuthMachineID: machineID,
		Outcome:       store.OutcomeAllowed,
		Detail: map[string]string{
			"provider":          provider,
			"flow_id":           id,
			"secret_ref":        conn.CredentialRef,
			"secret_generation": strconv.FormatInt(observed, 10),
		},
	}); err != nil {
		return startResult{}, &flowError{status: http.StatusServiceUnavailable, code: "unavailable",
			message: "credential flow refused: it could not be recorded (audit log unavailable)"}
	}

	s.mu.Lock()
	s.flows[id] = f
	s.mu.Unlock()

	return startResult{FlowID: id, AuthorizationURL: authURL, ExpiresAt: f.expiresAt}, nil
}

// lookup returns the caller's flow, applying lazy expiry.
//
// A flow belonging to another machine is reported as not found rather than
// forbidden: whether some other machine has a flow in progress is not this
// caller's business.
func (s *Service) lookup(id, machineID string) (*flow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.flows[id]
	if !ok || subtle.ConstantTimeCompare([]byte(f.machineID), []byte(machineID)) != 1 {
		return nil, false
	}
	s.expireLocked(f)
	return f, true
}

// expireLocked moves a pending flow past its deadline to expired. Expiry is
// evaluated on access rather than by a sweeper: a flow nobody asks about has no
// effect on anything, and a lazily-expired flow gives the same answer to the
// only caller who can ask.
func (s *Service) expireLocked(f *flow) {
	if f.state != StatePending || !s.cfg.Now().UTC().After(f.expiresAt) {
		return
	}
	f.state = StateExpired
	f.diag = &Diagnostic{
		ErrorCode: CodeFlowExpired,
		Message:   "the authorization window closed before consent was relayed; re-run add-credentials to start a new flow",
		Retryable: true,
	}
	// The existing credential was never touched, so there is nothing to undo.
	s.recordTerminal(f)
}

// view projects a flow for the wire.
func (s *Service) view(f *flow) Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Flow{
		FlowID:     f.id,
		Provider:   f.provider,
		State:      f.state,
		CreatedAt:  f.createdAt,
		ExpiresAt:  f.expiresAt,
		Diagnostic: f.diag,
	}
}

// relayOutcome is one of the two things the client's loopback listener can
// observe: an authorization code, or a provider denial.
type relayOutcome struct {
	Code  string
	Error string
	State string
}

// relay consumes the one-shot code relay and drives the flow to a terminal
// state.
func (s *Service) relay(ctx context.Context, f *flow, out relayOutcome) error {
	s.mu.Lock()
	switch {
	case f.relayed:
		s.mu.Unlock()
		return &flowError{status: http.StatusConflict, code: "conflict",
			message: "this flow's outcome has already been relayed; a code may be relayed exactly once"}
	case f.state.Terminal():
		s.mu.Unlock()
		return &flowError{status: http.StatusConflict, code: "conflict",
			message: fmt.Sprintf("flow is already %s", f.state)}
	}
	// The state parameter is verified before anything else is believed: it is
	// what binds this redirect to the flow this server started. A mismatch is
	// rejected WITHOUT consuming the one-shot, so a stray or forged callback
	// cannot burn a legitimate flow the human is still completing.
	if subtle.ConstantTimeCompare([]byte(out.State), []byte(f.oauthState)) != 1 {
		s.mu.Unlock()
		return &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "state parameter does not match this flow"}
	}
	f.relayed = true
	verifier, conn, observed := f.verifier, f.connector, f.observedGeneration
	redirectURI, provider, machineID := f.redirectURI, f.provider, f.machineID
	s.mu.Unlock()

	if out.Code == "" {
		s.terminate(f, StateDenied, &Diagnostic{
			ErrorCode: CodeProviderDenied,
			Message:   "the provider reported that authorization was denied (" + sanitizeProviderError(out.Error) + ")",
			Retryable: true,
		})
		return nil
	}

	// From here the request's cancellation is deliberately dropped. The exchange
	// and the store write are the moment at which a real credential comes into
	// existence; an agent that hangs up mid-exchange must not leave the server
	// having obtained tokens it then abandons half-recorded.
	work, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ExchangeTimeout)
	defer cancel()

	clientID, err := s.resolveDriverSecret(work, conn, "client_id_ref")
	if err != nil {
		s.terminate(f, StateFailed, storeDiag("the server's client credentials for this provider are unavailable"))
		return nil
	}
	clientSecret, err := s.resolveDriverSecret(work, conn, "client_secret_ref")
	if err != nil {
		s.terminate(f, StateFailed, storeDiag("the server's client credentials for this provider are unavailable"))
		return nil
	}

	tokens, err := exchangeCode(work, s.cfg.HTTPClient, conn, clientID, clientSecret, redirectURI, out.Code, verifier)
	if err != nil {
		// The provider's own words stop here. Only the failure CLASS travels on.
		s.log.Warn("credential exchange failed", "provider", provider, "flow_id", f.id, "error", err)
		s.terminate(f, StateFailed, &Diagnostic{
			ErrorCode: CodeExchangeFailed,
			Message:   "the provider did not issue a credential for this authorization; start a new flow to retry",
			Retryable: true,
		})
		return nil
	}

	cred := Credential{
		Provider:   provider,
		TokenType:  tokens.TokenType,
		Access:     tokens.AccessToken,
		Refresh:    tokens.RefreshToken,
		Scope:      tokens.Scope,
		ObtainedAt: s.cfg.Now().UTC(),
	}
	if tokens.ExpiresIn > 0 {
		cred.ExpiresAt = cred.ObtainedAt.Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	plaintext, err := json.Marshal(cred)
	if err != nil {
		s.terminate(f, StateFailed, storeDiag("the credential could not be prepared for storage"))
		return nil
	}
	ciphertext, err := s.sealer.Encrypt(plaintext)
	if err != nil {
		s.log.Error("seal credential", "provider", provider, "error", err)
		s.terminate(f, StateFailed, storeDiag("the credential could not be encrypted for storage"))
		return nil
	}

	lock := s.providerLock(provider)
	lock.Lock()
	generation, err := s.secrets.PutSecretCAS(work, conn.CredentialRef, ciphertext, observed,
		func(generation int64) []store.AuditEvent {
			return []store.AuditEvent{{
				Event:         store.EventCredentialFlowCommitted,
				ActorKind:     store.ActorMachine,
				AuthMachineID: machineID,
				Outcome:       store.OutcomeAllowed,
				Detail: map[string]string{
					"provider":          provider,
					"flow_id":           f.id,
					"secret_ref":        conn.CredentialRef,
					"secret_generation": strconv.FormatInt(generation, 10),
				},
			}}
		})
	lock.Unlock()

	switch {
	case errors.Is(err, store.ErrGenerationConflict):
		s.terminate(f, StateFailed, &Diagnostic{
			ErrorCode: CodeConcurrentReplacement,
			Message: "another add-credentials flow stored a credential for this provider while this one was " +
				"in progress; nothing was overwritten — re-run add-credentials if you still want to replace it",
			Retryable: true,
		})
		return nil
	case err != nil:
		s.log.Error("store credential", "provider", provider, "error", err)
		s.terminate(f, StateFailed, storeDiag("the credential could not be stored; nothing was changed"))
		return nil
	}

	s.mu.Lock()
	f.state = StateCompleted
	f.diag = nil
	s.mu.Unlock()
	s.log.Info("credential stored", "provider", provider, "flow_id", f.id, "generation", generation)
	return nil
}

// terminate records a terminal failure state and its diagnostic.
func (s *Service) terminate(f *flow, state State, diag *Diagnostic) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.state.Terminal() {
		return
	}
	f.state = state
	f.diag = diag
	s.recordTerminal(f)
}

// recordTerminal appends the flow's terminal failure row. It must be called
// with s.mu held.
//
// This row is best-effort ON PURPOSE, unlike the flow's start and its commit:
// a failure row accompanies no state change anywhere — the credential store was
// never touched — so refusing to report the failure because the log is down
// would replace a clear error with a confusing one and change nothing about
// what is stored.
func (s *Service) recordTerminal(f *flow) {
	if f.diag == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.audit.AppendAudit(ctx, store.AuditEvent{
		Event:         store.EventCredentialFlowFailed,
		ActorKind:     store.ActorMachine,
		AuthMachineID: f.machineID,
		Outcome:       store.OutcomeDenied,
		Reason:        f.diag.ErrorCode,
		Detail: map[string]string{
			"provider":   f.provider,
			"flow_id":    f.id,
			"secret_ref": f.connector.CredentialRef,
		},
	}); err != nil {
		s.log.Error("record credential flow failure", "flow_id", f.id, "error", err)
	}
}

func (s *Service) providerLock(provider string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.commit[provider]
	if !ok {
		l = &sync.Mutex{}
		s.commit[provider] = l
	}
	return l
}

// Credential is the stored provider credential. It exists server-side only: no
// endpoint in Homeplane returns this type, and the machine-side agent has no
// type to decode it into.
type Credential struct {
	Provider   string    `json:"provider"`
	TokenType  string    `json:"token_type,omitempty"`
	Access     string    `json:"access_token"`
	Refresh    string    `json:"refresh_token,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	ObtainedAt time.Time `json:"obtained_at"`
	ExpiresAt  time.Time `json:"expires_at,omitzero"`
}

// Credential resolves the stored credential for a provider — the path a
// grant-holding connector call takes to use what add-credentials brokered.
// It returns store.ErrNotFound when the provider has no credential yet.
func (s *Service) Credential(ctx context.Context, provider string) (Credential, int64, error) {
	conn, ok := s.registry.Connector(provider)
	if !ok {
		return Credential{}, 0, store.ErrNotFound
	}
	sec, err := s.secrets.GetSecret(ctx, conn.CredentialRef)
	if err != nil {
		return Credential{}, 0, err
	}
	plaintext, err := s.sealer.Decrypt(sec.Ciphertext)
	if err != nil {
		return Credential{}, 0, fmt.Errorf("credflow: decrypt credential for %q: %w", provider, err)
	}
	var cred Credential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return Credential{}, 0, fmt.Errorf("credflow: decode credential for %q: %w", provider, err)
	}
	return cred, sec.Generation, nil
}

// resolveDriverSecret reads a driver parameter that names a secret (client_id_ref,
// client_secret_ref) and returns the secret's value.
func (s *Service) resolveDriverSecret(ctx context.Context, conn connectors.Connector, param string) (string, error) {
	ref := conn.Credential.Params[param]
	if ref == "" {
		return "", &flowError{status: http.StatusServiceUnavailable, code: "unavailable",
			message: fmt.Sprintf("provider %q is missing driver parameter %q", conn.Provider, param)}
	}
	sec, err := s.secrets.GetSecret(ctx, ref)
	if errors.Is(err, store.ErrNotFound) {
		return "", &flowError{status: http.StatusServiceUnavailable, code: "unavailable",
			message: fmt.Sprintf("the server has no %s for provider %q; import it with "+
				"`homeplane-server admin secret import`", param, conn.Provider)}
	}
	if err != nil {
		return "", fmt.Errorf("credflow: read %s: %w", param, err)
	}
	plaintext, err := s.sealer.Decrypt(sec.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("credflow: decrypt %s: %w", param, err)
	}
	return string(plaintext), nil
}

func storeDiag(message string) *Diagnostic {
	return &Diagnostic{ErrorCode: CodeStoreFailed, Message: message + "; start a new flow to retry", Retryable: true}
}

// randomToken returns 256 bits of CSPRNG output in URL-safe base64 — used for
// the OAuth state parameter and the PKCE code verifier (43 characters, within
// RFC 7636's 43..128).
func randomToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("credflow: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func randomID() (string, error) {
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	return "flow-" + tok[:22], nil
}
