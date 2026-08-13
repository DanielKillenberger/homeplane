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
// The asynchrony is load-bearing, not decorative. The relay call CONSUMES the
// code and returns immediately; the exchange runs as a server-owned job whose
// lifetime is not tied to any request. A machine whose relay response is lost —
// to a timeout, a dropped connection, a laptop lid — therefore learns the real
// outcome by polling, instead of reporting a failure for a credential the
// server successfully stored.
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
// Flows themselves are in-memory, short-lived, and bounded. A flow holds no
// credential material worth persisting — only a pending intent plus PKCE state —
// so a server restart abandons pending flows, which is the same outcome as the
// human walking away: nothing partial is stored, and the machine re-runs the
// command.
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
	// StatePending means the flow is waiting on the human, or on the server's
	// exchange job.
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

// pendingTerminal is a terminal outcome that has been DECIDED but not yet
// recorded. The flow keeps reporting `pending` until its terminal row is in the
// audit log — see settle.
type pendingTerminal struct {
	state State
	diag  *Diagnostic
	actor store.ActorKind
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

	state      State
	diag       *Diagnostic
	createdAt  time.Time
	expiresAt  time.Time
	terminalAt time.Time

	// decided holds a terminal outcome awaiting its audit row.
	decided *pendingTerminal

	// observedGeneration is the credential generation at flow start — 0 when no
	// credential existed. It is the compare-and-swap token that makes
	// replacement atomic and makes a lost race detectable.
	observedGeneration int64

	// relayed records that the one-shot code relay has been used. It is set
	// before the exchange job starts, so a replay cannot start a second
	// exchange even while the first is still running.
	relayed bool

	// terminalMu serializes this flow's terminal-audit attempts so a poll and
	// the exchange job cannot write two terminal rows for one transition. It is
	// never held while the service lock is held.
	terminalMu sync.Mutex
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
	// ExchangeTimeout bounds the provider token-exchange job.
	ExchangeTimeout time.Duration
	// TerminalRetention is how long a finished flow stays readable so the agent
	// can poll its outcome. After that it is forgotten.
	TerminalRetention time.Duration
	// MaxActiveFlowsPerMachine bounds how many flows one machine can have open
	// at once.
	MaxActiveFlowsPerMachine int
	// HTTPClient performs the token exchange. Tests substitute a client that
	// trusts the fake provider's certificate.
	HTTPClient *http.Client
	// Now is the clock, injectable so expiry is testable without sleeping.
	Now func() time.Time
	// Logger receives operational logs. It never receives credential material.
	Logger *slog.Logger
}

// Defaults for Config.
const (
	// DefaultTTL is the lifetime of a pending flow.
	DefaultTTL = 10 * time.Minute
	// DefaultExchangeTimeout bounds the provider token exchange.
	DefaultExchangeTimeout = 20 * time.Second
	// DefaultTerminalRetention keeps a finished flow readable well past the
	// agent's poll interval, and far short of forever.
	DefaultTerminalRetention = 15 * time.Minute
	// DefaultMaxActiveFlowsPerMachine is deliberately small: a machine runs one
	// add-credentials at a time, and the spare few cover retries and a stale
	// flow the human abandoned minutes ago.
	DefaultMaxActiveFlowsPerMachine = 4
)

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

	// jobs tracks in-flight exchange jobs so a shutting-down server can wait
	// for a credential commit rather than killing it halfway.
	jobs sync.WaitGroup
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
	if cfg.TerminalRetention <= 0 {
		cfg.TerminalRetention = DefaultTerminalRetention
	}
	if cfg.MaxActiveFlowsPerMachine <= 0 {
		cfg.MaxActiveFlowsPerMachine = DefaultMaxActiveFlowsPerMachine
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

// Shutdown waits for in-flight exchange jobs to finish, or for ctx to end.
//
// It exists because those jobs deliberately outlive their request: a server
// stopping mid-exchange would otherwise abandon a credential the provider has
// already issued.
func (s *Service) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.jobs.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

	// Old flows are cleared before the caller's own limit is judged, so a
	// machine is never blocked by flows that stopped mattering minutes ago.
	s.sweep(ctx)
	if err := s.checkFlowBudget(machineID); err != nil {
		return startResult{}, err
	}

	// BOTH driver secrets are resolved here, before the human is sent to a
	// consent screen. Discovering a missing client secret at exchange time
	// would spend the human's consent and then report a storage failure that
	// never happened.
	clientID, err := s.resolveDriverSecret(ctx, conn, "client_id_ref")
	if err != nil {
		return startResult{}, err
	}
	if _, err := s.resolveDriverSecret(ctx, conn, "client_secret_ref"); err != nil {
		return startResult{}, err
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

	authURL, err := authorizationURL(conn, clientID, redirectURI, oauthState, verifier)
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

// checkFlowBudget refuses a machine that already holds its share of open flows.
//
// Flows are cheap but not free, and every one of them is created by an
// authenticated caller: without a ceiling, a machine (or a script wedged in a
// retry loop) could grow the map for as long as the server runs.
func (s *Service) checkFlowBudget(machineID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	for _, f := range s.flows {
		if f.machineID == machineID && !f.state.Terminal() {
			active++
		}
	}
	if active >= s.cfg.MaxActiveFlowsPerMachine {
		return &flowError{status: http.StatusTooManyRequests, code: "too_many_flows",
			message: fmt.Sprintf("this machine already has %d credential flows open; finish or abandon one "+
				"(an abandoned flow clears itself when its window closes)", active)}
	}
	return nil
}

// sweep expires flows whose window has closed and forgets finished ones.
//
// It runs on every start rather than on a timer: a server nobody is talking to
// holds at most the flows it already had, and every path that could grow the
// map passes through here first.
func (s *Service) sweep(ctx context.Context) {
	now := s.cfg.Now().UTC()

	s.mu.Lock()
	var stale []*flow
	for id, f := range s.flows {
		switch {
		case s.expirableLocked(f, now):
			stale = append(stale, f)
		case f.state.Terminal() && now.Sub(f.terminalAt) > s.cfg.TerminalRetention:
			delete(s.flows, id)
		}
	}
	s.mu.Unlock()

	// Expiry is a state transition like any other, so it is recorded before it
	// is believed — outside the lock, because it writes to the audit log.
	for _, f := range stale {
		if err := s.expire(ctx, f); err != nil {
			// The flow stays as it is and the next sweep or poll retries. An
			// unrecorded expiry must not become an unrecorded deletion.
			s.log.Error("record credential flow expiry", "flow_id", f.id, "error", err)
		}
	}
}

// expirableLocked reports whether a flow's CONSENT window has closed on it.
//
// The window governs the human, not the exchange. Once an outcome has been
// relayed the human's part is over and the server-owned exchange job becomes
// the sole author of this flow's ending — so a relayed flow is never expired,
// however long the provider takes. Expiring one would produce two terminal
// transitions for a single flow: an audited `expired` and, moments later, a
// stored credential reported as `completed`.
//
// It must be called with s.mu held.
func (s *Service) expirableLocked(f *flow, now time.Time) bool {
	return !f.state.Terminal() && f.decided == nil && !f.relayed && now.After(f.expiresAt)
}

// expire moves a pending flow past its deadline to expired. The existing
// credential was never touched, so there is nothing to undo.
//
// Eligibility and the decision are ONE atomic step (claimExpiry), not a check
// followed by a transition. Callers reach here from a check they made earlier —
// a sweep pass, a poll — and between that check and this call a relay can
// arrive. Re-deciding under the same lock the relay competes for is what makes
// the two mutually exclusive: either the relay is consumed first and expiry
// finds a relayed flow and abandons it, or expiry claims the flow first and the
// relay is refused as too late. Never both.
func (s *Service) expire(ctx context.Context, f *flow) error {
	expiryClaimBarrier()
	if !s.claimExpiry(f) {
		return nil
	}
	return s.commitTerminal(ctx, f)
}

// claimExpiry atomically re-tests eligibility and records the decision.
//
// Setting f.decided inside the lock is the claim: consumeRelay refuses any flow
// that already carries a decision, so once this returns true no relay can be
// consumed for this flow, and while a relay holds the lock this cannot succeed.
func (s *Service) claimExpiry(f *flow) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.expirableLocked(f, s.cfg.Now().UTC()) {
		return false
	}
	f.decided = &pendingTerminal{
		state: StateExpired,
		actor: store.ActorSystem,
		diag: &Diagnostic{
			ErrorCode: CodeFlowExpired,
			Message:   "the authorization window closed before consent was relayed; re-run add-credentials to start a new flow",
			Retryable: true,
		},
	}
	return true
}

// expiryClaimBarrier runs between an expiry's eligibility check and its claim.
// It is a TEST HOOK: it exists so a test can force the one interleaving that
// cannot otherwise be scheduled reliably — a relay landing inside that window —
// and it is a no-op in every build that does not set it (see export_test.go).
var (
	expiryBarrierMu sync.Mutex
	expiryBarrierFn func()
)

func expiryClaimBarrier() {
	expiryBarrierMu.Lock()
	fn := expiryBarrierFn
	expiryBarrierMu.Unlock()
	if fn != nil {
		fn()
	}
}

// lookup returns the caller's flow.
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
	return f, true
}

// settle brings a flow up to date before it is read or written: it applies a
// due expiry, and retries the audit row for a terminal outcome that has been
// decided but not yet recorded.
//
// A returned error means the flow's real state cannot be shown yet.
func (s *Service) settle(ctx context.Context, f *flow) error {
	s.mu.Lock()
	expired := s.expirableLocked(f, s.cfg.Now().UTC())
	undecided := f.decided != nil && !f.state.Terminal()
	s.mu.Unlock()

	switch {
	case expired:
		return s.expire(ctx, f)
	case undecided:
		return s.commitTerminal(ctx, f)
	}
	return nil
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

// relay consumes the one-shot code relay.
//
// It does NOT wait for the exchange. The machine is telling the server what the
// human did; redeeming that with the provider is server work that must survive
// the machine hanging up, so relay hands off to a job and returns. What the
// caller gets back is "received" — the outcome arrives by polling.
func (s *Service) relay(ctx context.Context, f *flow, out relayOutcome) error {
	code, err := s.consumeRelay(f, out)
	if err != nil {
		return err
	}
	if code == "" {
		// A denial is terminal immediately: there is nothing to redeem.
		return s.terminate(ctx, f, StateDenied, store.ActorMachine, &Diagnostic{
			ErrorCode: CodeProviderDenied,
			Message:   "the provider reported that authorization was denied (" + sanitizeProviderError(out.Error) + ")",
			Retryable: true,
		})
	}

	s.jobs.Add(1)
	go func() {
		defer s.jobs.Done()
		// The job's context is the SERVER's, never the request's: an agent that
		// hangs up mid-exchange must not cancel the redemption of a code that
		// can only be redeemed once.
		jobCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ExchangeTimeout)
		defer cancel()
		s.exchangeAndStore(jobCtx, f, code)
	}()
	return nil
}

// consumeRelay validates the one-shot relay and marks it used, returning the
// authorization code (empty on a denial).
func (s *Service) consumeRelay(f *flow, out relayOutcome) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case f.relayed:
		return "", &flowError{status: http.StatusConflict, code: "conflict",
			message: "this flow's outcome has already been relayed; a code may be relayed exactly once"}
	case f.state.Terminal() || f.decided != nil:
		// Including a DECIDED-but-unrecorded outcome is what makes expiry and
		// relay mutually exclusive: an expiry that claimed this flow a moment
		// ago has already written its decision here, so a late relay is
		// refused rather than starting an exchange nobody will believe.
		ended := f.state
		if f.decided != nil {
			ended = f.decided.state
		}
		return "", &flowError{status: http.StatusConflict, code: "conflict",
			message: fmt.Sprintf("this flow has already finished (%s); start a new one", ended)}
	}
	// The state parameter is verified before anything else is believed: it is
	// what binds this redirect to the flow this server started. A mismatch is
	// rejected WITHOUT consuming the one-shot, so a stray or forged callback
	// cannot burn a legitimate flow the human is still completing.
	if subtle.ConstantTimeCompare([]byte(out.State), []byte(f.oauthState)) != 1 {
		return "", &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "state parameter does not match this flow"}
	}
	f.relayed = true
	return out.Code, nil
}

// exchangeAndStore is the server-owned job: redeem the code, seal the tokens,
// and swap them in. It always ends the flow in a terminal state.
func (s *Service) exchangeAndStore(ctx context.Context, f *flow, code string) {
	s.mu.Lock()
	conn, verifier, redirectURI := f.connector, f.verifier, f.redirectURI
	observed, provider, machineID := f.observedGeneration, f.provider, f.machineID
	s.mu.Unlock()

	clientID, idErr := s.resolveDriverSecret(ctx, conn, "client_id_ref")
	clientSecret, secretErr := s.resolveDriverSecret(ctx, conn, "client_secret_ref")
	if idErr != nil || secretErr != nil {
		// Both were readable when the flow started, so this is a store fault
		// rather than a misconfiguration the operator can see coming.
		s.log.Error("client credentials unreadable mid-flow", "provider", provider,
			"error", errors.Join(idErr, secretErr))
		s.fail(ctx, f, storeDiag("the server's client credentials for this provider became unreadable"))
		return
	}

	tokens, err := exchangeCode(ctx, s.cfg.HTTPClient, conn, clientID, clientSecret, redirectURI, code, verifier)
	if err != nil {
		// The provider's own words stop here. Only the failure CLASS travels on.
		s.log.Warn("credential exchange failed", "provider", provider, "flow_id", f.id, "error", err)
		s.fail(ctx, f, &Diagnostic{
			ErrorCode: CodeExchangeFailed,
			Message:   "the provider did not issue a credential for this authorization; start a new flow to retry",
			Retryable: true,
		})
		return
	}

	ciphertext, err := s.sealCredential(provider, tokens)
	if err != nil {
		s.log.Error("seal credential", "provider", provider, "error", err)
		s.fail(ctx, f, storeDiag("the credential could not be encrypted for storage"))
		return
	}

	lock := s.providerLock(provider)
	lock.Lock()
	generation, err := s.secrets.PutSecretCAS(ctx, conn.CredentialRef, ciphertext, observed,
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
		s.fail(ctx, f, &Diagnostic{
			ErrorCode: CodeConcurrentReplacement,
			Message: "another add-credentials flow stored a credential for this provider while this one was " +
				"in progress; nothing was overwritten — re-run add-credentials if you still want to replace it",
			Retryable: true,
		})
		return
	case err != nil:
		s.log.Error("store credential", "provider", provider, "error", err)
		s.fail(ctx, f, storeDiag("the credential could not be stored; nothing was changed"))
		return
	}

	s.complete(f, generation)
}

// complete records the flow's one success transition.
//
// Success needs no separate audit row and cannot be held back by one: the
// commit event was written INSIDE the store transaction that stored the
// credential, so the record and the credential landed together.
//
// The guard is an invariant check, not a race to win. A flow that is already
// terminal here would mean something else ended it while its exchange was
// running — the flow would then have TWO endings, one of them audited and
// wrong. Since a relayed flow is excluded from consent-window expiry, nothing
// else can end it; if that ever changes, this logs loudly rather than papering
// over a credential whose recorded outcome disagrees with the store.
func (s *Service) complete(f *flow, generation int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.state.Terminal() {
		s.log.Error("credential stored for a flow that had already finished — its recorded outcome is wrong",
			"provider", f.provider, "flow_id", f.id, "recorded_state", f.state, "generation", generation)
		return
	}
	f.state = StateCompleted
	f.diag = nil
	f.decided = nil
	f.terminalAt = s.cfg.Now().UTC()
	s.log.Info("credential stored", "provider", f.provider, "flow_id", f.id, "generation", generation)
}

// sealCredential renders and encrypts the stored credential.
func (s *Service) sealCredential(provider string, tokens tokenResponse) ([]byte, error) {
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
		return nil, fmt.Errorf("credflow: encode credential: %w", err)
	}
	return s.sealer.Encrypt(plaintext)
}

// fail ends a flow in StateFailed, logging if the outcome could not be recorded
// yet — the caller is a background job with nobody to return an error to. The
// flow keeps reporting `pending` until the record lands (see settle).
func (s *Service) fail(ctx context.Context, f *flow, diag *Diagnostic) {
	if err := s.terminate(ctx, f, StateFailed, store.ActorSystem, diag); err != nil {
		s.log.Error("record credential flow failure", "flow_id", f.id, "error_code", diag.ErrorCode, "error", err)
	}
}

// errTerminalUnrecorded means a flow has finished but its audit row is not
// written, so its outcome must not be shown yet.
var errTerminalUnrecorded = errors.New("credflow: terminal state could not be recorded")

// terminate decides a terminal failure state and records it.
//
// Deciding and exposing are separate steps on purpose. The audit log is
// authoritative (D13), and this package's contract is that a flow produces a
// start event and exactly one terminal event; a flow that reported `denied`
// while the log never learned of it would break that quietly. So the outcome is
// held as `decided` and only becomes visible once its row is written — every
// later poll retrying the write.
func (s *Service) terminate(ctx context.Context, f *flow, state State, actor store.ActorKind, diag *Diagnostic) error {
	s.mu.Lock()
	if f.state.Terminal() {
		s.mu.Unlock()
		return nil
	}
	if f.decided == nil {
		f.decided = &pendingTerminal{state: state, diag: diag, actor: actor}
	}
	s.mu.Unlock()
	return s.commitTerminal(ctx, f)
}

// commitTerminal writes the decided terminal row and, only then, exposes the
// state.
func (s *Service) commitTerminal(ctx context.Context, f *flow) error {
	// One writer per flow: a poll and the exchange job can arrive together, and
	// two rows for one transition would be a fiction in an append-only log.
	f.terminalMu.Lock()
	defer f.terminalMu.Unlock()

	s.mu.Lock()
	decided := f.decided
	if decided == nil || f.state.Terminal() {
		s.mu.Unlock()
		return nil
	}
	event := store.AuditEvent{
		Event:         store.EventCredentialFlowFailed,
		ActorKind:     decided.actor,
		AuthMachineID: f.machineID,
		Outcome:       store.OutcomeDenied,
		Reason:        decided.diag.ErrorCode,
		Detail: map[string]string{
			"provider":   f.provider,
			"flow_id":    f.id,
			"secret_ref": f.connector.CredentialRef,
		},
	}
	s.mu.Unlock()

	// The write is detached from the caller's context: a poll that times out
	// must not leave the flow's outcome unrecorded for the next caller.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalWriteTimeout)
	defer cancel()
	if err := s.audit.AppendAudit(writeCtx, event); err != nil {
		return fmt.Errorf("%w: %v", errTerminalUnrecorded, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if f.state.Terminal() {
		// The row is already written, so this is not recoverable — it is
		// reported. A flow that ended twice means the audit log now disagrees
		// with what the credential store actually holds, which is the one thing
		// this package must never let happen quietly.
		s.log.Error("credential flow reached a second terminal state — its audit trail is inconsistent",
			"flow_id", f.id, "provider", f.provider, "recorded_state", f.state, "second_state", decided.state)
		return nil
	}
	f.state = decided.state
	f.diag = decided.diag
	f.terminalAt = s.cfg.Now().UTC()
	f.decided = nil
	return nil
}

// terminalWriteTimeout bounds a terminal audit write.
const terminalWriteTimeout = 5 * time.Second

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
