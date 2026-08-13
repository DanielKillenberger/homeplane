// Package credflow is the machine half of R13's add-credentials flow.
//
// Its whole job is to be the place a human can consent from — the machine where
// Daniel is sitting and has a browser — while remaining structurally unable to
// hold what that consent produces. It binds a loopback listener, asks the
// server for an authorization URL bound to that exact address, opens the
// browser, relays the single outcome the listener sees, and polls until the
// server reports a terminal state.
//
// The custody rule (R17) is visible in what this package does NOT contain:
// there is no token type, no credential file, no provider request, and nothing
// here writes to the agent's state directory. The two secrets it does touch —
// the authorization code and the OAuth state parameter — exist only in memory,
// travel only over the tailnet to the server, and are never logged, never
// printed, and never placed in argv.
package credflow

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

// DefaultPollInterval paces the poll loop while a human is consenting.
const DefaultPollInterval = time.Second

// DefaultTimeout bounds the whole flow from this side. The server enforces its
// own, shorter-or-equal window; this one exists so the CLI cannot hang forever
// when the human closes the browser and walks away.
const DefaultTimeout = 10 * time.Minute

// Options configures one add-credentials run.
type Options struct {
	// Client is an authenticated control-plane client.
	Client *agent.Client
	// Provider is the connector provider name, as the manifest declares it.
	Provider string
	// Replace authorizes overwriting an existing credential. Without it, a
	// provider that already has one is refused by the server.
	Replace bool
	// ListenHost is the loopback address to bind. Defaults to 127.0.0.1.
	ListenHost string
	// OpenBrowser opens the consent URL. Nil uses the platform opener; a
	// failure is never fatal — the URL is printed instead, which is also the
	// path for a headless machine.
	OpenBrowser func(ctx context.Context, url string) error
	// PollInterval and Timeout pace and bound the wait.
	PollInterval time.Duration
	Timeout      time.Duration
	// Out receives human-readable progress. It never receives the
	// authorization code.
	Out io.Writer
}

// Result is what the flow ended as.
type Result struct {
	Provider  string `json:"provider"`
	FlowID    string `json:"flow_id"`
	State     string `json:"state"`
	ErrorCode string `json:"error_code,omitempty"`
	Message   string `json:"message,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
}

// Succeeded reports whether the credential was stored server-side.
func (r Result) Succeeded() bool { return r.State == "completed" }

// AddCredentials runs the flow to a terminal state.
//
// A non-nil error means the flow could not be run (unreachable server, refused
// start, no browser outcome). A terminal-but-unsuccessful flow is NOT an error
// here: it is a Result the caller reports, because "the provider said no" is an
// answer, not a malfunction.
func AddCredentials(ctx context.Context, opts Options) (Result, error) {
	if opts.Client == nil {
		return Result{}, errors.New("add-credentials: an authenticated control-plane client is required")
	}
	if strings.TrimSpace(opts.Provider) == "" {
		return Result{}, errors.New("add-credentials: a provider is required")
	}
	if opts.ListenHost == "" {
		opts.ListenHost = "127.0.0.1"
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.OpenBrowser == nil {
		opts.OpenBrowser = OpenBrowser
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// The listener is bound BEFORE the flow is started, and that ordering is
	// the point: the redirect URI must name a port this machine already owns.
	// Asking the server first and binding afterwards would leave a window where
	// the authorization URL points at a port something else could take.
	listener, err := newRelayListener(opts.ListenHost)
	if err != nil {
		return Result{}, err
	}
	defer listener.Close()

	start, err := opts.Client.StartCredentialFlow(ctx, opts.Provider, listener.RedirectURI(), opts.Replace)
	if err != nil {
		return Result{}, err
	}

	fmt.Fprintf(opts.Out, "authorize Homeplane for %s in the browser that just opened.\n", opts.Provider)
	fmt.Fprintf(opts.Out, "if it did not open, visit:\n  %s\n", start.AuthorizationURL)
	if err := opts.OpenBrowser(ctx, start.AuthorizationURL); err != nil {
		fmt.Fprintf(opts.Out, "(could not open a browser automatically: %v)\n", err)
	}

	outcome, err := listener.Wait(ctx)
	if err != nil {
		// No outcome arrived. Nothing was relayed, so the server's flow simply
		// expires and the existing credential — if any — was never touched.
		return Result{Provider: opts.Provider, FlowID: start.FlowID, State: "abandoned"},
			fmt.Errorf("add-credentials: %w (nothing was changed on the server)", err)
	}

	// The relay is one-shot and carries the only copy of the code. It is
	// deliberately given a context detached from the browser wait so that a
	// nearly-expired deadline cannot drop an outcome the human already gave.
	relayCtx, relayCancel := context.WithTimeout(context.WithoutCancel(ctx), agent.DefaultTimeout)
	defer relayCancel()
	flow, err := opts.Client.RelayCredentialOutcome(relayCtx, start.FlowID, outcome.Code, outcome.Error, outcome.State)
	if err != nil {
		return Result{Provider: opts.Provider, FlowID: start.FlowID}, err
	}

	for !terminal(flow.State) {
		select {
		case <-ctx.Done():
			return result(opts.Provider, flow), fmt.Errorf("add-credentials: gave up waiting for the server to finish the flow: %w", ctx.Err())
		case <-time.After(opts.PollInterval):
		}
		flow, err = opts.Client.PollCredentialFlow(ctx, start.FlowID)
		if err != nil {
			return Result{Provider: opts.Provider, FlowID: start.FlowID}, err
		}
	}
	return result(opts.Provider, flow), nil
}

func terminal(state string) bool { return state != "" && state != "pending" }

func result(provider string, flow agent.CredentialFlow) Result {
	r := Result{Provider: provider, FlowID: flow.FlowID, State: flow.State}
	if flow.Diagnostic != nil {
		r.ErrorCode = flow.Diagnostic.ErrorCode
		r.Message = flow.Diagnostic.Message
		r.Retryable = flow.Diagnostic.Retryable
	}
	return r
}

// relayOutcome is what the provider's redirect delivered.
type relayOutcome struct {
	Code  string
	Error string
	State string
}

// relayListener is the one-shot loopback listener the provider redirects to.
type relayListener struct {
	ln       net.Listener
	srv      *http.Server
	outcomes chan relayOutcome
	host     string
	port     string
}

func newRelayListener(host string) (*relayListener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return nil, fmt.Errorf("add-credentials: could not bind a loopback listener on %s: %w", host, err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("add-credentials: loopback listener address %q is unusable: %w", ln.Addr(), err)
	}
	l := &relayListener{
		ln: ln,
		// Buffered so the HTTP handler never blocks on a receiver: the handler
		// must be able to finish rendering the browser page even if the CLI is
		// momentarily elsewhere.
		outcomes: make(chan relayOutcome, 1),
		host:     host,
		port:     port,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.handle)
	l.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

// RedirectURI is the exact address the server will build into the
// authorization URL and repeat at token exchange.
func (l *relayListener) RedirectURI() string {
	host := l.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + l.port
}

func (l *relayListener) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	outcome := relayOutcome{Code: q.Get("code"), Error: q.Get("error"), State: q.Get("state")}
	if outcome.Code == "" && outcome.Error == "" {
		// Not the redirect — a stray request (a browser probing for a favicon,
		// something scanning loopback). It must not consume the one-shot.
		http.Error(w, "homeplane: this is the add-credentials callback listener", http.StatusBadRequest)
		return
	}

	select {
	case l.outcomes <- outcome:
	default:
		// An outcome is already captured; a second redirect changes nothing.
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if outcome.Error != "" {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, page("Authorization was declined",
			"Homeplane did not receive access. Nothing on the server was changed. You can close this window."))
		return
	}
	_, _ = io.WriteString(w, page("Authorization received",
		"Homeplane is finishing setup on the server. You can close this window."))
}

// Wait blocks for the single outcome, or for the context to end.
func (l *relayListener) Wait(ctx context.Context) (relayOutcome, error) {
	select {
	case o := <-l.outcomes:
		return o, nil
	case <-ctx.Done():
		return relayOutcome{}, errors.New("no authorization response arrived before the flow window closed")
	}
}

// Close stops the listener.
func (l *relayListener) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return l.srv.Shutdown(ctx)
}

// page renders the browser's closing screen. It is deliberately static: the
// query string that produced it contains an authorization code, and nothing
// from it is echoed back into the document.
func page(title, body string) string {
	return "<!doctype html><meta charset=\"utf-8\"><title>Homeplane</title>" +
		"<body style=\"font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem\">" +
		"<h1 style=\"font-size:1.25rem\">" + title + "</h1><p>" + body + "</p></body>"
}

// OpenBrowser opens url in the platform's default browser.
//
// The URL is passed as a separate argv element and never through a shell: it
// carries the OAuth state parameter, and shell interpretation of a URL is both
// an injection risk and a way for a query string to end up in shell history.
func OpenBrowser(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("refusing to open %q: not an http(s) URL", raw)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", raw)
	case "linux":
		cmd = exec.CommandContext(ctx, "xdg-open", raw)
	default:
		return fmt.Errorf("no known browser opener for %s", runtime.GOOS)
	}
	return cmd.Start()
}
