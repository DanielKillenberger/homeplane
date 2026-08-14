package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/DanielKillenberger/homeplane/internal/health"
	"github.com/DanielKillenberger/homeplane/internal/policy"
	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/server"
	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
	"github.com/DanielKillenberger/homeplane/internal/server/edge"
	"github.com/DanielKillenberger/homeplane/internal/store"
	"github.com/DanielKillenberger/homeplane/internal/tsnetid"
)

type serveFlags struct {
	stateDir     string
	hostname     string
	addr         string
	endpointURL  string
	gatewayURL   string
	gatewayMCP   string
	manifestPath string
	edgePath     string
	gatewayProbe time.Duration
	credDir      string
	credAccount  string
	credGroup    bool
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var f serveFlags
	fs.StringVar(&f.stateDir, "state-dir", defaultStateDir(), "directory holding homeplane.db, the age key, and tsnet state")
	fs.StringVar(&f.hostname, "hostname", "homeplane", "tsnet hostname to advertise on the tailnet")
	fs.StringVar(&f.addr, "addr", ":443", "address to listen on WITHIN the tailnet")
	fs.StringVar(&f.endpointURL, "connector-endpoint-url", "", "connector edge URL handed to harnesses with each grant")
	fs.StringVar(&f.gatewayURL, "gateway-health-url", "", "loopback health URL of the composed gateway runtime (ToolHive)")
	fs.StringVar(&f.gatewayMCP, "gateway-mcp-url", "", "LOOPBACK MCP endpoint of the composed gateway, e.g. http://127.0.0.1:44022/mcp")
	fs.StringVar(&f.manifestPath, "connector-manifest", "", "path to the connector manifest the edge authorizes against")
	fs.StringVar(&f.edgePath, "connector-edge-path", defaultEdgePath, "path the connector edge is served on")
	fs.DurationVar(&f.gatewayProbe, "gateway-probe-timeout", 2*time.Second, "timeout for the gateway health probe")
	fs.StringVar(&f.credDir, "workload-credential-dir", "",
		"server-local directory the connector workload mounts; brokered credentials are materialized here")
	fs.StringVar(&f.credAccount, "workload-credential-account", "",
		"the account brokered credentials belong to (the connector looks its credential up by that name)")
	fs.BoolVar(&f.credGroup, "workload-credential-group-readable", false,
		"write the delivered credential 0640 instead of 0600, for a connector that reads it through the "+
			"group its container runs as (the directory must be setgid to that group; `other` is never granted)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "homeplane-server serve — run the control plane over tsnet\n\n")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), `
/healthz reports SERVER components only (store, gateway runtime, tsnet,
credential store) and returns 503 with a component-level payload when any is
degraded. Machine-side state belongs to `+"`homeplane-agent status`"+`.

Leaving -gateway-health-url empty makes the gateway_runtime component report
degraded. That is intentional: an unwired component must never render as
healthy.

The connector edge is served on -connector-edge-path (default `+defaultEdgePath+`) once
BOTH -connector-manifest and -gateway-mcp-url are given. The gateway MCP URL
must be a LOOPBACK address: the isolation guarantee is that the only route to
the gateway from another tailnet node runs through the edge, where the grant
token, the WhoIs machine binding and the manifest apply.`)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := os.MkdirAll(f.stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	st, err := store.Open(dbPath(f.stateDir))
	if err != nil {
		return err
	}
	defer st.Close()

	keyPath := keyFilePath(f.stateDir)
	keyring, err := secrets.LoadKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("credential store unusable: %w (run `homeplane-server admin secret init-key`)", err)
	}

	// The credential broker exists only when there is a manifest to broker
	// credentials against: without one there is no provider to name, and a
	// route that can only ever answer "unknown provider" is worse than no route.
	var broker *credflow.Service
	if f.manifestPath != "" {
		manifest, err := connectors.LoadFile(f.manifestPath)
		if err != nil {
			return fmt.Errorf("connector manifest: %w", err)
		}
		engine, err := connectors.Register(manifest)
		if err != nil {
			return fmt.Errorf("connector manifest: %w", err)
		}
		// Delivery is built before the broker so the broker can call it on
		// commit, and it holds a pointer to the broker that is filled in below —
		// the two are genuinely mutually dependent: the broker owns the stored
		// credential, delivery owns where it has to land.
		delivery := &workloadDeliveryRef{}
		broker, err = credflow.New(engine, st, keyring, st, credflow.Config{
			Logger:      log,
			OnCommitted: delivery.deliver,
		})
		if err != nil {
			return fmt.Errorf("credential broker: %w", err)
		}
		d, err := newWorkloadDelivery(broker, st, keyring, engine, f.credDir, f.credAccount, f.credGroup, log)
		if err != nil {
			return err
		}
		delivery.set(d)
		// A restart re-materializes whatever is already stored, so the workload's
		// credential directory converges on the store rather than on whoever last
		// ran a consent flow.
		d.deliverStored(context.Background())
		log.Info("credential broker enabled", "providers", engine.Providers(),
			"workload_delivery", d != nil)
	}

	ts := &tsnet.Server{
		Hostname: f.hostname,
		Dir:      filepath.Join(f.stateDir, "tsnet"),
		Logf:     func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) },
		// UserLogf carries the operator-facing lines — above all the login URL
		// printed while the node is unauthenticated. It is deliberately NOT
		// folded into Logf: that one is the verbose backend firehose and runs at
		// Debug, so an unattended first boot would hide the single line the
		// operator has to act on behind a log level nobody enables in
		// production. tsnet's default for UserLogf is log.Printf, which bypasses
		// the structured logger entirely.
		//
		// No auth key is ever printed here: tsnet's user-facing lines carry the
		// login URL and status, never the key (which arrives via TS_AUTHKEY from
		// a 0600 EnvironmentFile, never as an argv value).
		UserLogf: func(format string, args ...any) { log.Info(fmt.Sprintf(format, args...)) },
	}
	defer ts.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if _, err := ts.Up(ctx); err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	localClient, err := ts.LocalClient()
	if err != nil {
		return fmt.Errorf("tsnet local client: %w", err)
	}

	checker := health.New(
		health.Component{Name: health.ComponentStore, Probe: health.StoreProbe(st)},
		health.Component{Name: health.ComponentCredentialStore, Probe: health.CredentialStoreProbe(keyPath)},
		health.Component{Name: health.ComponentTsnet, Probe: tsnetProbe(localClient)},
		health.Component{Name: health.ComponentGatewayRuntime, Probe: health.GatewayProbe(f.gatewayURL, f.gatewayProbe)},
	)

	// The edge configuration is resolved BEFORE the control plane is built:
	// the endpoint URL handed to harnesses with every grant has to be the URL
	// the edge is actually mounted at, and that can only be checked once both
	// are known.
	wiring, err := resolveEdgeWiring(f, log)
	if err != nil {
		return err
	}

	srv, err := server.New(st, tsnetid.New(localClient), checker, server.Config{
		ConnectorEndpointURL: wiring.endpointURL,
		Policy:               policy.Default(),
		Credentials:          broker,
		Logger:               log,
	})
	if err != nil {
		return err
	}

	handler, err := composeHandler(srv, st, tsnetid.New(localClient), wiring, log)
	if err != nil {
		return err
	}

	ln, err := ts.Listen("tcp", f.addr)
	if err != nil {
		return fmt.Errorf("tsnet listen %s: %w", f.addr, err)
	}
	read, write := serveTimeouts(wiring.enabled, defaultReadTimeout)
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       read,
		WriteTimeout:      write,
		IdleTimeout:       defaultIdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("homeplane-server listening", "hostname", f.hostname, "addr", f.addr, "state_dir", f.stateDir)
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := httpSrv.Shutdown(shutdownCtx)
		// Credential exchanges deliberately outlive their request, so the
		// server waits for one in flight rather than abandoning a credential
		// the provider has already issued.
		if broker != nil {
			if waitErr := broker.Shutdown(shutdownCtx); waitErr != nil {
				log.Warn("credential exchange still running at shutdown", "error", waitErr)
			}
		}
		return err
	}
}

// defaultEdgePath is where the connector edge is served. It is the path a
// grant's endpoint_url points a harness at.
const defaultEdgePath = "/mcp"

// Listener deadlines.
const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 120 * time.Second
)

// serveTimeouts returns the listener's read and write deadlines.
//
// Wiring the edge lifts the WRITE deadline and only that: an MCP SSE stream is
// a single long-lived response, and a whole-response write deadline would cut
// every session at 30 seconds. The READ deadline stays, because nothing about a
// long response justifies letting an authenticated client hold a goroutine open
// by dripping a request body one byte at a time — the body's size limit is not
// a time limit.
func serveTimeouts(edgeWired bool, read time.Duration) (readTimeout, writeTimeout time.Duration) {
	if edgeWired {
		return read, 0
	}
	return read, defaultWriteTimeout
}

// reservedControlPlanePaths are the control plane's own routes (see
// server.Handler). The edge may not be mounted on one, or under one: it would
// shadow enrolment, the grant lifecycle or health with an MCP endpoint, and the
// symptom — grants that cannot be issued — would look nothing like the cause.
var reservedControlPlanePaths = []string{"/enrol", "/grants", "/healthz"}

// edgeWiring is a VALIDATED connector-edge configuration: a resolved mount
// path, the endpoint URL harnesses are handed, the registered manifest and the
// loopback gateway. Building it is where a deployment mistake is caught; by the
// time it exists, nothing about it can still be inconsistent.
type edgeWiring struct {
	enabled     bool
	path        string
	endpointURL string
	engine      *connectors.Engine
	upstream    *url.URL
}

// resolveEdgeWiring validates the connector-edge flags.
//
// The edge is wired only when BOTH the manifest and the gateway's loopback MCP
// endpoint are given. Giving one without the other is an error rather than a
// quiet fallback: an operator who configured half an edge would otherwise get a
// server that looks healthy and serves no connectors at all.
func resolveEdgeWiring(f serveFlags, log *slog.Logger) (edgeWiring, error) {
	switch {
	case f.manifestPath == "" && f.gatewayMCP == "":
		log.Warn("connector edge not wired; control plane only",
			"hint", "pass -connector-manifest and -gateway-mcp-url to serve connectors")
		// Without an edge there is nothing to check the endpoint URL against;
		// it is whatever the operator configured (an edge on another host).
		return edgeWiring{endpointURL: f.endpointURL}, nil
	case f.manifestPath == "":
		return edgeWiring{}, fmt.Errorf("-gateway-mcp-url was given without -connector-manifest")
	case f.gatewayMCP == "":
		return edgeWiring{}, fmt.Errorf("-connector-manifest was given without -gateway-mcp-url")
	}

	path, err := normalizeEdgePath(f.edgePath)
	if err != nil {
		return edgeWiring{}, err
	}
	endpointURL, err := resolveEndpointURL(f.endpointURL, path, log)
	if err != nil {
		return edgeWiring{}, err
	}

	manifest, err := connectors.LoadFile(f.manifestPath)
	if err != nil {
		return edgeWiring{}, fmt.Errorf("connector manifest: %w", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		return edgeWiring{}, fmt.Errorf("connector manifest: %w", err)
	}
	upstream, err := edge.ParseUpstream(f.gatewayMCP)
	if err != nil {
		return edgeWiring{}, err
	}

	return edgeWiring{
		enabled:     true,
		path:        path,
		endpointURL: endpointURL,
		engine:      engine,
		upstream:    upstream,
	}, nil
}

// normalizeEdgePath turns the flag into a literal mount path, or refuses it.
//
// It is refused rather than best-effort registered because the value goes
// straight to ServeMux, where a wildcard or a malformed pattern PANICS the
// server at startup and a reserved path silently shadows the control plane.
func normalizeEdgePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return defaultEdgePath, nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("-connector-edge-path %q must start with /", raw)
	}
	if strings.ContainsAny(p, "{}*? #\t\r\n") {
		return "", fmt.Errorf("-connector-edge-path %q must be a literal path (no wildcards, query or fragment)", raw)
	}
	// One trailing slash is tolerated and dropped; both forms are registered.
	trimmed := strings.TrimSuffix(p, "/")
	if trimmed == "" {
		return "", fmt.Errorf("-connector-edge-path may not be %q: the edge would swallow the control plane", raw)
	}
	if cleaned := path.Clean(trimmed); cleaned != trimmed {
		return "", fmt.Errorf("-connector-edge-path %q is not a clean path (did you mean %q?)", raw, cleaned)
	}
	for _, reserved := range reservedControlPlanePaths {
		if trimmed == reserved || strings.HasPrefix(reserved, trimmed+"/") {
			return "", fmt.Errorf("-connector-edge-path %q would shadow the control-plane route %q", raw, reserved)
		}
	}
	return trimmed, nil
}

// resolveEndpointURL settles the URL handed to every harness with its grant.
//
// A wired edge REQUIRES one, and it must point at the path the edge is actually
// mounted on. Without this check a server can start happily, issue grants, and
// hand every harness an endpoint_url that answers 404 — a failure that surfaces
// on the machine, far from the flag that caused it. A URL with no path is
// completed from the mount path rather than refused: that is the one case where
// the operator's intent is unambiguous.
func resolveEndpointURL(raw, edgePath string, log *slog.Logger) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("-connector-endpoint-url is required when the connector edge is wired " +
			"(it is the URL handed to every harness with its grant)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("-connector-endpoint-url %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("-connector-endpoint-url %q must be an absolute http(s) URL", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("-connector-endpoint-url %q has no host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("-connector-endpoint-url %q must not carry a query or fragment", raw)
	}

	got := strings.TrimSuffix(u.Path, "/")
	switch {
	case got == "":
		u.Path = edgePath
		log.Info("derived the connector endpoint path from -connector-edge-path", "endpoint_url", u.String())
	case got != edgePath:
		return "", fmt.Errorf("-connector-endpoint-url path %q does not match -connector-edge-path %q; "+
			"harnesses would be sent somewhere the edge is not mounted", got, edgePath)
	default:
		u.Path = got
	}
	return u.String(), nil
}

// composeHandler puts the control plane and (when configured) the connector
// edge behind one tsnet listener, so both are reached over the same tailnet
// identity the WhoIs resolver reports.
func composeHandler(srv *server.Server, st *store.SQLite, resolver edge.IdentityResolver,
	w edgeWiring, log *slog.Logger) (http.Handler, error) {
	control := srv.Handler()
	if !w.enabled {
		return control, nil
	}

	connectorEdge, err := edge.New(edge.Config{
		Store:    st,
		Identity: resolver,
		Broker:   connectors.NewBroker(w.engine, edge.NewHTTPRuntime(w.upstream, nil), st),
		Upstream: w.upstream,
		Logger:   log,
	})
	if err != nil {
		return nil, err
	}

	// Two registrations, never more: the exact path and its subtree. w.path is
	// normalized without a trailing slash, so neither form can duplicate the
	// other (a duplicate pattern panics ServeMux).
	mux := http.NewServeMux()
	mux.Handle("/", control)
	mux.Handle(w.path, connectorEdge.Handler())
	mux.Handle(w.path+"/", connectorEdge.Handler())

	log.Info("connector edge wired", "path", w.path, "endpoint_url", w.endpointURL,
		"gateway", w.upstream.String(), "providers", strings.Join(w.engine.Providers(), ","))
	return mux, nil
}

// tsnetProbe reports whether the embedded tailnet node is actually up. Without
// it, a server that has lost its tailnet would answer /healthz happily while
// being unreachable by every machine it serves.
func tsnetProbe(client *local.Client) health.Probe {
	return func(ctx context.Context) error {
		st, err := client.Status(ctx)
		if err != nil {
			return fmt.Errorf("tsnet status: %w", err)
		}
		if st.BackendState != "Running" {
			return fmt.Errorf("tsnet backend state is %q", st.BackendState)
		}
		return nil
	}
}

func defaultStateDir() string {
	if v := os.Getenv("HOMEPLANE_STATE_DIR"); v != "" {
		return v
	}
	return "/var/lib/homeplane"
}

func dbPath(stateDir string) string      { return filepath.Join(stateDir, "homeplane.db") }
func keyFilePath(stateDir string) string { return filepath.Join(stateDir, "secrets.age-key") }
