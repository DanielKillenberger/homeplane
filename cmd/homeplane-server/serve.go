package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
		broker, err = credflow.New(engine, st, keyring, st, credflow.Config{Logger: log})
		if err != nil {
			return fmt.Errorf("credential broker: %w", err)
		}
		log.Info("credential broker enabled", "providers", engine.Providers())
	}

	ts := &tsnet.Server{
		Hostname: f.hostname,
		Dir:      filepath.Join(f.stateDir, "tsnet"),
		Logf:     func(format string, args ...any) { log.Debug(fmt.Sprintf(format, args...)) },
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

	srv, err := server.New(st, tsnetid.New(localClient), checker, server.Config{
		ConnectorEndpointURL: f.endpointURL,
		Policy:               policy.Default(),
		Credentials:          broker,
		Logger:               log,
	})
	if err != nil {
		return err
	}

	handler, edgeWired, err := composeHandler(srv, st, tsnetid.New(localClient), f, log)
	if err != nil {
		return err
	}

	ln, err := ts.Listen("tcp", f.addr)
	if err != nil {
		return fmt.Errorf("tsnet listen %s: %w", f.addr, err)
	}
	httpSrv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if edgeWired {
		// The connector edge carries long-lived streamable-HTTP responses (the
		// MCP SSE stream), which a whole-response write deadline would cut mid
		// session. Header and body reads stay bounded; only the write deadline
		// is lifted, and only because a stream shares this listener.
		httpSrv.WriteTimeout = 0
		httpSrv.ReadTimeout = 0
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
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// defaultEdgePath is where the connector edge is served. It is the path a
// grant's endpoint_url points a harness at.
const defaultEdgePath = "/mcp"

// composeHandler puts the control plane and (when configured) the connector
// edge behind one tsnet listener, so both are reached over the same tailnet
// identity the WhoIs resolver reports.
//
// The edge is wired only when BOTH the manifest and the gateway's loopback MCP
// endpoint are given. Giving one without the other is an error rather than a
// quiet fallback: an operator who configured half an edge would otherwise get a
// server that looks healthy and serves no connectors at all.
func composeHandler(srv *server.Server, st *store.SQLite, resolver edge.IdentityResolver,
	f serveFlags, log *slog.Logger) (http.Handler, bool, error) {
	control := srv.Handler()

	switch {
	case f.manifestPath == "" && f.gatewayMCP == "":
		log.Warn("connector edge not wired; control plane only",
			"hint", "pass -connector-manifest and -gateway-mcp-url to serve connectors")
		return control, false, nil
	case f.manifestPath == "":
		return nil, false, fmt.Errorf("-gateway-mcp-url was given without -connector-manifest")
	case f.gatewayMCP == "":
		return nil, false, fmt.Errorf("-connector-manifest was given without -gateway-mcp-url")
	}

	manifest, err := connectors.LoadFile(f.manifestPath)
	if err != nil {
		return nil, false, fmt.Errorf("connector manifest: %w", err)
	}
	engine, err := connectors.Register(manifest)
	if err != nil {
		return nil, false, fmt.Errorf("connector manifest: %w", err)
	}
	upstream, err := edge.ParseUpstream(f.gatewayMCP)
	if err != nil {
		return nil, false, err
	}

	connectorEdge, err := edge.New(edge.Config{
		Store:    st,
		Identity: resolver,
		Broker:   connectors.NewBroker(engine, edge.NewHTTPRuntime(upstream, nil), st),
		Upstream: upstream,
		Logger:   log,
	})
	if err != nil {
		return nil, false, err
	}

	path := f.edgePath
	if path == "" {
		path = defaultEdgePath
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false, fmt.Errorf("-connector-edge-path %q must start with /", path)
	}

	mux := http.NewServeMux()
	mux.Handle("/", control)
	mux.Handle(path, connectorEdge.Handler())
	mux.Handle(strings.TrimSuffix(path, "/")+"/", connectorEdge.Handler())

	log.Info("connector edge wired", "path", path, "gateway", upstream.String(),
		"providers", strings.Join(engine.Providers(), ","))
	return mux, true, nil
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
