package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/credflow"
)

// openBrowser is the platform browser opener, indirected so an end-to-end CLI
// test can stand in for the human at the consent screen.
var openBrowser = credflow.OpenBrowser

// runAddCredentials brokers a provider credential through the server (R13).
//
// Exit codes follow the rest of the CLI: 0 only when the credential is stored
// server-side, 1 for every terminal failure, 2 when the machine is not
// enrolled. A denied or expired flow is a failure with an explanation, not a
// silent no-op — the operator ran this command to end up with a working
// provider, and must be told plainly when they did not.
func runAddCredentials(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("add-credentials", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		server       = fs.String("server", os.Getenv(agent.EnvServerURL), "control-plane URL (default: the enrolled server)")
		stateDir     = fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
		replace      = fs.Bool("replace", false, "replace an existing credential for this provider")
		noBrowser    = fs.Bool("no-browser", false, "print the authorization URL instead of opening a browser")
		timeout      = fs.Duration("timeout", credflow.DefaultTimeout, "how long to wait for authorization")
		pollInterval = fs.Duration("poll-interval", credflow.DefaultPollInterval, "how often to poll the server for the flow's state")
		asJSON       = fs.Bool("json", false, "print the outcome as JSON")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `homeplane-agent add-credentials <provider> — authorize a provider for Homeplane

Runs the provider's OAuth consent flow in a browser on THIS machine and hands
the result to the server, which exchanges and stores it. The credential lives
only on the server: this machine never receives, writes, or logs a provider
token, and every enrolled machine's grants can use the credential immediately.

A provider that already has a credential is refused unless -replace is given.
Even then the existing credential stays active until the new one is durably
stored: a declined, expired, or failed flow leaves it exactly as it was.

`)
		fs.PrintDefaults()
	}
	// `flag` stops at the first non-flag argument, which would make the natural
	// `add-credentials google-drive -replace` silently unparsed. Lifting a
	// leading provider out before parsing lets it sit on either side of the
	// flags, which is how everyone will actually type it.
	var provider string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		provider, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	switch {
	case provider == "" && fs.NArg() == 1:
		// `add-credentials -replace google-drive`
		provider = fs.Arg(0)
	case provider == "" || fs.NArg() > 0:
		fmt.Fprintln(stderr, "homeplane-agent add-credentials: exactly one provider is required")
		fs.Usage()
		return exitUsage
	}

	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	store, err := agent.Open(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	state, _, err := store.Load()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}
	credential, err := store.Credential()
	if errors.Is(err, agent.ErrNotEnroled) {
		fmt.Fprintln(stderr, "homeplane-agent add-credentials: this machine is not enrolled; run `homeplane-agent enrol` first")
		return agent.ExitNotEnrolled
	}
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	serverURL := *server
	if serverURL == "" {
		serverURL = state.ServerURL
	}
	client, err := agent.NewClient(serverURL, agent.DefaultTimeout)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent add-credentials: "+err.Error())
		return 1
	}

	// In JSON mode stdout carries exactly one JSON value and nothing else.
	// Progress — including the authorization URL, which a human may need to
	// paste — goes to stderr, where it stays visible to a person without
	// breaking a parser.
	progress := stdout
	if *asJSON {
		progress = stderr
	}

	opts := credflow.Options{
		Client:       client.WithCredential(credential),
		Provider:     provider,
		Replace:      *replace,
		PollInterval: *pollInterval,
		Timeout:      *timeout,
		Out:          progress,
	}
	if *noBrowser {
		opts.OpenBrowser = func(context.Context, string) error { return nil }
	} else {
		opts.OpenBrowser = openBrowser
	}

	result, err := credflow.AddCredentials(ctx, opts)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent add-credentials: "+err.Error())
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"provider":    result.Provider,
			"flow_id":     result.FlowID,
			"state":       result.State,
			"error_code":  result.ErrorCode,
			"message":     result.Message,
			"retryable":   result.Retryable,
			"finished_at": time.Now().UTC(),
		}); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent add-credentials: "+err.Error())
			return 1
		}
	} else if result.Ready() {
		fmt.Fprintf(stdout, "stored a %s credential on %s; every enrolled machine's grants can use it now.\n",
			result.Provider, client.BaseURL())
		fmt.Fprintln(stdout, "no provider token was written to this machine.")
	} else if result.Stored() {
		// Stored, and not usable. Saying "success" here would send the operator
		// looking for an authorization problem that does not exist; saying
		// "failed" would send them back through a consent screen for a
		// credential the server already holds.
		fmt.Fprintf(stdout, "stored a %s credential on %s.\n", result.Provider, client.BaseURL())
		fmt.Fprintln(stdout, "no provider token was written to this machine.")
		fmt.Fprintf(stderr, "\nthe credential is NOT usable yet (%s): %s\n", result.ErrorCode, result.Message)
		fmt.Fprintln(stderr, "do NOT run add-credentials again — the credential is stored; this is a server-side fault.")
	} else {
		fmt.Fprintf(stderr, "add-credentials for %s ended as %s (%s): %s\n",
			result.Provider, result.State, result.ErrorCode, result.Message)
		if result.Retryable {
			fmt.Fprintln(stderr, "nothing was changed on the server; re-run this command to try again.")
		}
	}
	// `undelivered` exits non-zero too: the credential is stored, and the thing
	// the operator asked for — a connector they can use — did not happen.
	if !result.Ready() {
		return 1
	}
	return 0
}
