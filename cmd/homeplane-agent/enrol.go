package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

func runEnrol(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		server   = fs.String("server", os.Getenv(agent.EnvServerURL), "control-plane URL (reuses the recorded one on re-enrol)")
		name     = fs.String("name", "", "machine name to register (default: this host's name)")
		stateDir = fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
		timeout  = fs.Duration("timeout", agent.DefaultTimeout, "control-plane request timeout")
		asJSON   = fs.Bool("json", false, "print the outcome as JSON")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `homeplane-agent enrol — register this machine with the control plane

Enrolment is identity-preserving: re-running it from the same machine rotates
this machine's credential on the SAME server-side record rather than creating a
second one, and the previous credential stops working immediately.

If the server cannot be reached, nothing is written to the state directory.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "homeplane-agent enrol: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	outcome, err := agent.Enrol(ctx, agent.EnrolOptions{
		StateDir:    dir,
		ServerURL:   *server,
		MachineName: *name,
		Timeout:     *timeout,
	})
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent enrol: "+err.Error())
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		// The credential is deliberately absent from this payload: it belongs in
		// the 0600 file and nowhere a shell pipeline could capture it.
		if err := enc.Encode(map[string]any{
			"machine_id":         outcome.MachineID,
			"machine_name":       outcome.MachineName,
			"server_url":         outcome.ServerURL,
			"state_dir":          outcome.StateDir,
			"rotated":            outcome.Rotated,
			"credential_version": outcome.CredentialVersion,
			"enroled_at":         time.Now().UTC(),
		}); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent enrol: "+err.Error())
			return 1
		}
		return 0
	}

	verb := "enrolled"
	if outcome.Rotated {
		verb = "re-enrolled (credential rotated; the previous credential is now invalid)"
	}
	fmt.Fprintf(stdout, "%s machine %s (%s) with %s\n", verb, outcome.MachineID, outcome.MachineName, outcome.ServerURL)
	fmt.Fprintf(stdout, "credential version %d, state in %s\n", outcome.CredentialVersion, outcome.StateDir)
	// Enrolment gives the machine an identity; it gives the harnesses nothing.
	// Naming the next step here is what keeps "enrolled" from being mistaken
	// for "usable from an agent".
	fmt.Fprintln(stdout, "next: `homeplane-agent gno activate` to bind the vault, "+
		"then `homeplane-agent configure-harnesses` to wire Claude Code and Codex")
	return 0
}
