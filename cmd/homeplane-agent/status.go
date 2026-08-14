package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		stateDir = fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
		timeout  = fs.Duration("timeout", agent.DefaultTimeout, "control-plane request timeout")
		offline  = fs.Bool("offline", false, "skip the control-plane reconcile (server-dependent state reads `unknown`)")
		asJSON   = fs.Bool("json", false, "print the full report as JSON")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `homeplane-agent status — report what this machine can actually do

Grants are reconciled LIVE against the server on every run. A revoked grant
shows as revoked; a server that cannot be reached makes grant state `+"`unknown`"+`,
never a stale `+"`active`"+`.

Exit codes: 0 ok, 1 a component is degraded, 2 this machine is not enrolled.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "homeplane-agent status: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	report, err := agent.Status(ctx, agent.StatusOptions{
		StateDir:   dir,
		Timeout:    *timeout,
		SkipServer: *offline,
	})
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent status: "+err.Error())
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent status: "+err.Error())
			return 1
		}
		return report.ExitCode()
	}

	printReport(stdout, report)
	return report.ExitCode()
}

func printReport(w io.Writer, report agent.Report) {
	fmt.Fprintf(w, "homeplane: %s\n", report.Status)
	fmt.Fprintf(w, "state dir: %s\n", report.StateDir)
	if report.MachineID != "" {
		fmt.Fprintf(w, "machine:   %s (%s, %s)\n", report.MachineID, report.MachineName, report.MachineOS)
	}
	if report.ServerURL != "" {
		fmt.Fprintf(w, "server:    %s\n", report.ServerURL)
	}

	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "COMPONENT\tSTATE\tDETAIL")
	for _, c := range report.Components {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Name, c.State, c.Detail)
	}
	tw.Flush()

	if len(report.Grants) > 0 {
		fmt.Fprintln(w)
		gw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(gw, "GRANT\tHARNESS\tSTATE\tCAPABILITIES")
		for _, g := range report.Grants {
			state := g.State
			if g.RevokedAt != "" {
				state += " (" + g.RevokedAt + ")"
			}
			fmt.Fprintf(gw, "%s\t%s\t%s\t%v\n", g.GrantID, g.Harness, state, g.Capabilities)
		}
		gw.Flush()
	}

	if degraded := report.Degraded(); len(degraded) > 0 {
		fmt.Fprintln(w)
		for _, c := range degraded {
			fmt.Fprintf(w, "! %s: %s — %s\n", c.Name, c.State, c.Detail)
		}
	}
}
