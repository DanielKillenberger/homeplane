package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/harness"
)

const configureHarnessesUsage = `homeplane-agent configure-harnesses — wire this machine's agent harnesses

Configures every installed harness (Claude Code, Codex) with the two Homeplane
capability surfaces:

  the local retrieval engine, from the endpoint descriptor ` + "`gno activate`" + ` published;
  the server's connector endpoint, using a grant token minted for THAT harness.

Each run mints a fresh grant per harness, which supersedes that harness's
previous grant server-side, and then rewrites only the Homeplane-managed MCP
entries. So the command is safe to re-run: it is how a machine repairs a
configuration a failed run left half-written.

Writes are merge-only. Unrelated configuration in each harness's file is
preserved — verified by re-parsing after the write — a timestamped backup is
taken first, and a config that cannot be parsed causes that harness to be
SKIPPED rather than repaired. Grant tokens are written only into user-scoped
0600 files; nothing here can write a project-scoped, git-shareable config.
`

func runConfigureHarnesses(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("configure-harnesses", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), configureHarnessesUsage+"\nFlags:\n")
		fs.PrintDefaults()
	}
	stateDir := fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)")
	only := fs.String("harness", "", "configure only these harnesses (comma-separated; default: all installed)")
	timeout := fs.Duration("timeout", agent.DefaultTimeout, "control-plane request timeout")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	detectOnly := fs.Bool("detect", false, "report what is installed and exit without touching anything")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "homeplane-agent configure-harnesses: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	dir, err := resolveStateDir(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent: "+err.Error())
		return 1
	}

	locator := harness.Locator{}
	if *detectOnly {
		return reportDetection(locator, *asJSON, stdout, stderr)
	}

	store, err := agent.Open(dir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}
	state, enrolled, err := store.Load()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}
	if !enrolled || !state.Enroled() {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: this machine is not enrolled — run `homeplane-agent enrol` first")
		return 2
	}
	credential, err := store.Credential()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}
	client, err := agent.NewClient(state.ServerURL, *timeout)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}

	cfg := harness.Configurator{
		StateDir: dir,
		Locator:  locator,
		Issuer:   grantIssuer{client: client.WithCredential(credential)},
		// The whole run — issuance, write, record, state — is one critical
		// section, so a second `configure-harnesses` cannot interleave its
		// issuance between this one's issuance and its write.
		Lock: store.Lock,
	}
	if trimmed := strings.TrimSpace(*only); trimmed != "" {
		cfg.Only = strings.Split(trimmed, ",")
	}

	report, err := cfg.Configure(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}

	// `status` reports this list, so it must describe the WHOLE machine, not
	// just this run. A `-harness codex` run says nothing about Claude Code, and
	// replacing the list wholesale would erase it; a harness this run attempted
	// and did not configure must drop OUT of it, or a half-failed run would keep
	// reporting a healthy machine.
	state.Harnesses = mergeHarnessState(state.Harnesses, report)
	state.Harness = harnessComponentState(report)
	if err := store.Save(state); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
			return 1
		}
	} else {
		printHarnessReport(report, stdout)
	}

	if err := report.Err(); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}
	return 0
}

// grantIssuer adapts the control-plane client to the narrow interface the
// harness package asks for. The adapter exists so that package never sees a
// client it could use to do anything but request a grant.
type grantIssuer struct{ client *agent.Client }

func (g grantIssuer) IssueGrant(ctx context.Context, name string) (harness.Grant, error) {
	issued, err := g.client.IssueGrant(ctx, name)
	if err != nil {
		return harness.Grant{}, err
	}
	return harness.Grant{
		GrantID:           issued.GrantID,
		Harness:           issued.Harness,
		Capabilities:      issued.Capabilities,
		EndpointURL:       issued.EndpointURL,
		Token:             issued.GrantToken,
		SupersededGrantID: issued.SupersededGrantID,
	}, nil
}

func reportDetection(locator harness.Locator, asJSON bool, stdout, stderr io.Writer) int {
	found, err := locator.DetectAll()
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
		return 1
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"harnesses": found}); err != nil {
			fmt.Fprintln(stderr, "homeplane-agent configure-harnesses: "+err.Error())
			return 1
		}
		return 0
	}
	for _, d := range found {
		state := "not installed"
		if d.Installed {
			state = "installed"
		}
		fmt.Fprintf(stdout, "%-12s %-14s %s\n", d.Harness, state, d.ConfigPath)
		if d.Reason != "" {
			fmt.Fprintf(stdout, "%-12s %s\n", "", d.Reason)
		}
	}
	return 0
}

func printHarnessReport(report harness.Report, stdout io.Writer) {
	for _, o := range report.Outcomes {
		fmt.Fprintf(stdout, "%-12s %s\n", o.Harness, o.Status)
		if o.ConfigPath != "" {
			fmt.Fprintf(stdout, "  config     %s\n", o.ConfigPath)
		}
		if len(o.Managed) > 0 {
			fmt.Fprintf(stdout, "  servers    %s\n", strings.Join(o.Managed, ", "))
		}
		if len(o.Retired) > 0 {
			fmt.Fprintf(stdout, "  retired    %s\n", strings.Join(o.Retired, ", "))
		}
		if o.GrantID != "" {
			// The token is never printed. The grant id is what `status`,
			// `GET /grants` and the audit log all speak in.
			fmt.Fprintf(stdout, "  grant      %s (%s)\n", o.GrantID, strings.Join(o.Capabilities, ", "))
		}
		if o.SupersededGrantID != "" {
			fmt.Fprintf(stdout, "  superseded %s\n", o.SupersededGrantID)
		}
		if o.EndpointURL != "" {
			fmt.Fprintf(stdout, "  endpoint   %s\n", o.EndpointURL)
		}
		if o.BackupPath != "" {
			fmt.Fprintf(stdout, "  backup     %s\n", o.BackupPath)
		}
		if !o.Changed && o.Status == harness.StatusConfigured {
			fmt.Fprintf(stdout, "  unchanged  the configuration was already what this run would have written\n")
		}
		if o.Message != "" {
			fmt.Fprintf(stdout, "  note       %s\n", o.Message)
		}
	}
}

// mergeHarnessState folds one run's outcomes into the machine's harness list.
//
// Only the harnesses this run ATTEMPTED are affected: each one is added when it
// ended configured and removed otherwise, and every harness the run did not
// touch keeps whatever the machine already believed about it. That is what
// makes `-harness codex` a statement about Codex rather than a claim that
// Claude Code is now unconfigured.
func mergeHarnessState(previous []string, report harness.Report) []string {
	keep := map[string]bool{}
	for _, h := range previous {
		keep[h] = true
	}
	for _, o := range report.Outcomes {
		keep[o.Harness] = o.Status == harness.StatusConfigured
	}
	out := make([]string, 0, len(keep))
	for h, ok := range keep {
		if ok {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// harnessComponentState records whether this run left the machine's harnesses
// healthy, so `status` can report a PARTIAL configuration as degraded.
//
// Without it, a run where Claude Code succeeded and Codex failed persists the
// same harness list as a run that only attempted Claude Code, and status —
// which reads that list — calls both machines fine. An installed harness that
// could not be configured is exactly the case an operator needs told.
func harnessComponentState(report harness.Report) *agent.ComponentState {
	degraded := report.Degraded()
	if len(degraded) == 0 {
		return &agent.ComponentState{State: agent.StateOK}
	}
	reasons := make([]string, 0, len(degraded))
	for _, o := range report.Outcomes {
		if !o.Installed || o.Status == harness.StatusConfigured {
			continue
		}
		reasons = append(reasons, o.Harness+" is installed but NOT configured ("+o.Status+")")
	}
	return &agent.ComponentState{State: agent.StateDegraded, Detail: strings.Join(reasons, "; ")}
}
