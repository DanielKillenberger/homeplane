// Command homeplane-agent is the machine side of Homeplane: it enrols a
// machine with the control plane over the tailnet and reports, truthfully,
// what that machine can currently do.
//
// Only two subcommands exist in the walking skeleton — `enrol` and `status`.
// Everything else a machine eventually does (vault sync, GNO supervision,
// harness configuration, skill provisioning) plugs into the same state
// directory and the same status report in later tasks.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/DanielKillenberger/homeplane/internal/agent"
)

const usage = `homeplane-agent — the Homeplane machine agent

Usage:
  homeplane-agent enrol [flags]    register this machine with the control plane
  homeplane-agent status [flags]   report machine-side state (live-reconciled)
  homeplane-agent vault <cmd>      find the vault; supervise continuous sync
  homeplane-agent gno <cmd>        supervise the local retrieval engine over the
                                   vault and publish its endpoint descriptor
  homeplane-agent configure-harnesses [flags]
                                   wire this machine's agent harnesses to the
                                   local retrieval engine and the server's
                                   connector endpoint (one grant per harness)
  homeplane-agent add-credentials <provider> [flags]
                                   authorize a provider; the credential is
                                   stored on the server, never on this machine
  homeplane-agent skills <cmd>     link vault-authored skills into this
                                   machine's harnesses (list/provision/refresh)
  homeplane-agent version          print the installed agent version

Run any subcommand with -h for its flags.

Environment:
  ` + agent.EnvServerURL + `   default control-plane URL
  ` + agent.EnvStateDir + `   override the agent state directory (default ~/.homeplane)

Exit codes:
  0   ok
  1   error, or status reports a degraded component
  2   status reports that this machine is not enrolled
  64  usage error
`

// exitUsage is EX_USAGE: a mistake in the command line, distinct from a
// machine that is merely not enrolled (2) or degraded (1).
const exitUsage = 64

// version is stamped by scripts/stage-release.sh at build time so an installed
// agent can say which artifact it came from.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "enrol", "enroll":
		return runEnrol(ctx, args[1:], stdout, stderr)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr)
	case "vault":
		return runVault(ctx, args[1:], stdout, stderr)
	case "gno":
		return runGNO(ctx, args[1:], stdout, stderr)
	case "configure-harnesses":
		return runConfigureHarnesses(ctx, args[1:], stdout, stderr)
	case "add-credentials":
		return runAddCredentials(ctx, args[1:], stdout, stderr)
	case "skills":
		return runSkills(ctx, args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintln(stdout, "homeplane-agent "+version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprint(stderr, usage)
		fmt.Fprintf(stderr, "\nhomeplane-agent: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// resolveStateDir applies the -state-dir flag, then the environment, then the
// platform default.
func resolveStateDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return agent.DefaultStateDir()
}
