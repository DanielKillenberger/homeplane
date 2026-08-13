// Command homeplane-server is the Homeplane control plane: a tsnet-embedded
// HTTP server (enrolment, grants, audit, health) plus a SERVER-LOCAL operator
// admin CLI.
//
// The admin surface is deliberately not an HTTP API. The operator identity in
// the skeleton is shell access to the server host itself (single-operator
// reality, D2/D12): there is no operator credential to steal, phish, or leak
// into a machine's config, and machines can never read the global audit log or
// revoke another machine's grants.
package main

import (
	"fmt"
	"os"
)

const usage = `homeplane-server — Homeplane control plane

Usage:
  homeplane-server serve [flags]                 run the control plane over tsnet
  homeplane-server admin audit [flags]           read the append-only audit log
  homeplane-server admin revoke-grant <grant-id> revoke any grant (operator authority)
  homeplane-server admin secret import <ref>     import a provider app credential
  homeplane-server admin secret init-key         create the age key protecting secrets

Run any subcommand with -h for its flags.

Admin subcommands are server-local only: they operate directly on the state
directory and are never exposed over HTTP.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "homeplane-server: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return fmt.Errorf("no subcommand given")
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "admin":
		return runAdmin(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}
