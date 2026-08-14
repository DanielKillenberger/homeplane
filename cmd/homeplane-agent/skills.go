package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/agent"
	"github.com/DanielKillenberger/homeplane/internal/agent/skills"
)

const skillsUsage = `homeplane-agent skills — provision vault-authored skills into this machine's harnesses

Usage:
  homeplane-agent skills list [flags]        show what the vault holds and what the profile assigns
  homeplane-agent skills provision [flags]   link the assigned skills into each harness
  homeplane-agent skills refresh [flags]     re-scan, re-link, and withdraw links the profile dropped

The vault is the only original. A harness reaches a skill through a symlink
into the vault, never through a copy, so editing the skill in Obsidian changes
what every harness reads.

Nothing in the vault is written, and no harness CONFIG file is touched: both
supported harnesses discover skills from a directory. Inside that directory
Homeplane only ever creates, repoints or withdraws entries IT created and
recorded — an entry it did not create is left exactly as it was.

A skill carrying credential material or runtime state is rejected and never
linked. A skill that drives host scheduling or service control is marked
unsupported with the matched line, because Homeplane distributes instructions
and not initiative.

  -verify  spawn each harness and require it to enumerate what was linked.
           That, not our own record, is what proves provisioning.
`

func runSkills(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, skillsUsage)
		return exitUsage
	}
	switch args[0] {
	case "list":
		return runSkillsList(ctx, args[1:], stdout, stderr)
	case "provision":
		return runSkillsProvision(ctx, args[1:], false, stdout, stderr)
	case "refresh":
		return runSkillsProvision(ctx, args[1:], true, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, skillsUsage)
		return 0
	default:
		fmt.Fprint(stderr, skillsUsage)
		fmt.Fprintf(stderr, "\nhomeplane-agent skills: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// skillsFlags are the flags every skills subcommand shares.
type skillsFlags struct {
	set       *flag.FlagSet
	stateDir  *string
	vaultPath *string
	profile   *string
	machine   *string
	harnesses *string
	asJSON    *bool
}

func newSkillsFlags(name string, stderr io.Writer) skillsFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return skillsFlags{
		set:       fs,
		stateDir:  fs.String("state-dir", "", "agent state directory (default: ~/.homeplane)"),
		vaultPath: fs.String("vault-path", "", "vault directory (default: the path recorded by `vault detect`)"),
		profile:   fs.String("profile", "", "profile file (default: <vault>/skills/"+skills.ProfileFileName+")"),
		machine:   fs.String("machine", "", "machine name for per-machine profile blocks (default: the enrolled name)"),
		harnesses: fs.String("harness", "", "restrict to these harnesses (comma-separated; default: all known)"),
		asJSON:    fs.Bool("json", false, "emit the report as JSON"),
	}
}

// skillsContext is everything a subcommand needs, resolved once.
type skillsContext struct {
	stateDir   string
	vaultRoot  string
	skillsRoot string
	machine    string
	harnesses  []string
	catalog    skills.Catalog
	profile    skills.Profile
}

func (f skillsFlags) resolve(stderr io.Writer) (skillsContext, int) {
	var out skillsContext

	dir, err := resolveStateDir(*f.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error())
		return out, 1
	}
	out.stateDir = dir

	vaultPath := strings.TrimSpace(*f.vaultPath)
	machine := strings.TrimSpace(*f.machine)
	if vaultPath == "" || machine == "" {
		store, err := agent.Open(dir)
		if err != nil {
			fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error())
			return out, 1
		}
		state, _, err := store.Load()
		if err != nil {
			fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error())
			return out, 1
		}
		if vaultPath == "" {
			vaultPath = strings.TrimSpace(state.VaultPath)
		}
		if machine == "" {
			machine = strings.TrimSpace(state.MachineName)
		}
	}
	if vaultPath == "" {
		fmt.Fprintln(stderr, "homeplane-agent skills: no vault path — run `homeplane-agent vault detect -record`, or pass -vault-path")
		return out, 1
	}
	out.vaultRoot = vaultPath
	out.machine = machine
	out.skillsRoot = filepath.Join(vaultPath, "skills")

	if strings.TrimSpace(*f.harnesses) != "" {
		for _, h := range strings.Split(*f.harnesses, ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			known := false
			for _, k := range skills.Known() {
				if h == k {
					known = true
				}
			}
			if !known {
				fmt.Fprintf(stderr, "homeplane-agent skills: unknown harness %q (known: %s)\n", h, strings.Join(skills.Known(), ", "))
				return out, exitUsage
			}
			out.harnesses = append(out.harnesses, h)
		}
	}

	catalog, err := skills.Discover(out.skillsRoot)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error())
		return out, 1
	}
	out.catalog = catalog

	profile, err := skills.FindProfile(*f.profile, out.skillsRoot)
	if err != nil {
		if errors.Is(err, skills.ErrNoProfile) {
			fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error()+
				"\nWrite one (see docs/decisions/d14-skills-linking.md) or pass -profile.")
			return out, 1
		}
		fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error())
		return out, 1
	}
	out.profile = profile
	return out, 0
}

// skillsListing is the `skills list` report.
type skillsListing struct {
	VaultSkills string              `json:"vault_skills_root"`
	Profile     string              `json:"profile"`
	ProfilePath string              `json:"profile_path"`
	Machine     string              `json:"machine"`
	Skills      []skills.Skill      `json:"skills"`
	Findings    []skills.Finding    `json:"findings"`
	Assigned    map[string][]string `json:"assigned"`
}

func runSkillsList(_ context.Context, args []string, stdout, stderr io.Writer) int {
	f := newSkillsFlags("skills list", stderr)
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), skillsUsage+"\nFlags:\n")
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	if f.set.NArg() > 0 {
		fmt.Fprintf(stderr, "homeplane-agent skills list: unexpected argument %q\n", f.set.Arg(0))
		return exitUsage
	}
	sc, code := f.resolve(stderr)
	if code != 0 {
		return code
	}

	targets := sc.harnesses
	if len(targets) == 0 {
		targets = skills.Known()
	}
	listing := skillsListing{
		VaultSkills: sc.catalog.Root,
		Profile:     sc.profile.Name,
		ProfilePath: sc.profile.Path,
		Machine:     sc.machine,
		Skills:      sc.catalog.Skills,
		Findings:    sc.catalog.Findings,
		Assigned:    map[string][]string{},
	}
	for _, h := range targets {
		listing.Assigned[h] = sc.profile.Assign(sc.machine, h)
	}

	if *f.asJSON {
		return emitJSON(stdout, stderr, listing)
	}

	fmt.Fprintf(stdout, "vault skills: %s\n", listing.VaultSkills)
	fmt.Fprintf(stdout, "profile:      %s (%s)\n", listing.Profile, listing.ProfilePath)
	if listing.Machine != "" {
		fmt.Fprintf(stdout, "machine:      %s\n", listing.Machine)
	}
	fmt.Fprintf(stdout, "\nlinkable (%d):\n", len(listing.Skills))
	for _, s := range listing.Skills {
		fmt.Fprintf(stdout, "  %-28s %s\n", s.Slug, firstSentence(s.Description))
	}
	if len(listing.Findings) > 0 {
		fmt.Fprintf(stdout, "\nnot linked (%d):\n", len(listing.Findings))
		for _, f := range listing.Findings {
			fmt.Fprintf(stdout, "  %-28s %s [%s] %s\n", f.Slug, f.Status, f.Rule, f.Reason)
			if f.Evidence != "" {
				fmt.Fprintf(stdout, "  %-28s   evidence: %s\n", "", f.Evidence)
			}
		}
	}
	fmt.Fprintln(stdout, "\nassigned by profile:")
	for _, h := range targets {
		assigned := listing.Assigned[h]
		if len(assigned) == 0 {
			fmt.Fprintf(stdout, "  %-14s (none)\n", h)
			continue
		}
		fmt.Fprintf(stdout, "  %-14s %s\n", h, strings.Join(assigned, ", "))
	}
	return 0
}

func runSkillsProvision(ctx context.Context, args []string, prune bool, stdout, stderr io.Writer) int {
	name := "skills provision"
	if prune {
		name = "skills refresh"
	}
	f := newSkillsFlags(name, stderr)
	verify := f.set.Bool("verify", false, "spawn each harness and require it to enumerate what was linked")
	f.set.Usage = func() {
		fmt.Fprint(f.set.Output(), skillsUsage+"\nFlags:\n")
		f.set.PrintDefaults()
	}
	if err := f.set.Parse(args); err != nil {
		return exitUsage
	}
	if f.set.NArg() > 0 {
		fmt.Fprintf(stderr, "homeplane-agent %s: unexpected argument %q\n", name, f.set.Arg(0))
		return exitUsage
	}
	sc, code := f.resolve(stderr)
	if code != 0 {
		return code
	}

	store, err := agent.Open(sc.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent "+name+": "+err.Error())
		return 1
	}
	p := skills.Provisioner{
		StateDir:  sc.stateDir,
		Machine:   sc.machine,
		Harnesses: sc.harnesses,
		Prune:     prune,
		// The manifest is a read-modify-write, so the run is serialised on the
		// same state lock the harness configurator uses.
		Lock: store.Lock,
	}
	report, err := p.Provision(sc.catalog, sc.profile)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent "+name+": "+err.Error())
		return 1
	}

	verifyErr := error(nil)
	if *verify {
		verifyErr = skills.Verifier{}.Verify(ctx, &report)
	}

	// Record what landed. The list comes from the ownership MANIFEST, not from
	// this run's report: a `-harness`-narrowed run touches one harness, and a
	// non-pruning run deliberately leaves links it no longer assigns, so the
	// report describes this run while the manifest describes the machine.
	//
	// Health is recorded AFTER verification, because a run whose links landed
	// and whose harness could not see them is degraded, not ok.
	installed, err := skills.InstalledSlugs(sc.stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "homeplane-agent "+name+": "+err.Error())
		return 1
	}
	health := skillsHealth(report, *verify, verifyErr)
	if err := mutateState(sc.stateDir, func(st *agent.State) {
		st.Skills = installed
		st.SkillsHealth = health
	}); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent "+name+": "+err.Error())
		return 1
	}

	if *f.asJSON {
		if code := emitJSON(stdout, stderr, report); code != 0 {
			return code
		}
	} else {
		printSkillsReport(stdout, report)
	}

	if verifyErr != nil {
		fmt.Fprintln(stderr, "homeplane-agent "+name+": "+verifyErr.Error())
		return 1
	}
	return 0
}

// skillsHealth judges the run for `status`.
//
// A skipped skill is not on its own a failure — an operator's own entry of the
// same name, or a skill the profile marks unsupported, is the system working.
// What IS a failure is a fresh harness that could not see what we linked, and a
// run that never verified cannot claim it was verified.
func skillsHealth(report skills.Report, verified bool, verifyErr error) *agent.ComponentState {
	if verifyErr != nil {
		return &agent.ComponentState{State: agent.StateDegraded, Detail: verifyErr.Error()}
	}
	var probed []string
	for _, hr := range report.Harnesses {
		if len(hr.Verified) > 0 {
			probed = append(probed, hr.Harness)
		}
	}
	if verified && len(probed) > 0 {
		sort.Strings(probed)
		return &agent.ComponentState{
			State:  agent.StateOK,
			Detail: "discovery verified by a fresh process of: " + strings.Join(probed, ", "),
		}
	}
	return &agent.ComponentState{
		State:  agent.StateOK,
		Detail: "links provisioned; discovery not verified this run (re-run with -verify)",
	}
}

func printSkillsReport(w io.Writer, report skills.Report) {
	fmt.Fprintf(w, "profile:      %s (%s)\n", report.Profile, report.ProfilePath)
	fmt.Fprintf(w, "vault skills: %s\n", report.VaultSkills)
	for _, hr := range report.Harnesses {
		fmt.Fprintf(w, "\n%s → %s\n", hr.Harness, hr.SkillsDir)
		if len(hr.Results) == 0 {
			fmt.Fprintln(w, "  (the profile assigns nothing to this harness)")
		}
		for _, r := range hr.Results {
			fmt.Fprintf(w, "  %-12s %-28s", r.Action, r.Slug)
			switch {
			case r.Reason != "":
				fmt.Fprintf(w, " %s\n", r.Reason)
			case r.Target != "":
				fmt.Fprintf(w, " → %s\n", r.Target)
			default:
				fmt.Fprintln(w)
			}
		}
		switch {
		case hr.VerifyError != "":
			fmt.Fprintf(w, "  verification FAILED: %s\n", hr.VerifyError)
		case len(hr.Verified) > 0:
			fmt.Fprintf(w, "  verified by a fresh %s process (%d skills enumerated)\n", hr.Harness, len(hr.Verified))
		}
	}
	if len(report.Findings) > 0 {
		fmt.Fprintf(w, "\nnot linked (%d):\n", len(report.Findings))
		for _, f := range report.Findings {
			fmt.Fprintf(w, "  %-28s %s [%s] %s\n", f.Slug, f.Status, f.Rule, f.Reason)
		}
	}
}

func emitJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, "homeplane-agent skills: "+err.Error())
		return 1
	}
	return 0
}

func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		s = s[:i+1]
	}
	if len(s) > 100 {
		s = s[:100] + "…"
	}
	return s
}
