//go:build live_e2e

package e2e_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// fn-3: grok as a third harness, proven live on this machine against the same
// server the walking skeleton runs on.
//
// These stages are ADDITIONS to fn-1's list rather than edits of it. The stages
// above them are fn-1's record of a two-harness machine and say "both
// harnesses" because that is what they proved; re-writing their prose would
// falsify a historical artifact. What fn-3 has to establish is grok's own
// halves — its configuration, its skills, its grant, its calls, its denial —
// and the one claim that needs all three harnesses at once: that revoking one
// grant leaves the other two working.
//
// Everything a harness says about itself is recorded and believed about
// NOTHING. The server's audit log settles every connector claim here exactly as
// it does for Claude Code and Codex.

// grokHarness drives grok the way the other two are driven: one named tool
// call, fixed arguments, no shell.
var grokHarness = harnessUnderProof{
	name: "grok", grantHarness: "grok",
	call: func(s *stage, what, server, tool string, args map[string]any) harnessOutput {
		return s.grok(what, toolPrompt(server, tool, args, ""))
	},
}

// grokConfigPath is the file Homeplane writes grok's entries into. GROK_HOME
// relocates it, and the proof honours that rather than hard-coding a path the
// product does not promise.
func grokConfigPath() string {
	home := strings.TrimSpace(os.Getenv("GROK_HOME"))
	if home == "" {
		h, _ := os.UserHomeDir()
		home = filepath.Join(h, ".grok")
	}
	return filepath.Join(home, "config.toml")
}

// fileSHA256 hashes a file, or returns "" with the reason it could not.
func fileSHA256(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// harnessRow finds one harness's row in a status report.
func grokRow(rep statusReport, harness string) (harnessStatusRow, bool) {
	for _, h := range rep.Harnesses {
		if h.Harness == harness {
			return h, true
		}
	}
	return harnessStatusRow{}, false
}

// ── the harness: detection, configuration, custody, compat isolation ─────────

// stageGrokHarness is R1 and R2 for grok, plus the two states R6 can only
// observe here: `detected_unconfigured` BEFORE the write and `configured`
// after.
//
// It takes its own copy of `~/.grok/config.toml` before anything runs. The
// product takes a timestamped backup of its own and that is what the criterion
// asks for; this second copy exists because the file being written is a live
// operator's, and a proof that mutates a person's configuration should be able
// to put it back without depending on the thing under test.
func stageGrokHarness(s *stage) {
	cfg := grokConfigPath()
	before, beforeErr := fileSHA256(cfg)
	s.assert("grok's configuration is readable and its pre-run bytes are recorded",
		beforeErr == nil, "%s sha256 %s (%v)", cfg, before, beforeErr)

	home, _ := os.UserHomeDir()
	safe := filepath.Join(home, ".homeplane", "fn3-grok-backup")
	if err := os.MkdirAll(safe, 0o700); err == nil && beforeErr == nil {
		body, readErr := os.ReadFile(cfg)
		dst := filepath.Join(safe, fmt.Sprintf("config.toml.%s", time.Now().UTC().Format("20060102T150405Z")))
		writeErr := error(nil)
		if readErr == nil {
			writeErr = os.WriteFile(dst, body, 0o600)
		}
		s.assert("the proof holds its own restorable copy of grok's configuration",
			readErr == nil && writeErr == nil, "%s (%v/%v)", dst, readErr, writeErr)
	}

	// Detection FIRST, and read-only: `-detect` is the existing mode, and its
	// verdict before any write is R6's `detected_unconfigured`.
	det := s.agent("homeplane-agent configure-harnesses -detect (before any write)", 3*time.Minute,
		"configure-harnesses", "-detect", "-json")
	var detReport struct {
		Harnesses []struct {
			Harness       string   `json:"harness"`
			Installed     bool     `json:"installed"`
			ConfigPath    string   `json:"config_path"`
			ConfigExists  bool     `json:"config_exists"`
			BinaryPath    string   `json:"binary_path"`
			Version       string   `json:"version"`
			Support       string   `json:"support"`
			SupportReason string   `json:"support_reason"`
			CompatSources []string `json:"compat_sources"`
		} `json:"harnesses"`
	}
	_ = json.Unmarshal([]byte(det.full), &detReport)
	var grokDet = struct {
		found                             bool
		installed                         bool
		version, support, cfgPath, binary string
		compat                            []string
	}{}
	for _, h := range detReport.Harnesses {
		if h.Harness == "grok" {
			grokDet.found, grokDet.installed = true, h.Installed
			grokDet.version, grokDet.support = h.Version, h.Support
			grokDet.cfgPath, grokDet.binary, grokDet.compat = h.ConfigPath, h.BinaryPath, h.CompatSources
		}
	}
	s.assert("detection reports grok alongside the other harnesses, with an observed version and a support verdict",
		det.ExitCode == 0 && grokDet.found && grokDet.installed &&
			grokDet.version != "" && grokDet.support == "supported" && grokDet.cfgPath == cfg,
		"exit %d; grok installed=%v version=%q support=%q config=%s binary=%s",
		det.ExitCode, grokDet.installed, grokDet.version, grokDet.support, grokDet.cfgPath, grokDet.binary)

	// The compat residual is REPORTED, never claimed absent: the project-scope
	// `.mcp.json` source cannot be closed from a user config (D4b), so a
	// detection that listed nothing would be the one dishonest thing this
	// surface could say.
	s.assert("detection reports the compat sources grok would still inherit MCP servers from",
		len(grokDet.compat) > 0, "compat_sources %v", grokDet.compat)

	pre, _ := s.status()
	if row, ok := grokRow(pre, "grok"); ok {
		s.assert("before configuration, status reports grok as detected-unconfigured (R6 state 2 of 5)",
			row.State == "detected_unconfigured",
			"grok: state=%s detail=%s", row.State, firstLine(row.Detail))
	} else {
		s.assert("before configuration, status carries a grok row", false, "no grok row in %d harness row(s)", len(pre.Harnesses))
	}

	// The write, through the product's own entrypoint — no grok-specific
	// command, which is the architectural claim the whole spec is about.
	res := s.agent("homeplane-agent configure-harnesses (all three harnesses)", 8*time.Minute,
		"configure-harnesses", "-json")
	var report struct {
		Harnesses []struct {
			Harness     string   `json:"harness"`
			Status      string   `json:"status"`
			Config      string   `json:"config_path"`
			Backup      string   `json:"backup_path"`
			Managed     []string `json:"managed_servers"`
			GrantID     string   `json:"grant_id"`
			EndpointURL string   `json:"endpoint_url"`
			Message     string   `json:"message"`
		} `json:"harnesses"`
	}
	_ = json.Unmarshal([]byte(res.full), &report)
	if !s.assert("configure-harnesses completes", res.ExitCode == 0, "exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}

	grants := map[string]string{}
	var grokOutcome = struct {
		status, backup, endpoint string
		managed                  []string
	}{}
	for _, h := range report.Harnesses {
		grants[h.Harness] = h.GrantID
		if h.Harness == "grok" {
			grokOutcome.status, grokOutcome.backup = h.Status, h.Backup
			grokOutcome.managed, grokOutcome.endpoint = h.Managed, h.EndpointURL
		}
	}
	s.assert("grok is configured with both Homeplane surfaces and its own endpoint",
		grokOutcome.status == "configured" && len(grokOutcome.managed) == 2 && grokOutcome.endpoint != "",
		"status=%q managed=%v endpoint=%s", grokOutcome.status, grokOutcome.managed, grokOutcome.endpoint)
	if grokOutcome.backup != "" {
		_, err := os.Stat(grokOutcome.backup)
		s.assert("a timestamped backup precedes the write to grok's configuration", err == nil, "%s", grokOutcome.backup)
	} else {
		s.assert("a timestamped backup precedes the write to grok's configuration", false, "no backup path reported")
	}

	// Three harnesses, three DISTINCT grants. Everything R5 claims rests on
	// this being three credentials rather than one shared one.
	rep, _ := s.status()
	active := map[string]string{}
	for _, g := range rep.Grants {
		if g.State == "active" {
			active[g.Harness] = g.GrantID
		}
	}
	s.assert("each of the three harnesses holds its own distinct active grant",
		active["claude-code"] != "" && active["codex"] != "" && active["grok"] != "" &&
			active["grok"] != active["claude-code"] && active["grok"] != active["codex"] &&
			active["claude-code"] != active["codex"],
		"claude-code %s, codex %s, grok %s", active["claude-code"], active["codex"], active["grok"])

	if row, ok := grokRow(rep, "grok"); ok {
		s.assert("after configuration, status reports grok as configured (R6 state 4 of 5)",
			row.State == "configured" && row.GrantID == active["grok"],
			"grok: state=%s grant=%s detail=%s", row.State, row.GrantID, firstLine(row.Detail))
	}

	// Token custody. The MODE is checked here; containment (resolved symlinks +
	// `git check-ignore`) is the writer's own precondition and is unit-proven,
	// and this file is outside every repository by construction.
	if info, err := os.Stat(cfg); err == nil {
		s.assert("grok's configuration is 0600 after the write", info.Mode().Perm() == 0o600,
			"%s mode %o", cfg, info.Mode().Perm())
	} else {
		s.assert("grok's configuration is 0600 after the write", false, "%v", err)
	}

	// The file's CONTENT is read here and nothing of it is ever recorded: the
	// Authorization header is a bearer token, and `grok mcp list` echoes header
	// values verbatim, which is why that verb is not used at all. Only derived
	// booleans reach the evidence.
	body, readErr := os.ReadFile(cfg)
	if !s.assert("grok's configuration can be re-read after the write", readErr == nil, "%v", readErr) {
		return
	}
	text := string(body)
	s.assert("both Homeplane entries are present under grok's own MCP scope",
		strings.Contains(text, "[mcp_servers.homeplane]") && strings.Contains(text, "[mcp_servers.gno]"),
		"homeplane entry present=%v, gno entry present=%v",
		strings.Contains(text, "[mcp_servers.homeplane]"), strings.Contains(text, "[mcp_servers.gno]"))

	// D4 and D4b: grok's connector access is its own grant and nobody else's.
	// Both compat cells are closed, and re-asserted on every run — grok's own
	// tooling can undo them, so "we set it once" would not be a guarantee.
	s.assert("the Claude and Cursor MCP compat sources are closed (D4, D4b)",
		grokCompatClosed(text, "claude") && grokCompatClosed(text, "cursor"),
		"[compat.claude] mcps closed=%v; [compat.cursor] mcps closed=%v",
		grokCompatClosed(text, "claude"), grokCompatClosed(text, "cursor"))

	// Preservation, byte-level, against the copy taken before the run: every
	// line that is not part of a Homeplane-managed table or a compat `mcps`
	// key must still be there, comments included.
	if beforeErr == nil {
		if original, err := os.ReadFile(filepath.Join(safe, latestBackup(safe))); err == nil {
			missing := linesLost(string(original), text)
			s.assert("grok's pre-existing configuration and comments survive the write",
				len(missing) == 0, "%d line(s) lost: %s", len(missing), strings.Join(missing, " | "))
		}
	}

	after, _ := fileSHA256(cfg)
	s.assert("grok's configuration changed, and both its before and after bytes are recorded",
		after != "" && after != before, "sha256 before %s → after %s", before, after)

	// Idempotence: a second run converges rather than accumulating.
	againBefore, _ := fileSHA256(cfg)
	again := s.agent("homeplane-agent configure-harnesses again (idempotent convergence)", 8*time.Minute,
		"configure-harnesses", "-harness", "grok", "-json")
	againAfter, _ := fileSHA256(cfg)
	s.assert("a repeat configure of grok converges and leaves a re-parseable 0600 file",
		again.ExitCode == 0, "exit %d; sha256 %s → %s%s", again.ExitCode, againBefore, againAfter, tail(again.Stderr))

	live, _ := os.Stat(cfg)
	if live != nil {
		s.assert("0600 is re-asserted by the repeat run", live.Mode().Perm() == 0o600, "mode %o", live.Mode().Perm())
	}
	reread, _ := os.ReadFile(cfg)
	s.assert("the compat isolation is re-asserted by the repeat run",
		grokCompatClosed(string(reread), "claude") && grokCompatClosed(string(reread), "cursor"),
		"claude closed=%v cursor closed=%v",
		grokCompatClosed(string(reread), "claude"), grokCompatClosed(string(reread), "cursor"))
}

// grokCompatClosed reports whether `[compat.<vendor>] mcps` is present and
// false. It reads the table by name rather than the file as a whole: `mcps =
// false` elsewhere in the document would otherwise satisfy a naive search.
func grokCompatClosed(doc, vendor string) bool {
	header := "[compat." + vendor + "]"
	i := strings.Index(doc, header)
	if i < 0 {
		return false
	}
	rest := doc[i+len(header):]
	// The table ends at the next table header at column 0.
	for _, line := range strings.Split(rest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && trimmed != "" {
			return false
		}
		if !strings.HasPrefix(trimmed, "mcps") {
			continue
		}
		_, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		return strings.HasPrefix(strings.TrimSpace(value), "false")
	}
	return false
}

// linesLost names the substantive lines of the original document that are no
// longer in the written one, ignoring the tables Homeplane manages and the
// compat keys D4/D4b change. Comments are NOT ignored: dropping them is the
// exact harm that disqualified `grok mcp add` as the writer.
func linesLost(original, written string) []string {
	managed := map[string]bool{
		"[mcp_servers.homeplane]":         true,
		"[mcp_servers.homeplane.headers]": true,
		"[mcp_servers.gno]":               true,
		"[mcp_servers.gno.env]":           true,
	}
	present := map[string]int{}
	for _, line := range strings.Split(written, "\n") {
		present[strings.TrimSpace(line)]++
	}
	var lost []string
	var inManaged bool
	for _, line := range strings.Split(original, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inManaged = managed[trimmed]
		}
		if inManaged || trimmed == "" {
			continue
		}
		// The two keys D4/D4b deliberately rewrite.
		if strings.HasPrefix(trimmed, "mcps") {
			continue
		}
		if present[trimmed] > 0 {
			present[trimmed]--
			continue
		}
		lost = append(lost, trimmed)
	}
	return lost
}

// latestBackup names the newest file in a directory of timestamped copies.
func latestBackup(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[len(names)-1]
}

// ── R4, first half: the rollout gate ────────────────────────────────────────

// stageGrokRolloutGate is the check that has to pass BEFORE the active vault
// profile may name grok.
//
// The profile syncs to every machine, and a machine running a pre-fn-3 agent
// REFUSES a profile with an unknown harness key — fail-closed, by design
// (profile.go's unknown-key reject, which the typo test pins). So writing
// `[harness.grok]` into the shared file is a fleet-wide change, and the gate is
// the server's own list of enrolled machines: if it holds exactly this machine,
// nothing else can be broken by the edit.
//
// If it cannot be verified, the literal key is deferred and defaults apply —
// that deferral is recorded rather than assumed away.
func stageGrokRolloutGate(s *stage) {
	rep, _ := s.status()
	s.assert("this machine's identity is known, so the enrolled-machine list can be checked against it",
		rep.MachineID != "", "machine_id %q name %q", rep.MachineID, rep.MachineName)

	// The store is the authority: the audit log says what HAPPENED, and the
	// machines table says who exists now. Read-only, on the server, through the
	// same shell an operator has.
	rows := s.ssh("server: the enrolled-machine list (read-only)", 90*time.Second,
		fmt.Sprintf("sqlite3 -readonly %s/homeplane.db \"select id || '|' || name || '|' || node_name from machines order by id;\"",
			s.env.serverStateDir))
	var machines []string
	for _, line := range strings.Split(strings.TrimSpace(rows.full), "\n") {
		if strings.TrimSpace(line) != "" {
			machines = append(machines, strings.TrimSpace(line))
		}
	}
	if rows.ExitCode != 0 || len(machines) == 0 {
		s.recordLimitation("the rollout gate was settled against the server's enrolled-machine list",
			"not run: the server's machines table could not be read (exit "+fmt.Sprint(rows.ExitCode)+
				": "+firstLine(rows.Stderr)+"). Per R4 the literal `[harness.grok]` key must then be DEFERRED and "+
				"defaults applied until the fleet can be verified. Owner: whoever restores operator access to the "+
				"server host; the vault edit must be reverted if it was made before this check.")
		return
	}

	onlyThisMachine := len(machines) == 1 && strings.HasPrefix(machines[0], rep.MachineID+"|")
	s.assert("every machine consuming the synced profile is this one, so naming grok in it can break nothing else",
		onlyThisMachine, "%d enrolled machine(s): %s | this machine: %s",
		len(machines), strings.Join(machines, ", "), rep.MachineID)

	// The edit itself: made by the task, verified here. The pre-edit bytes are
	// kept beside the vault's own copy so the diff is checkable rather than
	// asserted.
	profile := filepath.Join(s.env.vaultPath, "skills", "homeplane.skills.toml")
	home, _ := os.UserHomeDir()
	backupDir := filepath.Join(home, ".homeplane", "fn3-vault-profile-backup")
	backup := filepath.Join(backupDir, "homeplane.skills.toml.pre-fn3")

	original, origErr := os.ReadFile(backup)
	current, curErr := os.ReadFile(profile)
	if !s.assert("the profile's pre-edit bytes and its current bytes are both readable",
		origErr == nil && curErr == nil, "backup %s (%v); active %s (%v)", backup, origErr, profile, curErr) {
		return
	}

	added, removed := lineDiff(string(original), string(current))

	// Every pre-existing ASSIGNMENT survives byte-for-byte. The one line the
	// edit is allowed to rewrite is the unsupported marking's harness list,
	// and only by EXTENDING it: `phone-home-coordinator` is bound to the
	// always-on Clawniel session, which is as true of grok as it is of the
	// other two, and a marking that named only two harnesses would leave grok
	// as the one harness permitted to host a skill its author declared
	// inapplicable. Anything else removed fails here.
	const markingBefore = `harnesses = ["claude-code", "codex"]`
	const markingAfter = `harnesses = ["claude-code", "codex", "grok"]`
	onlyMarkingRewritten := len(removed) == 0 ||
		(len(removed) == 1 && removed[0] == markingBefore && containsLine(added, markingAfter))
	s.assert("the vault edit preserves every pre-existing assignment byte-for-byte",
		onlyMarkingRewritten, "%d line(s) removed: %s", len(removed), strings.Join(removed, " | "))
	s.assert("the vault edit adds grok's own harness block",
		len(added) > 0 && containsLine(added, "[harness.grok]"),
		"%d line(s) added: %s", len(added), strings.Join(added, " | "))

	// And the file the machine actually reads still parses, through the product.
	list := s.agent("homeplane-agent skills list -json (the edited profile is read by the product)", 3*time.Minute,
		"skills", "list", "-json")
	var listing struct {
		ProfilePath string              `json:"profile_path"`
		Assigned    map[string][]string `json:"assigned"`
	}
	_ = json.Unmarshal([]byte(list.full), &listing)
	s.assert("the edited profile parses and assigns a skill set to grok",
		list.ExitCode == 0 && listing.ProfilePath == profile && len(listing.Assigned["grok"]) > 0,
		"exit %d; profile %s; grok assigned %v", list.ExitCode, listing.ProfilePath, listing.Assigned["grok"])
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}

// lineDiff reports the lines present only in b and only in a, by multiset.
func lineDiff(a, b string) (added, removed []string) {
	count := map[string]int{}
	for _, l := range strings.Split(a, "\n") {
		count[l]++
	}
	for _, l := range strings.Split(b, "\n") {
		if count[l] > 0 {
			count[l]--
			continue
		}
		if strings.TrimSpace(l) != "" {
			added = append(added, strings.TrimSpace(l))
		}
	}
	for l, n := range count {
		for i := 0; i < n; i++ {
			if strings.TrimSpace(l) != "" {
				removed = append(removed, strings.TrimSpace(l))
			}
		}
	}
	sort.Strings(removed)
	return added, removed
}

// ── R4, second half: skills into grok, proven by a fresh grok ───────────────

// stageGrokSkills provisions through the PRODUCT path and proves two separate
// things: that a vault-authored skill reaches grok and a fresh grok process
// enumerates it, and that grok's set comes from the profile's `[harness.grok]`
// key rather than from `[defaults]` happening to cover it.
//
// The second claim is not observable from a single run — a build that ignored
// the key entirely would provision the same set. So it is settled by
// FALSIFICATION: the same read-only product command is run against a copy of
// the active profile whose grok block alone is changed, and the assignment has
// to change with it.
func stageGrokSkills(s *stage) {
	if !s.grokFreshProcess() {
		return
	}

	res := s.agent("homeplane-agent skills provision -verify", 15*time.Minute,
		"skills", "provision", "-verify", "-json")
	var report struct {
		Harnesses []struct {
			Harness   string `json:"harness"`
			SkillsDir string `json:"skills_dir"`
			Results   []struct {
				Slug     string `json:"slug"`
				Action   string `json:"action"`
				LinkPath string `json:"link_path"`
				Target   string `json:"target"`
				Reason   string `json:"reason"`
				Rule     string `json:"rule"`
			} `json:"results"`
			Verified    []string `json:"verified"`
			VerifyError string   `json:"verify_error"`
		} `json:"harnesses"`
	}
	_ = json.Unmarshal([]byte(res.full), &report)
	if !s.assert("skills provision with fresh-process verification completes", res.ExitCode == 0,
		"exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}

	var grokReport = struct {
		found       bool
		dir         string
		linked      []string
		symlinked   int
		verified    []string
		verifyError string
	}{}
	for _, h := range report.Harnesses {
		if h.Harness != "grok" {
			continue
		}
		grokReport.found, grokReport.dir = true, h.SkillsDir
		grokReport.verified, grokReport.verifyError = h.Verified, h.VerifyError
		for _, r := range h.Results {
			switch r.Action {
			case "linked", "unchanged", "repointed":
				grokReport.linked = append(grokReport.linked, r.Slug)
				if strings.HasPrefix(r.Target, s.env.vaultPath) {
					grokReport.symlinked++
				}
			}
		}
	}
	if !s.assert("provisioning reports grok as a third harness with its own skills directory",
		grokReport.found && grokReport.dir != "", "grok report present=%v dir=%s", grokReport.found, grokReport.dir) {
		return
	}
	s.assert("vault-authored skills are LINKED into grok, never copied",
		len(grokReport.linked) > 0 && grokReport.symlinked == len(grokReport.linked),
		"%d linked (%v), %d resolving into the vault at %s",
		len(grokReport.linked), grokReport.linked, grokReport.symlinked, s.env.vaultPath)

	// The verification is a FRESH grok process enumerating what it can see —
	// the product's own `Discover("grok")`, not a probe written for this proof.
	s.assert("a fresh grok process enumerated the skills that were linked into it",
		grokReport.verifyError == "" && len(grokReport.verified) > 0,
		"verified %v; error %q", grokReport.verified, grokReport.verifyError)
	s.assert("the vault's Homeplane capability skill is among what grok discovered",
		containsString(grokReport.verified, "homeplane-capabilities"),
		"grok discovered %v", grokReport.verified)

	// Falsification: the `[harness.grok]` key is what decides grok's set.
	profile := filepath.Join(s.env.vaultPath, "skills", "homeplane.skills.toml")
	body, err := os.ReadFile(profile)
	if !s.assert("the active profile can be copied for the falsification", err == nil, "%v", err) {
		return
	}
	assigned := func(what, path string) map[string][]string {
		out := s.agent(what, 3*time.Minute, "skills", "list", "-json", "-profile", path)
		var doc struct {
			Assigned map[string][]string `json:"assigned"`
		}
		_ = json.Unmarshal([]byte(out.full), &doc)
		return doc.Assigned
	}

	dir := s.t.TempDir()
	verbatim := filepath.Join(dir, "verbatim.toml")
	mutated := filepath.Join(dir, "mutated.toml")
	_ = os.WriteFile(verbatim, body, 0o600)

	// One line of the grok block changes, and nothing else: the skill that is
	// dropped is one `[defaults]` still names, so a build that read defaults
	// instead of the key would answer identically.
	const dropped = "homeplane-capabilities"
	mutatedBody, ok := dropFromGrokBlock(string(body), dropped)
	if !s.assert("the falsification copy could be produced by editing only grok's block", ok,
		"could not find %q inside [harness.grok] in %s", dropped, profile) {
		return
	}
	_ = os.WriteFile(mutated, []byte(mutatedBody), 0o600)

	base := assigned("homeplane-agent skills list -json (a verbatim copy of the active profile)", verbatim)
	alt := assigned("homeplane-agent skills list -json (the same profile with ONLY grok's block changed)", mutated)

	s.assert("grok's assignment comes from the profile's [harness.grok] key: changing that key alone changes it",
		containsString(base["grok"], dropped) && !containsString(alt["grok"], dropped),
		"verbatim grok=%v; mutated grok=%v", base["grok"], alt["grok"])
	s.assert("and the change is confined to grok: the other harnesses' assignments are untouched",
		sameSet(base["claude-code"], alt["claude-code"]) && sameSet(base["codex"], alt["codex"]) &&
			containsString(alt["claude-code"], dropped),
		"claude-code %v → %v; codex %v → %v",
		base["claude-code"], alt["claude-code"], base["codex"], alt["codex"])

	rep, _ := s.status()
	state, detail := s.component(rep, "skills")
	s.assert("status reports the provisioned skills", state == "ok", "skills: %s (%s)", state, detail)
}

// dropFromGrokBlock removes one skill entry from the `[harness.grok]` table and
// leaves the rest of the document — every other block, every comment — exactly
// as it was.
func dropFromGrokBlock(doc, slug string) (string, bool) {
	lines := strings.Split(doc, "\n")
	inBlock, dropped := false, false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inBlock = trimmed == "[harness.grok]"
		}
		if inBlock && !dropped && strings.Contains(line, `"`+slug+`"`) {
			dropped = true
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), dropped
}

func containsString(haystack []string, want string) bool {
	for _, h := range haystack {
		if h == want {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ── R3, first half: grok reaches the local retrieval engine ─────────────────

func stageGrokGNO(s *stage) {
	if !s.grokFreshProcess() {
		return
	}
	const needle = "homeplane"
	prompt := "Use the gno MCP server to search the vault for \"" + needle + "\". " +
		"Call exactly one search tool, then reply with the first result's file path and nothing else. " +
		"Run no shell commands."

	s.waitForEngineRelease()
	out := s.grok("grok → local retrieval engine", prompt)
	s.waitForEngineRelease()
	s.assert("grok retrieves real vault content through the local engine",
		out.ok && looksLikeVaultHit(out.text, s.env.vaultPath), "%s", firstLine(out.text))
}

// ── R3, second half: the edge, under grok's OWN grant ───────────────────────

// stageGrokConnector is the Drive half: a real read that reaches Google, and
// the write the scope policy refuses.
func stageGrokConnector(s *stage) {
	if !s.grokFreshProcess() {
		return
	}
	h := grokHarness
	since := time.Now().UTC().Add(-30 * time.Second)

	read := h.call(s, "Drive read via grok", connectorServer, "search_drive_files", map[string]any{
		"query": "trashed = false", "page_size": 3, "user_google_email": s.env.account,
	})
	rows := s.audit("server audit after grok's Drive read", since)
	row, ok := lastRow(decisionRows(rowsForHarness(rows, h.grantHarness), "search_drive_files"))
	s.assert("grok: a Drive read reaches real Google through the edge, under grok's own grant",
		ok && row.Outcome == "allowed" && row.ActionClass == "read" && row.GrantID != "",
		"audit: outcome=%s class=%s grant=%s harness=%s | grok said: %s",
		row.Outcome, row.ActionClass, row.GrantID, row.Harness, firstLine(read.text))

	// Attribution is the claim D4/D4b exist to make true: before compat was
	// closed, grok reached this same edge through Claude Code's entry and would
	// have been audited as Claude Code.
	rep, _ := s.status()
	var grokGrant string
	for _, g := range rep.Grants {
		if g.State == "active" && g.Harness == "grok" {
			grokGrant = g.GrantID
		}
	}
	s.assert("the call is attributed to grok's grant, not to another harness's",
		row.GrantID != "" && row.GrantID == grokGrant, "audited grant %s; grok's active grant %s", row.GrantID, grokGrant)

	result, hasResult := lastRow(resultRows(rowsForHarness(rows, h.grantHarness), "search_drive_files"))
	s.assert("grok: the Drive read is audited against the file it returned",
		hasResult && identified(result), "audit: artifact=%s | grok said: %s", result.ArtifactID, firstLine(read.text))

	since = time.Now().UTC().Add(-5 * time.Second)
	write := h.call(s, "Drive write (must be refused) via grok", connectorServer, "create_drive_file", map[string]any{
		"file_name": "homeplane-e2e-must-not-exist.txt", "content": "this call must never reach Google",
		"mime_type": "text/plain", "user_google_email": s.env.account,
	})
	rows = s.audit("server audit after grok's Drive write attempt", since)
	row, ok = lastRow(decisionRows(rowsForHarness(rows, h.grantHarness), "create_drive_file"))
	s.assert("grok: a Drive write is refused fail-closed and audited as a policy violation",
		ok && row.Outcome == "denied" && row.Event == "policy_violation",
		"audit: event=%s outcome=%s reason=%s | grok said: %s",
		row.Event, row.Outcome, row.Reason, firstLine(write.text))
}

// stageGrokCalendar is the guarded write R3 asks for, run as the same six-op
// sequence the other two harnesses were held to: every mutation carries
// send_updates:"none", one deliberate call without it must be refused, and the
// event is deleted and its absence proven.
func stageGrokCalendar(s *stage) {
	if !s.grokFreshProcess() {
		return
	}
	runSixOp(s, grokHarness)
}

// ── R5: revocation asymmetry, both directions, with produced failures ───────

// stageGrokRevocation proves the property that makes per-harness grants worth
// having, in both directions, by PRODUCING each failure rather than reasoning
// about it: a real call that a real revocation refused, with the other two
// harnesses calling successfully in the same window.
func stageGrokRevocation(s *stage) {
	if !s.grokFreshProcess() {
		return
	}
	before := activeGrants(s)
	if !s.assert("all three harnesses hold an active grant before the revocation proof",
		before["claude-code"] != "" && before["codex"] != "" && before["grok"] != "",
		"claude-code %s, codex %s, grok %s", before["claude-code"], before["codex"], before["grok"]) {
		return
	}

	// Direction 1 — revoke GROK. grok must be refused; the other two must not
	// notice.
	revokedGrok := revokeAndProve(s, "grok", before["grok"], []string{"claude-code", "codex"})

	// R6's fifth state, produced by a real revocation rather than by editing a
	// record: the machine still holds a configuration whose grant is dead.
	if revokedGrok {
		rep, _ := s.status()
		if row, ok := grokRow(rep, "grok"); ok {
			s.assert("while its grant is revoked, status reports grok as revoked (R6 state 5 of 5)",
				row.State == "revoked" && row.GrantID == before["grok"],
				"grok: state=%s grant=%s detail=%s", row.State, row.GrantID, firstLine(row.Detail))
		}
	}

	restore := s.agent("homeplane-agent configure-harnesses (restore grok's grant)", 8*time.Minute,
		"configure-harnesses", "-json")
	s.assert("grok recovers by re-running configure-harnesses", restore.ExitCode == 0,
		"exit %d%s", restore.ExitCode, tail(restore.Stderr))
	mid := activeGrants(s)
	s.assert("grok holds a NEW active grant after the restore",
		mid["grok"] != "" && mid["grok"] != before["grok"], "grok %s (was %s)", mid["grok"], before["grok"])

	// Direction 2 — revoke CLAUDE CODE. grok and Codex must keep working, which
	// is the half that would fail if grok were still reaching the edge through
	// Claude Code's inherited entry.
	revokeAndProve(s, "claude-code", mid["claude-code"], []string{"grok", "codex"})

	restore2 := s.agent("homeplane-agent configure-harnesses (restore Claude Code's grant)", 8*time.Minute,
		"configure-harnesses", "-json")
	s.assert("Claude Code recovers by re-running configure-harnesses", restore2.ExitCode == 0,
		"exit %d%s", restore2.ExitCode, tail(restore2.Stderr))

	after := activeGrants(s)
	s.assert("all three harnesses end the proof holding a live grant, none of them the revoked one",
		after["claude-code"] != "" && after["claude-code"] != mid["claude-code"] &&
			after["codex"] != "" && after["grok"] != "" && after["grok"] != before["grok"],
		"claude-code %s (was %s), codex %s, grok %s (was %s)",
		after["claude-code"], mid["claude-code"], after["codex"], after["grok"], before["grok"])
}

// revokeAndProve revokes one harness's grant through the OPERATOR surface, then
// makes a real call from that harness and from each survivor.
func revokeAndProve(s *stage, victim, grantID string, survivors []string) bool {
	since := time.Now().UTC().Add(-30 * time.Second)
	revoked := time.Now()
	rev := s.ssh("server: admin revoke-grant ("+victim+")", 60*time.Second,
		fmt.Sprintf("%s/bin/homeplane-server admin revoke-grant -state-dir %s %s",
			serverPrefix(s.env), s.env.serverStateDir, grantID))
	if !s.assert("the operator revokes "+victim+"'s grant from the server", rev.ExitCode == 0,
		"exit %d: %s", rev.ExitCode, firstLine(rev.Stdout+rev.Stderr)) {
		return false
	}

	failing := harnessByName(victim).call(s, victim+" after ITS grant was revoked (must fail)",
		connectorServer, "search_drive_files", map[string]any{
			"query": "trashed = false", "page_size": 1, "user_google_email": s.env.account})
	elapsed := time.Since(revoked)

	rows := s.audit("server audit after the revoked harness called", since)
	var refused bool
	var admittedAfter int
	for _, r := range rows {
		if r.GrantID == grantID && r.Outcome == "denied" && (strings.Contains(r.Reason, "revoked") ||
			strings.Contains(r.Reason, "invalid_token") || strings.Contains(r.Reason, "unknown_grant")) {
			refused = true
		}
		if r.Event == "connector_tool_call" && r.GrantID == grantID &&
			r.Outcome == "allowed" && r.TS.After(revoked.UTC()) {
			admittedAfter++
		}
	}
	ok := s.assert(victim+" is refused within a token-validation interval, and its grant admits nothing after",
		refused && admittedAfter == 0 && elapsed < 90*time.Second,
		"refusal audited=%v on grant %s, %d call(s) admitted after, %s elapsed | %s said: %s",
		refused, grantID, admittedAfter, elapsed.Round(time.Second), victim, firstLine(failing.text))

	for _, name := range survivors {
		out := harnessByName(name).call(s, name+" while "+victim+" is revoked (must still work)",
			connectorServer, "search_drive_files", map[string]any{
				"query": "trashed = false", "page_size": 1, "user_google_email": s.env.account})
		rows := s.audit("server audit after "+name+" called", since)
		row, found := lastRow(decisionRows(rowsForHarness(rows, name), "search_drive_files"))
		s.assert(name+" is unaffected by "+victim+"'s revocation",
			found && row.Outcome == "allowed" && row.GrantID != grantID,
			"audit: outcome=%s grant=%s | %s said: %s", row.Outcome, row.GrantID, name, firstLine(out.text))
	}
	return ok
}

func harnessByName(name string) harnessUnderProof {
	switch name {
	case "claude-code":
		return claudeCodeHarness
	case "codex":
		return codexHarness
	default:
		return grokHarness
	}
}

func activeGrants(s *stage) map[string]string {
	rep, _ := s.status()
	out := map[string]string{}
	for _, g := range rep.Grants {
		if g.State == "active" {
			out[g.Harness] = g.GrantID
		}
	}
	return out
}

// ── R6: the five states, each produced ──────────────────────────────────────

// stageGrokStatusTruth holds `status` to the claim that its five per-harness
// states are DISTINCT and each reachable, by producing every one of them.
//
// Two are the machine as it stands (configured now; detected-unconfigured
// observed before the write, in the harness stage). The other three are
// produced here rather than asserted about:
//
//   - `revoked` from a grant the revocation stage really revoked, carried into
//     a COPY of this machine's state so nothing live is disturbed;
//   - `not_detected` by pointing detection at a home with no grok and a PATH
//     with no grok binary — the product's own inputs, not a test hook;
//   - `detected_unsupported` by putting a grok on PATH that reports a major
//     version this build never captured, which is the verdict's whole point.
//
// Nothing here touches the operator's grok installation.
func stageGrokStatusTruth(s *stage) {
	rep, _ := s.status()
	row, ok := grokRow(rep, "grok")
	if !s.assert("status carries a grok row alongside the other harnesses",
		ok && len(rep.Harnesses) >= 3, "%d harness row(s)", len(rep.Harnesses)) {
		return
	}
	s.assert("state 4/5 `configured`: the machine as it stands, with a live grant",
		row.State == "configured" && row.GrantID != "" && row.Version != "",
		"grok: state=%s grant=%s version=%s", row.State, row.GrantID, row.Version)
	s.assert("the configured row still names the compat source Homeplane cannot close",
		len(row.CompatSources) > 0, "compat_sources %v; detail %s", row.CompatSources, firstLine(row.Detail))

	// `detected_unconfigured` — a copy of this machine's state with grok's
	// configuration record removed. The DETECTION is real; only the memory of
	// having configured it is gone, which is exactly the state a machine is in
	// before its first run.
	if dir, err := copyStateDir(s, "grok-unconfigured"); err == nil {
		if err := dropHarnessRecord(dir, "grok"); err == nil {
			res := s.agent("homeplane-agent status with no grok configuration record", 2*time.Minute,
				"status", "-json", "-state-dir", dir)
			var alt statusReport
			_ = json.Unmarshal([]byte(res.full), &alt)
			r, _ := grokRow(alt, "grok")
			s.assert("state 2/5 `detected_unconfigured`: grok is here and Homeplane has not wired it",
				r.State == "detected_unconfigured" && r.Version != "",
				"grok: state=%s version=%s detail=%s", r.State, r.Version, firstLine(r.Detail))
		} else {
			s.assert("a state copy without grok's record could be produced", false, "%v", err)
		}
	} else {
		s.assert("a state copy could be made for the unconfigured mode", false, "%v", err)
	}

	// `revoked` — a real revoked grant, from the revocation stage, in a copy.
	revokedGrant := ""
	for _, g := range rep.Grants {
		if g.Harness == "grok" && g.State == "revoked" {
			revokedGrant = g.GrantID
		}
	}
	if revokedGrant == "" {
		s.assert("state 5/5 `revoked`: a revoked grok grant is available to reconcile against", false,
			"no revoked grok grant in the server's list — run the grok-revocation stage first")
	} else if dir, err := copyStateDir(s, "grok-revoked"); err == nil {
		if err := pointHarnessRecord(dir, "grok", revokedGrant); err == nil {
			res := s.agent("homeplane-agent status against a REVOKED grok grant", 2*time.Minute,
				"status", "-json", "-state-dir", dir)
			var alt statusReport
			_ = json.Unmarshal([]byte(res.full), &alt)
			r, _ := grokRow(alt, "grok")
			s.assert("state 5/5 `revoked`: a configuration whose grant the server no longer honours is not called configured",
				r.State == "revoked" && r.GrantID == revokedGrant,
				"grok: state=%s grant=%s (revoked server-side) detail=%s", r.State, r.GrantID, firstLine(r.Detail))
		} else {
			s.assert("a state copy pointing at the revoked grant could be produced", false, "%v", err)
		}
	}

	// `not_detected` — no grok binary on PATH, and a grok home with no
	// configuration in it.
	emptyHome := filepath.Join(s.t.TempDir(), "grok-home-absent")
	_ = os.MkdirAll(emptyHome, 0o700)
	bare := s.runWithEnv("homeplane-agent status on a machine without grok",
		map[string]string{"GROK_HOME": emptyHome, "PATH": "/usr/bin:/bin"}, 2*time.Minute,
		agentBin(), "status", "-json")
	var bareRep statusReport
	_ = json.Unmarshal([]byte(bare.full), &bareRep)
	r, _ := grokRow(bareRep, "grok")
	s.assert("state 1/5 `not_detected`: a machine without grok is reported as not having it, and is not a fault",
		r.State == "not_detected", "grok: state=%s detail=%s", r.State, firstLine(r.Detail))

	// `detected_unsupported` — a grok that answers `--version` with a major
	// release nobody captured. The stub is a shell script whose only job is to
	// print that line: the verdict is a version judgement, and it must gate
	// BEFORE any grant is issued.
	stubDir := filepath.Join(s.t.TempDir(), "stub-bin")
	_ = os.MkdirAll(stubDir, 0o755)
	stub := filepath.Join(stubDir, "grok")
	_ = os.WriteFile(stub, []byte("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'grok 2.0.0 (stub)'; exit 0; fi\nexit 127\n"), 0o755)
	drifted := s.runWithEnv("homeplane-agent status against a grok major version this build never captured",
		map[string]string{"GROK_HOME": emptyHome, "PATH": stubDir + ":/usr/bin:/bin"}, 2*time.Minute,
		agentBin(), "status", "-json")
	var driftedRep statusReport
	_ = json.Unmarshal([]byte(drifted.full), &driftedRep)
	r, _ = grokRow(driftedRep, "grok")
	s.assert("state 3/5 `detected_unsupported`: an unverified version is refused with the observed version and a reason",
		r.State == "detected_unsupported" && r.Version == "2.0.0" && r.Support == "unsupported" && r.Detail != "",
		"grok: state=%s version=%s support=%s detail=%s", r.State, r.Version, r.Support, firstLine(r.Detail))

	// And the five are genuinely five: no two of the states observed here
	// render the same.
	seen := map[string]bool{"configured": true, "detected_unconfigured": true, "not_detected": true,
		"detected_unsupported": true, "revoked": revokedGrant != ""}
	s.assert("the five states are distinct and each was produced on this machine, not described",
		len(seen) == 5 && seen["revoked"], "states produced: %v", sortedKeys(seen))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dropHarnessRecord removes one harness's configuration record from a COPY of
// the agent state, producing the state a machine is in before its first
// configure run. Detection still runs for real against the real machine — only
// the memory of having configured grok is gone.
func dropHarnessRecord(dir, harness string) error {
	path := filepath.Join(dir, "harnesses", harness+".json")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no %s record to remove in the state copy: %w", harness, err)
	}
	return os.Remove(path)
}

// pointHarnessRecord repoints one harness's record at another grant id, so the
// copy describes a machine whose configuration names a grant the server has
// revoked.
func pointHarnessRecord(dir, harness, grantID string) error {
	path := filepath.Join(dir, "harnesses", harness+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		return err
	}
	rec["grant_id"] = grantID
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// ── the audit review for grok's half of the run ─────────────────────────────

func stageGrokAudit(s *stage) {
	since := time.Now().UTC().Add(-6 * time.Hour)
	rows := s.audit("server audit: grok's half of the run", since)
	s.assert("the operator CLI reads the authoritative log", len(rows) > 0, "%d row(s)", len(rows))

	classes := map[string]int{}
	harnesses := map[string]int{}
	var grokRows []auditRow
	var unattributed, unidentified int
	for _, r := range rows {
		if r.Harness != "" {
			harnesses[r.Harness]++
		}
		if r.Harness != "grok" {
			continue
		}
		grokRows = append(grokRows, r)
		if r.ActionClass != "" {
			classes[r.ActionClass]++
		}
		if r.Event == "connector_tool_call" && (r.GrantID == "" || r.AuthMachineID == "") {
			unattributed++
		}
		// A result row for a mutation must name what it touched.
		if r.Event == "connector_tool_result" && r.Tool == "manage_event" &&
			r.Reason != "tool_failed" && !identified(r) {
			unidentified++
		}
	}
	s.assert("all three harnesses appear in the audit under their own names",
		harnesses["claude-code"] > 0 && harnesses["codex"] > 0 && harnesses["grok"] > 0,
		"claude-code %d, codex %d, grok %d rows", harnesses["claude-code"], harnesses["codex"], harnesses["grok"])
	s.assert("every connector call grok made is attributed to (machine, harness, grant)",
		len(grokRows) > 0 && unattributed == 0, "%d unattributed of %d grok row(s)", unattributed, len(grokRows))
	s.assert("grok's calendar mutations each name the event they acted on — never `unknown`",
		unidentified == 0, "%d unidentified manage_event result row(s)", unidentified)
	s.assert("grok exercised all three action classes and each was recorded",
		classes["read"] > 0 && classes["write"] > 0 && classes["delete"] > 0,
		"read %d, write %d, delete %d", classes["read"], classes["write"], classes["delete"])

	var denied int
	for _, r := range grokRows {
		if r.Outcome == "denied" {
			denied++
		}
	}
	s.assert("grok's refusals are recorded rather than dropped",
		denied > 0, "%d denied grok row(s)", denied)

	var payloadish int
	for _, r := range grokRows {
		for _, v := range r.Detail {
			if len(v) > 512 {
				payloadish++
			}
		}
	}
	s.assert("no grok audit row carries anything payload-sized (metadata only)", payloadish == 0,
		"%d oversized detail value(s) across %d grok rows", payloadish, len(grokRows))
}
