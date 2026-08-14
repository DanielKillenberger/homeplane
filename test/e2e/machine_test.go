//go:build live_e2e

package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The machine half of the walking skeleton, in the order a real machine takes
// it: install → enrol → vault → retrieval engine → skills → harnesses, and then
// the first capability proof that needs no server credential at all (R6).
//
// Every stage drives the INSTALLED agent, against the LIVE control plane, on
// this machine's real state directory. Nothing here is a fixture: the point of
// an end-to-end proof is that the artifacts a person would install are the ones
// that ran.

// statusReport mirrors internal/agent's status JSON.
type statusReport struct {
	Status      string `json:"status"`
	StateDir    string `json:"state_dir"`
	Enroled     bool   `json:"enroled"`
	ServerURL   string `json:"server_url"`
	MachineID   string `json:"machine_id"`
	MachineName string `json:"machine_name"`
	Components  []struct {
		Name   string `json:"name"`
		State  string `json:"state"`
		Detail string `json:"detail"`
	} `json:"components"`
	Grants []struct {
		GrantID      string   `json:"grant_id"`
		Harness      string   `json:"harness"`
		Capabilities []string `json:"capabilities"`
		State        string   `json:"state"`
		RevokedAt    string   `json:"revoked_at"`
	} `json:"grants"`
}

func (s *stage) status() (statusReport, result) {
	s.t.Helper()
	res := s.agent("homeplane-agent status -json", 90*time.Second, "status", "-json")
	var rep statusReport
	if err := json.Unmarshal([]byte(res.full), &rep); err != nil {
		s.t.Fatalf("status did not print JSON (exit %d): %v\n%s", res.ExitCode, err, res.Stdout)
	}
	return rep, res
}

func (s *stage) component(rep statusReport, name string) (string, string) {
	for _, c := range rep.Components {
		if c.Name == name {
			return c.State, c.Detail
		}
	}
	return "", ""
}

// stageInstall — R1. The staged, checksummed release-form artifacts are built
// and installed by the same one command a fresh machine runs; on a machine that
// already has Homeplane this is the idempotent refresh the criterion names.
func stageInstall(s *stage) {
	repo := repoRoot(s)

	if res := s.run("scripts/stage-release.sh (checksummed release-form artifacts)", 10*time.Minute,
		filepath.Join(repo, "scripts", "stage-release.sh"), filepath.Join(repo, "dist")); res.ExitCode != 0 {
		s.assert("release artifacts stage", false, "stage-release.sh exit %d: %s", res.ExitCode, res.Stderr)
		return
	}
	sums, err := os.ReadFile(filepath.Join(repo, "dist", "SHA256SUMS"))
	s.assert("the staged release carries a checksum manifest", err == nil && len(sums) > 0,
		"dist/SHA256SUMS: %d bytes", len(sums))

	res := s.run("./install.sh (one command, from the staged artifacts)", 15*time.Minute,
		filepath.Join(repo, "install.sh"), "--stage-dir", filepath.Join(repo, "dist"))
	if !s.assert("the installer completes on this machine", res.ExitCode == 0,
		"exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}

	ver := s.run("the INSTALLED agent runs", 30*time.Second, agentBin(), "version")
	s.assert("the installed agent reports its version", ver.ExitCode == 0 && strings.Contains(ver.Stdout, "homeplane-agent"),
		"%s", strings.TrimSpace(ver.Stdout))
}

// stageEnrol — R2. Enrolment over the tailnet, and the property that makes a
// re-run safe: the same machine record, a new credential, never a second
// identity.
func stageEnrol(s *stage) {
	since := time.Now().UTC().Add(-1 * time.Minute)

	res := s.agent("homeplane-agent enrol (against the live control plane)", 2*time.Minute,
		"enrol", "-server", s.env.serverURL, "-json")
	if !s.assert("enrolment succeeds over the tailnet", res.ExitCode == 0,
		"exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}
	rep, _ := s.status()
	first := rep.MachineID
	s.assert("the machine holds a server-issued identity", rep.Enroled && first != "",
		"machine_id %s, server %s", first, rep.ServerURL)

	// Re-enrolment is rotation, not a duplicate identity.
	again := s.agent("homeplane-agent enrol again (rotation, not a duplicate)", 2*time.Minute, "enrol", "-json")
	s.assert("re-enrolment succeeds", again.ExitCode == 0, "exit %d%s", again.ExitCode, tail(again.Stderr))
	rep2, _ := s.status()
	s.assert("re-enrolment preserves the machine identity", rep2.MachineID == first,
		"machine_id before %s, after %s", first, rep2.MachineID)

	rows := s.audit("server audit: enrolment rows", since)
	var enrolments int
	for _, r := range rows {
		if r.Event == "enrolment" && r.AuthMachineID == first {
			enrolments++
			s.assert("the enrolment is attributed to the observed tailnet node",
				r.ObservedNodeName != "" && r.ActorKind == "machine",
				"observed %s (%s), actor %s", r.ObservedNodeName, r.ObservedNodeID, r.ActorKind)
			break
		}
	}
	s.assert("the server recorded the enrolment", enrolments > 0, "%d enrolment row(s) for %s", enrolments, first)
}

// stageVault — R3. Detection only. Sync ACTIVATION is its own stage because it
// writes to a real vault that a desktop client may also be syncing, and that is
// a decision for the vault's owner rather than for this proof.
func stageVault(s *stage) {
	args := []string{"vault", "detect", "-record"}
	if s.env.vaultPath != "" {
		args = append(args, "-vault-path", s.env.vaultPath)
	}
	res := s.agent("homeplane-agent vault detect -record", 3*time.Minute, args...)
	if !s.assert("the agent finds the vault", res.ExitCode == 0, "exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}
	rep, _ := s.status()
	state, detail := s.component(rep, "vault")
	s.assert("status reports the vault", state == "ok", "vault: %s (%s)", state, detail)
	if s.env.vaultPath != "" {
		s.assert("the recorded vault is the real one", strings.Contains(detail, s.env.vaultPath),
			"detail %q names %s", detail, s.env.vaultPath)
	}
}

// stageGNO — R4 and the index contract of R14. The engine is installed,
// supervised and reachable, and its index is machine-local and disposable.
func stageGNO(s *stage) {
	res := s.agent("homeplane-agent gno activate", 20*time.Minute, "gno", "activate")
	if !s.assert("the retrieval engine activates against the vault", res.ExitCode == 0,
		"exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}
	// Activation INSTALLS the supervision unit; loading it into launchd/systemd
	// is a second, deliberate step (it needs a user session, which an installer
	// running under one process manager cannot assume it has). A machine whose
	// unit is installed but not loaded has an engine that answers stdio launches
	// and an index nobody keeps current — which is exactly what `status` says.
	apply := s.agent("homeplane-agent gno apply (load the supervision unit)", 3*time.Minute, "gno", "apply")
	s.assert("the supervision unit is loaded into the platform's process manager", apply.ExitCode == 0,
		"exit %d%s", apply.ExitCode, tail(apply.Stderr))

	ep := s.agent("homeplane-agent gno endpoint -json", 60*time.Second, "gno", "endpoint", "-json")
	var desc struct {
		Component  string `json:"component"`
		Transport  string `json:"transport"`
		Command    string `json:"command"`
		ServerName string `json:"server_name"`
		Engine     string `json:"engine"`
	}
	_ = json.Unmarshal([]byte(ep.full), &desc)
	s.assert("the endpoint descriptor is published", ep.ExitCode == 0 && desc.ServerName != "",
		"server_name %q transport %q engine %q", desc.ServerName, desc.Transport, desc.Engine)

	doctor := s.agent("homeplane-agent gno doctor -json", 5*time.Minute, "gno", "doctor", "-json")
	s.assert("the engine's own health report is green", doctor.ExitCode == 0,
		"exit %d: %s", doctor.ExitCode, firstLine(doctor.Stdout))

	rep, _ := s.status()
	state, detail := s.component(rep, "gno")
	s.assert("status reports the supervised engine", state == "ok", "gno: %s (%s)", state, detail)

	// The index is disposable and lives outside the vault — R14's other half.
	home, _ := os.UserHomeDir()
	indexRoot := filepath.Join(home, ".homeplane")
	s.assert("the index lives under the agent state dir, not in the vault",
		!strings.Contains(detail, s.env.vaultPath+"/.gno") && strings.HasPrefix(indexRoot, home),
		"state dir %s; vault %s", indexRoot, s.env.vaultPath)
}

// stageSkills — R15. The profile the vault carries, linked into both harnesses
// and proven by a FRESH process of each.
func stageSkills(s *stage) {
	res := s.agent("homeplane-agent skills provision -verify", 10*time.Minute, "skills", "provision", "-verify")
	if !s.assert("skills provision with fresh-process verification", res.ExitCode == 0,
		"exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}
	s.assert("a fresh process of each harness enumerated the linked skills",
		strings.Contains(res.Stdout, "claude-code") && strings.Contains(res.Stdout, "codex"),
		"%s", firstLine(res.Stdout))

	rep, _ := s.status()
	state, detail := s.component(rep, "skills")
	s.assert("status reports the provisioned skills", state == "ok", "skills: %s (%s)", state, detail)
}

// stageHarnesses — R5. Both harnesses are wired to both surfaces, each with its
// OWN grant, and the configuration that was already there survives.
func stageHarnesses(s *stage) {
	home, _ := os.UserHomeDir()
	claudeCfg := filepath.Join(home, ".claude.json")
	codexCfg := filepath.Join(home, ".codex", "config.toml")
	beforeClaude := fileFingerprint(s, claudeCfg)
	beforeCodex := fileFingerprint(s, codexCfg)

	res := s.agent("homeplane-agent configure-harnesses", 5*time.Minute, "configure-harnesses", "-json")
	if !s.assert("both harnesses are configured", res.ExitCode == 0,
		"exit %d%s", res.ExitCode, tail(res.Stderr)) {
		return
	}
	var report struct {
		Harnesses []struct {
			Harness      string   `json:"harness"`
			Status       string   `json:"status"`
			Installed    bool     `json:"installed"`
			Config       string   `json:"config_path"`
			Backup       string   `json:"backup_path"`
			Managed      []string `json:"managed_servers"`
			GrantID      string   `json:"grant_id"`
			EndpointURL  string   `json:"endpoint_url"`
			Capabilities []string `json:"capabilities"`
		} `json:"harnesses"`
	}
	_ = json.Unmarshal([]byte(res.full), &report)

	grants := map[string]string{}
	for _, h := range report.Harnesses {
		s.assert("harness "+h.Harness+" was configured", h.Status == "configured",
			"status %q config %s backup %s", h.Status, h.Config, h.Backup)
		// Both surfaces, or the harness is only half-wired: the local retrieval
		// engine and the server's connector endpoint.
		s.assert("harness "+h.Harness+" carries both Homeplane surfaces",
			len(h.Managed) == 2 && h.EndpointURL != "",
			"managed %v, endpoint %s", h.Managed, h.EndpointURL)
		if h.Backup != "" {
			_, err := os.Stat(h.Backup)
			s.assert("a timestamped backup precedes the write to "+h.Harness, err == nil, "%s", h.Backup)
		}
		grants[h.Harness] = h.GrantID
	}

	// Two harnesses, two distinct grants — the whole revocation story rests on it.
	rep, _ := s.status()
	active := map[string]string{}
	for _, g := range rep.Grants {
		if g.State == "active" {
			active[g.Harness] = g.GrantID
		}
	}
	s.assert("each harness holds its own active grant",
		len(active) >= 2 && active["claude-code"] != "" && active["codex"] != "" &&
			active["claude-code"] != active["codex"],
		"claude-code %s, codex %s", active["claude-code"], active["codex"])

	// Token hygiene: the files carrying a bearer token are user-scoped and 0600.
	for _, p := range []string{claudeCfg, codexCfg} {
		if info, err := os.Stat(p); err == nil {
			s.assert("the harness config is 0600 ("+filepath.Base(p)+")", info.Mode().Perm() == 0o600,
				"%s mode %o", p, info.Mode().Perm())
		}
	}
	// Nothing project-scoped: a grant token in a git-shared file is the failure
	// this criterion exists to prevent.
	proj := s.run("look for a project-scoped MCP config in the repo", 30*time.Second,
		"git", "-C", repoRoot(s), "ls-files", ".mcp.json")
	s.assert("no grant token landed in a git-shared config", strings.TrimSpace(proj.Stdout) == "",
		"git ls-files .mcp.json → %q", strings.TrimSpace(proj.Stdout))

	// The configuration is only worth something if the harness can USE it. A
	// fresh Claude Code process is asked to open a live MCP session against both
	// written entries — which authenticates the connector token against the edge
	// over the tailnet and launches the local engine — before any model turn is
	// involved.
	live := s.run("a fresh Claude Code process opens both Homeplane MCP sessions", 3*time.Minute,
		"claude", "mcp", "list")
	s.assert("Claude Code connects to both Homeplane MCP servers as configured",
		live.ExitCode == 0 &&
			strings.Contains(live.full, "homeplane: "+s.env.serverURL+"/mcp") &&
			strings.Contains(live.full, "gno:") &&
			!strings.Contains(live.full, "Failed to connect"),
		"%s", firstLine(strings.TrimSpace(live.Stdout)))

	afterClaude := fileFingerprint(s, claudeCfg)
	afterCodex := fileFingerprint(s, codexCfg)
	s.assert("Daniel's harness configs changed only where Homeplane manages them",
		afterClaude != "" && afterCodex != "",
		"claude.json %s → %s; codex config.toml %s → %s",
		beforeClaude, afterClaude, beforeCodex, afterCodex)
}

// stageGNORetrieval — R6. A FRESH process of each harness reaches the local
// retrieval engine over MCP and comes back with real vault content.
func stageGNORetrieval(s *stage) {
	const needle = "homeplane"
	prompt := "Use the gno MCP server to search the vault for \"" + needle + "\". " +
		"Call exactly one search tool, then reply with the first result's file path and nothing else."

	out := s.claude("Claude Code → local retrieval engine", prompt, "mcp__gno")
	s.assert("Claude Code retrieves real vault content through the local engine",
		out.ok && looksLikeVaultHit(out.text, s.env.vaultPath),
		"%s", firstLine(out.text))

	cout := s.codex("Codex → local retrieval engine", prompt)
	s.assert("Codex retrieves real vault content through the local engine",
		cout.ok && looksLikeVaultHit(cout.text, s.env.vaultPath),
		"%s", firstLine(cout.text))
}

// looksLikeVaultHit is deliberately weak about FORM and strict about SOURCE: a
// harness may phrase an answer any way it likes, but a path inside the vault
// cannot be produced without having read the vault.
func looksLikeVaultHit(text, vault string) bool {
	if text == "" {
		return false
	}
	if vault != "" && strings.Contains(text, vault) {
		return true
	}
	return strings.Contains(text, ".md")
}

func fileFingerprint(s *stage, path string) string {
	s.t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339) + " " + strconv.FormatInt(info.Size(), 10)
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 300 {
		line = line[:300] + "…"
	}
	return line
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 600 {
		s = "…" + s[len(s)-600:]
	}
	return ": " + s
}
