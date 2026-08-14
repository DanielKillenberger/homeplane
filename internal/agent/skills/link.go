package skills

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EnvClaudeConfigDir and EnvCodexHome are the harnesses' own overrides for the
// directory their skills live under. Both were verified against the installed
// CLIs: with CLAUDE_CONFIG_DIR set, Claude Code enumerates
// $CLAUDE_CONFIG_DIR/skills and IGNORES ~/.claude/skills; Codex enumerates
// $CODEX_HOME/skills. Honouring them is not politeness — writing to the wrong
// directory would provision a harness nobody runs.
const (
	EnvClaudeConfigDir = "CLAUDE_CONFIG_DIR"
	EnvCodexHome       = "CODEX_HOME"
)

// Locator resolves each harness's skills directory. Every field is a seam, so
// the whole linker suite runs against fixture directories rather than against
// the operator's real harnesses.
type Locator struct {
	// Home is the user's home directory. Empty means ask the OS.
	Home string
	// ClaudeConfigDir overrides Claude Code's configuration directory. Empty
	// means read EnvClaudeConfigDir, then fall back to <Home>/.claude.
	ClaudeConfigDir string
	// CodexHome overrides Codex's configuration directory. Empty means read
	// EnvCodexHome, then fall back to <Home>/.codex.
	CodexHome string
}

func (l Locator) home() (string, error) {
	if l.Home != "" {
		return l.Home, nil
	}
	return os.UserHomeDir()
}

// SkillsDir is the directory a harness enumerates skills from.
func (l Locator) SkillsDir(harnessID string) (string, error) {
	switch harnessID {
	case ClaudeCode:
		dir := strings.TrimSpace(l.ClaudeConfigDir)
		if dir == "" {
			dir = strings.TrimSpace(os.Getenv(EnvClaudeConfigDir))
		}
		if dir == "" {
			home, err := l.home()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".claude")
		}
		return filepath.Join(dir, "skills"), nil
	case Codex:
		dir := strings.TrimSpace(l.CodexHome)
		if dir == "" {
			dir = strings.TrimSpace(os.Getenv(EnvCodexHome))
		}
		if dir == "" {
			home, err := l.home()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".codex")
		}
		return filepath.Join(dir, "skills"), nil
	default:
		return "", fmt.Errorf("skills: unknown harness %q (known: %s)", harnessID, strings.Join(Known(), ", "))
	}
}

// Link actions, as reported per skill.
const (
	ActionLinked    = "linked"    // a new symlink was created
	ActionUnchanged = "unchanged" // our link was already correct
	ActionRepointed = "repointed" // our link pointed elsewhere and was moved
	ActionRemoved   = "removed"   // our link was withdrawn (refresh)
	ActionSkipped   = "skipped"   // something else owns the entry, or the skill is not linkable
)

// LinkResult is what happened to one (harness, skill) pair.
type LinkResult struct {
	Harness string `json:"harness"`
	Slug    string `json:"slug"`
	Action  string `json:"action"`
	// LinkPath is the entry inside the harness's skills directory.
	LinkPath string `json:"link_path"`
	// Target is the vault directory it points at.
	Target string `json:"target,omitempty"`
	// Reason explains a skip, and is empty otherwise.
	Reason string `json:"reason,omitempty"`
	// Rule names the discovery rule behind a skip, when there was one.
	Rule string `json:"rule,omitempty"`
}

// Skipped reports whether this pair was not provisioned.
func (r LinkResult) Skipped() bool { return r.Action == ActionSkipped }

// HarnessReport is one harness's provisioning outcome.
type HarnessReport struct {
	Harness   string       `json:"harness"`
	SkillsDir string       `json:"skills_dir"`
	Results   []LinkResult `json:"results"`
	// Verified lists the skills a FRESH harness process enumerated, when
	// verification ran. Empty means verification did not run.
	Verified []string `json:"verified,omitempty"`
	// VerifyError records why verification could not run or did not pass.
	VerifyError string `json:"verify_error,omitempty"`
}

// Report is a whole provisioning run.
type Report struct {
	Profile     string          `json:"profile"`
	ProfilePath string          `json:"profile_path"`
	Machine     string          `json:"machine"`
	VaultSkills string          `json:"vault_skills_root"`
	Harnesses   []HarnessReport `json:"harnesses"`
	// Findings are the discovery verdicts for every candidate that is not
	// linkable — carried into the report so an unsupported or rejected skill is
	// surfaced rather than silently missing (R15).
	Findings []Finding `json:"findings"`
}

// ManifestSchemaVersion is the ownership record's schema.
const ManifestSchemaVersion = 1

// ManifestFileName is the ownership record inside the agent state directory.
//
// It lives in Homeplane's state, NOT in the harness's skills directory: the
// harness enumerates that directory, and a bookkeeping file there is a file the
// harness has to be trusted to ignore.
const ManifestFileName = "skill-links.json"

// ManifestEntry is one link Homeplane created and is therefore allowed to
// change or withdraw. Anything not in this list belongs to somebody else.
type ManifestEntry struct {
	Harness  string    `json:"harness"`
	Slug     string    `json:"slug"`
	LinkPath string    `json:"link_path"`
	Target   string    `json:"target"`
	LinkedAt time.Time `json:"linked_at"`
}

// Manifest is the ownership record.
type Manifest struct {
	SchemaVersion int             `json:"schema_version"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Profile       string          `json:"profile,omitempty"`
	Links         []ManifestEntry `json:"links"`
}

// ManifestPath is the ownership record's path inside a state directory.
func ManifestPath(stateDir string) string {
	return filepath.Join(stateDir, "skills", ManifestFileName)
}

// LoadManifest reads the ownership record. A missing file is an empty manifest,
// not an error: a machine that has never provisioned owns nothing.
func LoadManifest(stateDir string) (Manifest, error) {
	path := ManifestPath(stateDir)
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{SchemaVersion: ManifestSchemaVersion}, nil
	}
	if err != nil {
		return Manifest{}, fmt.Errorf("skills: manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("skills: manifest %s: %w", path, err)
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		return Manifest{}, fmt.Errorf("skills: manifest %s: schema %d is not supported (this agent reads schema %d)", path, m.SchemaVersion, ManifestSchemaVersion)
	}
	return m, nil
}

// SaveManifest writes the ownership record atomically.
func SaveManifest(stateDir string, m Manifest) error {
	m.SchemaVersion = ManifestSchemaVersion
	m.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	sort.Slice(m.Links, func(i, j int) bool {
		if m.Links[i].Harness != m.Links[j].Harness {
			return m.Links[i].Harness < m.Links[j].Harness
		}
		return m.Links[i].Slug < m.Links[j].Slug
	})
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("skills: manifest: %w", err)
	}
	raw = append(raw, '\n')

	path := ManifestPath(stateDir)
	if err := os.MkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("skills: manifest: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".skill-links-*.tmp")
	if err != nil {
		return fmt.Errorf("skills: manifest: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("skills: manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("skills: manifest: %w", err)
	}
	if err := os.Chmod(tmpName, filePerm); err != nil {
		return fmt.Errorf("skills: manifest: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("skills: manifest: %w", err)
	}
	return nil
}

// owns reports whether Homeplane may change or withdraw this entry.
//
// Being in the manifest is NOT sufficient. Ownership is the manifest record AND
// the link still pointing where the record says it points: if the operator
// repointed or replaced our link with one of their own, it is theirs now, and
// removing it would be exactly the silent clobber the preservation rule
// forbids. A vault MOVE stays distinguishable — there the link still points at
// the recorded (old) target, so it is still ours to repoint.
func (m Manifest) owns(harnessID, linkPath string) (ManifestEntry, bool) {
	for _, e := range m.Links {
		if e.Harness != harnessID || e.LinkPath != linkPath {
			continue
		}
		current, err := os.Readlink(linkPath)
		if err != nil || current != e.Target {
			return e, false
		}
		return e, true
	}
	return ManifestEntry{}, false
}

// recorded reports whether the manifest claims this entry at all, regardless of
// where it currently points. It is how drift is told apart from a stranger's
// entry that was never ours.
// InstalledSlugs is every skill this machine currently has provisioned,
// according to the ownership manifest.
//
// It is deliberately read from the manifest and not from a run's report: the
// report describes ONE run — which may have been narrowed to a single harness,
// or may have deliberately left links it no longer assigns — while the manifest
// describes the machine. Status must describe the machine.
func InstalledSlugs(stateDir string) ([]string, error) {
	m, err := LoadManifest(stateDir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(m.Links))
	for _, e := range m.Links {
		if !seen[e.Slug] {
			seen[e.Slug] = true
			out = append(out, e.Slug)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m Manifest) recorded(harnessID, linkPath string) (ManifestEntry, bool) {
	for _, e := range m.Links {
		if e.Harness == harnessID && e.LinkPath == linkPath {
			return e, true
		}
	}
	return ManifestEntry{}, false
}

func (m *Manifest) record(e ManifestEntry) {
	for i, existing := range m.Links {
		if existing.Harness == e.Harness && existing.LinkPath == e.LinkPath {
			m.Links[i] = e
			return
		}
	}
	m.Links = append(m.Links, e)
}

func (m *Manifest) forget(harnessID, linkPath string) {
	out := m.Links[:0]
	for _, e := range m.Links {
		if e.Harness == harnessID && e.LinkPath == linkPath {
			continue
		}
		out = append(out, e)
	}
	m.Links = out
}

// Provisioner links a profile's skills into the harnesses on this machine.
type Provisioner struct {
	// Locator resolves each harness's skills directory.
	Locator Locator
	// StateDir is the agent state directory holding the ownership manifest.
	StateDir string
	// Machine is this machine's name, used to resolve per-machine profile
	// blocks. Empty means the profile's machine blocks never match.
	Machine string
	// Harnesses restricts the run. Empty means every known harness.
	Harnesses []string
	// Prune withdraws links Homeplane owns that the profile no longer assigns,
	// or whose vault skill has gone. This is `skills refresh`; provisioning
	// alone never removes anything.
	Prune bool
	// Lock serialises the whole run. It is the agent state lock
	// (`agent.Store.Lock`), the same one the harness configurator holds, and it
	// is not optional in production: the manifest is a read-modify-write, so
	// two concurrent runs without it lose each other's records. Nil is the test
	// seam, and nil in a real command is a bug.
	Lock func() (func(), error)
}

// Provision links every assigned, linkable skill and returns what it did.
//
// It is idempotent: a second run over an unchanged vault and profile reports
// every skill "unchanged" and writes no link.
//
// Two orderings are load-bearing, and both are about the manifest being the
// only thing that says which links are ours.
//
//   - The whole run is held under the agent state lock, because it is a
//     read-modify-write of the manifest. Without it, two `skills provision`
//     processes both load the same manifest and the loser's save erases the
//     winner's links from the record — leaving real links on disk that nothing
//     claims, which `refresh` can then never withdraw and a later run reads as
//     a stranger's entry.
//
//   - Every filesystem mutation is recorded BEFORE the next one is attempted,
//     and the manifest's writability is proven BEFORE the first link is made.
//     Saving once at the end meant any later failure — a second harness's
//     directory, an unwritable state directory — left links created and
//     unrecorded. The cost is one small atomic write per changed link, which is
//     nothing beside an untracked link in an operator's harness.
func (p Provisioner) Provision(cat Catalog, profile Profile) (Report, error) {
	targets := p.Harnesses
	if len(targets) == 0 {
		targets = Known()
	}
	for _, h := range targets {
		if _, err := p.Locator.SkillsDir(h); err != nil {
			return Report{}, err
		}
	}
	if strings.TrimSpace(p.StateDir) == "" {
		return Report{}, errors.New("skills: provision: empty state directory")
	}

	if p.Lock != nil {
		release, err := p.Lock()
		if err != nil {
			return Report{}, fmt.Errorf("skills: provision: %w", err)
		}
		defer release()
	}

	manifest, err := LoadManifest(p.StateDir)
	if err != nil {
		return Report{}, err
	}
	manifest.Profile = profile.Name

	// Preflight: prove the manifest can be written before anything on disk
	// changes. A state directory that cannot hold the record is a run that must
	// not create links.
	if err := SaveManifest(p.StateDir, manifest); err != nil {
		return Report{}, err
	}
	save := func() error { return SaveManifest(p.StateDir, manifest) }

	report := Report{
		Profile:     profile.Name,
		ProfilePath: profile.Path,
		Machine:     p.Machine,
		VaultSkills: cat.Root,
		Findings:    cat.Findings,
	}

	for _, harnessID := range targets {
		dir, err := p.Locator.SkillsDir(harnessID)
		if err != nil {
			return Report{}, err
		}
		hr := HarnessReport{Harness: harnessID, SkillsDir: dir}
		assigned := profile.Assign(p.Machine, harnessID)

		if len(assigned) > 0 {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return Report{}, fmt.Errorf("skills: provision %s: %w", harnessID, err)
			}
		}

		wanted := make(map[string]bool, len(assigned))
		for _, slug := range assigned {
			linkPath := filepath.Join(dir, slug)

			// The profile's own per-harness marking is checked FIRST and beats
			// every assignment: a skill named in both `[defaults]` and
			// `[unsupported]` is refused, never linked (R15).
			if reason, blocked := profile.UnsupportedOn(slug, harnessID); blocked {
				hr.Results = append(hr.Results, LinkResult{
					Harness: harnessID, Slug: slug, Action: ActionSkipped, LinkPath: linkPath,
					Rule: RuleProfileUnsupported, Reason: reason,
				})
				continue
			}

			skill, ok := cat.Lookup(slug)
			if !ok {
				res := LinkResult{Harness: harnessID, Slug: slug, Action: ActionSkipped, LinkPath: linkPath}
				if f, found := cat.Finding(slug); found {
					res.Reason = f.Reason
					res.Rule = f.Rule
				} else {
					res.Reason = "the profile assigns this skill, but the vault has no such skill"
					res.Rule = RuleNoSkillMD
				}
				hr.Results = append(hr.Results, res)
				continue
			}
			wanted[linkPath] = true
			res, changed := p.link(&manifest, harnessID, skill, linkPath)
			if changed {
				if err := save(); err != nil {
					return Report{}, err
				}
			}
			hr.Results = append(hr.Results, res)
		}

		if p.Prune {
			pruned, changed, err := p.prune(&manifest, harnessID, dir, wanted, cat, save)
			if err != nil {
				return Report{}, err
			}
			_ = changed
			hr.Results = append(hr.Results, pruned...)
		}

		sort.Slice(hr.Results, func(i, j int) bool { return hr.Results[i].Slug < hr.Results[j].Slug })
		report.Harnesses = append(report.Harnesses, hr)
	}

	if err := save(); err != nil {
		return Report{}, err
	}
	return report, nil
}

// link creates, confirms or repoints one entry. It never removes something it
// does not own, and never replaces a real directory: an operator's own skill of
// the same name wins, and is reported.
// It reports whether it CHANGED anything, so the caller records the change
// before attempting the next one.
func (p Provisioner) link(manifest *Manifest, harnessID string, skill Skill, linkPath string) (LinkResult, bool) {
	res := LinkResult{Harness: harnessID, Slug: skill.Slug, LinkPath: linkPath, Target: skill.Dir}

	info, err := os.Lstat(linkPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Symlink(skill.Dir, linkPath); err != nil {
			res.Action = ActionSkipped
			res.Reason = "could not create the link: " + err.Error()
			return res, false
		}
		manifest.record(ManifestEntry{Harness: harnessID, Slug: skill.Slug, LinkPath: linkPath, Target: skill.Dir, LinkedAt: time.Now().UTC().Truncate(time.Second)})
		res.Action = ActionLinked
		return res, true

	case err != nil:
		res.Action = ActionSkipped
		res.Reason = "could not inspect the existing entry: " + err.Error()
		return res, false

	case info.Mode()&fs.ModeSymlink != 0:
		owned, isOurs := manifest.owns(harnessID, linkPath)
		current, readErr := os.Readlink(linkPath)
		if !isOurs {
			res.Action = ActionSkipped
			if claimed, wasOurs := manifest.recorded(harnessID, linkPath); wasOurs {
				// We made this link once and somebody moved it. That is a
				// takeover, not a stale link of ours: repointing it would undo
				// a deliberate change the operator made.
				res.Reason = fmt.Sprintf("this link was Homeplane's but now points at %s instead of the recorded %s; it was taken over and left untouched", current, claimed.Target)
			} else {
				res.Reason = "an existing entry Homeplane did not create is already here; it was left untouched"
			}
			return res, false
		}
		if readErr == nil && current == skill.Dir {
			// Re-record: the target is right, but the manifest may predate a
			// profile rename.
			manifest.record(ManifestEntry{Harness: harnessID, Slug: skill.Slug, LinkPath: linkPath, Target: skill.Dir, LinkedAt: owned.LinkedAt})
			res.Action = ActionUnchanged
			return res, false
		}
		// Still pointing where we recorded, but the vault moved: ours to repoint.
		if err := os.Remove(linkPath); err != nil {
			res.Action = ActionSkipped
			res.Reason = "could not replace our stale link: " + err.Error()
			return res, false
		}
		if err := os.Symlink(skill.Dir, linkPath); err != nil {
			manifest.forget(harnessID, linkPath)
			res.Action = ActionSkipped
			res.Reason = "could not recreate the link: " + err.Error()
			return res, true
		}
		manifest.record(ManifestEntry{Harness: harnessID, Slug: skill.Slug, LinkPath: linkPath, Target: skill.Dir, LinkedAt: time.Now().UTC().Truncate(time.Second)})
		res.Action = ActionRepointed
		return res, true

	default:
		res.Action = ActionSkipped
		res.Reason = "a real file or directory is already here; Homeplane links, and never replaces an operator's own skill"
		return res, false
	}
}

// prune withdraws links we own that the profile no longer wants, or whose vault
// skill is gone.
//
// "Own" is the strict sense: recorded in the manifest AND still pointing where
// the record says. A recorded entry that now points somewhere else has been
// taken over by the operator and is reported as drift rather than removed —
// removing it would delete something Homeplane no longer owns, which is the
// preservation rule's whole point.
func (p Provisioner) prune(manifest *Manifest, harnessID, dir string, wanted map[string]bool, cat Catalog, save func() error) ([]LinkResult, bool, error) {
	var out []LinkResult
	changed := false
	var stale []ManifestEntry
	for _, e := range manifest.Links {
		if e.Harness != harnessID || wanted[e.LinkPath] {
			continue
		}
		if filepath.Dir(e.LinkPath) != dir {
			// The harness's skills directory moved (CODEX_HOME changed). The
			// old link is not ours to reason about from here.
			continue
		}
		stale = append(stale, e)
	}
	for _, e := range stale {
		res := LinkResult{Harness: harnessID, Slug: e.Slug, LinkPath: e.LinkPath, Target: e.Target}
		mutated := false
		info, err := os.Lstat(e.LinkPath)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			manifest.forget(harnessID, e.LinkPath)
			mutated = true
			res.Action = ActionRemoved
			res.Reason = "the link was already gone; the record was dropped"
		case err != nil:
			res.Action = ActionSkipped
			res.Reason = "could not inspect the recorded link: " + err.Error()
		case info.Mode()&fs.ModeSymlink == 0:
			res.Action = ActionSkipped
			res.Reason = "the recorded entry is no longer a link; it was left untouched"
		default:
			if _, isOurs := manifest.owns(harnessID, e.LinkPath); !isOurs {
				current, _ := os.Readlink(e.LinkPath)
				res.Action = ActionSkipped
				res.Reason = fmt.Sprintf("this link now points at %s instead of the recorded %s; it was taken over and left untouched", current, e.Target)
				break
			}
			if err := os.Remove(e.LinkPath); err != nil {
				res.Action = ActionSkipped
				res.Reason = "could not remove our link: " + err.Error()
			} else {
				manifest.forget(harnessID, e.LinkPath)
				mutated = true
				res.Action = ActionRemoved
				if _, ok := cat.Lookup(e.Slug); !ok {
					res.Reason = "the skill is no longer discoverable in the vault"
				} else {
					res.Reason = "the profile no longer assigns this skill to this harness"
				}
			}
		}
		if mutated {
			changed = true
			if err := save(); err != nil {
				return nil, changed, err
			}
		}
		out = append(out, res)
	}
	return out, changed, nil
}

// Canonical reports where a provisioned entry actually leads, and whether the
// harness holds an independent copy.
//
// This is the R15 "no independent editable copies" check, made from the
// filesystem rather than from our own record: the entry must be a symlink, it
// must resolve into the vault, and the SKILL.md the harness reads must be the
// SAME FILE as the vault's — same device and inode, not merely equal bytes.
type Canonical struct {
	LinkPath string `json:"link_path"`
	// IsSymlink reports whether the harness entry is a link rather than a copy.
	IsSymlink bool `json:"is_symlink"`
	// Resolved is the entry's canonical location.
	Resolved string `json:"resolved"`
	// SameFile reports whether <entry>/SKILL.md and the vault's SKILL.md are
	// one file.
	SameFile bool `json:"same_file"`
	// InVault reports whether Resolved is inside the vault skills root.
	InVault bool `json:"in_vault"`
}

// Inspect performs the canonical-location check for one provisioned skill.
func Inspect(linkPath string, skill Skill, vaultRoot string) (Canonical, error) {
	c := Canonical{LinkPath: linkPath}
	info, err := os.Lstat(linkPath)
	if err != nil {
		return c, fmt.Errorf("skills: inspect %s: %w", linkPath, err)
	}
	c.IsSymlink = info.Mode()&fs.ModeSymlink != 0

	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return c, fmt.Errorf("skills: inspect %s: %w", linkPath, err)
	}
	c.Resolved = resolved
	c.InVault = within(vaultRoot, resolved)

	linkedMD, err := os.Stat(filepath.Join(linkPath, "SKILL.md"))
	if err != nil {
		return c, fmt.Errorf("skills: inspect %s: %w", linkPath, err)
	}
	vaultMD, err := os.Stat(skill.SkillMD)
	if err != nil {
		return c, fmt.Errorf("skills: inspect %s: %w", skill.SkillMD, err)
	}
	c.SameFile = os.SameFile(linkedMD, vaultMD)
	return c, nil
}
