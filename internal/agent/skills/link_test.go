package skills

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture is a whole machine: a vault, a state directory, and a fixture home
// holding both harnesses' skill directories. Nothing here touches the
// operator's real vault or harnesses.
type fixture struct {
	vaultSkills string
	stateDir    string
	home        string
	locator     Locator
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	f := &fixture{
		vaultSkills: filepath.Join(base, "vault", "skills"),
		stateDir:    filepath.Join(base, "state"),
		home:        filepath.Join(base, "home"),
	}
	for _, d := range []string{f.vaultSkills, f.stateDir, f.home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.locator = Locator{
		ClaudeConfigDir: filepath.Join(f.home, ".claude"),
		CodexHome:       filepath.Join(f.home, ".codex"),
		GrokHome:        filepath.Join(f.home, ".grok"),
	}
	return f
}

func (f *fixture) skillsDir(t *testing.T, harnessID string) string {
	t.Helper()
	dir, err := f.locator.SkillsDir(harnessID)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func (f *fixture) provisioner() Provisioner {
	return Provisioner{Locator: f.locator, StateDir: f.stateDir, Machine: "studio"}
}

func (f *fixture) catalog(t *testing.T) Catalog {
	t.Helper()
	return discover(t, f.vaultSkills)
}

func (f *fixture) profile(t *testing.T, body string) Profile {
	t.Helper()
	path := filepath.Join(f.vaultSkills, ProfileFileName)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	return p
}

func resultFor(t *testing.T, report Report, harnessID, slug string) LinkResult {
	t.Helper()
	for _, hr := range report.Harnesses {
		if hr.Harness != harnessID {
			continue
		}
		for _, r := range hr.Results {
			if r.Slug == slug {
				return r
			}
		}
	}
	t.Fatalf("no result for %s/%s in %+v", harnessID, slug, report.Harnesses)
	return LinkResult{}
}

// The whole point of R15: the harness reads the vault's file, not a copy of it.
func TestProvisionLinksIntoBothHarnessesWithoutCopying(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Lead with the point.")
	cat := f.catalog(t)
	profile := f.profile(t, skeletonProfileFor("professional-writing"))

	report, err := f.provisioner().Provision(cat, profile)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	skill, _ := cat.Lookup("professional-writing")
	for _, h := range Known() {
		res := resultFor(t, report, h, "professional-writing")
		if res.Action != ActionLinked {
			t.Fatalf("%s action = %s (%s), want linked", h, res.Action, res.Reason)
		}
		c, err := Inspect(res.LinkPath, skill, cat.Root)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if !c.IsSymlink {
			t.Fatalf("%s entry is not a symlink; a copy is an independent original", h)
		}
		if !c.InVault {
			t.Fatalf("%s entry resolves to %s, outside the vault", h, c.Resolved)
		}
		if !c.SameFile {
			t.Fatalf("%s SKILL.md is not the same file as the vault's", h)
		}
	}
}

func skeletonProfileFor(slugs ...string) string {
	quoted := make([]string, 0, len(slugs))
	for _, s := range slugs {
		quoted = append(quoted, `"`+s+`"`)
	}
	return "schema = 1\nprofile = \"test\"\n\n[defaults]\nskills = [" + strings.Join(quoted, ", ") + "]\n"
}

// An edit in the vault is visible through the link with no re-provisioning:
// that is what "one original" buys.
func TestLinkedSkillTracksVaultEdits(t *testing.T) {
	f := newFixture(t)
	dir := writeSkill(t, f.vaultSkills, "casual-writing", "First revision.")
	cat := f.catalog(t)
	report, err := f.provisioner().Provision(cat, f.profile(t, skeletonProfileFor("casual-writing")))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	res := resultFor(t, report, ClaudeCode, "casual-writing")

	updated := "---\nname: casual-writing\ndescription: d\n---\n\nSecond revision.\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(res.LinkPath, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Second revision") {
		t.Fatal("the harness still reads the old text; the link is not tracking the vault")
	}
}

func TestProvisionIsIdempotent(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "karpathy-guidelines", "Small things.")
	cat := f.catalog(t)
	profile := f.profile(t, skeletonProfileFor("karpathy-guidelines"))

	if _, err := f.provisioner().Provision(cat, profile); err != nil {
		t.Fatalf("first Provision: %v", err)
	}
	report, err := f.provisioner().Provision(cat, profile)
	if err != nil {
		t.Fatalf("second Provision: %v", err)
	}
	for _, h := range Known() {
		if got := resultFor(t, report, h, "karpathy-guidelines").Action; got != ActionUnchanged {
			t.Fatalf("%s second run = %s, want unchanged", h, got)
		}
	}
}

// The preservation rule, and the one that matters most: an entry Homeplane did
// not create is never touched, whatever its name.
func TestProvisionNeverTouchesAnEntryItDoesNotOwn(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, linkPath string)
		check func(t *testing.T, linkPath string)
	}{
		{
			name: "operator's own directory",
			setup: func(t *testing.T, linkPath string) {
				if err := os.MkdirAll(linkPath, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(linkPath, "SKILL.md"), []byte("mine\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			check: func(t *testing.T, linkPath string) {
				got, err := os.ReadFile(filepath.Join(linkPath, "SKILL.md"))
				if err != nil || string(got) != "mine\n" {
					t.Fatalf("the operator's own skill was modified: %q, %v", got, err)
				}
			},
		},
		{
			name: "somebody else's symlink",
			setup: func(t *testing.T, linkPath string) {
				elsewhere := filepath.Join(t.TempDir(), "theirs")
				if err := os.MkdirAll(elsewhere, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(elsewhere, linkPath); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			check: func(t *testing.T, linkPath string) {
				target, err := os.Readlink(linkPath)
				if err != nil || !strings.HasSuffix(target, "theirs") {
					t.Fatalf("somebody else's link was repointed to %q (%v)", target, err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
			dir := f.skillsDir(t, ClaudeCode)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			linkPath := filepath.Join(dir, "professional-writing")
			tc.setup(t, linkPath)

			report, err := f.provisioner().Provision(f.catalog(t), f.profile(t, skeletonProfileFor("professional-writing")))
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			res := resultFor(t, report, ClaudeCode, "professional-writing")
			if res.Action != ActionSkipped {
				t.Fatalf("action = %s, want skipped", res.Action)
			}
			if res.Reason == "" {
				t.Fatal("a skip must say why")
			}
			tc.check(t, linkPath)
		})
	}
}

// Unrelated entries in the same directory are left exactly as they were: the
// same discipline R5 applies to harness config files, at directory granularity.
func TestProvisionPreservesUnrelatedEntries(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
	dir := f.skillsDir(t, Codex)
	if err := os.MkdirAll(filepath.Join(dir, "their-skill"), 0o755); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(dir, "their-skill", "SKILL.md")
	if err := os.WriteFile(theirs, []byte("theirs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(theirs)
	if err != nil {
		t.Fatal(err)
	}

	p := f.provisioner()
	p.Prune = true
	if _, err := p.Provision(f.catalog(t), f.profile(t, skeletonProfileFor("professional-writing"))); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	after, err := os.Stat(theirs)
	if err != nil {
		t.Fatalf("an unrelated skill disappeared: %v", err)
	}
	if !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		t.Fatal("an unrelated skill was rewritten")
	}
}

// A profile that assigns an unsupported or rejected skill gets a reasoned skip
// carrying the discovery rule — never a silent link (R15).
func TestProvisionSurfacesUnsupportedAndRejected(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, filepath.Join(f.vaultSkills, "hermes"), "daily-brief", "Nested.")
	leaky := writeSkill(t, f.vaultSkills, "leaky", "Ordinary.")
	if err := os.WriteFile(filepath.Join(leaky, ".env"), []byte("TOKEN=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := f.provisioner().Provision(f.catalog(t), f.profile(t, skeletonProfileFor("hermes", "leaky", "ghost")))
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}

	want := map[string]string{"hermes": RuleNoSkillMD, "leaky": RuleCredential, "ghost": RuleNoSkillMD}
	for slug, rule := range want {
		res := resultFor(t, report, ClaudeCode, slug)
		if res.Action != ActionSkipped {
			t.Fatalf("%s action = %s, want skipped", slug, res.Action)
		}
		if res.Rule != rule {
			t.Fatalf("%s rule = %s, want %s", slug, res.Rule, rule)
		}
		if res.Reason == "" {
			t.Fatalf("%s skip carries no reason", slug)
		}
		if _, err := os.Lstat(res.LinkPath); err == nil {
			t.Fatalf("%s was linked despite being %s", slug, rule)
		}
	}
	if len(report.Findings) == 0 {
		t.Fatal("the report must carry the discovery findings")
	}
}

// Refresh withdraws our own links and only our own.
func TestRefreshPrunesOnlyOurLinks(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
	writeSkill(t, f.vaultSkills, "casual-writing", "Also ours.")
	cat := f.catalog(t)

	both := f.profile(t, skeletonProfileFor("professional-writing", "casual-writing"))
	if _, err := f.provisioner().Provision(cat, both); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	// A foreign entry appears in the same directory, and must survive.
	dir := f.skillsDir(t, ClaudeCode)
	foreign := filepath.Join(dir, "not-ours")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}

	narrowed := f.profile(t, skeletonProfileFor("professional-writing"))
	p := f.provisioner()
	p.Prune = true
	report, err := p.Provision(cat, narrowed)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	res := resultFor(t, report, ClaudeCode, "casual-writing")
	if res.Action != ActionRemoved {
		t.Fatalf("dropped skill action = %s (%s), want removed", res.Action, res.Reason)
	}
	if _, err := os.Lstat(filepath.Join(dir, "casual-writing")); err == nil {
		t.Fatal("the withdrawn link is still there")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("a foreign entry was pruned: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "professional-writing")); err != nil {
		t.Fatalf("the still-assigned link was removed: %v", err)
	}

	// And the ownership record no longer claims what it withdrew.
	m, err := LoadManifest(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Links {
		if e.Slug == "casual-writing" {
			t.Fatal("the manifest still claims a withdrawn link")
		}
	}
}

// Provisioning alone never removes anything — only `refresh` prunes.
func TestProvisionWithoutPruneLeavesDroppedLinks(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
	writeSkill(t, f.vaultSkills, "casual-writing", "Also ours.")
	cat := f.catalog(t)
	if _, err := f.provisioner().Provision(cat, f.profile(t, skeletonProfileFor("professional-writing", "casual-writing"))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.provisioner().Provision(cat, f.profile(t, skeletonProfileFor("professional-writing"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.skillsDir(t, ClaudeCode), "casual-writing")); err != nil {
		t.Fatal("provision pruned a link; only refresh may withdraw")
	}
}

// A stale link Homeplane owns is repointed when the VAULT moves: the link still
// points where the manifest records, so it is still ours.
func TestProvisionRepointsOurOwnStaleLink(t *testing.T) {
	f := newFixture(t)
	oldVault := filepath.Join(t.TempDir(), "old-vault", "skills")
	writeSkill(t, oldVault, "professional-writing", "Ours.")
	oldCat := discover(t, oldVault)
	profile := f.profile(t, skeletonProfileFor("professional-writing"))
	report, err := f.provisioner().Provision(oldCat, profile)
	if err != nil {
		t.Fatal(err)
	}
	linkPath := resultFor(t, report, ClaudeCode, "professional-writing").LinkPath

	// The vault moves. The link is untouched — still pointing at the recorded
	// old target — and the catalog now names the new location.
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
	newCat := f.catalog(t)

	report, err = f.provisioner().Provision(newCat, profile)
	if err != nil {
		t.Fatal(err)
	}
	if got := resultFor(t, report, ClaudeCode, "professional-writing").Action; got != ActionRepointed {
		t.Fatalf("action = %s, want repointed", got)
	}
	target, err := os.Readlink(linkPath)
	if err != nil || target != filepath.Join(newCat.Root, "professional-writing") {
		t.Fatalf("link target = %q (%v)", target, err)
	}
}

// The takeover case, and the one the review caught: a link Homeplane made that
// the OPERATOR has since repointed is no longer Homeplane's. Manifest
// membership alone is not ownership — the link must still point where the
// record says — or provisioning silently undoes a deliberate change and refresh
// deletes an entry it does not own.
func TestProvisionLeavesATakenOverLinkAlone(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
	cat := f.catalog(t)
	profile := f.profile(t, skeletonProfileFor("professional-writing"))
	report, err := f.provisioner().Provision(cat, profile)
	if err != nil {
		t.Fatal(err)
	}
	linkPath := resultFor(t, report, ClaudeCode, "professional-writing").LinkPath

	// The operator repoints our link at their own copy of the skill.
	theirs := filepath.Join(t.TempDir(), "their-fork")
	writeSkill(t, theirs, "professional-writing", "Theirs.")
	theirSkill := filepath.Join(theirs, "professional-writing")
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(theirSkill, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// Provisioning must not take it back.
	report, err = f.provisioner().Provision(cat, profile)
	if err != nil {
		t.Fatal(err)
	}
	res := resultFor(t, report, ClaudeCode, "professional-writing")
	if res.Action != ActionSkipped {
		t.Fatalf("action = %s, want skipped", res.Action)
	}
	if !strings.Contains(res.Reason, "taken over") {
		t.Fatalf("reason = %q, want it to name the takeover", res.Reason)
	}
	if got, _ := os.Readlink(linkPath); got != theirSkill {
		t.Fatalf("the operator's link was repointed to %q", got)
	}

	// And refresh must not delete it either, even though the profile no longer
	// assigns it.
	p := f.provisioner()
	p.Prune = true
	report, err = p.Provision(cat, f.profile(t, skeletonProfileFor()))
	if err != nil {
		t.Fatal(err)
	}
	res = resultFor(t, report, ClaudeCode, "professional-writing")
	if res.Action != ActionSkipped {
		t.Fatalf("refresh action = %s, want skipped", res.Action)
	}
	if got, err := os.Readlink(linkPath); err != nil || got != theirSkill {
		t.Fatalf("refresh deleted a link it did not own: %q (%v)", got, err)
	}
}

// The profile's own per-harness marking beats every assignment. This is the
// case no mechanical rule can reach — a skill bound to another agent's runtime
// — so it is stated in the vault and ENFORCED here (R15).
func TestProvisionRefusesProfileUnsupportedSkills(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "phone-home-coordinator", "How the server agent answers the bus.")
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")

	profile := f.profile(t, `
schema  = 1
profile = "test"

[defaults]
skills = ["phone-home-coordinator", "professional-writing"]

[unsupported.phone-home-coordinator]
reason = "bound to the always-on server session; an ordinary harness has no bus"
harnesses = ["claude-code"]
`)
	report, err := f.provisioner().Provision(f.catalog(t), profile)
	if err != nil {
		t.Fatal(err)
	}

	// Refused on the marked harness...
	res := resultFor(t, report, ClaudeCode, "phone-home-coordinator")
	if res.Action != ActionSkipped || res.Rule != RuleProfileUnsupported {
		t.Fatalf("result = %+v, want a profile-unsupported skip", res)
	}
	if !strings.Contains(res.Reason, "no bus") {
		t.Fatalf("the marking's own reason must be surfaced, got %q", res.Reason)
	}
	if _, err := os.Lstat(res.LinkPath); err == nil {
		t.Fatal("a profile-unsupported skill was linked anyway")
	}
	// ...and linked on the harness the marking does not name.
	if got := resultFor(t, report, Codex, "phone-home-coordinator").Action; got != ActionLinked {
		t.Fatalf("codex action = %s; the marking named only claude-code", got)
	}
	// Everything else is unaffected.
	if got := resultFor(t, report, ClaudeCode, "professional-writing").Action; got != ActionLinked {
		t.Fatalf("professional-writing action = %s", got)
	}
}

// An unmarked profile is unchanged: this is a new refusal path, not a new
// default.
func TestProvisionUnsupportedMarkingIsOptional(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")
	report, err := f.provisioner().Provision(f.catalog(t), f.profile(t, skeletonProfileFor("professional-writing")))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range Known() {
		if got := resultFor(t, report, h, "professional-writing").Action; got != ActionLinked {
			t.Fatalf("%s action = %s", h, got)
		}
	}
}

// A link must never exist without a record of it. Saving the manifest only at
// the end meant a later failure left links nothing could withdraw, so
// writability is proven BEFORE the first link is created.
func TestProvisionRefusesWhenTheManifestCannotBeWritten(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")

	// A regular file where the manifest directory must go.
	if err := os.WriteFile(filepath.Join(f.stateDir, "skills"), []byte("in the way\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := f.provisioner().Provision(f.catalog(t), f.profile(t, skeletonProfileFor("professional-writing")))
	if err == nil {
		t.Fatal("an unwritable manifest must stop the run")
	}
	for _, h := range Known() {
		dir := f.skillsDir(t, h)
		if _, statErr := os.Lstat(filepath.Join(dir, "professional-writing")); statErr == nil {
			t.Fatalf("%s: a link was created that nothing recorded", h)
		}
	}
}

// The run is serialised on the agent state lock, because the manifest is a
// read-modify-write: without it, two concurrent runs each save a manifest that
// omits the other's links, and the omitted links become unremovable strangers.
func TestProvisionHoldsTheLockAcrossTheRun(t *testing.T) {
	f := newFixture(t)
	writeSkill(t, f.vaultSkills, "professional-writing", "Ours.")

	held := 0
	maxHeld := 0
	released := 0
	p := f.provisioner()
	p.Lock = func() (func(), error) {
		held++
		if held > maxHeld {
			maxHeld = held
		}
		return func() { held--; released++ }, nil
	}
	if _, err := p.Provision(f.catalog(t), f.profile(t, skeletonProfileFor("professional-writing"))); err != nil {
		t.Fatal(err)
	}
	if maxHeld != 1 || released != 1 || held != 0 {
		t.Fatalf("lock taken %d / released %d / still held %d", maxHeld, released, held)
	}

	// A lock that cannot be taken stops the run before anything is linked.
	p.Lock = func() (func(), error) { return nil, errors.New("busy") }
	if _, err := p.Provision(f.catalog(t), f.profile(t, skeletonProfileFor("professional-writing"))); err == nil {
		t.Fatal("an unavailable lock must stop the run")
	}
}

func TestSkillsDirHonoursHarnessOverrides(t *testing.T) {
	home := t.TempDir()
	l := Locator{Home: home}
	t.Setenv(EnvClaudeConfigDir, "")
	t.Setenv(EnvCodexHome, "")

	claude, err := l.SkillsDir(ClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	if claude != filepath.Join(home, ".claude", "skills") {
		t.Fatalf("claude skills dir = %q", claude)
	}
	codex, err := l.SkillsDir(Codex)
	if err != nil {
		t.Fatal(err)
	}
	if codex != filepath.Join(home, ".codex", "skills") {
		t.Fatalf("codex skills dir = %q", codex)
	}

	// The harnesses' own environment overrides win over the home default,
	// because the harness itself honours them.
	t.Setenv(EnvClaudeConfigDir, "/tmp/cc")
	t.Setenv(EnvCodexHome, "/tmp/cx")
	if got, _ := l.SkillsDir(ClaudeCode); got != filepath.Join("/tmp/cc", "skills") {
		t.Fatalf("CLAUDE_CONFIG_DIR ignored: %q", got)
	}
	if got, _ := l.SkillsDir(Codex); got != filepath.Join("/tmp/cx", "skills") {
		t.Fatalf("CODEX_HOME ignored: %q", got)
	}

	if _, err := l.SkillsDir("cursor"); err == nil {
		t.Fatal("an unknown harness must error")
	}
}

func TestManifestRoundTripAndSchemaGuard(t *testing.T) {
	dir := t.TempDir()
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("a machine that never provisioned must load an empty manifest: %v", err)
	}
	if len(m.Links) != 0 {
		t.Fatal("empty manifest is not empty")
	}
	m.Links = append(m.Links, ManifestEntry{Harness: Codex, Slug: "b", LinkPath: "/x/b"},
		ManifestEntry{Harness: ClaudeCode, Slug: "a", LinkPath: "/y/a"})
	if err := SaveManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	back, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Links) != 2 || back.Links[0].Harness != ClaudeCode {
		t.Fatalf("manifest did not round-trip in a stable order: %+v", back.Links)
	}
	info, err := os.Stat(ManifestPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != filePerm {
		t.Fatalf("manifest perms = %v, want %v", info.Mode().Perm(), filePerm)
	}

	if err := os.WriteFile(ManifestPath(dir), []byte(`{"schema_version":99,"links":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(dir); err == nil {
		t.Fatal("a future schema must be refused, not half-understood")
	}
}

func TestProvisionRequiresStateDir(t *testing.T) {
	f := newFixture(t)
	p := f.provisioner()
	p.StateDir = ""
	if _, err := p.Provision(f.catalog(t), f.profile(t, skeletonProfileFor())); err == nil {
		t.Fatal("an empty state directory must error")
	}
}
