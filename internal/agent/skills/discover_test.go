package skills

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSkill lays down a minimal well-formed skill and returns its directory.
func writeSkill(t *testing.T, root, slug, body string) string {
	t.Helper()
	dir := filepath.Join(root, slug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	md := "---\nname: " + slug + "\ndescription: The " + slug + " skill, for tests.\n---\n\n# " + slug + "\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fixtureVault(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault", "skills")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func discover(t *testing.T, root string) Catalog {
	t.Helper()
	cat, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return cat
}

func TestDiscoverFindsWellFormedSkills(t *testing.T) {
	root := fixtureVault(t)
	writeSkill(t, root, "professional-writing", "Write like this.")
	writeSkill(t, root, "casual-writing", "Write like that.")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("not a skill"), 0o644); err != nil {
		t.Fatal(err)
	}

	cat := discover(t, root)
	if len(cat.Skills) != 2 {
		t.Fatalf("skills = %d, want 2: %+v", len(cat.Skills), cat.Skills)
	}
	if cat.Skills[0].Slug != "casual-writing" || cat.Skills[1].Slug != "professional-writing" {
		t.Fatalf("skills are not sorted by slug: %+v", cat.Skills)
	}
	if len(cat.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", cat.Findings)
	}
	if got := cat.Skills[0].Description; !strings.Contains(got, "casual-writing skill") {
		t.Fatalf("description = %q", got)
	}
	if !strings.HasSuffix(cat.Skills[0].SkillMD, filepath.Join("casual-writing", "SKILL.md")) {
		t.Fatalf("SkillMD = %q", cat.Skills[0].SkillMD)
	}
}

// A directory of skills is not itself a skill. This is the `hermes` shape in
// Daniel's real vault, and the acceptance criterion's harness-specific
// exemplar: it is marked unsupported with a reason, never silently linked.
func TestDiscoverMarksCollectionUnsupported(t *testing.T) {
	root := fixtureVault(t)
	writeSkill(t, filepath.Join(root, "hermes"), "daily-brief", "Nested.")

	cat := discover(t, root)
	if len(cat.Skills) != 0 {
		t.Fatalf("a collection must not be linkable: %+v", cat.Skills)
	}
	f, ok := cat.Finding("hermes")
	if !ok {
		t.Fatalf("no finding for hermes: %+v", cat.Findings)
	}
	if f.Status != StatusUnsupported || f.Rule != RuleNoSkillMD {
		t.Fatalf("finding = %+v, want unsupported/%s", f, RuleNoSkillMD)
	}
	if f.Reason == "" || f.Evidence == "" {
		t.Fatalf("an unsupported marking must carry a reason and evidence: %+v", f)
	}
}

// The initiative boundary: a skill that drives host scheduling or service
// control is held back, with the matched line as evidence.
func TestDiscoverMarksInitiativeBearingUnsupported(t *testing.T) {
	cases := []struct {
		slug string
		body string
	}{
		{"session-monitor", "Schedule the first 90-min cron ping, then check in."},
		{"restart", "Persist state, then restart the clawniel systemd service."},
		{"morning", "Register a launchd job so this runs every weekday."},
	}
	for _, tc := range cases {
		t.Run(tc.slug, func(t *testing.T) {
			root := fixtureVault(t)
			writeSkill(t, root, tc.slug, tc.body)

			cat := discover(t, root)
			if len(cat.Skills) != 0 {
				t.Fatalf("an initiative-bearing skill must not be linkable: %+v", cat.Skills)
			}
			f, ok := cat.Finding(tc.slug)
			if !ok {
				t.Fatalf("no finding: %+v", cat.Findings)
			}
			if f.Status != StatusUnsupported || f.Rule != RuleInitiativeSignal {
				t.Fatalf("finding = %+v, want unsupported/%s", f, RuleInitiativeSignal)
			}
			if !strings.HasPrefix(f.Evidence, "SKILL.md:") {
				t.Fatalf("evidence must quote the matched line, got %q", f.Evidence)
			}
		})
	}
}

// The baseline three must survive the initiative classifier. If prose about
// writing trips it, the classifier is too blunt to ship.
func TestDiscoverKeepsBaselineSkillsLinkable(t *testing.T) {
	root := fixtureVault(t)
	writeSkill(t, root, "professional-writing", "Lead with the point. No em dashes, ever.")
	writeSkill(t, root, "casual-writing", "Short sentences. Warmth is economical.")
	writeSkill(t, root, "karpathy-guidelines", "Prefer the smallest thing that works.")

	cat := discover(t, root)
	if len(cat.Skills) != 3 {
		t.Fatalf("baseline skills = %d, want 3 (findings: %+v)", len(cat.Skills), cat.Findings)
	}
}

func TestDiscoverRejectsCredentialMaterial(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		rule string
	}{
		{"anthropic key in prose", "SKILL.md", "", RuleCredential},
		{"env file", ".env", "TOKEN=abc\n", RuleCredential},
		{"pem file", "deploy.pem", "not really a key\n", RuleCredential},
		{"private key body", "notes.md", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n", RuleCredential},
		{"assigned secret", "notes.md", "api_key: 0123456789abcdef0123456789abcdef\n", RuleCredential},
		{"sqlite state", "index.sqlite", "SQLite format 3\n", RuleRuntimeState},
		{"runtime log", "run.log", "started\n", RuleRuntimeState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureVault(t)
			dir := writeSkill(t, root, "leaky", "Ordinary instructions.")
			if tc.file == "SKILL.md" {
				// A credential pasted into the skill's own text.
				if err := os.WriteFile(filepath.Join(dir, "SKILL.md"),
					[]byte("---\nname: leaky\ndescription: d\n---\n\nUse sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF0011 to call.\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}

			cat := discover(t, root)
			if len(cat.Skills) != 0 {
				t.Fatalf("a skill carrying %s must never be linkable", tc.name)
			}
			f, ok := cat.Finding("leaky")
			if !ok {
				t.Fatalf("no finding: %+v", cat.Findings)
			}
			if f.Status != StatusRejected || f.Rule != tc.rule {
				t.Fatalf("finding = %+v, want rejected/%s", f, tc.rule)
			}
			if f.Reason == "" {
				t.Fatal("a rejection must carry a clear message")
			}
		})
	}
}

// A skill is not a place to smuggle a wider read path. A link out of the skill
// directory is refused even though the link itself is inside the vault.
func TestDiscoverRejectsEscapingLinks(t *testing.T) {
	root := fixtureVault(t)
	dir := writeSkill(t, root, "reacher", "Ordinary.")
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "elsewhere")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cat := discover(t, root)
	f, ok := cat.Finding("reacher")
	if !ok {
		t.Fatalf("no finding: %+v", cat.Findings)
	}
	if f.Status != StatusRejected || f.Rule != RuleEscapesVault {
		t.Fatalf("finding = %+v, want rejected/%s", f, RuleEscapesVault)
	}
}

// A skill directory that is itself a link out of the vault is not a vault
// skill, whatever it contains.
func TestDiscoverRejectsSkillLinkedFromOutsideTheVault(t *testing.T) {
	root := fixtureVault(t)
	elsewhere := filepath.Join(t.TempDir(), "outside")
	writeSkill(t, elsewhere, "smuggled", "Ordinary.")
	if err := os.Symlink(filepath.Join(elsewhere, "smuggled"), filepath.Join(root, "smuggled")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cat := discover(t, root)
	if len(cat.Skills) != 0 {
		t.Fatalf("a skill outside the vault must not be linkable: %+v", cat.Skills)
	}
	f, ok := cat.Finding("smuggled")
	if !ok || f.Rule != RuleEscapesVault {
		t.Fatalf("finding = %+v, want %s", f, RuleEscapesVault)
	}
}

// A long description is written as a YAML block scalar in real SKILL.md files
// (Daniel's `negotiation` skill is one). Reading the indicator as the value
// would report a description of ">-".
func TestDiscoverReadsBlockScalarDescriptions(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"folded":  {"---\nname: neg\ndescription: >-\n  First line\n  second line\n---\n", "First line second line"},
		"literal": {"---\nname: neg\ndescription: |\n  First line\n  second line\n---\n", "First line\nsecond line"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := fixtureVault(t)
			dir := filepath.Join(root, "neg")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			cat := discover(t, root)
			s, ok := cat.Lookup("neg")
			if !ok {
				t.Fatalf("not linkable: %+v", cat.Findings)
			}
			if s.Description != tc.want {
				t.Fatalf("description = %q, want %q", s.Description, tc.want)
			}
		})
	}
}

func TestDiscoverRejectsMalformedFrontmatter(t *testing.T) {
	cases := map[string]string{
		"no frontmatter": "# just a heading\n",
		"unclosed":       "---\nname: x\ndescription: y\n",
		"no name":        "---\ndescription: y\n---\n",
		"no description": "---\nname: x\n---\n",
		"path in name":   "---\nname: ../escape\ndescription: y\n---\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			root := fixtureVault(t)
			dir := filepath.Join(root, "broken")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}

			cat := discover(t, root)
			f, ok := cat.Finding("broken")
			if !ok {
				t.Fatalf("no finding: %+v", cat.Findings)
			}
			if f.Status != StatusRejected || f.Rule != RuleInvalidSkillMD {
				t.Fatalf("finding = %+v, want rejected/%s", f, RuleInvalidSkillMD)
			}
		})
	}
}

// Claude Code names a skill after the LINK directory and Codex after the
// frontmatter `name` — verified against both installed CLIs. A skill whose two
// names disagree would answer to different names per harness, so it is not
// published.
func TestDiscoverMarksNameMismatchUnsupported(t *testing.T) {
	root := fixtureVault(t)
	dir := filepath.Join(root, "on-disk-name")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"),
		[]byte("---\nname: frontmatter-name\ndescription: d\n---\n\n# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cat := discover(t, root)
	f, ok := cat.Finding("on-disk-name")
	if !ok {
		t.Fatalf("no finding: %+v", cat.Findings)
	}
	if f.Status != StatusUnsupported || f.Rule != RuleNameMismatch {
		t.Fatalf("finding = %+v, want unsupported/%s", f, RuleNameMismatch)
	}
}

// Containment beats shape: a directory with no SKILL.md AND a private key is
// reported as carrying a private key, not as "not a skill".
func TestDiscoverPrefersCredentialFindingOverShape(t *testing.T) {
	root := fixtureVault(t)
	dir := filepath.Join(root, "both-wrong")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.md"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cat := discover(t, root)
	f, _ := cat.Finding("both-wrong")
	if f.Rule != RuleCredential {
		t.Fatalf("finding = %+v, want %s", f, RuleCredential)
	}
}

func TestDiscoverRejectsUnscannableFiles(t *testing.T) {
	root := fixtureVault(t)
	dir := writeSkill(t, root, "huge", "Ordinary.")
	big := make([]byte, maxScanBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	cat := discover(t, root)
	f, ok := cat.Finding("huge")
	if !ok || f.Status != StatusRejected {
		t.Fatalf("an unscanned file must be treated as unproven, got %+v", cat.Findings)
	}
}

func TestDiscoverErrors(t *testing.T) {
	if _, err := Discover(""); err == nil {
		t.Fatal("empty root must error")
	}
	if _, err := Discover(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("missing root must error")
	}
}
