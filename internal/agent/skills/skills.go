// Package skills provisions vault-authored skills into this machine's agent
// harnesses.
//
// The vault is the only place a skill's text lives. A harness reaches it
// through a symlink Homeplane created, never through a copy — so editing the
// skill in Obsidian changes what every harness reads, and no harness can drift
// into holding an independently editable second original (R15).
//
// Four rules shape everything here.
//
//   - The vault is the canonical source and is never written. Discovery reads;
//     provisioning writes only into each harness's own skills directory, and
//     only entries Homeplane created and recorded. An existing entry that
//     Homeplane did not create is never overwritten, moved or deleted — it is
//     skipped with a reason, which is the same preservation discipline R5
//     applies to harness config files. No harness CONFIG file is touched at
//     all: both supported harnesses discover skills from a directory, so there
//     is nothing to merge (see docs/decisions/d14-skills-linking.md).
//
//   - Fail closed on anything that looks like a secret or like machine state.
//     A skill directory carrying credential material or runtime state is
//     REJECTED and never linked, because a symlink into a harness's skills
//     directory is a read path an agent will follow. The classifier is
//     deliberately blunt: a false rejection costs one unlinked skill, a false
//     acceptance publishes a secret.
//
//   - Instructions, not initiative. The spec's boundary says Homeplane
//     distributes access and instructions and never initiative. A skill whose
//     text drives host scheduling or service control (cron, launchd, systemd)
//     is marked UNSUPPORTED with the matched line as evidence, rather than
//     linked. Same direction of error: not linking is recoverable, silently
//     handing an ordinary harness a self-scheduling skill is not.
//
//   - Discovery is proven by a fresh harness process, not by our own bookkeeping.
//     Verify spawns the real CLI and reads the skill list IT reports
//     (`claude --output-format stream-json` init event; `codex debug
//     prompt-input`). A link we created that the harness does not enumerate is
//     a failure, and says so.
package skills

import (
	"io/fs"

	"github.com/DanielKillenberger/homeplane/internal/agent/harness"
)

// Harness identifiers. They are the same strings the rest of the agent uses;
// re-exporting them keeps callers from importing two packages to name one
// harness.
const (
	ClaudeCode = harness.ClaudeCode
	Codex      = harness.Codex
)

// Known lists the harnesses this package provisions, in a stable order.
func Known() []string { return harness.Known() }

// Permissions for everything this package creates. Nothing here holds a secret
// — a rejected skill never gets linked — but the manifest names paths inside
// the operator's vault, so it stays owner-only like the rest of the state dir.
const (
	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// Status is the verdict discovery reached about one candidate skill.
type Status string

const (
	// StatusLinkable means the skill may be provisioned into a harness.
	StatusLinkable Status = "linkable"
	// StatusUnsupported means the skill is a real skill that Homeplane will
	// not link — harness-specific, or initiative-bearing. Recorded with a
	// reason and surfaced; never silently linked (R15).
	StatusUnsupported Status = "unsupported"
	// StatusRejected means the directory must not be published to a harness at
	// all: it carries credential material or runtime state, or it is not a
	// well-formed skill.
	StatusRejected Status = "rejected"
)

// Rule identifiers for a non-linkable verdict. They are stable strings so the
// evidence artifact and the tests can name the same rule.
const (
	RuleNoSkillMD        = "no-skill-md"
	RuleInvalidSkillMD   = "invalid-skill-md"
	RuleNameMismatch     = "name-mismatch"
	RuleCredential       = "credential-material"
	RuleRuntimeState     = "runtime-state"
	RuleEscapesVault     = "escapes-vault"
	RuleInitiativeSignal = "initiative-signal"
	// RuleProfileUnsupported is the profile's own per-harness marking: the
	// vault owner declared this skill unsupported on this harness, with a
	// reason. It is the one verdict no mechanical rule can reach, which is why
	// it is stated rather than inferred (see UnsupportedSkill).
	RuleProfileUnsupported = "profile-unsupported"
)

// Skill is one discovered, linkable vault skill.
type Skill struct {
	// Slug is the directory name in the vault. It is the identity a harness
	// sees: Claude Code derives its slash command from the LINK's directory
	// name, so Homeplane links under the vault slug and refuses a skill whose
	// SKILL.md `name` disagrees with it (see RuleNameMismatch).
	Slug string `json:"slug"`
	// Name is the SKILL.md frontmatter name. Codex derives its skill name from
	// this field rather than from the directory.
	Name string `json:"name"`
	// Description is the frontmatter description, as the harness will show it.
	Description string `json:"description"`
	// Dir is the skill directory, resolved through symlinks: the canonical
	// location, which must be inside the vault.
	Dir string `json:"dir"`
	// SkillMD is the path to the skill's SKILL.md, under Dir.
	SkillMD string `json:"skill_md"`
}

// Finding records why a candidate is not linkable. Every non-linkable verdict
// produces one — R15 forbids a silent skip.
type Finding struct {
	Slug   string `json:"slug"`
	Status Status `json:"status"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
	// Evidence is the concrete thing that triggered the rule: a path, or a
	// path and the matched line. It exists so the marking is auditable rather
	// than asserted.
	Evidence string `json:"evidence,omitempty"`
}

// Catalog is the result of scanning a vault skills directory.
type Catalog struct {
	// Root is the scanned directory, symlinks resolved.
	Root string `json:"root"`
	// Skills are the linkable skills, sorted by slug.
	Skills []Skill `json:"skills"`
	// Findings are every non-linkable verdict, sorted by slug.
	Findings []Finding `json:"findings"`
}

// Lookup returns the linkable skill with this slug.
func (c Catalog) Lookup(slug string) (Skill, bool) {
	for _, s := range c.Skills {
		if s.Slug == slug {
			return s, true
		}
	}
	return Skill{}, false
}

// Finding returns the recorded verdict for a slug that is not linkable.
func (c Catalog) Finding(slug string) (Finding, bool) {
	for _, f := range c.Findings {
		if f.Slug == slug {
			return f, true
		}
	}
	return Finding{}, false
}
