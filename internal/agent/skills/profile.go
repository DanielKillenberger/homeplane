package skills

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// ProfileFileName is the profile's conventional name. D15 pins the profile as a
// VAULT-RESIDENT file: it is Daniel's assignment of skills to harnesses, it
// belongs beside the skills it names, and it syncs to every machine for free.
const ProfileFileName = "homeplane.skills.toml"

// ProfileSchemaVersion is the only schema this build reads. A profile written
// by a newer agent is refused rather than half-understood.
const ProfileSchemaVersion = 1

// DefaultProfilePath is where a vault keeps its profile: <vault>/skills/<name>.
func DefaultProfilePath(vaultSkillsRoot string) string {
	return filepath.Join(vaultSkillsRoot, ProfileFileName)
}

// Profile is the pinned D15 format: a small TOML file mapping machine and
// harness to a skill set.
//
//	schema  = 1
//	profile = "daniel-skeleton"
//
//	[defaults]
//	skills = ["professional-writing", "casual-writing", "karpathy-guidelines"]
//
//	[harness.codex]
//	skills = ["professional-writing"]
//
//	[machine."studio"]
//	skills = ["professional-writing", "casual-writing"]
//
//	[machine."studio".harness.claude-code]
//	skills = []
//
// Resolution is most-specific-wins, and a block REPLACES the less specific set
// rather than adding to it: machine+harness, then machine, then harness, then
// defaults. Replacement is the honest semantic for a rule that has to be able
// to say "not on this machine" — an additive model cannot subtract.
type Profile struct {
	Schema  int    `toml:"schema"`
	Name    string `toml:"profile"`
	Path    string `toml:"-"`
	Default Skills `toml:"defaults"`
	// Harness maps a harness id to its skill set.
	Harness map[string]Skills `toml:"harness"`
	// Machine maps a machine name to its own defaults and per-harness sets.
	Machine map[string]MachineProfile `toml:"machine"`
	// Unsupported records skills that must NOT be linked into some or all
	// harnesses, with the reason. See Unsupported.
	Unsupported map[string]UnsupportedSkill `toml:"unsupported"`
}

// UnsupportedSkill records a skill that is harness-specific in a way no
// mechanical rule can see.
//
// R15 requires genuinely harness-specific skills to be marked unsupported with
// a reason rather than silently linked. Discovery catches the mechanical cases
// (a directory of skills, a skill that drives the host's scheduler). It cannot
// catch "this skill only means anything inside the always-on server session",
// which is true of Daniel's `phone-home-coordinator` and is a judgement about
// what the skill IS, not about what its text contains. Guessing at that would
// be a classifier that is wrong in both directions.
//
// So the vault owner states it, in the same vault-resident file that assigns
// the skills, and Homeplane ENFORCES it: an unsupported entry beats every
// assignment, including a `[defaults]` block that names the skill. That is what
// makes per-harness incompatibility representable rather than a comment.
type UnsupportedSkill struct {
	// Reason is required. A marking without one is not a marking.
	Reason string `toml:"reason"`
	// Harnesses narrows the marking. Empty means every harness.
	Harnesses []string `toml:"harnesses"`
}

// Supports reports whether this marking applies to a harness.
func (u UnsupportedSkill) applies(harnessID string) bool {
	if len(u.Harnesses) == 0 {
		return true
	}
	for _, h := range u.Harnesses {
		if h == harnessID {
			return true
		}
	}
	return false
}

// UnsupportedOn reports whether the profile forbids this skill on this harness,
// and why. It is consulted for every assignment, so a skill named in both
// `[defaults]` and `[unsupported]` is refused rather than linked.
func (p Profile) UnsupportedOn(slug, harnessID string) (string, bool) {
	u, ok := p.Unsupported[slug]
	if !ok || !u.applies(harnessID) {
		return "", false
	}
	return u.Reason, true
}

// Skills is one skill set.
type Skills struct {
	Skills []string `toml:"skills"`
	set    bool
}

// MachineProfile narrows a profile to one machine.
type MachineProfile struct {
	Skills  []string          `toml:"skills"`
	Harness map[string]Skills `toml:"harness"`
	set     bool
}

// LoadProfile reads and validates a profile file.
func LoadProfile(path string) (Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("skills: profile: %w", err)
	}
	return parseProfile(path, raw)
}

func parseProfile(path string, raw []byte) (Profile, error) {
	var p Profile
	md, err := toml.Decode(string(raw), &p)
	if err != nil {
		return Profile{}, fmt.Errorf("skills: profile %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		// An unknown key is a typo or a newer schema. Either way the operator's
		// intent is not what this build would do, so say so instead of
		// silently provisioning a different set than they wrote.
		return Profile{}, fmt.Errorf("skills: profile %s: unknown key(s): %s", path, strings.Join(keys, ", "))
	}
	p.Path = path

	if p.Schema != ProfileSchemaVersion {
		return Profile{}, fmt.Errorf("skills: profile %s: schema %d is not supported (this agent reads schema %d)", path, p.Schema, ProfileSchemaVersion)
	}
	if strings.TrimSpace(p.Name) == "" {
		return Profile{}, fmt.Errorf("skills: profile %s: `profile` name is required", path)
	}

	// Record which blocks were actually present, so an explicitly EMPTY set
	// ("no skills on this harness") is distinguishable from an absent block
	// ("inherit"). TOML decoding alone cannot tell those apart.
	p.Default.set = md.IsDefined("defaults")
	for name, s := range p.Harness {
		if err := validateHarness(path, name); err != nil {
			return Profile{}, err
		}
		s.set = md.IsDefined("harness", name)
		p.Harness[name] = s
	}
	for machine, mp := range p.Machine {
		if strings.TrimSpace(machine) == "" {
			return Profile{}, fmt.Errorf("skills: profile %s: empty machine name", path)
		}
		mp.set = md.IsDefined("machine", machine, "skills")
		for name, s := range mp.Harness {
			if err := validateHarness(path, name); err != nil {
				return Profile{}, err
			}
			s.set = md.IsDefined("machine", machine, "harness", name)
			mp.Harness[name] = s
		}
		p.Machine[machine] = mp
	}

	for slug, u := range p.Unsupported {
		if err := validateSlug(path, slug); err != nil {
			return Profile{}, err
		}
		// A marking with no reason is not a marking. R15's whole requirement is
		// that an unsupported skill is recorded WITH a reason, so an empty one
		// is refused rather than surfaced as an unexplained skip.
		if strings.TrimSpace(u.Reason) == "" {
			return Profile{}, fmt.Errorf("skills: profile %s: [unsupported.%s] needs a `reason`", path, slug)
		}
		for _, h := range u.Harnesses {
			if err := validateHarness(path, h); err != nil {
				return Profile{}, err
			}
		}
	}

	for _, slug := range p.allSlugs() {
		if err := validateSlug(path, slug); err != nil {
			return Profile{}, err
		}
	}
	return p, nil
}

func validateHarness(path, name string) error {
	for _, known := range Known() {
		if name == known {
			return nil
		}
	}
	return fmt.Errorf("skills: profile %s: unknown harness %q (known: %s)", path, name, strings.Join(Known(), ", "))
}

// validateSlug refuses anything that is not a plain directory name. The slug
// becomes a path component under the harness's skills directory, so `..` or an
// absolute path here would be a write outside it.
func validateSlug(path, slug string) error {
	if strings.TrimSpace(slug) == "" {
		return fmt.Errorf("skills: profile %s: empty skill name", path)
	}
	if slug != filepath.Base(slug) || slug == "." || slug == ".." || strings.ContainsAny(slug, `/\`) || strings.HasPrefix(slug, ".") {
		return fmt.Errorf("skills: profile %s: %q is not a plain skill name", path, slug)
	}
	return nil
}

func (p Profile) allSlugs() []string {
	var out []string
	out = append(out, p.Default.Skills...)
	for _, s := range p.Harness {
		out = append(out, s.Skills...)
	}
	for _, mp := range p.Machine {
		out = append(out, mp.Skills...)
		for _, s := range mp.Harness {
			out = append(out, s.Skills...)
		}
	}
	return out
}

// Assign returns the skill set this profile assigns to one harness on one
// machine, most-specific-wins. The result is sorted and de-duplicated so two
// runs of the same profile provision in the same order.
func (p Profile) Assign(machine, harnessID string) []string {
	if mp, ok := p.Machine[machine]; ok {
		if s, ok := mp.Harness[harnessID]; ok && s.set {
			return normalize(s.Skills)
		}
		if mp.set {
			return normalize(mp.Skills)
		}
	}
	if s, ok := p.Harness[harnessID]; ok && s.set {
		return normalize(s.Skills)
	}
	if p.Default.set {
		return normalize(p.Default.Skills)
	}
	return nil
}

func normalize(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ErrNoProfile reports a missing profile file, so a caller can tell "not set up
// yet" from "set up wrongly".
var ErrNoProfile = errors.New("skills: no profile file")

// FindProfile locates the profile: an explicit path if given, otherwise the
// vault's own. A missing file is ErrNoProfile.
func FindProfile(explicit, vaultSkillsRoot string) (Profile, error) {
	path := strings.TrimSpace(explicit)
	if path == "" {
		if strings.TrimSpace(vaultSkillsRoot) == "" {
			return Profile{}, ErrNoProfile
		}
		path = DefaultProfilePath(vaultSkillsRoot)
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Profile{}, fmt.Errorf("%w at %s", ErrNoProfile, path)
		}
		return Profile{}, fmt.Errorf("skills: profile: %w", err)
	}
	return LoadProfile(path)
}
