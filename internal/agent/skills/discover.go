package skills

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// maxScanBytes bounds how much of one file the content classifiers read. A
// skill is prose; anything larger is either not prose or has its giveaway in
// the first megabyte.
const maxScanBytes = 1 << 20

// maxFilesPerSkill bounds the walk of a single skill directory, so a skill that
// (accidentally) contains a checkout cannot turn discovery into a filesystem
// crawl. Hitting the cap is itself a rejection: an unscanned file is an
// unproven file, and the secret classifier fails closed.
const maxFilesPerSkill = 2000

// Discover scans a vault skills directory and classifies every entry.
//
// root is the vault's skills area (`<vault>/skills`). Each immediate
// subdirectory is one candidate skill. The scan never writes, and never
// follows a link out of the vault: a candidate whose canonical location is
// outside root is rejected rather than published to a harness.
func Discover(root string) (Catalog, error) {
	if strings.TrimSpace(root) == "" {
		return Catalog{}, errors.New("skills: discover: empty skills root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Catalog{}, fmt.Errorf("skills: discover: resolve %s: %w", root, err)
	}
	info, err := os.Stat(resolvedRoot)
	if err != nil {
		return Catalog{}, fmt.Errorf("skills: discover: %w", err)
	}
	if !info.IsDir() {
		return Catalog{}, fmt.Errorf("skills: discover: %s is not a directory", root)
	}

	entries, err := os.ReadDir(resolvedRoot)
	if err != nil {
		return Catalog{}, fmt.Errorf("skills: discover: %w", err)
	}

	cat := Catalog{Root: resolvedRoot}
	for _, entry := range entries {
		slug := entry.Name()
		if strings.HasPrefix(slug, ".") {
			continue
		}
		candidate := filepath.Join(resolvedRoot, slug)
		// Directory-ness is judged AFTER resolution: a symlink to a directory
		// is a legitimate way to lay a vault out.
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				cat.Findings = append(cat.Findings, Finding{
					Slug: slug, Status: StatusRejected, Rule: RuleEscapesVault,
					Reason:   "dangling link: the entry does not resolve to an existing path",
					Evidence: candidate,
				})
				continue
			}
			return Catalog{}, fmt.Errorf("skills: discover: resolve %s: %w", candidate, err)
		}
		if !within(resolvedRoot, resolved) {
			cat.Findings = append(cat.Findings, Finding{
				Slug: slug, Status: StatusRejected, Rule: RuleEscapesVault,
				Reason:   "resolves outside the vault skills root; Homeplane publishes vault-authored skills only",
				Evidence: resolved,
			})
			continue
		}
		resolvedInfo, err := os.Stat(resolved)
		if err != nil {
			return Catalog{}, fmt.Errorf("skills: discover: stat %s: %w", resolved, err)
		}
		if !resolvedInfo.IsDir() {
			// A loose file beside the skill directories (a README) is not a
			// candidate at all, and is not worth a finding.
			continue
		}

		skill, finding := classify(slug, resolved)
		if finding != nil {
			cat.Findings = append(cat.Findings, *finding)
			continue
		}
		cat.Skills = append(cat.Skills, skill)
	}

	sort.Slice(cat.Skills, func(i, j int) bool { return cat.Skills[i].Slug < cat.Skills[j].Slug })
	sort.Slice(cat.Findings, func(i, j int) bool { return cat.Findings[i].Slug < cat.Findings[j].Slug })
	return cat, nil
}

// classify decides one candidate's verdict.
//
// The order is the precedence: containment first (a secret must be caught
// whatever else is wrong), then shape, then the initiative boundary. It is
// deliberately NOT "cheapest check first" — a directory with no SKILL.md that
// also contains a private key is reported as carrying a private key.
func classify(slug, dir string) (Skill, *Finding) {
	containment, initiative := scanContents(slug, dir)
	if containment != nil {
		return Skill{}, containment
	}

	skillMD := filepath.Join(dir, "SKILL.md")
	info, err := os.Stat(skillMD)
	if err != nil || info.IsDir() {
		return Skill{}, &Finding{
			Slug: slug, Status: StatusUnsupported, Rule: RuleNoSkillMD,
			Reason:   "not a skill: no SKILL.md at the directory root (a collection of skills is not itself linkable)",
			Evidence: skillMD,
		}
	}

	raw, err := os.ReadFile(skillMD)
	if err != nil {
		return Skill{}, &Finding{
			Slug: slug, Status: StatusRejected, Rule: RuleInvalidSkillMD,
			Reason: "SKILL.md is unreadable: " + err.Error(), Evidence: skillMD,
		}
	}
	name, description, err := parseFrontmatter(raw)
	if err != nil {
		return Skill{}, &Finding{
			Slug: slug, Status: StatusRejected, Rule: RuleInvalidSkillMD,
			Reason: err.Error(), Evidence: skillMD,
		}
	}
	if name != slug {
		// Not cosmetic. Claude Code names the skill after the LINK directory,
		// Codex after this field (verified against both installed CLIs), so a
		// mismatch means the same skill answers to two different names
		// depending on the harness. Homeplane will not publish an identity it
		// cannot keep consistent.
		return Skill{}, &Finding{
			Slug: slug, Status: StatusUnsupported, Rule: RuleNameMismatch,
			Reason:   fmt.Sprintf("SKILL.md name %q does not match the directory %q; the two harnesses would expose different names", name, slug),
			Evidence: skillMD,
		}
	}

	// The initiative verdict comes from the whole directory, not just SKILL.md.
	// A benign-looking SKILL.md that points the harness at a bundled script
	// which installs a cron job or a systemd unit is exactly the case a
	// SKILL.md-only scan misses, and it is the case that matters most.
	if initiative != nil {
		return Skill{}, initiative
	}

	return Skill{Slug: slug, Name: name, Description: description, Dir: dir, SkillMD: skillMD}, nil
}

// secretFileNames are files whose NAME is the giveaway, whatever they contain.
var secretFileNames = map[string]bool{
	".env":                 true,
	".envrc":               true,
	".netrc":               true,
	"auth.json":            true,
	"credentials":          true,
	"credentials.json":     true,
	"id_dsa":               true,
	"id_ecdsa":             true,
	"id_ed25519":           true,
	"id_rsa":               true,
	"secrets.json":         true,
	"service-account.json": true,
}

var secretFileSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"}

// stateFileSuffixes name machine state. A skill is text; an index, a database
// or a socket in a skill directory means the directory is somebody's runtime,
// and runtime does not sync (the same reason the GNO index never enters the
// vault).
var stateFileSuffixes = []string{
	".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm", ".db", ".db-wal", ".db-shm",
	".log", ".pid", ".sock", ".lock",
}

var stateFileNames = map[string]bool{
	"state.json": true,
}

// secretPatterns match credential material in a file's TEXT. Each is anchored
// on a provider's own key shape, or on an assignment of a long opaque value to
// a secret-sounding key — the two forms a pasted credential actually takes.
var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"PEM private key", regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`)},
	{"Anthropic API key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}`)},
	{"GitHub token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}`)},
	{"GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}`)},
	{"AWS access key id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"assigned secret value", regexp.MustCompile(`(?i)\b(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|refresh[_\-]?token|client[_\-]?secret|password)\b\s*[:=]\s*["']?[A-Za-z0-9/+=_\-]{20,}`)},
}

// scanContents walks a skill directory and classifies every file in it.
//
// It returns TWO verdicts because they have different precedence and different
// stopping rules. A containment problem (a credential, runtime state, a link
// out of the directory, anything unscannable) is fatal and stops the walk
// immediately. An initiative signal is not fatal — it is a verdict the caller
// applies only after the shape checks — so the walk continues past the first
// one, and the first is kept.
//
// Every unreadable or unscannable file is a containment rejection, not a pass:
// the classifier's whole value is that it cannot be talked into a maybe.
func scanContents(slug, dir string) (containment, initiative *Finding) {
	files := 0

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			containment = reject(slug, RuleRuntimeState, "unreadable entry in the skill directory: "+err.Error(), path)
			return filepath.SkipAll
		}
		if path == dir {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			rel = path
		}

		if d.Type()&fs.ModeSymlink != 0 {
			target, resolveErr := filepath.EvalSymlinks(path)
			if resolveErr != nil || !within(dir, target) {
				containment = reject(slug, RuleEscapesVault,
					"the skill contains a link that leaves the skill directory; a link published to a harness must not widen its reach", rel)
				return filepath.SkipAll
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			containment = reject(slug, RuleRuntimeState,
				"the skill contains a non-regular file (socket, device or fifo), which is runtime state rather than instructions", rel)
			return filepath.SkipAll
		}

		files++
		if files > maxFilesPerSkill {
			containment = reject(slug, RuleRuntimeState,
				fmt.Sprintf("the skill directory holds more than %d files; it was not scanned in full and an unscanned file is treated as unproven", maxFilesPerSkill), rel)
			return filepath.SkipAll
		}

		bad, text := scanFile(slug, path, rel, d)
		if bad != nil {
			containment = bad
			return filepath.SkipAll
		}
		if initiative == nil {
			initiative = matchInitiative(slug, rel, text)
		}
		return nil
	})
	if err != nil && containment == nil {
		containment = reject(slug, RuleRuntimeState, "the skill directory could not be scanned: "+err.Error(), dir)
	}
	if containment != nil {
		return containment, nil
	}
	return nil, initiative
}

func reject(slug, rule, reason, evidence string) *Finding {
	return &Finding{Slug: slug, Status: StatusRejected, Rule: rule, Reason: reason, Evidence: evidence}
}

// scanFile classifies one regular file. It returns a containment rejection, or
// the file's text for the initiative scan to read.
func scanFile(slug, path, rel string, d fs.DirEntry) (*Finding, []byte) {
	name := strings.ToLower(d.Name())
	if secretFileNames[name] {
		return reject(slug, RuleCredential,
			"the skill contains a credential file; skills carry instructions, and credentials live on the server", rel), nil
	}
	for _, suffix := range secretFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return reject(slug, RuleCredential,
				"the skill contains a key file ("+suffix+"); skills carry instructions, and credentials live on the server", rel), nil
		}
	}
	if stateFileNames[name] {
		return reject(slug, RuleRuntimeState,
			"the skill contains runtime state ("+d.Name()+"); a synchronized skill must be instructions only", rel), nil
	}
	for _, suffix := range stateFileSuffixes {
		if strings.HasSuffix(name, suffix) {
			return reject(slug, RuleRuntimeState,
				"the skill contains runtime state ("+suffix+"); a synchronized skill must be instructions only", rel), nil
		}
	}

	info, err := d.Info()
	if err != nil {
		return reject(slug, RuleRuntimeState, "unreadable entry in the skill directory: "+err.Error(), rel), nil
	}
	// `>=`, not `>`. At exactly maxScanBytes the file used to be accepted and
	// then handed to a line scanner with the SAME maximum token size, so a
	// single-line file of exactly that length produced ErrTooLong and was
	// scanned as if it were empty — a credential in it passed silently. The
	// scan is now over the whole (bounded) byte slice, and this boundary is
	// closed as well, because two independent bugs met at one number.
	if info.Size() >= maxScanBytes {
		return reject(slug, RuleRuntimeState,
			fmt.Sprintf("the skill contains a file of %d bytes or more, which is not scanned in full; an unscanned file is treated as unproven", maxScanBytes), rel), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return reject(slug, RuleRuntimeState, "unreadable entry in the skill directory: "+err.Error(), rel), nil
	}
	if bytes.IndexByte(data, 0) >= 0 {
		// Binary. Not classifiable as prose, so not publishable either.
		return reject(slug, RuleRuntimeState,
			"the skill contains a binary file, which cannot be read as instructions", rel), nil
	}
	if kind, line, ok := matchSecret(data); ok {
		return &Finding{
			Slug: slug, Status: StatusRejected, Rule: RuleCredential,
			Reason:   "the skill contains what looks like a credential (" + kind + "); skills carry instructions, and credentials live on the server",
			Evidence: fmt.Sprintf("%s:%d", rel, line),
		}, nil
	}
	return nil, data
}

// matchSecret reports the first credential-shaped match and its 1-based line.
//
// The patterns run over the whole byte slice, which the caller has already
// bounded, rather than over a line scanner: a line scanner has a maximum token
// size, and a file with no newline before that limit would be silently skipped
// instead of scanned. The line number is computed only once something matched.
func matchSecret(data []byte) (string, int, bool) {
	for _, p := range secretPatterns {
		if loc := p.re.FindIndex(data); loc != nil {
			return p.name, bytes.Count(data[:loc[0]], []byte("\n")) + 1, true
		}
	}
	return "", 0, false
}

// initiativePatterns name host scheduling and service control. The spec's
// boundary is that Homeplane distributes instructions and never initiative, so
// a skill that reaches for these is marked unsupported rather than linked.
//
// This is a conservative classifier on purpose: it fires on a mention, not on
// proven intent, so a skill that merely discusses cron is also held back. That
// is the safe direction of error, and the reason is recorded with the matched
// line so the operator can see exactly what tripped it and decide.
var initiativePatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"cron", regexp.MustCompile(`(?i)\bcron(tab|job)?\b`)},
	{"launchd", regexp.MustCompile(`(?i)\blaunchd\b|\blaunchctl\b`)},
	{"systemd", regexp.MustCompile(`(?i)\bsystemd\b|\bsystemctl\b`)},
	{"scheduled wakeup", regexp.MustCompile(`(?i)\bschedule[sd]?\b[^.\n]{0,40}\b(check-?in|ping|wake-?up|job|task|restart)\b`)},
}

// matchInitiative reports the first scheduling or service-control signal in one
// file's text, naming the file so a signal inside a bundled script is as
// visible as one in SKILL.md.
func matchInitiative(slug, rel string, data []byte) *Finding {
	for _, p := range initiativePatterns {
		loc := p.re.FindIndex(data)
		if loc == nil {
			continue
		}
		line := bytes.Count(data[:loc[0]], []byte("\n")) + 1
		start := bytes.LastIndexByte(data[:loc[0]], '\n') + 1
		end := bytes.IndexByte(data[loc[0]:], '\n')
		if end < 0 {
			end = len(data)
		} else {
			end += loc[0]
		}
		return &Finding{
			Slug: slug, Status: StatusUnsupported, Rule: RuleInitiativeSignal,
			Reason:   "the skill drives host scheduling or service control (" + p.name + "); Homeplane distributes instructions, not initiative, so it is not linked into an ordinary harness",
			Evidence: fmt.Sprintf("%s:%d: %s", rel, line, strings.TrimSpace(truncate(string(data[start:end]), 120))),
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// parseFrontmatter reads the YAML-ish `---` header every SKILL.md carries. It
// is deliberately a small reader for the two fields both harnesses read, not a
// YAML implementation: anything it cannot understand is a rejection, and a
// rejection is safe.
func parseFrontmatter(raw []byte) (name, description string, err error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if !strings.HasPrefix(text, "---\n") {
		return "", "", errors.New("SKILL.md does not start with a `---` frontmatter block")
	}
	rest := text[len("---\n"):]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return "", "", errors.New("SKILL.md frontmatter block is not closed by `---`")
	}
	block := rest[:end]

	lines := strings.Split(block, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		// Block scalars (`>`, `>-`, `|`, `|-`) are how a long description is
		// written in a real SKILL.md, and Daniel's vault has one. Reading the
		// indicator as the value would report a description of ">-".
		if value == ">" || value == ">-" || value == ">+" || value == "|" || value == "|-" || value == "|+" {
			folded := value[0] == '>'
			var parts []string
			for i+1 < len(lines) {
				next := lines[i+1]
				if strings.TrimSpace(next) != "" && !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "\t") {
					break
				}
				parts = append(parts, strings.TrimSpace(next))
				i++
			}
			joiner := "\n"
			if folded {
				joiner = " "
			}
			value = strings.TrimSpace(strings.Join(parts, joiner))
		} else {
			value = unquote(value)
		}

		switch key {
		case "name":
			name = value
		case "description":
			description = value
		}
	}
	if name == "" {
		return "", "", errors.New("SKILL.md frontmatter has no `name`")
	}
	if description == "" {
		return "", "", errors.New("SKILL.md frontmatter has no `description`")
	}
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", "", fmt.Errorf("SKILL.md frontmatter name %q is not a plain directory name", name)
	}
	return name, description, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// within reports whether path is root or lives under it. Both are expected to
// be already resolved.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
