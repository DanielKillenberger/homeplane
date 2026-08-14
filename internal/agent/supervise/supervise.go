// Package supervise renders and installs the per-user supervision units that
// keep Homeplane's long-running machine-side processes alive: vault sync now
// (R14), GNO later (R4). Both tasks share this framework so that "supervised"
// means the same thing — and fails the same way — for either process.
//
// Two deliberate limits:
//
//   - Rendering and installing a unit is separate from ACTIVATING it. Writing a
//     plist is a file write; `launchctl bootstrap` mutates a live user session.
//     The activation commands are returned as data and executed only through an
//     injected runner, so tests exercise the whole path without ever touching
//     the developer's own launchd or systemd.
//   - No secret ever enters a unit. Units run `homeplane-agent`, which reads
//     credentials from its own 0600 files; the unit itself is non-secret and
//     safe to read, copy, and diff.
package supervise

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// Platform selects the supervision system.
type Platform string

const (
	// Launchd is macOS per-user supervision (LaunchAgents).
	Launchd Platform = "launchd"
	// Systemd is Linux per-user supervision (`systemctl --user` + linger).
	Systemd Platform = "systemd"
)

// ErrUnsupportedPlatform is returned for anything that is neither launchd nor
// systemd. The installer rejects rather than improvises (R1's stance, applied
// to supervision).
var ErrUnsupportedPlatform = errors.New("supervise: unsupported supervision platform")

// DetectPlatform maps a GOOS onto a supervision system.
func DetectPlatform(goos string) (Platform, error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case "darwin":
		return Launchd, nil
	case "linux":
		return Systemd, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, goos)
	}
}

// Canonical unit labels. They live here rather than in each owning package so
// that `status` can read a unit's restart ledger without importing the package
// that installs it.
const (
	// VaultSyncLabel is the continuous Obsidian Sync process (task .5).
	VaultSyncLabel = "com.homeplane.vault-sync"
	// GNOLabel is the supervised GNO process (task .11).
	GNOLabel = "com.homeplane.gno"
)

// Unit is one supervised process, expressed independently of the platform.
type Unit struct {
	// Label is the reverse-DNS identifier (launchd Label; systemd unit stem).
	Label string
	// Description is human-readable; systemd shows it, launchd ignores it.
	Description string
	// Program is an absolute path to the executable.
	Program string
	// Args are its arguments. They must not contain secrets: a unit file is
	// non-secret by construction.
	Args []string
	// Env holds non-secret environment variables.
	Env map[string]string
	// WorkingDir is optional.
	WorkingDir string
	// StdoutPath / StderrPath are optional log destinations.
	StdoutPath string
	StderrPath string
	// KeepAlive restarts the process whenever it exits (launchd KeepAlive /
	// systemd Restart=always). False means restart only on failure.
	KeepAlive bool
	// RunAtLoad starts the process when the unit is loaded.
	RunAtLoad bool
	// ThrottleSeconds is the minimum interval between restarts. A supervisor
	// with no throttle turns a crash into a busy loop.
	ThrottleSeconds int
}

// DefaultThrottleSeconds is the restart floor used when a unit sets none.
const DefaultThrottleSeconds = 10

// Validate rejects units that would render into something unsafe or unloadable.
func (u Unit) Validate() error {
	switch {
	case strings.TrimSpace(u.Label) == "":
		return errors.New("supervise: unit label is required")
	case strings.ContainsAny(u.Label, " \t\n/"):
		return fmt.Errorf("supervise: unit label %q contains whitespace or a path separator", u.Label)
	case strings.TrimSpace(u.Program) == "":
		return errors.New("supervise: unit program is required")
	case !filepath.IsAbs(u.Program):
		return fmt.Errorf("supervise: unit program %q must be an absolute path", u.Program)
	}
	for _, a := range u.Args {
		if strings.ContainsAny(a, "\n\r") {
			return fmt.Errorf("supervise: unit argument %q contains a newline", a)
		}
	}
	for k, v := range u.Env {
		if strings.TrimSpace(k) == "" || strings.ContainsAny(k, "=\n\r") {
			return fmt.Errorf("supervise: invalid environment key %q", k)
		}
		if strings.ContainsAny(v, "\n\r") {
			return fmt.Errorf("supervise: environment value for %q contains a newline", k)
		}
	}
	return nil
}

// AssertNoSecrets fails if any secret appears in the unit's rendered surface.
// Called by the installer on every write: a leaked credential in a 0644 plist
// is exactly the custody failure the spec forbids.
func (u Unit) AssertNoSecrets(secrets ...string) error {
	fields := append([]string{u.Program, u.WorkingDir, u.StdoutPath, u.StderrPath}, u.Args...)
	for k, v := range u.Env {
		fields = append(fields, k, v)
	}
	for _, s := range secrets {
		if strings.TrimSpace(s) == "" {
			continue
		}
		for _, f := range fields {
			if strings.Contains(f, s) {
				return errors.New("supervise: refusing to render a unit containing a secret")
			}
		}
	}
	return nil
}

// FileName is the unit's file name on the given platform.
func (u Unit) FileName(p Platform) (string, error) {
	switch p {
	case Launchd:
		return u.Label + ".plist", nil
	case Systemd:
		return serviceName(u.Label), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, p)
	}
}

// serviceName turns a reverse-DNS label into a systemd unit name, since
// `com.homeplane.sync.service` reads badly in `systemctl --user status`.
func serviceName(label string) string {
	name := label
	if strings.HasPrefix(name, "com.") {
		name = strings.TrimPrefix(name, "com.")
	}
	return strings.ReplaceAll(name, ".", "-") + ".service"
}

var funcs = template.FuncMap{
	"xml":   xmlEscape,
	"shell": shellQuote,
	"quote": func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` },
}

// Render produces the unit file's contents for a platform.
func (u Unit) Render(p Platform) (string, error) {
	if err := u.Validate(); err != nil {
		return "", err
	}
	view := u
	if view.ThrottleSeconds <= 0 {
		view.ThrottleSeconds = DefaultThrottleSeconds
	}
	if view.Description == "" {
		view.Description = view.Label
	}
	var name string
	switch p {
	case Launchd:
		name = "launchd.plist.tmpl"
	case Systemd:
		name = "systemd.service.tmpl"
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, p)
	}
	tmpl, err := template.New(filepath.Base(name)).Funcs(funcs).ParseFS(templateFS, "templates/"+name)
	if err != nil {
		return "", fmt.Errorf("supervise: parse template %s: %w", name, err)
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, view); err != nil {
		return "", fmt.Errorf("supervise: render %s: %w", name, err)
	}
	out := sb.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out, nil
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// shellQuote single-quotes a systemd ExecStart word. systemd parses ExecStart
// with its own quoting rules, and an unquoted path with a space silently
// becomes two arguments.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"\\$") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Installer writes unit files into a directory.
//
// Dir is injected rather than derived, which is what lets the tests install a
// full unit into a temporary directory without ever writing to the developer's
// ~/Library/LaunchAgents.
type Installer struct {
	Platform Platform
	Dir      string
	// Runner executes an activation command. Nil means "render and install
	// only" — the default, because activating a unit is a live-system change.
	Runner func(name string, args ...string) error
}

// DefaultUnitDir is where each platform keeps per-user units.
func DefaultUnitDir(p Platform, home string) (string, error) {
	if strings.TrimSpace(home) == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("supervise: locate home directory: %w", err)
		}
		home = h
	}
	switch p {
	case Launchd:
		return filepath.Join(home, "Library", "LaunchAgents"), nil
	case Systemd:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "systemd", "user"), nil
		}
		return filepath.Join(home, ".config", "systemd", "user"), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPlatform, p)
	}
}

// Path is where a unit's file would live.
func (i Installer) Path(u Unit) (string, error) {
	name, err := u.FileName(i.Platform)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(i.Dir) == "" {
		return "", errors.New("supervise: installer directory is required")
	}
	return filepath.Join(i.Dir, name), nil
}

const unitFilePerm fs.FileMode = 0o644

// Install renders and writes the unit file, refusing any unit that carries one
// of the given secrets.
func (i Installer) Install(u Unit, secrets ...string) (string, error) {
	if err := u.AssertNoSecrets(secrets...); err != nil {
		return "", err
	}
	contents, err := u.Render(i.Platform)
	if err != nil {
		return "", err
	}
	path, err := i.Path(u)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("supervise: create unit directory: %w", err)
	}
	// Atomic: a re-install that dies mid-write must never leave a truncated unit
	// behind. A half-written plist is a unit the supervisor refuses to load, and
	// the caller's rollback cannot tell a corrupt file from a replaced one.
	if err := writeFileAtomic(path, []byte(contents), unitFilePerm); err != nil {
		return "", fmt.Errorf("supervise: write unit %s: %w", path, err)
	}
	return path, nil
}

// Uninstall removes the unit file. A missing file is success.
func (i Installer) Uninstall(u Unit) error {
	path, err := i.Path(u)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("supervise: remove unit %s: %w", path, err)
	}
	return nil
}

// Command is one activation step, kept as data so it can be printed to an
// operator, recorded in evidence, or executed through a runner.
type Command struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

// String renders the command the way an operator would type it.
func (c Command) String() string {
	return strings.TrimSpace(c.Name + " " + strings.Join(c.Args, " "))
}

// ActivationCommands are the steps that make an installed unit actually run.
//
// On systemd this includes `loginctl enable-linger`, without which a user unit
// dies at logout — precisely the "sync stopped and nobody noticed" failure R14
// is about.
func (i Installer) ActivationCommands(u Unit, uid string) ([]Command, error) {
	path, err := i.Path(u)
	if err != nil {
		return nil, err
	}
	switch i.Platform {
	case Launchd:
		target := "gui/" + uid
		return []Command{
			{Name: "launchctl", Args: []string{"bootstrap", target, path}},
			{Name: "launchctl", Args: []string{"enable", target + "/" + u.Label}},
			{Name: "launchctl", Args: []string{"kickstart", "-k", target + "/" + u.Label}},
		}, nil
	case Systemd:
		name := serviceName(u.Label)
		return []Command{
			{Name: "loginctl", Args: []string{"enable-linger"}},
			{Name: "systemctl", Args: []string{"--user", "daemon-reload"}},
			{Name: "systemctl", Args: []string{"--user", "enable", "--now", name}},
		}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, i.Platform)
	}
}

// StopCommands halt a running unit WITHOUT forgetting it.
//
// This is distinct from deactivation, and the distinction matters: an operator
// rebuilding a machine-local index needs the supervised process to let go of its
// files for a moment, not to be uninstalled. On launchd, stopping a KeepAlive
// job means booting it out of the session — `launchctl stop` is undone
// immediately by KeepAlive — so the unit FILE stays on disk and StartCommands
// bootstraps it back.
func (i Installer) StopCommands(u Unit, uid string) ([]Command, error) {
	path, err := i.Path(u)
	if err != nil {
		return nil, err
	}
	switch i.Platform {
	case Launchd:
		return []Command{{Name: "launchctl", Args: []string{"bootout", "gui/" + uid, path}}}, nil
	case Systemd:
		return []Command{{Name: "systemctl", Args: []string{"--user", "stop", serviceName(u.Label)}}}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, i.Platform)
	}
}

// StartCommands bring a stopped unit back up.
func (i Installer) StartCommands(u Unit, uid string) ([]Command, error) {
	path, err := i.Path(u)
	if err != nil {
		return nil, err
	}
	switch i.Platform {
	case Launchd:
		target := "gui/" + uid
		return []Command{
			{Name: "launchctl", Args: []string{"bootstrap", target, path}},
			{Name: "launchctl", Args: []string{"kickstart", "-k", target + "/" + u.Label}},
		}, nil
	case Systemd:
		return []Command{{Name: "systemctl", Args: []string{"--user", "start", serviceName(u.Label)}}}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, i.Platform)
	}
}

// DeactivationCommands stop and unload an installed unit.
func (i Installer) DeactivationCommands(u Unit, uid string) ([]Command, error) {
	path, err := i.Path(u)
	if err != nil {
		return nil, err
	}
	switch i.Platform {
	case Launchd:
		return []Command{{Name: "launchctl", Args: []string{"bootout", "gui/" + uid, path}}}, nil
	case Systemd:
		return []Command{{Name: "systemctl", Args: []string{"--user", "disable", "--now", serviceName(u.Label)}}}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, i.Platform)
	}
}

// Activate runs the activation commands through the injected runner. Without a
// runner it reports what it WOULD run and changes nothing, so the default
// behaviour of this package is never to mutate a live session.
func (i Installer) Activate(u Unit, uid string) ([]Command, error) {
	cmds, err := i.ActivationCommands(u, uid)
	if err != nil {
		return nil, err
	}
	if i.Runner == nil {
		return cmds, nil
	}
	for _, c := range cmds {
		if err := i.Runner(c.Name, c.Args...); err != nil {
			return cmds, fmt.Errorf("supervise: %s: %w", c, err)
		}
	}
	return cmds, nil
}
