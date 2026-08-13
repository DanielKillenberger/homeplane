package supervise

import (
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests validate unit files STRUCTURALLY — the plist is parsed as XML and
// linted with `plutil` where it exists, the systemd unit is checked with
// `systemd-analyze verify` where it exists. Nothing here installs a unit into
// the developer's own launchd or systemd session: units are written into
// temporary directories, and activation runs only through an injected runner.

func syncUnit() Unit {
	return Unit{
		Label:           "com.homeplane.vault-sync",
		Description:     "Homeplane: continuous Obsidian Sync",
		Program:         "/opt/homeplane/bin/homeplane-agent",
		Args:            []string{"vault", "sync", "run", "-state-dir", "/Users/d/.homeplane"},
		WorkingDir:      "/Users/d/.homeplane",
		StdoutPath:      "/Users/d/.homeplane/logs/vault-sync.log",
		StderrPath:      "/Users/d/.homeplane/logs/vault-sync.err.log",
		KeepAlive:       true,
		RunAtLoad:       true,
		ThrottleSeconds: 10,
	}
}

func TestRenderLaunchdPlistIsWellFormed(t *testing.T) {
	out, err := syncUnit().Render(Launchd)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if err := xml.Unmarshal([]byte(out), new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("plist is not well-formed XML: %v\n%s", err, out)
	}
	for _, want := range []string{
		"<key>Label</key>", "com.homeplane.vault-sync",
		"<key>KeepAlive</key>", "<true/>",
		"<key>ThrottleInterval</key>", "<integer>10</integer>",
		"vault", "sync", "run",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("plist missing %q:\n%s", want, out)
		}
	}
	lintPlist(t, out)
}

func TestRenderSystemdUnitIsWellFormed(t *testing.T) {
	out, err := syncUnit().Render(Systemd)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"[Unit]", "[Service]", "[Install]",
		"ExecStart=/opt/homeplane/bin/homeplane-agent vault sync run",
		"Restart=always", "RestartSec=10", "WantedBy=default.target",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("unit missing %q:\n%s", want, out)
		}
	}
	verifySystemdUnit(t, out)
}

// A path with a space must survive as ONE argument, or the supervised process
// silently syncs the wrong directory.
func TestRenderQuotesPathsWithSpaces(t *testing.T) {
	u := syncUnit()
	u.Args = []string{"vault", "sync", "run", "-state-dir", "/Users/d/My State"}

	plist, err := u.Render(Launchd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plist, "<string>/Users/d/My State</string>") {
		t.Fatalf("plist split the path:\n%s", plist)
	}

	unit, err := u.Render(Systemd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(unit, `'/Users/d/My State'`) {
		t.Fatalf("systemd unit did not quote the path:\n%s", unit)
	}
}

func TestRenderEscapesXML(t *testing.T) {
	u := syncUnit()
	u.Args = []string{"vault", "sync", "run", "-state-dir", `/tmp/a&b<c>"d"`}
	out, err := u.Render(Launchd)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "a&b") {
		t.Fatalf("ampersand was not escaped:\n%s", out)
	}
	if err := xml.Unmarshal([]byte(out), new(struct {
		XMLName xml.Name `xml:"plist"`
	})); err != nil {
		t.Fatalf("plist is not well-formed after escaping: %v\n%s", err, out)
	}
}

func TestValidateRejectsBadUnits(t *testing.T) {
	cases := map[string]func(*Unit){
		"no label":       func(u *Unit) { u.Label = "" },
		"label with /":   func(u *Unit) { u.Label = "com/homeplane" },
		"no program":     func(u *Unit) { u.Program = "" },
		"relative path":  func(u *Unit) { u.Program = "homeplane-agent" },
		"newline arg":    func(u *Unit) { u.Args = []string{"a\nb"} },
		"bad env key":    func(u *Unit) { u.Env = map[string]string{"A=B": "x"} },
		"newline in env": func(u *Unit) { u.Env = map[string]string{"A": "x\ny"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := syncUnit()
			mutate(&u)
			if err := u.Validate(); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// A unit file is world-readable; a credential inside one is a custody failure.
func TestInstallRefusesAUnitCarryingASecret(t *testing.T) {
	u := syncUnit()
	u.Env = map[string]string{"OBSIDIAN_SYNC_PASSWORD": "hunter2"}
	i := Installer{Platform: Launchd, Dir: t.TempDir()}

	if _, err := i.Install(u, "hunter2"); err == nil {
		t.Fatal("a unit containing the credential was installed")
	}
	entries, _ := os.ReadDir(i.Dir)
	if len(entries) != 0 {
		t.Fatal("a rejected unit still wrote a file")
	}
}

func TestInstallAndUninstall(t *testing.T) {
	for _, p := range []Platform{Launchd, Systemd} {
		t.Run(string(p), func(t *testing.T) {
			i := Installer{Platform: p, Dir: filepath.Join(t.TempDir(), "units")}
			u := syncUnit()

			path, err := i.Install(u)
			if err != nil {
				t.Fatalf("Install: %v", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("unit not written: %v", err)
			}
			if err := i.Uninstall(u); err != nil {
				t.Fatalf("Uninstall: %v", err)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unit survived uninstall: %v", err)
			}
			// Uninstalling twice is not an error: converging on "absent" must be
			// idempotent for a re-run to be safe.
			if err := i.Uninstall(u); err != nil {
				t.Fatalf("second Uninstall: %v", err)
			}
		})
	}
}

func TestFileNames(t *testing.T) {
	u := syncUnit()
	plist, err := u.FileName(Launchd)
	if err != nil {
		t.Fatal(err)
	}
	if plist != "com.homeplane.vault-sync.plist" {
		t.Fatalf("plist name = %q", plist)
	}
	service, err := u.FileName(Systemd)
	if err != nil {
		t.Fatal(err)
	}
	if service != "homeplane-vault-sync.service" {
		t.Fatalf("service name = %q", service)
	}
	if _, err := u.FileName("windows"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("err = %v, want ErrUnsupportedPlatform", err)
	}
}

// Linger is what keeps a systemd user unit alive across logout — its absence is
// exactly the "sync quietly stopped" failure R14 forbids.
func TestActivationCommandsIncludeLinger(t *testing.T) {
	i := Installer{Platform: Systemd, Dir: t.TempDir()}
	cmds, err := i.ActivationCommands(syncUnit(), "1000")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commandStrings(cmds), "; ")
	for _, want := range []string{"loginctl enable-linger", "systemctl --user daemon-reload", "systemctl --user enable --now homeplane-vault-sync.service"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("activation commands missing %q: %s", want, joined)
		}
	}
}

func TestLaunchdActivationTargetsTheUserSession(t *testing.T) {
	i := Installer{Platform: Launchd, Dir: t.TempDir()}
	cmds, err := i.ActivationCommands(syncUnit(), "501")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(commandStrings(cmds), "; ")
	if !strings.Contains(joined, "gui/501") {
		t.Fatalf("launchd activation does not target gui/501: %s", joined)
	}
	if strings.Contains(joined, "system/") {
		t.Fatalf("launchd activation targets the system domain: %s", joined)
	}
}

// The default is inert: no runner, no live-session change.
func TestActivateWithoutRunnerChangesNothing(t *testing.T) {
	i := Installer{Platform: Launchd, Dir: t.TempDir()}
	cmds, err := i.Activate(syncUnit(), "501")
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if len(cmds) == 0 {
		t.Fatal("Activate reported no commands")
	}
}

func TestActivatePropagatesRunnerFailure(t *testing.T) {
	boom := errors.New("launchctl exploded")
	i := Installer{
		Platform: Launchd,
		Dir:      t.TempDir(),
		Runner:   func(string, ...string) error { return boom },
	}
	if _, err := i.Activate(syncUnit(), "501"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the runner's error", err)
	}
}

func TestDetectPlatform(t *testing.T) {
	if p, err := DetectPlatform("darwin"); err != nil || p != Launchd {
		t.Fatalf("darwin -> %v, %v", p, err)
	}
	if p, err := DetectPlatform("linux"); err != nil || p != Systemd {
		t.Fatalf("linux -> %v, %v", p, err)
	}
	if _, err := DetectPlatform("plan9"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("err = %v, want ErrUnsupportedPlatform", err)
	}
}

func TestDefaultUnitDir(t *testing.T) {
	dir, err := DefaultUnitDir(Launchd, "/Users/d")
	if err != nil || dir != "/Users/d/Library/LaunchAgents" {
		t.Fatalf("launchd dir = %q, %v", dir, err)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	dir, err = DefaultUnitDir(Systemd, "/home/d")
	if err != nil || dir != "/home/d/.config/systemd/user" {
		t.Fatalf("systemd dir = %q, %v", dir, err)
	}
}

func commandStrings(cmds []Command) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, c.String())
	}
	return out
}

// lintPlist runs `plutil -lint` when it exists (macOS), and is a no-op
// elsewhere: the structural XML assertions above already ran.
func lintPlist(t *testing.T, contents string) {
	t.Helper()
	bin, err := exec.LookPath("plutil")
	if err != nil {
		t.Log("plutil unavailable; relying on the XML parse")
		return
	}
	path := filepath.Join(t.TempDir(), "unit.plist")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-lint", path).CombinedOutput(); err != nil {
		t.Fatalf("plutil -lint failed: %v\n%s\n%s", err, out, contents)
	}
}

// verifySystemdUnit runs `systemd-analyze verify` when it exists (Linux).
func verifySystemdUnit(t *testing.T, contents string) {
	t.Helper()
	bin, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Log("systemd-analyze unavailable; relying on the section assertions")
		return
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "homeplane-vault-sync.service")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "verify", "--user", path).CombinedOutput()
	if err != nil && strings.Contains(string(out), "Failed to parse") {
		t.Fatalf("systemd-analyze rejected the unit: %v\n%s\n%s", err, out, contents)
	}
}
