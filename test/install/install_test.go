// Package install_test exercises install.sh.
//
// The installer's guarantees are all about what it does NOT do — not install
// on an unsupported machine, not place a binary whose checksum is wrong, not
// leave a half-installed agent behind — so the tests here mostly assert
// absence. They drive the platform matrix through the installer's documented
// test hooks rather than requiring a fleet of machines.
package install_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func installScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "install.sh")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("install.sh not found: %v", err)
	}
	return path
}

// stage builds a staged, checksummed release directory: a fake agent binary
// plus a SHA256SUMS manifest, exactly the shape install.sh consumes.
type stage struct {
	dir      string
	manifest map[string]string // artifact name -> recorded checksum
}

func newStage(t *testing.T) *stage {
	t.Helper()
	return &stage{dir: t.TempDir(), manifest: map[string]string{}}
}

// addArtifact writes a file and records its REAL checksum.
func (s *stage) addArtifact(t *testing.T, name string, content []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(s.dir, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	sum := sha256.Sum256(content)
	s.manifest[name] = hex.EncodeToString(sum[:])
}

// corrupt rewrites an artifact's bytes WITHOUT updating the manifest — the
// tampered-download case.
func (s *stage) corrupt(t *testing.T, name string) {
	t.Helper()
	path := filepath.Join(s.dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatalf("corrupt %s: %v", name, err)
	}
}

func (s *stage) writeManifest(t *testing.T) {
	t.Helper()
	var b strings.Builder
	for name, sum := range s.manifest {
		fmt.Fprintf(&b, "%s  %s\n", sum, name)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "SHA256SUMS"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// hostPlatform is the (os, arch) pair install.sh would compute here; tests
// override it where they mean to exercise a different machine.
func hostPlatform() (string, string) {
	arch := runtime.GOARCH
	if arch != "arm64" {
		arch = "amd64"
	}
	return runtime.GOOS, arch
}

type runOpts struct {
	stage  *stage
	prefix string
	env    map[string]string
}

type runResult struct {
	code   int
	output string
}

func runInstaller(t *testing.T, opts runOpts) runResult {
	t.Helper()
	cmd := exec.Command("bash", installScript(t))
	cmd.Env = append(os.Environ(),
		"HOMEPLANE_STAGE_DIR="+opts.stage.dir,
		"HOMEPLANE_PREFIX="+opts.prefix,
		// Default: pretend a supported supervisor exists and Node 22 is already
		// installed. Individual tests override these to exercise the gates.
		"HOMEPLANE_INIT_OVERRIDE="+defaultInit(),
		"HOMEPLANE_NODE_BIN="+fakeNode(t, 22),
		// ...and that Bun 1.3 is already installed. Both runtimes are
		// prerequisites, so a default for one without the other would make
		// every unrelated test depend on whatever the developer's machine
		// happens to have.
		"HOMEPLANE_BUN_BIN="+fakeBun(t, "1.3.11"),
	)
	cmd.Env = append(cmd.Env, supportedHostEnv()...)
	for k, v := range opts.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if err != nil {
		if ok := asExitError(err, &exitErr); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run install.sh: %v", err)
		}
	}
	return runResult{code: code, output: string(out)}
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func defaultInit() string {
	if runtime.GOOS == "darwin" {
		return "launchd"
	}
	return "systemd"
}

// supportedHostEnv pins the supported-host probes to a supported answer, for
// the same reason the runtimes are faked: otherwise every unrelated installer
// test would depend on the macOS version, the user bus and the logind state of
// whatever machine runs the suite. The gate itself is exercised by the tests
// that override these.
func supportedHostEnv() []string {
	return []string{
		"HOMEPLANE_MACOS_VERSION=14.0",
		"HOMEPLANE_USER_MANAGER_STATE=running",
		"HOMEPLANE_LINGER_STATE=yes",
	}
}

// fakeNode writes a stand-in `node` that reports the given major version, so
// the Node gate can be tested without installing a real runtime.
func fakeNode(t *testing.T, major int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "node")
	script := fmt.Sprintf("#!/bin/sh\necho v%d.0.0\n", major)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake node: %v", err)
	}
	return path
}

// fakeBun writes a stand-in `bun` reporting the given version, so the Bun gate
// can be tested without a real runtime.
func fakeBun(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bun")
	script := fmt.Sprintf("#!/bin/sh\necho %s\n", version)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake bun: %v", err)
	}
	return path
}

func stagedAgent(t *testing.T) (*stage, string) {
	t.Helper()
	osName, arch := hostPlatform()
	s := newStage(t)
	artifact := fmt.Sprintf("homeplane-agent-%s-%s", osName, arch)
	s.addArtifact(t, artifact, []byte("#!/bin/sh\necho homeplane-agent stub\n"), 0o755)
	s.writeManifest(t)
	return s, artifact
}

func installedBinary(prefix string) string { return filepath.Join(prefix, "bin", "homeplane-agent") }

func assertNotInstalled(t *testing.T, prefix string) {
	t.Helper()
	if _, err := os.Stat(installedBinary(prefix)); !os.IsNotExist(err) {
		t.Errorf("a binary was installed at %s despite the failure (stat err: %v)", installedBinary(prefix), err)
	}
}

func TestInstallPlacesTheAgentAndIsIdempotent(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	first := runInstaller(t, runOpts{stage: s, prefix: prefix})
	if first.code != 0 {
		t.Fatalf("install exit = %d:\n%s", first.code, first.output)
	}
	info, err := os.Stat(installedBinary(prefix))
	if err != nil {
		t.Fatalf("agent was not installed: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed binary is not executable (mode %o)", info.Mode().Perm())
	}

	// A re-run is a refresh, not a second installation, and it must not disturb
	// enrolment state living under the same prefix.
	stateFile := filepath.Join(prefix, "state.json")
	if err := os.WriteFile(stateFile, []byte(`{"machine_id":"m-1"}`), 0o600); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	second := runInstaller(t, runOpts{stage: s, prefix: prefix})
	if second.code != 0 {
		t.Fatalf("re-run exit = %d:\n%s", second.code, second.output)
	}
	if _, err := os.Stat(installedBinary(prefix)); err != nil {
		t.Errorf("agent missing after re-run: %v", err)
	}
	kept, err := os.ReadFile(stateFile)
	if err != nil || string(kept) != `{"machine_id":"m-1"}` {
		t.Errorf("re-running the installer disturbed enrolment state: %q (err %v)", string(kept), err)
	}
	entries, err := os.ReadDir(filepath.Join(prefix, "bin"))
	if err != nil {
		t.Fatalf("read bin: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "incoming") {
			t.Errorf("installer left a staging file behind: %s", e.Name())
		}
	}
}

func TestTamperedArtifactAbortsWithNoPartialInstall(t *testing.T) {
	s, artifact := stagedAgent(t)
	s.corrupt(t, artifact)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{stage: s, prefix: prefix})
	if res.code == 0 {
		t.Fatalf("installer accepted a tampered artifact:\n%s", res.output)
	}
	if !strings.Contains(res.output, "checksum mismatch") {
		t.Errorf("output does not name the checksum mismatch:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestUnlistedArtifactIsRefused(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	// Stage the artifact but leave the manifest empty: unverifiable is refused
	// exactly like mismatched.
	artifact := fmt.Sprintf("homeplane-agent-%s-%s", osName, arch)
	path := filepath.Join(s.dir, artifact)
	if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	s.writeManifest(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{stage: s, prefix: prefix})
	if res.code == 0 {
		t.Fatalf("installer accepted an artifact with no manifest entry:\n%s", res.output)
	}
	if !strings.Contains(res.output, "no entry") {
		t.Errorf("output does not explain the missing manifest entry:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestMissingManifestIsRefused(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	if err := os.WriteFile(filepath.Join(s.dir, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch)),
		[]byte("stub"), 0o755); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{stage: s, prefix: prefix})
	if res.code == 0 {
		t.Fatalf("installer ran without a checksum manifest:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestUnsupportedInitSystemIsRejectedBeforeInstalling(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_UNAME_S": "Linux", "HOMEPLANE_INIT_OVERRIDE": "none"},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted a non-systemd Linux machine:\n%s", res.output)
	}
	if !strings.Contains(res.output, "systemd") {
		t.Errorf("rejection does not explain the requirement:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

// The supported set (R1) is macOS 13+ and a Linux whose user service manager
// actually works. The three tests below are the negative half of that gate:
// each machine has the right OS and the right binaries on PATH and is still
// outside the supported set, which is exactly the case a presence check misses.

func TestOldMacOSIsRejectedBeforeInstalling(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env: map[string]string{
			"HOMEPLANE_UNAME_S":       "Darwin",
			"HOMEPLANE_INIT_OVERRIDE": "launchd",
			"HOMEPLANE_MACOS_VERSION": "12.7.4",
		},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted macOS 12:\n%s", res.output)
	}
	if !strings.Contains(res.output, "macOS 12.7.4 is not supported") {
		t.Errorf("rejection does not name the version floor:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestUnreadableMacOSVersionIsRejectedBeforeInstalling(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env: map[string]string{
			"HOMEPLANE_UNAME_S":       "Darwin",
			"HOMEPLANE_INIT_OVERRIDE": "launchd",
			"HOMEPLANE_MACOS_VERSION": "not-a-version",
		},
	})
	if res.code == 0 {
		t.Fatalf("an unreadable macOS version was treated as supported:\n%s", res.output)
	}
	if !strings.Contains(res.output, "could not read this machine's macOS version") {
		t.Errorf("rejection message = %q", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestLinuxWithoutAUsableUserManagerIsRejectedBeforeInstalling(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
		want  string
	}{
		{name: "no user bus", state: "", want: "could not reach a user service manager"},
		{name: "offline", state: "offline", want: "is 'offline', not running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := stagedAgent(t)
			prefix := filepath.Join(t.TempDir(), "homeplane")

			res := runInstaller(t, runOpts{
				stage:  s,
				prefix: prefix,
				env: map[string]string{
					"HOMEPLANE_UNAME_S":            "Linux",
					"HOMEPLANE_INIT_OVERRIDE":      "systemd",
					"HOMEPLANE_USER_MANAGER_STATE": tc.state,
					"HOMEPLANE_LINGER_STATE":       "yes",
				},
			})
			if res.code == 0 {
				t.Fatalf("installer accepted a Linux machine with no usable user manager:\n%s", res.output)
			}
			if !strings.Contains(res.output, tc.want) {
				t.Errorf("rejection does not name the fault (want %q):\n%s", tc.want, res.output)
			}
			assertNotInstalled(t, prefix)
		})
	}
}

func TestLinuxWithoutLingerAvailabilityIsRejectedBeforeInstalling(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env: map[string]string{
			"HOMEPLANE_UNAME_S":            "Linux",
			"HOMEPLANE_INIT_OVERRIDE":      "systemd",
			"HOMEPLANE_USER_MANAGER_STATE": "running",
			// logind cannot answer for this user at all: enable-linger would
			// fail later and the services would stop at logout.
			"HOMEPLANE_LINGER_STATE": "",
		},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted a machine where lingering cannot be read:\n%s", res.output)
	}
	if !strings.Contains(res.output, "could not report the lingering state") {
		t.Errorf("rejection message = %q", res.output)
	}
	assertNotInstalled(t, prefix)
}

// Lingering that is merely OFF is not a refusal: the agent enables it when it
// activates its services, so the installer says so and proceeds.
func TestLingerOffIsAcceptedWithANotice(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env: map[string]string{
			"HOMEPLANE_UNAME_S":            "Linux",
			"HOMEPLANE_INIT_OVERRIDE":      "systemd",
			"HOMEPLANE_USER_MANAGER_STATE": "running",
			"HOMEPLANE_LINGER_STATE":       "no",
		},
	})
	if !strings.Contains(res.output, "lingering is off") {
		t.Errorf("installer did not mention that lingering is off:\n%s", res.output)
	}
	// The run itself stops later for a platform reason (the staged artifact is
	// this host's, not the faked Linux one); what matters is that the host gate
	// did not reject the machine.
	if strings.Contains(res.output, "Nothing has been installed.") {
		t.Errorf("lingering being off was treated as an unsupported host:\n%s", res.output)
	}
}

func TestUnsupportedOperatingSystemIsRejected(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_UNAME_S": "FreeBSD"},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted FreeBSD:\n%s", res.output)
	}
	if !strings.Contains(res.output, "unsupported operating system") {
		t.Errorf("rejection message = %q", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestUnsupportedArchitectureIsRejected(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_UNAME_M": "riscv64"},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted riscv64:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestAnArtifactThatCannotRunHereIsRefusedAndLeavesTheOldAgentInPlace(t *testing.T) {
	osName, arch := hostPlatform()
	prefix := filepath.Join(t.TempDir(), "homeplane")

	good, _ := stagedAgent(t)
	if res := runInstaller(t, runOpts{stage: good, prefix: prefix}); res.code != 0 {
		t.Fatalf("first install exit = %d:\n%s", res.code, res.output)
	}

	// Checksum-valid bytes that are not runnable on this machine — what a
	// wrong-platform artifact looks like from the installer's point of view.
	broken := newStage(t)
	broken.addArtifact(t, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch),
		[]byte("\x7fELF-but-not-for-this-machine\x00\x00"), 0o755)
	broken.writeManifest(t)

	res := runInstaller(t, runOpts{stage: broken, prefix: prefix})
	if res.code == 0 {
		t.Fatalf("installer accepted an artifact that cannot run here:\n%s", res.output)
	}
	if !strings.Contains(res.output, "did not run") {
		t.Errorf("output does not explain the failure:\n%s", res.output)
	}
	installed, err := os.ReadFile(installedBinary(prefix))
	if err != nil {
		t.Fatalf("the previously installed agent was destroyed: %v", err)
	}
	if !strings.Contains(string(installed), "homeplane-agent stub") {
		t.Error("the working agent was replaced by the unrunnable artifact")
	}
}

func TestMissingNodeWithoutAProvisioningSourceFailsTheInstall(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		// A node that reports v18: present, but too old. There is no staged
		// tarball and package provisioning is not opted into.
		env: map[string]string{"HOMEPLANE_NODE_BIN": fakeNode(t, 18)},
	})
	if res.code == 0 {
		t.Fatalf("installer succeeded on a machine with no usable Node:\n%s", res.output)
	}
	if !strings.Contains(res.output, "node >= 22") {
		t.Errorf("failure does not name the Node prerequisite:\n%s", res.output)
	}
	// "Degraded-only is not acceptable for a supported platform": no binary.
	assertNotInstalled(t, prefix)
}

func TestNodeIsProvisionedFromTheChecksummedTarball(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	artifact := fmt.Sprintf("homeplane-agent-%s-%s", osName, arch)
	s.addArtifact(t, artifact, []byte("#!/bin/sh\necho homeplane-agent stub\n"), 0o755)

	nodeArch := "x64"
	if arch == "arm64" {
		nodeArch = "arm64"
	}
	archiveName := fmt.Sprintf("node-v22.11.0-%s-%s.tar.gz", osName, nodeArch)
	s.addArtifact(t, archiveName, fakeNodeTarball(t, "node-v22.11.0-"+osName+"-"+nodeArch, 22), 0o644)
	s.writeManifest(t)

	prefix := filepath.Join(t.TempDir(), "homeplane")
	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_NODE_BIN": fakeNode(t, 18)},
	})
	if res.code != 0 {
		t.Fatalf("install with a staged node tarball exit = %d:\n%s", res.code, res.output)
	}
	if _, err := os.Stat(filepath.Join(prefix, "node", "bin", "node")); err != nil {
		t.Errorf("node was not provisioned into the prefix: %v", err)
	}
	link, err := os.Readlink(filepath.Join(prefix, "bin", "node"))
	if err != nil {
		t.Errorf("no node symlink in bin: %v", err)
	} else if !strings.HasSuffix(link, "node/bin/node") {
		t.Errorf("node symlink points at %q", link)
	}
	if _, err := os.Stat(installedBinary(prefix)); err != nil {
		t.Errorf("agent was not installed: %v", err)
	}
}

func TestTamperedNodeTarballAbortsBeforeInstallingTheAgent(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	artifact := fmt.Sprintf("homeplane-agent-%s-%s", osName, arch)
	s.addArtifact(t, artifact, []byte("#!/bin/sh\necho stub\n"), 0o755)

	nodeArch := "x64"
	if arch == "arm64" {
		nodeArch = "arm64"
	}
	archiveName := fmt.Sprintf("node-v22.11.0-%s-%s.tar.gz", osName, nodeArch)
	s.addArtifact(t, archiveName, fakeNodeTarball(t, "node-v22.11.0-"+osName+"-"+nodeArch, 22), 0o644)
	s.writeManifest(t)
	s.corrupt(t, archiveName)

	prefix := filepath.Join(t.TempDir(), "homeplane")
	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_NODE_BIN": fakeNode(t, 18)},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted a tampered node tarball:\n%s", res.output)
	}
	if !strings.Contains(res.output, "checksum mismatch") {
		t.Errorf("output does not name the mismatch:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
	if _, err := os.Stat(filepath.Join(prefix, "node")); !os.IsNotExist(err) {
		t.Errorf("a node directory survived the aborted install (stat err: %v)", err)
	}
}

// stageWithNode builds a staging dir holding the agent plus a node tarball
// whose runtime reports the given major version.
func stageWithNode(t *testing.T, nodeMajor int) *stage {
	t.Helper()
	osName, arch := hostPlatform()
	nodeArch := "x64"
	if arch == "arm64" {
		nodeArch = "arm64"
	}
	root := fmt.Sprintf("node-v22.11.0-%s-%s", osName, nodeArch)

	s := newStage(t)
	s.addArtifact(t, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch),
		[]byte("#!/bin/sh\necho homeplane-agent stub\n"), 0o755)
	s.addArtifact(t, root+".tar.gz", fakeNodeTarball(t, root, nodeMajor), 0o644)
	s.writeManifest(t)
	return s
}

// TestAFailedInstallRestoresThePreviousNodeRuntime is the atomicity guarantee:
// a checksum-valid but malformed release must not be able to destroy the
// runtime a working machine already has.
func TestAFailedInstallRestoresThePreviousNodeRuntime(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "homeplane")
	noNode := map[string]string{"HOMEPLANE_NODE_BIN": filepath.Join(t.TempDir(), "absent")}

	good := stageWithNode(t, 22)
	if res := runInstaller(t, runOpts{stage: good, prefix: prefix, env: noNode}); res.code != 0 {
		t.Fatalf("first install exit = %d:\n%s", res.code, res.output)
	}
	nodeBin := filepath.Join(prefix, "node", "bin", "node")
	before, err := exec.Command(nodeBin, "--version").Output()
	if err != nil {
		t.Fatalf("provisioned node does not run: %v", err)
	}

	// A release whose Node is checksum-valid but too old — the malformed-release
	// case. It is only detectable by running the extracted runtime.
	bad := stageWithNode(t, 18)
	res := runInstaller(t, runOpts{stage: bad, prefix: prefix, env: noNode})
	if res.code == 0 {
		t.Fatalf("installer accepted a release whose node reports v18:\n%s", res.output)
	}

	after, err := exec.Command(nodeBin, "--version").Output()
	if err != nil {
		t.Fatalf("the working node runtime did not survive the failed install: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("node runtime changed across a failed install: %q -> %q", before, after)
	}
	if _, err := os.Stat(installedBinary(prefix)); err != nil {
		t.Errorf("the agent did not survive the failed install: %v", err)
	}
	if _, err := os.Stat(filepath.Join(prefix, "node.previous")); !os.IsNotExist(err) {
		t.Errorf("a node.previous directory was left behind (stat err: %v)", err)
	}
}

// TestAFailureAfterTheNodeSwapRollsTheRuntimeBack exercises the rollback trap
// itself: the failure happens AFTER the new runtime has been moved into the
// prefix, which is the only window in which the previous one can be lost.
func TestAFailureAfterTheNodeSwapRollsTheRuntimeBack(t *testing.T) {
	prefix := filepath.Join(t.TempDir(), "homeplane")
	noNode := map[string]string{"HOMEPLANE_NODE_BIN": filepath.Join(t.TempDir(), "absent")}

	first := stageWithNode(t, 22)
	if res := runInstaller(t, runOpts{stage: first, prefix: prefix, env: noNode}); res.code != 0 {
		t.Fatalf("first install exit = %d:\n%s", res.code, res.output)
	}
	// A marker identifies THIS runtime directory, so the assertion below can
	// tell a restored runtime from a newly extracted one.
	marker := filepath.Join(prefix, "node", "INSTALLED-FIRST")
	if err := os.WriteFile(marker, []byte("original"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	// Make the bin directory read-only: the runtime swap succeeds, and the very
	// next step (symlink/agent placement) fails.
	binDir := filepath.Join(prefix, "bin")
	if err := os.Chmod(binDir, 0o555); err != nil {
		t.Fatalf("chmod bin: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(binDir, 0o755) })

	second := stageWithNode(t, 22)
	res := runInstaller(t, runOpts{stage: second, prefix: prefix, env: noNode})
	if res.code == 0 {
		t.Fatalf("install succeeded despite an unwritable bin directory:\n%s", res.output)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the original node runtime was not restored after the failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(prefix, "node.previous")); !os.IsNotExist(err) {
		t.Errorf("node.previous was left behind (stat err: %v)", err)
	}
	if !strings.Contains(res.output, "restored the previous node runtime") {
		t.Errorf("the rollback was not reported to the operator:\n%s", res.output)
	}
}

// TestAReleaseWithoutABundledNodeBinaryIsRejectedBeforeTheSwap covers the other
// malformed shape: an archive that extracts but contains no runtime at all.
func TestAReleaseWithoutABundledNodeBinaryIsRejectedBeforeTheSwap(t *testing.T) {
	osName, arch := hostPlatform()
	nodeArch := "x64"
	if arch == "arm64" {
		nodeArch = "arm64"
	}
	prefix := filepath.Join(t.TempDir(), "homeplane")
	noNode := map[string]string{"HOMEPLANE_NODE_BIN": filepath.Join(t.TempDir(), "absent")}

	good := stageWithNode(t, 22)
	if res := runInstaller(t, runOpts{stage: good, prefix: prefix, env: noNode}); res.code != 0 {
		t.Fatalf("first install exit = %d:\n%s", res.code, res.output)
	}

	empty := newStage(t)
	empty.addArtifact(t, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch),
		[]byte("#!/bin/sh\necho stub\n"), 0o755)
	empty.addArtifact(t, fmt.Sprintf("node-v22.11.0-%s-%s.tar.gz", osName, nodeArch),
		emptyTarball(t, fmt.Sprintf("node-v22.11.0-%s-%s", osName, nodeArch)), 0o644)
	empty.writeManifest(t)

	res := runInstaller(t, runOpts{stage: empty, prefix: prefix, env: noNode})
	if res.code == 0 {
		t.Fatalf("installer accepted an archive with no bin/node:\n%s", res.output)
	}
	if _, err := exec.Command(filepath.Join(prefix, "node", "bin", "node"), "--version").Output(); err != nil {
		t.Errorf("the working node runtime did not survive: %v", err)
	}
}

// fakeNodeTarball builds a gzipped tar shaped like a Node release: a single
// top-level directory containing bin/node.
func fakeNodeTarball(t *testing.T, root string, major int) []byte {
	t.Helper()
	var buf strings.Builder
	gz := gzip.NewWriter(&stringWriter{&buf})
	tw := tar.NewWriter(gz)

	script := fmt.Sprintf("#!/bin/sh\necho v%d.11.0\n", major)
	entries := []struct {
		name string
		mode int64
		body string
		dir  bool
	}{
		{name: root + "/", mode: 0o755, dir: true},
		{name: root + "/bin/", mode: 0o755, dir: true},
		{name: root + "/bin/node", mode: 0o755, body: script},
	}
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body))}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
		} else {
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if !e.dir {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("tar body: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return []byte(buf.String())
}

// emptyTarball builds a release-shaped archive whose top-level directory holds
// no runtime at all.
func emptyTarball(t *testing.T, root string) []byte {
	t.Helper()
	var buf strings.Builder
	gz := gzip.NewWriter(&stringWriter{&buf})
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: root + "/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return []byte(buf.String())
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }
