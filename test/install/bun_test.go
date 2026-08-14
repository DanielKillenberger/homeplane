package install_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Bun is a prerequisite in its own right, not a Node substitute: vault sync
// runs on Node (obsidian-headless) and the retrieval engine runs on Bun (GNO,
// D8). These tests mirror the Node ones exactly, because the failure they guard
// against is the same — an installer that "succeeds" onto a machine that cannot
// actually run the workloads it was installed for.

func bunPinFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "bun-pinned.sha256")
}

func pinnedBunVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(bunPinFile(t))
	if err != nil {
		t.Fatalf("read bun pin file: %v", err)
	}
	m := regexp.MustCompile(`(?m)^version\s*=\s*([0-9.]+)\s*$`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("scripts/bun-pinned.sha256 states no version")
	}
	return string(m[1])
}

// The one piece of duplication the scripts cannot avoid: install.sh names the
// version it expects to find staged, the pin file names the version that gets
// staged. Drift means a fresh machine finds no usable archive.
func TestInstallerAndPinFileAgreeOnTheBunVersion(t *testing.T) {
	raw, err := os.ReadFile(installScript(t))
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	m := regexp.MustCompile(`BUN_VERSION="\$\{HOMEPLANE_BUN_VERSION:-([0-9.]+)\}"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("could not find the BUN_VERSION default in install.sh")
	}
	if got, want := string(m[1]), pinnedBunVersion(t); got != want {
		t.Errorf("install.sh pins bun %s but scripts/bun-pinned.sha256 pins %s", got, want)
	}
}

func TestPinnedBunChecksumsCoverEverySupportedPlatform(t *testing.T) {
	raw, err := os.ReadFile(bunPinFile(t))
	if err != nil {
		t.Fatalf("read bun pin file: %v", err)
	}
	for _, want := range []string{
		"bun-darwin-aarch64.zip",
		"bun-darwin-x64.zip",
		"bun-linux-aarch64.zip",
		"bun-linux-x64.zip",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("no pinned checksum for %s — a supported platform cannot be staged", want)
		}
	}
	// Every checksum line must be a real sha256, or the verification it is
	// supposed to perform is decorative.
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "version") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 {
			t.Errorf("malformed pin line %q", line)
		}
	}
}

func bunArchiveName(t *testing.T) string {
	t.Helper()
	osName, arch := hostPlatform()
	bunArch := "x64"
	if arch == "arm64" {
		bunArch = "aarch64"
	}
	return fmt.Sprintf("bun-v%s-%s-%s.zip", pinnedBunVersion(t), osName, bunArch)
}

// fakeBunZip builds an archive shaped like a Bun release: a top-level directory
// containing an executable named `bun`.
func fakeBunZip(t *testing.T, version string, includeBinary bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if includeBinary {
		header := &zip.FileHeader{Name: "bun-release/bun", Method: zip.Deflate}
		header.SetMode(0o755)
		w, err := zw.CreateHeader(header)
		if err != nil {
			t.Fatalf("zip header: %v", err)
		}
		if _, err := w.Write([]byte(fmt.Sprintf("#!/bin/sh\necho %s\n", version))); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	} else {
		w, err := zw.Create("bun-release/README.md")
		if err != nil {
			t.Fatalf("zip header: %v", err)
		}
		if _, err := w.Write([]byte("no runtime here\n")); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// runStageReleaseWithEnv invokes the staging script and returns its combined output.
func runStageReleaseWithEnv(t *testing.T, out string, args []string, env map[string]string) (string, error) {
	t.Helper()
	argv := append([]string{filepath.Join(repoRoot(t), "scripts", "stage-release.sh"), out}, args...)
	cmd := exec.Command("bash", argv...)
	cmd.Dir = repoRoot(t)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	raw, err := cmd.CombinedOutput()
	return string(raw), err
}

func absentBin(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "absent")
}

// A machine with neither a usable Bun nor a staged archive must fail closed:
// installing the agent there would produce a machine whose retrieval engine can
// never start.
func TestMissingBunWithoutAStagedArchiveFailsTheInstall(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_BUN_BIN": absentBin(t)},
	})
	if res.code == 0 {
		t.Fatalf("installer succeeded on a machine with no usable Bun:\n%s", res.output)
	}
	if !strings.Contains(res.output, "bun >= 1.3") {
		t.Errorf("failure does not name the Bun prerequisite:\n%s", res.output)
	}
	if !strings.Contains(res.output, "retrieval engine") {
		t.Errorf("failure does not say WHY Bun is needed:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

// Bun 1.0 is present but too old: the minor version is load-bearing, unlike
// Node's major-only gate.
func TestATooOldBunIsRejected(t *testing.T) {
	s, _ := stagedAgent(t)
	prefix := filepath.Join(t.TempDir(), "homeplane")

	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_BUN_BIN": fakeBun(t, "1.2.9")},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted bun 1.2.9:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}

func TestBunIsProvisionedFromTheChecksummedArchive(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	s.addArtifact(t, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch),
		[]byte("#!/bin/sh\necho homeplane-agent stub\n"), 0o755)
	s.addArtifact(t, bunArchiveName(t), fakeBunZip(t, pinnedBunVersion(t), true), 0o644)
	s.writeManifest(t)

	prefix := filepath.Join(t.TempDir(), "homeplane")
	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_BUN_BIN": absentBin(t)},
	})
	if res.code != 0 {
		t.Fatalf("install with a staged bun archive exit = %d:\n%s", res.code, res.output)
	}
	if _, err := os.Stat(filepath.Join(prefix, "bun", "bun")); err != nil {
		t.Errorf("bun was not provisioned into the prefix: %v", err)
	}
	link, err := os.Readlink(filepath.Join(prefix, "bin", "bun"))
	if err != nil {
		t.Errorf("no bun symlink in bin: %v", err)
	} else if !strings.HasSuffix(link, "bun/bun") {
		t.Errorf("bun symlink points at %q", link)
	}
	if _, err := os.Stat(installedBinary(prefix)); err != nil {
		t.Errorf("agent was not installed: %v", err)
	}
}

func TestTamperedBunArchiveAbortsBeforeInstallingTheAgent(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	s.addArtifact(t, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch),
		[]byte("#!/bin/sh\necho stub\n"), 0o755)
	archive := bunArchiveName(t)
	s.addArtifact(t, archive, fakeBunZip(t, pinnedBunVersion(t), true), 0o644)
	s.writeManifest(t)
	s.corrupt(t, archive)

	prefix := filepath.Join(t.TempDir(), "homeplane")
	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_BUN_BIN": absentBin(t)},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted a tampered bun archive:\n%s", res.output)
	}
	if !strings.Contains(res.output, "checksum mismatch") {
		t.Errorf("failure does not name the checksum mismatch:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
	if _, err := os.Stat(filepath.Join(prefix, "bun")); !os.IsNotExist(err) {
		t.Errorf("a bun directory was left behind (stat err: %v)", err)
	}
}

// Staging is the other half of deterministic provisioning: a mirror that serves
// different bytes than the pin describes must never reach a staging directory.
func TestStagingVerifiesTheBunArchiveAgainstThePin(t *testing.T) {
	osName, arch := hostPlatform()
	bunArch := "x64"
	if arch == "arm64" {
		bunArch = "aarch64"
	}
	version := pinnedBunVersion(t)
	asset := fmt.Sprintf("bun-%s-%s.zip", osName, bunArch)

	dist := t.TempDir()
	releaseDir := filepath.Join(dist, "bun-v"+version)
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := fakeBunZip(t, version, true)
	if err := os.WriteFile(filepath.Join(releaseDir, asset), content, 0o644); err != nil {
		t.Fatal(err)
	}

	writePin := func(sum string) string {
		path := filepath.Join(t.TempDir(), "bun-pinned.sha256")
		body := fmt.Sprintf("version = %s\n%s  %s\n", version, sum, asset)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	stage := func(pin string) (string, string, error) {
		out := filepath.Join(t.TempDir(), "dist")
		raw, err := runStageReleaseWithEnv(t, out, []string{"--skip-node"}, map[string]string{
			"HOMEPLANE_BUN_DIST_URL":    "file://" + dist,
			"HOMEPLANE_BUN_PIN_FILE":    pin,
			"HOMEPLANE_BUN_CACHE":       filepath.Join(t.TempDir(), "cache"),
			"HOMEPLANE_STAGE_PLATFORMS": osName + " " + arch,
		})
		return out, raw, err
	}

	// The honest mirror stages, under a version-qualified name.
	out, raw, err := stage(writePin(sha256Hex(content)))
	if err != nil {
		t.Fatalf("stage-release.sh: %v\n%s", err, raw)
	}
	staged := filepath.Join(out, bunArchiveName(t))
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("the bun archive was not staged as %s: %v", bunArchiveName(t), err)
	}
	manifest, err := os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), bunArchiveName(t)) {
		t.Fatalf("the staged bun archive is not in the manifest:\n%s", manifest)
	}

	// A pin that disagrees with the bytes stages nothing.
	badOut, raw, err := stage(writePin(strings.Repeat("0", 64)))
	if err == nil {
		t.Fatalf("staging accepted an archive that failed its pinned checksum:\n%s", raw)
	}
	if !strings.Contains(raw, "checksum mismatch") {
		t.Errorf("the refusal does not name the mismatch:\n%s", raw)
	}
	if _, statErr := os.Stat(filepath.Join(badOut, bunArchiveName(t))); !os.IsNotExist(statErr) {
		t.Errorf("an unverified archive was staged anyway (stat err: %v)", statErr)
	}
}

// The other malformed shape: an archive that extracts but contains no runtime.
func TestABunArchiveWithoutARuntimeIsRejectedBeforeTheSwap(t *testing.T) {
	osName, arch := hostPlatform()
	s := newStage(t)
	s.addArtifact(t, fmt.Sprintf("homeplane-agent-%s-%s", osName, arch),
		[]byte("#!/bin/sh\necho stub\n"), 0o755)
	s.addArtifact(t, bunArchiveName(t), fakeBunZip(t, pinnedBunVersion(t), false), 0o644)
	s.writeManifest(t)

	prefix := filepath.Join(t.TempDir(), "homeplane")
	res := runInstaller(t, runOpts{
		stage:  s,
		prefix: prefix,
		env:    map[string]string{"HOMEPLANE_BUN_BIN": absentBin(t)},
	})
	if res.code == 0 {
		t.Fatalf("installer accepted an archive with no bun executable:\n%s", res.output)
	}
	assertNotInstalled(t, prefix)
}
