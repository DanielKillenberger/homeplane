package install_test

import (
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

// These tests cover the half of R1 that a unit test of install.sh cannot: that
// the release the STAGING SCRIPT actually produces is installable onto a fresh
// machine — one with no Node at all, which on macOS has no package-manager
// fallback to rescue it.
//
// They run the real scripts. Only the Node distribution is substituted: the
// staging script fetches from a file:// dist tree holding a small stand-in
// runtime, pinned in a test-owned checksum file. Every code path under test —
// download, pinned-checksum verification, manifest generation, install-time
// re-verification, extraction, runtime validation — is the production one.

func pinFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "node-pinned.sha256")
}

// pinnedNodeVersion reads the version the repository pins.
func pinnedNodeVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(pinFile(t))
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	re := regexp.MustCompile(`node-v(\d+\.\d+\.\d+)-`)
	versions := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if m := re.FindStringSubmatch(line); m != nil {
			versions[m[1]] = true
		}
	}
	if len(versions) != 1 {
		t.Fatalf("pin file pins %d node versions, want exactly 1", len(versions))
	}
	for v := range versions {
		return v
	}
	return ""
}

// TestInstallerAndPinFileAgreeOnTheNodeVersion guards the one piece of
// duplication the two scripts cannot avoid: install.sh names the version it
// expects to find staged, and the pin file names the version that gets staged.
// If they drift, a fresh machine finds no usable archive and the install fails
// in a way no other test would catch.
func TestInstallerAndPinFileAgreeOnTheNodeVersion(t *testing.T) {
	raw, err := os.ReadFile(installScript(t))
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	m := regexp.MustCompile(`NODE_VERSION="\$\{HOMEPLANE_NODE_VERSION:-([0-9.]+)\}"`).FindSubmatch(raw)
	if m == nil {
		t.Fatal("could not find the NODE_VERSION default in install.sh")
	}
	if got, want := string(m[1]), pinnedNodeVersion(t); got != want {
		t.Errorf("install.sh pins node %s but scripts/node-pinned.sha256 pins %s", got, want)
	}
}

func TestPinnedChecksumsCoverEverySupportedPlatform(t *testing.T) {
	raw, err := os.ReadFile(pinFile(t))
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	version := pinnedNodeVersion(t)
	for _, want := range []string{
		fmt.Sprintf("node-v%s-darwin-arm64.tar.gz", version),
		fmt.Sprintf("node-v%s-darwin-x64.tar.gz", version),
		fmt.Sprintf("node-v%s-linux-arm64.tar.gz", version),
		fmt.Sprintf("node-v%s-linux-x64.tar.gz", version),
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("no pinned checksum for %s — a supported platform cannot be staged", want)
		}
	}
}

// fakeDist builds a file:// Node distribution tree plus the matching pin file,
// and returns (distRoot, pinPath, archiveName).
func fakeDist(t *testing.T, corruptPin bool) (string, string, string) {
	t.Helper()
	version := pinnedNodeVersion(t)
	osName, arch := hostPlatform()
	nodeArch := "x64"
	if arch == "arm64" {
		nodeArch = "arm64"
	}
	archive := fmt.Sprintf("node-v%s-%s-%s.tar.gz", version, osName, nodeArch)

	dist := t.TempDir()
	verDir := filepath.Join(dist, "v"+version)
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	body := fakeNodeTarball(t, fmt.Sprintf("node-v%s-%s-%s", version, osName, nodeArch), 22)
	if err := os.WriteFile(filepath.Join(verDir, archive), body, 0o644); err != nil {
		t.Fatalf("write dist archive: %v", err)
	}

	sum := sha256.Sum256(body)
	recorded := hex.EncodeToString(sum[:])
	if corruptPin {
		recorded = strings.Repeat("0", 64)
	}
	pin := filepath.Join(t.TempDir(), "node-pinned.sha256")
	if err := os.WriteFile(pin, []byte(fmt.Sprintf("%s  %s\n", recorded, archive)), 0o644); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	return dist, pin, archive
}

type stageResult struct {
	code   int
	output string
	dir    string
}

func runStageRelease(t *testing.T, dist, pin string, extraEnv ...string) stageResult {
	t.Helper()
	osName, arch := hostPlatform()
	out := filepath.Join(t.TempDir(), "dist")

	cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts", "stage-release.sh"), out)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(),
		"HOMEPLANE_NODE_DIST_URL=file://"+dist,
		"HOMEPLANE_NODE_PIN_FILE="+pin,
		"HOMEPLANE_NODE_CACHE="+filepath.Join(t.TempDir(), "cache"),
		// Staging the whole matrix would cross-compile four binaries; the host
		// platform is the one this test then installs.
		"HOMEPLANE_STAGE_PLATFORMS="+osName+" "+arch,
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	raw, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if err != nil {
		if asExitError(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run stage-release.sh: %v", err)
		}
	}
	return stageResult{code: code, output: string(raw), dir: out}
}

func TestStagedReleaseInstallsOntoAMachineWithNoNodeAtAll(t *testing.T) {
	dist, pin, archive := fakeDist(t, false)

	staged := runStageRelease(t, dist, pin)
	if staged.code != 0 {
		t.Fatalf("stage-release.sh exit = %d:\n%s", staged.code, staged.output)
	}

	manifest, err := os.ReadFile(filepath.Join(staged.dir, "SHA256SUMS"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(manifest), archive) {
		t.Errorf("the generated manifest does not cover the node runtime:\n%s", manifest)
	}
	if !strings.Contains(string(manifest), "homeplane-agent-") {
		t.Errorf("the generated manifest does not cover the agent:\n%s", manifest)
	}
	if _, err := os.Stat(filepath.Join(staged.dir, archive)); err != nil {
		t.Fatalf("the node runtime was not staged: %v", err)
	}

	// Install onto a machine with NO node: HOMEPLANE_NODE_BIN points at a path
	// that does not exist, so the installer must provision from the staged
	// tarball or fail.
	prefix := filepath.Join(t.TempDir(), "homeplane")
	cmd := exec.Command("bash", installScript(t), "--stage-dir", staged.dir, "--prefix", prefix)
	cmd.Env = append(os.Environ(),
		"HOMEPLANE_INIT_OVERRIDE="+defaultInit(),
		"HOMEPLANE_NODE_BIN="+filepath.Join(t.TempDir(), "no-such-node"),
	)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install from the staged release failed: %v\n%s", err, raw)
	}
	if _, err := os.Stat(installedBinary(prefix)); err != nil {
		t.Errorf("agent not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(prefix, "node", "bin", "node")); err != nil {
		t.Errorf("node was not provisioned from the staged release: %v", err)
	}
}

func TestStagingRefusesARuntimeThatFailsItsPinnedChecksum(t *testing.T) {
	dist, pin, archive := fakeDist(t, true)

	staged := runStageRelease(t, dist, pin)
	if staged.code == 0 {
		t.Fatalf("stage-release.sh accepted a runtime that does not match its pin:\n%s", staged.output)
	}
	if !strings.Contains(staged.output, "checksum mismatch") {
		t.Errorf("output does not name the mismatch:\n%s", staged.output)
	}
	if _, err := os.Stat(filepath.Join(staged.dir, archive)); !os.IsNotExist(err) {
		t.Errorf("the unverified runtime was staged anyway (stat err: %v)", err)
	}
}

func TestSkipNodeStagesAnAgentOnlyRelease(t *testing.T) {
	dist, pin, archive := fakeDist(t, false)
	osName, arch := hostPlatform()
	out := filepath.Join(t.TempDir(), "dist")

	cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts", "stage-release.sh"), out, "--skip-node")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(),
		"HOMEPLANE_NODE_DIST_URL=file://"+dist,
		"HOMEPLANE_NODE_PIN_FILE="+pin,
		"HOMEPLANE_STAGE_PLATFORMS="+osName+" "+arch,
	)
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stage-release.sh --skip-node: %v\n%s", err, raw)
	}
	if _, err := os.Stat(filepath.Join(out, archive)); !os.IsNotExist(err) {
		t.Errorf("--skip-node staged a node runtime anyway (stat err: %v)", err)
	}

	// And such a release must still fail closed on a machine without Node,
	// rather than installing an agent that cannot run its own workloads.
	prefix := filepath.Join(t.TempDir(), "homeplane")
	install := exec.Command("bash", installScript(t), "--stage-dir", out, "--prefix", prefix)
	install.Env = append(os.Environ(),
		"HOMEPLANE_INIT_OVERRIDE="+defaultInit(),
		"HOMEPLANE_NODE_BIN="+filepath.Join(t.TempDir(), "no-such-node"),
	)
	raw, err := install.CombinedOutput()
	if err == nil {
		t.Fatalf("installing an agent-only release onto a Node-less machine succeeded:\n%s", raw)
	}
	if !strings.Contains(string(raw), "node >= 22") {
		t.Errorf("failure does not name the missing prerequisite:\n%s", raw)
	}
	assertNotInstalled(t, prefix)
}
