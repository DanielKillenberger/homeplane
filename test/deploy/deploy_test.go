// Package deploy_test guards the parts of the server deployment that can be
// checked without a server.
//
// The deployment itself is proved live, from a second tailnet node
// (deploy/server/verify.sh, recorded in this task's evidence artifact). What a
// live run CANNOT do is notice that someone has since edited the unit template
// or the manifest into something that would not deploy — the next live run is
// weeks away, and the failure would surface as a production server that is
// wrong rather than as a red test. These tests hold the invariants a live run
// established, so an edit that breaks one fails here first.
package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func deployFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "deploy", "server", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(raw)
}

// TestDeployedManifestIsValid is the cheapest possible version of "the server
// will start". A manifest the connector engine refuses takes the whole control
// plane down at boot — after the binary has already been swapped in — so the
// manifest that ships to the host is validated by the same code that will load
// it there.
func TestDeployedManifestIsValid(t *testing.T) {
	path := filepath.Join(repoRoot(t), "deploy", "server", "manifest.json")
	m, err := connectors.LoadFile(path)
	if err != nil {
		t.Fatalf("deploy/server/manifest.json is not a valid connector manifest: %v", err)
	}
	if _, err := connectors.Register(m); err != nil {
		t.Fatalf("deploy/server/manifest.json does not register: %v", err)
	}
	if len(m.Connectors) == 0 {
		t.Fatal("deployed manifest declares no connectors")
	}
}

// TestDeployedManifestKeepsDriveWritesUnmapped pins the D18 scope policy at the
// only place it is enforced for a deployed server: an unmapped tool is refused
// by the edge. A well-meaning edit that "completes" the tool list would quietly
// grant Drive write authority to every grant holder.
func TestDeployedManifestKeepsDriveWritesUnmapped(t *testing.T) {
	m, err := connectors.LoadFile(filepath.Join(repoRoot(t), "deploy", "server", "manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	for _, c := range m.Connectors {
		for _, tool := range c.Tools {
			switch tool.Tool {
			case "create_drive_file", "update_drive_file":
				t.Errorf("connector %q maps Drive write tool %q; D18 makes Drive read-only",
					c.Provider, tool.Tool)
			}
			if tool.ActionClass != connectors.ActionRead {
				t.Errorf("connector %q maps %q as %q: this deployment ships the read surface only "+
					"(fn-1.12 owns the Calendar write mapping and its through-the-stack proof)",
					c.Provider, tool.Tool, tool.ActionClass)
			}
		}
	}
}

// TestGatewayUnitBindsLoopbackOnly guards the bypass boundary in the one file
// that decides it. Everything else about the isolation guarantee — the edge,
// the grant token, the machine binding — is downstream of the gateway not being
// reachable from another node, and that is a single flag.
func TestGatewayUnitBindsLoopbackOnly(t *testing.T) {
	unit := deployFile(t, filepath.Join("units", "homeplane-gateway.service.tmpl"))
	if !strings.Contains(unit, "--host 127.0.0.1") {
		t.Error("the gateway unit does not pin --host 127.0.0.1: the workload proxy could be reachable from other tailnet nodes")
	}
	if !strings.Contains(unit, "--foreground") {
		t.Error("the gateway unit does not pass --foreground: thv would detach and systemd would supervise an exited process")
	}
	if !strings.Contains(unit, "--enable-audit") {
		t.Error("the gateway unit does not pass --enable-audit (D6: supplementary per-tool-call diagnostics)")
	}
}

// TestServerUnitTakesTheAuthKeyFromAFileNotArgv is the argv-hygiene invariant in
// unit form: a tailnet auth key on the command line would be world-readable in
// `ps` for as long as the server runs.
func TestServerUnitTakesTheAuthKeyFromAFileNotArgv(t *testing.T) {
	unit := deployFile(t, filepath.Join("units", "homeplane-server.service.tmpl"))
	if !strings.Contains(unit, "EnvironmentFile=-@PREFIX@/etc/authkey.env") {
		t.Error("the server unit does not read the auth key from an EnvironmentFile")
	}
	if strings.Contains(unit, "TS_AUTHKEY=") {
		t.Error("the server unit inlines TS_AUTHKEY: the key must never be part of the unit or of argv")
	}
	for _, want := range []string{"-state-dir", "-connector-manifest", "-gateway-mcp-url", "-gateway-health-url"} {
		if !strings.Contains(unit, want) {
			t.Errorf("the server unit does not pass %s", want)
		}
	}
	// The upstream the edge proxies to must be loopback, or the edge is
	// proxying to something another node could have reached directly.
	if !strings.Contains(unit, "-gateway-mcp-url http://127.0.0.1:") {
		t.Error("the server unit's gateway MCP URL is not a loopback address")
	}
}

// TestUnitTemplatePlaceholdersAreAllRendered catches the failure mode of a
// hand-edited template: a placeholder the installer does not know about is
// substituted by nothing and reaches the host verbatim, so systemd starts a
// unit with a literal "@SOMETHING@" in its command line.
func TestUnitTemplatePlaceholdersAreAllRendered(t *testing.T) {
	installer := deployFile(t, "install-server.sh")
	placeholder := regexp.MustCompile(`@[A-Z_]+@`)
	for _, unit := range []string{"homeplane-gateway.service.tmpl", "homeplane-server.service.tmpl"} {
		body := deployFile(t, filepath.Join("units", unit))
		for _, found := range placeholder.FindAllString(body, -1) {
			// The installer's sed program names every placeholder it renders.
			if !strings.Contains(installer, "s#"+found+"#") {
				t.Errorf("%s uses placeholder %s, which install-server.sh does not substitute", unit, found)
			}
		}
	}
}

// TestToolHivePinsCoverBothLinuxArchitectures: the installer picks its archive
// by architecture, and a missing line is only discovered on the host it cannot
// install onto.
func TestToolHivePinsCoverBothLinuxArchitectures(t *testing.T) {
	pins := deployFile(t, "toolhive-pinned.sha256")
	line := regexp.MustCompile(`(?m)^([0-9a-f]{64})\s+(toolhive_[0-9.]+_linux_(amd64|arm64)\.tar\.gz)$`)
	found := map[string]bool{}
	for _, m := range line.FindAllStringSubmatch(pins, -1) {
		found[m[3]] = true
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if !found[arch] {
			t.Errorf("no pinned ToolHive archive for linux/%s", arch)
		}
	}
}

// TestInstallerVerifiesEverythingBeforeMutatingTheDeployment holds the
// installer's central safety property structurally: acquisition and
// verification happen in a preflight phase, and the first write that touches
// the running deployment comes after it. Without the ordering, a failed
// ToolHive download or a missing unit template leaves a host with a new server
// binary and an old everything-else — a state no test and no operator asked for.
func TestInstallerVerifiesEverythingBeforeMutatingTheDeployment(t *testing.T) {
	body := deployFile(t, "install-server.sh")
	commit := strings.Index(body, "# --- commit ---")
	if commit < 0 {
		t.Fatal("install-server.sh has no commit phase marker; the preflight/commit split is the safety property")
	}
	// Everything that can fail on missing input, network, or checksum must be
	// upstream of the commit marker.
	for _, preflight := range []string{
		`verify "$STAGE_DIR/$SERVER_ARTIFACT" "$SERVER_SHA"`,
		`missing unit template`,
		`no manifest.json in $STAGE_DIR`,
		`could not download $url`,
	} {
		idx := strings.Index(body, preflight)
		if idx < 0 {
			t.Errorf("install-server.sh no longer contains preflight step %q", preflight)
			continue
		}
		if idx > commit {
			t.Errorf("preflight step %q happens AFTER the commit phase; a failure there would leave a half-upgraded host", preflight)
		}
	}
	// ...and the first mutation of the live deployment must be downstream.
	install := strings.Index(body, `run install -m 0755 "$STAGE_DIR/$SERVER_ARTIFACT" "$BIN_DIR/homeplane-server"`)
	if install < 0 {
		t.Fatal("install-server.sh no longer installs the server binary the way this test expects")
	}
	if install < commit {
		t.Error("the server binary is installed before the commit phase: acquisition failures would leave a partially upgraded prefix")
	}
}

// TestInstallerHandlesTheInstalledConfigFallback: an upgrade with no staged
// config reuses the INSTALLED one, which makes `install src dst` a same-file
// call — and GNU install rejects that, aborting the advertised fallback under
// `set -e`. Verified live on the host as well; this keeps the guard from being
// refactored away.
func TestInstallerHandlesTheInstalledConfigFallback(t *testing.T) {
	body := deployFile(t, "install-server.sh")
	if !strings.Contains(body, `if [[ "$(abs_path "$CONFIG")" == "$(abs_path "$ETC_DIR/server.env")" ]]; then`) {
		t.Error("install-server.sh does not guard the same-file config install; the installed-config upgrade fallback would abort")
	}
}

// TestDeployScriptsAreSyntacticallyValid. They run on a production host, often
// unattended; `bash -n` is the floor.
func TestDeployScriptsAreSyntacticallyValid(t *testing.T) {
	for _, script := range []string{"install-server.sh", "deploy.sh", "verify.sh"} {
		path := filepath.Join(repoRoot(t), "deploy", "server", script)
		if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", script, err, out)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", script, err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable", script)
		}
	}
}

// TestStagingBuildsTheServerArtifact: install-server.sh installs
// homeplane-server-linux-<arch> and verifies it against SHA256SUMS, so the
// staging script has to produce exactly that name.
func TestStagingBuildsTheServerArtifact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "stage-release.sh"))
	if err != nil {
		t.Fatalf("read stage-release.sh: %v", err)
	}
	script := string(raw)
	if !strings.Contains(script, "homeplane-server-${goos}-${goarch}") {
		t.Error("stage-release.sh does not build a homeplane-server artifact")
	}
	if !strings.Contains(script, "homeplane-server-*") {
		t.Error("stage-release.sh does not include the server artifacts in SHA256SUMS")
	}
	installer := deployFile(t, "install-server.sh")
	if !strings.Contains(installer, `homeplane-server-linux-${GOARCH}`) {
		t.Error("install-server.sh does not install the staged server artifact name")
	}
}
