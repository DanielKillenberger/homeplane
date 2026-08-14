package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// scripts/capture-grok-contract.sh produces COMMITTED EVIDENCE: the testdata
// that fn-3's decision record and task .2's contract test both rest on. That
// makes its failure mode the thing worth testing, not its success.
//
// The bug these tests exist for is real and was shipped: an earlier revision
// recorded each probe's exit status and then unconditionally returned success,
// so a `grok inspect` that failed, timed out, or printed nothing produced zero
// decoy matches — and the script wrote "GROK_HOME relocated BOTH config and
// skills discovery" on the strength of that silence. An evidence producer that
// fails OPEN is worse than none: it manufactures confidence.
//
// Each test drives the real script with a STUB grok on PATH, so no real grok
// and no network are involved.

// stubGrok writes a fake `grok` executable and returns a PATH that finds it
// first. The body is a bash script; `$1..` are grok's own arguments.
func stubGrok(t *testing.T, body string) (pathEnv string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/usr/bin/env bash\n" + body + "\n"
	bin := filepath.Join(dir, "grok")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// runCapture runs the capture script against a stub grok, into a throwaway
// repo root so a failing run can never touch the committed testdata.
func runCapture(t *testing.T, pathEnv string) (combined string, err error) {
	t.Helper()
	repoRoot, rootErr := filepath.Abs("../../..")
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	script := filepath.Join(repoRoot, "scripts", "capture-grok-contract.sh")
	if _, statErr := os.Stat(script); statErr != nil {
		t.Skipf("capture script not present: %v", statErr)
	}

	// Copy the script into a scratch "repo" so its OUT_DIR
	// (<script>/../internal/agent/harness/testdata) lands in the temp tree.
	scratch := t.TempDir()
	if mkErr := os.MkdirAll(filepath.Join(scratch, "scripts"), 0o755); mkErr != nil {
		t.Fatal(mkErr)
	}
	src, readErr := os.ReadFile(script)
	if readErr != nil {
		t.Fatal(readErr)
	}
	copied := filepath.Join(scratch, "scripts", "capture-grok-contract.sh")
	if wErr := os.WriteFile(copied, src, 0o755); wErr != nil {
		t.Fatal(wErr)
	}

	cmd := exec.Command("bash", copied)
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
	out, runErr := cmd.CombinedOutput()
	return string(out), runErr
}

// The headline case: a probe that FAILS must abort the capture. Before the
// fix, `inspect` failing still produced a contract file asserting relocation.
func TestTheCaptureFailsWhenAProbeFails(t *testing.T) {
	// A grok that answers everything plausibly EXCEPT `inspect`, which fails
	// the way a broken install or a timeout would.
	stub := `
case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
  inspect)   echo "boom" >&2; exit 1 ;;
esac
exit 0
`
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED with a failing `grok inspect`.\n"+
			"An evidence producer that fails open manufactures confidence.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "CAPTURE ABORTED") {
		t.Errorf("the capture failed but never said why; output:\n%s", out)
	}
}

// The subtler case, and the one that motivated the positive sentinels: a grok
// that "succeeds" while reporting NOTHING. Its output contains no decoy names,
// so a decoy-absence check alone reads that silence as proof of relocation.
func TestTheCaptureFailsWhenProbesSucceedButReportNothing(t *testing.T) {
	stub := `
case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
esac
exit 0
`
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED against a grok that reported nothing.\n"+
			"Absence of the decoy is not evidence of relocation when the probes\n"+
			"returned nothing at all.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "CAPTURE ABORTED") {
		t.Errorf("the capture failed but never said why; output:\n%s", out)
	}
}

// A failed capture must not leave a partial contract behind for someone to
// commit as though it were a real observation.
func TestAFailedCaptureLeavesNoContractFile(t *testing.T) {
	stub := `
case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
  inspect)   exit 1 ;;
esac
exit 0
`
	pathEnv := stubGrok(t, stub)

	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(filepath.Join(repoRoot, "scripts", "capture-grok-contract.sh")); statErr != nil {
		t.Skipf("capture script not present: %v", statErr)
	}

	scratch := t.TempDir()
	if mkErr := os.MkdirAll(filepath.Join(scratch, "scripts"), 0o755); mkErr != nil {
		t.Fatal(mkErr)
	}
	src, readErr := os.ReadFile(filepath.Join(repoRoot, "scripts", "capture-grok-contract.sh"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	copied := filepath.Join(scratch, "scripts", "capture-grok-contract.sh")
	if wErr := os.WriteFile(copied, src, 0o755); wErr != nil {
		t.Fatal(wErr)
	}

	cmd := exec.Command("bash", copied)
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
	if out, runErr := cmd.CombinedOutput(); runErr == nil {
		t.Fatalf("expected the capture to fail; output:\n%s", out)
	}

	testdata := filepath.Join(scratch, "internal", "agent", "harness", "testdata")
	entries, readDirErr := os.ReadDir(testdata)
	if readDirErr != nil {
		return // no testdata directory at all is the strongest form of "nothing left behind"
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "-contract.txt") {
			t.Errorf("a failed capture left %s behind; it could be committed as a real observation", e.Name())
		}
	}
}

// The committed contract must itself be complete — the marker the script
// checks for before declaring success. A truncated contract that still parses
// would silently weaken every assertion task .2 builds on it.
func TestTheCommittedGrokContractIsComplete(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("testdata", "grok-*-contract.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no grok contract committed yet")
	}
	for _, path := range matches {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		body := string(raw)
		if !strings.Contains(body, "=== END OF CAPTURE ===") {
			t.Errorf("%s has no end marker: it is a truncated capture", path)
		}
		// The relocation claim in docs/decisions/fn3-grok-surfaces.md rests on
		// these two, together. Either alone is not evidence.
		if !strings.Contains(body, "relocation gate: positive sentinels") {
			t.Errorf("%s records no positive sentinels", path)
		}
		if !strings.Contains(body, "0 decoy references") {
			t.Errorf("%s does not record decoy absence", path)
		}
		if strings.Contains(body, "decoy-must-never-appear") &&
			!strings.Contains(body, "must NEVER appear") {
			t.Errorf("%s contains a decoy reference outside its declaration", path)
		}
	}
}
