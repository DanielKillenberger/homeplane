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

// stagedScript copies the capture script into a throwaway "repo" and returns
// that root plus the copied script's path. The copy matters: the script writes
// to <script>/../internal/agent/harness/testdata, so running the real one in
// place would let a deliberately-failing test scribble on committed testdata.
func stagedScript(t *testing.T) (scratch, script string) {
	t.Helper()
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(repoRoot, "scripts", "capture-grok-contract.sh")
	src, err := os.ReadFile(real)
	if err != nil {
		t.Skipf("capture script not present: %v", err)
	}

	scratch = t.TempDir()
	if err := os.MkdirAll(filepath.Join(scratch, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(scratch, "scripts", "capture-grok-contract.sh")
	if err := os.WriteFile(script, src, 0o755); err != nil {
		t.Fatal(err)
	}
	return scratch, script
}

// runCapture runs the capture script against a stub grok, into a throwaway
// repo root so a failing run can never touch the committed testdata.
func runCapture(t *testing.T, pathEnv string) (combined string, err error) {
	t.Helper()
	_, script := stagedScript(t)
	cmd := exec.Command("bash", script)
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

// Failures early in the run matter as much as late ones. Help capture happens
// before any assertion-heavy section, and an earlier revision checked exit
// status only for a few late probes — so a grok whose `--help` was broken
// still produced a contract full of empty sections.
func TestTheCaptureFailsWhenAnEarlyHelpProbeFails(t *testing.T) {
	stub := `
case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
  --help)    echo "help is broken" >&2; exit 1 ;;
esac
exit 0
`
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED with a failing `grok --help`;\noutput:\n%s", out)
	}
	if !strings.Contains(out, "CAPTURE ABORTED") {
		t.Errorf("the capture failed but never said why; output:\n%s", out)
	}
}

// The failure-shape section captures probes precisely FOR their non-zero exit.
// A probe that HUNG and got killed by the alarm also exits non-zero — and
// recording that as a "fast, non-interactive failure" would invert the very
// finding the section exists to establish, since the whole point is that grok
// does not sit waiting on a hidden prompt.
func TestTheCaptureRejectsATimedOutProbeRatherThanCallingItAFastFailure(t *testing.T) {
	// 142 is 128+SIGALRM: exactly what the perl alarm leaves behind when a
	// probe runs long. Exiting it directly tests the rejection faithfully and
	// instantly, instead of making the suite sit through a real 30s hang.
	// reject_timeout is shared by expect_ok and expect_rc, so proving it fires
	// on one path proves it for the deliberate-failure probes too.
	stub := `
case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
  --help)    exit 142 ;;
esac
exit 0
`
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED with a probe that hung until its alarm;\n"+
			"a killed probe is not evidence of a fast non-interactive failure.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "TIMED OUT") {
		t.Errorf("the capture failed but not with a timeout diagnosis; output:\n%s", out)
	}
}

// A transient failure must not destroy the last known-good contract. Writing
// straight to the committed path would truncate it before the replacement is
// known to be any good.
func TestAFailedRecaptureLeavesAnExistingContractByteIdentical(t *testing.T) {
	scratch, script := stagedScript(t)

	// Stand in a previous, known-good contract.
	testdata := filepath.Join(scratch, "internal", "agent", "harness", "testdata")
	if err := os.MkdirAll(testdata, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(testdata, "grok-9.9.9-contract.txt")
	golden := []byte("the previous, known-good capture\n=== END OF CAPTURE ===\n")
	if err := os.WriteFile(existing, golden, 0o644); err != nil {
		t.Fatal(err)
	}

	// A grok that reports its version (so the script targets the SAME file)
	// but then fails partway through.
	stub := `
case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
  inspect)   exit 1 ;;
esac
exit 0
`
	cmd := exec.Command("bash", script)
	cmd.Env = append(os.Environ(), "PATH="+stubGrok(t, stub))
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected the recapture to fail; output:\n%s", out)
	}

	after, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("the previous contract is GONE after a failed recapture: %v", err)
	}
	if string(after) != string(golden) {
		t.Errorf("a failed recapture modified the previous contract.\nwant:\n%s\ngot:\n%s", golden, after)
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
	scratch, script := stagedScript(t)

	cmd := exec.Command("bash", script)
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
