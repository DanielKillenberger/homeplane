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
  leader)    echo "No leader candidates found."; exit 0 ;;
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
  leader)    echo "No leader candidates found."; exit 0 ;;
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
  leader)    echo "No leader candidates found."; exit 0 ;;
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
  leader)    echo "No leader candidates found."; exit 0 ;;
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

// The LAST probe in the script used to fail open: its output was piped
// straight into `sed ... || true`, so an unexpanded target still reached the
// end marker and replaced the known-good contract with a capture that proved
// the opposite of what it claimed.
func TestTheCaptureFailsWhenTheVariableIsNotExpanded(t *testing.T) {
	// A grok that never expands ${VAR}: doctor reports the placeholder even
	// with the variable set.
	// The shape stays correct in every other respect — only the expansion is
	// missing — so the failure this asserts is the expansion check itself and
	// not some earlier assertion tripping first.
	stub := wellBehavedStub(`
if [ "$1" = mcp ] && [ "$2" = doctor ]; then
  shift 2
  who=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) shift ;;
      --leader-socket) shift 2 ;;
      -*) shift ;;
      *) who="$1"; shift ;;
    esac
  done
  printf '{"sources":[],"servers":[{"name":"%s","transport":"http","target":"https://PLACEHOLDER-NEVER-EXPANDED/mcp","checks":[{"label":"server started","passed":true},{"label":"handshake failed","passed":false}],"healthy":false}],"healthy_count":0,"failing_count":1}\n' "$who"
  exit 1
fi
`)
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED against a grok that never expanded ${VAR};\n"+
			"the load-time expansion claim would have been recorded as proven.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "was NOT expanded") {
		t.Errorf("the capture failed but not with an expansion diagnosis; output:\n%s", out)
	}
}

// The negative tests above all prove the capture REFUSES bad input. This one
// proves it still accepts good input — without it, a script that failed on
// everything would pass the whole suite while producing no evidence at all.
//
// The stub behaves the way the real grok was observed to behave: it drops
// comments, resets the mode, clobbers an entry wholesale, stores ${VAR}
// verbatim and expands it at load, and reports the frontmatter name only.
// wellBehavedStub is a grok that behaves the way the real one was OBSERVED to
// behave: it drops comments, resets the mode to 0644, clobbers an entry
// wholesale, stores ${VAR} verbatim, expands it at load time, and reports the
// frontmatter name only. Tests override one behaviour at a time by splicing
// `extra` in ahead of it, which is what lets a test reach a LATE probe before
// failing — the early-failing stubs cannot show whether late probes are
// checked at all.
func wellBehavedStub(extra string) string {
	return "\n" + extra + `
cfg="$GROK_HOME/config.toml"

emit_config() {
  # A serializer round-trip: comments gone, entries kept, headers as a
  # sub-table. Written fresh each time, and always at mode 0644.
  {
    echo '[ui]'
    echo 'max_thoughts_width = 120'
    echo
    echo '[mcp_servers.preexisting-thing]'
    echo 'command = "/usr/bin/true"'
    echo 'args = ["--keep-me"]'
    echo 'enabled = true'
    cat "$GROK_HOME/.entries" 2>/dev/null
  } > "$cfg"
  chmod 644 "$cfg"
}

case "$1" in
  --version) echo "grok 9.9.9 (stubbed)"; exit 0 ;;
  leader)    echo "No leader candidates found."; exit 0 ;;
  --help|help) echo "stub help"; exit 0 ;;
  inspect)
    echo "  Skills (3)"
    echo "  └ hp-probe-alpha         user"
    echo "  └ frontmatter-beta-name  user"
    echo "  └ gamma-dir-name         user"
    exit 0 ;;
  leader) echo "No leader candidates found."; exit 0 ;;
esac

if [ "$1" = mcp ]; then
  case "$2" in
    add)
      # Real grok refuses these before writing anything: its own refusal is 1,
      # a clap parse error is 2. The capture asserts both exactly.
      case " $* " in
        *" -t carrier-pigeon "*) echo "error: invalid value" >&2; exit 2 ;;
      esac
      case " $* " in
        *"bad name!"*) echo "Error: Invalid name" >&2; exit 1 ;;
      esac
      name=""; url=""; header=""
      shift 2
      while [ $# -gt 0 ]; do
        case "$1" in
          -t|--transport|-s|--scope) shift 2; continue ;;
          -H|--header) header="$2"; shift 2; continue ;;
          --leader-socket) shift 2; continue ;;
          -*) shift; continue ;;
          *) if [ -z "$name" ]; then name="$1"; else url="$1"; fi; shift ;;
        esac
      done
      # A differing re-add replaces the entry wholesale, so drop any previous
      # copy (and its headers) before appending the new one.
      if [ -f "$GROK_HOME/.entries" ]; then
        grep -v "^#ENTRY $name\$" "$GROK_HOME/.entries" > "$GROK_HOME/.entries.new" 2>/dev/null || true
        awk -v n="$name" '
          $0 == "#ENTRY " n {skip=1; next}
          /^#ENTRY /        {skip=0}
          !skip             {print}
        ' "$GROK_HOME/.entries" > "$GROK_HOME/.entries.new"
        mv "$GROK_HOME/.entries.new" "$GROK_HOME/.entries"
      fi
      {
        echo "#ENTRY $name"
        echo
        echo "[mcp_servers.$name]"
        echo "url = \"$url\""
        echo "enabled = true"
        if [ -n "$header" ]; then
          echo
          echo "[mcp_servers.$name.headers]"
          echo "Authorization = \"${header#Authorization: }\""
        fi
      } >> "$GROK_HOME/.entries"
      emit_config
      echo "Added"
      exit 0 ;;
    list)
      case " $* " in
        *" --json "*)
          # One object per entry, all enabled — the observed default.
          printf '['
          sep=""
          while read -r _ n; do
            [ -n "$n" ] || continue
            printf '%s{"name":"%s","url":"https://x.invalid/mcp","enabled":true,"scope":"user"}' "$sep" "$n"
            sep=","
          done < <(grep '^#ENTRY ' "$GROK_HOME/.entries" 2>/dev/null)
          printf ']\n'
          exit 0 ;;
      esac
      # Names only; enough for the relocation gate's positive sentinels.
      grep '^#ENTRY ' "$GROK_HOME/.entries" 2>/dev/null | sed 's/^#ENTRY /  /'
      exit 0 ;;
    remove) echo "No MCP server named 'x'"; exit 1 ;;
    enable) echo "No MCP server named 'x'"; exit 1 ;;
    doctor)
      # ${VAR} expanded at LOAD time, exactly as observed. The server name
      # echoes the one asked about, and the failure shape is reported the way
      # real grok reports it for a host that will not resolve.
      shift 2
      who=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --json) shift ;;
          --leader-socket) shift 2 ;;
          -*) shift ;;
          *) who="$1"; shift ;;
        esac
      done
      target="https://${HP_PROBE_HOST:-UNSET-PLACEHOLDER}/mcp"
      printf '{"sources":[],"servers":[{"name":"%s","transport":"http","target":"%s","checks":[{"label":"server started","passed":true},{"label":"handshake failed","passed":false,"detail":"dns error"}],"healthy":false}],"healthy_count":0,"failing_count":1}\n' "$who" "$target"
      exit 1 ;;
  esac
fi
exit 0
`
}

func TestTheCaptureSucceedsAgainstAGrokThatBehavesAsRecorded(t *testing.T) {
	stub := wellBehavedStub("")
	out, err := runCapture(t, stubGrok(t, stub))
	if err != nil {
		t.Fatalf("the capture FAILED against a grok behaving exactly as recorded.\n"+
			"A capture that refuses everything proves nothing.\nerror: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "wrote ") {
		t.Errorf("the capture succeeded but reported no output file; output:\n%s", out)
	}
}

// "Entries land enabled, so no `grok mcp enable` step is needed" is a
// conclusion task .2's writer depends on. A release that started writing
// enabled=false must break this capture, not slip past it.
func TestTheCaptureFailsWhenAnAddedEntryIsNotEnabled(t *testing.T) {
	stub := wellBehavedStub(`
if [ "$1" = mcp ] && [ "$2" = list ]; then
  case " $* " in
    *" --json "*)
      echo '[{"name":"homeplane-edge","url":"https://edge.example.invalid/mcp","enabled":false},{"name":"staleness-probe","enabled":true},{"name":"expand-probe","enabled":true}]'
      exit 0 ;;
  esac
fi
`)
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED with an entry that landed DISABLED;\n"+
			"the 'no enable step needed' conclusion would have been recorded as proven.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "did not land enabled") {
		t.Errorf("the capture failed but not with an enabled diagnosis; output:\n%s", out)
	}
}

// The fresh-process contract rests on there being no resident leader. A
// capture taken on a machine that DOES run one must fail loudly rather than
// record a guarantee that machine cannot honour — and it very nearly could
// not: forcing --leader-socket onto every probe made the leader DETECTOR
// point at a socket guaranteed to be absent, so it answered "no leader" by
// construction.
func TestTheCaptureFailsWhenALeaderIsRunning(t *testing.T) {
	stub := wellBehavedStub(`
if [ "$1" = leader ]; then
  echo "leader 4242 (pid 4242) on /somewhere/leader.sock"
  exit 0
fi
`)
	out, err := runCapture(t, stubGrok(t, stub))
	if err == nil {
		t.Fatalf("the capture SUCCEEDED on a machine with a resident leader;\n"+
			"the fresh-process contract would have been recorded as observed.\noutput:\n%s", out)
	}
	if !strings.Contains(out, "leader appears to be running") {
		t.Errorf("the capture failed but not with a leader diagnosis; output:\n%s", out)
	}
}

// doctor's SHAPE is what the decision record cites — the server identity, the
// handshake check, the health state. Parsing "some JSON" is not the same
// claim, and an earlier revision accepted a doctor that reported a healthy
// server with no checks at all.
func TestTheCaptureFailsWhenDoctorReportsNoFailureShape(t *testing.T) {
	for _, tc := range []struct {
		name, doctorBody string
	}{
		{
			name: "healthy despite an unreachable host",
			doctorBody: `echo '{"sources":[],"servers":[{"name":"homeplane-edge","transport":"http","target":"https://x/mcp","checks":[{"label":"ok","passed":true}],"healthy":true}],"failing_count":0}'
      exit 1`,
		},
		{
			name: "no checks, so no evidenced failure shape",
			doctorBody: `echo '{"sources":[],"servers":[{"name":"homeplane-edge","transport":"http","target":"https://x/mcp","checks":[],"healthy":false}],"failing_count":1}'
      exit 1`,
		},
		{
			name: "unexpected exit code",
			doctorBody: `echo '{"sources":[],"servers":[{"name":"homeplane-edge","transport":"http","target":"https://x/mcp","checks":[{"label":"handshake failed","passed":false}],"healthy":false}],"failing_count":1}'
      exit 0`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := wellBehavedStub(`
if [ "$1" = mcp ] && [ "$2" = doctor ]; then
      ` + tc.doctorBody + `
fi
`)
			out, err := runCapture(t, stubGrok(t, stub))
			if err == nil {
				t.Fatalf("the capture SUCCEEDED with doctor reporting %s;\noutput:\n%s", tc.name, out)
			}
			if !strings.Contains(out, "CAPTURE ABORTED") {
				t.Errorf("the capture failed but never said why; output:\n%s", out)
			}
		})
	}
}

// The documented `[path-to-grok]` argument is allowed to be relative, but every
// probe runs from a sealed working directory where a relative path no longer
// resolves — so it must be canonicalised up front.
func TestTheCaptureAcceptsARelativeBinaryPath(t *testing.T) {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(binDir, "grok")
	body := "#!/usr/bin/env bash\n" + wellBehavedStub("") + "\n"
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	_, script := stagedScript(t)
	cmd := exec.Command("bash", script, "./bin/grok")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the capture failed with a RELATIVE binary path, which the usage line allows.\n"+
			"error: %v\noutput:\n%s", err, out)
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
  leader)    echo "No leader candidates found."; exit 0 ;;
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
  leader)    echo "No leader candidates found."; exit 0 ;;
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
		// The decoy names appear EXACTLY twice in a valid contract: once each
		// in the block that declares them. Any further occurrence means a
		// decoy leaked into real grok output — i.e. GROK_HOME did not relocate
		// — which is the whole point of seeding them.
		//
		// An earlier version of this check asked whether the contract
		// contained a decoy name AND lacked the declaration text. Both are
		// always true of a valid contract, so the condition could never fire:
		// it would have passed a contract riddled with leaked decoys.
		const wantDecoyMentions = 2
		got := strings.Count(body, "decoy-must-never-appear") +
			strings.Count(body, "decoy-skill-must-never-appear")
		if got != wantDecoyMentions {
			t.Errorf("%s mentions the decoys %d times, want exactly %d "+
				"(one declaration line each); any extra occurrence means a decoy "+
				"leaked into captured grok output and GROK_HOME did not relocate",
				path, got, wantDecoyMentions)
		}
	}
}
