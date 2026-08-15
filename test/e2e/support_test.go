//go:build live_e2e

package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- the environment the proof runs against ----------------------------------

// env is the deployment under proof. Every field is an operational fact — a
// running server, an installed agent, an account that consented — and none of
// them has a default: a proof that invented its own target would prove nothing.
type env struct {
	// serverURL is the control plane over the tailnet.
	serverURL string
	// sshHost reaches the server host for the OPERATOR surface (admin audit,
	// admin revoke-grant), which is deliberately server-local (spec: operator
	// identity is local shell access).
	sshHost string
	// stateDir is the server's state directory on that host.
	serverStateDir string
	// account is the Google account the credential was consented for.
	account string
	// calendarID is the calendar R8's isolated test event lives on.
	calendarID string
	// vaultPath is the Daniel-OS vault on this machine.
	vaultPath string
	// stages selects which stages run (empty = all).
	stages map[string]bool
	// evidencePath is where the machine-readable record is written.
	evidencePath string
}

func loadEnv(t *testing.T) env {
	t.Helper()
	if os.Getenv("HOMEPLANE_E2E") != "1" {
		t.Skip("set HOMEPLANE_E2E=1 (and the deployment vars) to run the end-to-end proof")
	}
	e := env{
		serverURL:      os.Getenv("HOMEPLANE_E2E_SERVER"),
		sshHost:        os.Getenv("HOMEPLANE_E2E_SSH_HOST"),
		serverStateDir: os.Getenv("HOMEPLANE_E2E_SERVER_STATE_DIR"),
		account:        os.Getenv("HOMEPLANE_E2E_ACCOUNT"),
		calendarID:     os.Getenv("HOMEPLANE_E2E_CALENDAR_ID"),
		vaultPath:      os.Getenv("HOMEPLANE_E2E_VAULT"),
		evidencePath:   os.Getenv("HOMEPLANE_E2E_EVIDENCE"),
	}
	if e.serverURL == "" || e.sshHost == "" || e.account == "" {
		t.Fatal("HOMEPLANE_E2E_SERVER, HOMEPLANE_E2E_SSH_HOST and HOMEPLANE_E2E_ACCOUNT are required")
	}
	if e.serverStateDir == "" {
		e.serverStateDir = "homeplane/var"
	}
	if e.calendarID == "" {
		e.calendarID = "primary"
	}
	if e.evidencePath == "" {
		e.evidencePath = filepath.Join("..", "evidence", "fn-1-homeplane-walking-skeleton-install.7.live.json")
	} else if !filepath.IsAbs(e.evidencePath) {
		// `go test` runs in the package directory, so a caller who passed
		// `test/evidence/…` from the repository root means the repository root.
		// Resolving it here rather than silently writing `test/e2e/test/evidence/…`
		// — which is what happened, and produced an artifact nobody was looking at.
		out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
		if err != nil {
			t.Fatalf("HOMEPLANE_E2E_EVIDENCE is relative (%s) and the repository root could not be resolved: %v",
				e.evidencePath, err)
		}
		e.evidencePath = filepath.Join(strings.TrimSpace(string(out)), e.evidencePath)
	}
	if raw := strings.TrimSpace(os.Getenv("HOMEPLANE_E2E_STAGES")); raw != "" {
		e.stages = map[string]bool{}
		for _, s := range strings.Split(raw, ",") {
			e.stages[strings.TrimSpace(s)] = true
		}
	}
	return e
}

// agentBin is the INSTALLED agent — the artifact the installer placed, not a
// `go run` of the working tree. The proof is of a machine that was installed.
func agentBin() string {
	if v := os.Getenv("HOMEPLANE_E2E_AGENT"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".homeplane", "bin", "homeplane-agent")
}

// --- running things ----------------------------------------------------------

// result is one executed command, recorded whether it succeeded or not.
type result struct {
	What     string   `json:"what"`
	Command  []string `json:"command"`
	ExitCode int      `json:"exit_code"`
	Stdout   string   `json:"stdout_excerpt"`
	Stderr   string   `json:"stderr_excerpt"`
	At       string   `json:"at"`
	Duration string   `json:"duration"`

	// full is the untruncated stdout. Callers parse THIS; the excerpt above is
	// for the record a human reads. Parsing the excerpt is how a proof starts
	// failing on output that merely grew — which it did, the first time an
	// agent accumulated enough grants to push its status report past the limit.
	full string
}

const excerptLimit = 4000

func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= excerptLimit {
		return s
	}
	return s[:excerptLimit] + fmt.Sprintf("\n…[%d bytes truncated]", len(s)-excerptLimit)
}

// run executes a command and records it. It never fails the test by itself:
// the proof decides what a non-zero exit means, and a stage that EXPECTS a
// failure (a denial, a revoked grant) needs the same recording as one that
// expects success.
func (s *stage) run(what string, timeout time.Duration, name string, args ...string) result {
	s.t.Helper()
	started := time.Now().UTC()
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		res := result{What: what, Command: append([]string{name}, args...), ExitCode: -1,
			Stderr: err.Error(), At: started.Format(time.RFC3339), Duration: "0s"}
		s.steps = append(s.steps, res)
		return res
	}
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		err = <-done
		stderr.WriteString(fmt.Sprintf("\n[killed after %s]", timeout))
	}

	code := 0
	if err != nil {
		code = cmd.ProcessState.ExitCode()
		if code == 0 {
			code = -1
		}
	}
	res := result{
		What: what, Command: append([]string{name}, args...), ExitCode: code,
		Stdout: excerpt(stdout.String()), Stderr: excerpt(stderr.String()), full: stdout.String(),
		At: started.Format(time.RFC3339), Duration: time.Since(started).Round(time.Millisecond).String(),
	}
	s.steps = append(s.steps, res)
	s.t.Logf("· %s → exit %d (%s)", what, code, res.Duration)
	return res
}

// agent runs the installed agent CLI.
func (s *stage) agent(what string, timeout time.Duration, args ...string) result {
	s.t.Helper()
	return s.run(what, timeout, agentBin(), args...)
}

// runWithEnv is run() with named environment overrides, and it exists for one
// job: producing the detection states a machine reaches when a harness is NOT
// the way this machine has it.
//
// `not_detected` and `detected_unsupported` are real states of the product's
// own detection path, and the only two ways to reach them are to change the
// machine or to change what the machine looks at. Changing the machine would
// mean uninstalling or downgrading the operator's grok, which this proof
// refuses to do; changing what detection looks at — PATH and GROK_HOME, both
// first-class inputs the product documents — produces the same code path with
// the same binary. The environment used is recorded in the step, so a reader
// sees exactly which run was doctored and how.
func (s *stage) runWithEnv(what string, env map[string]string, timeout time.Duration, name string, args ...string) result {
	s.t.Helper()
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	overrides := make([]string, 0, len(keys))
	for _, k := range keys {
		overrides = append(overrides, k+"="+env[k])
	}
	// `env K=V… cmd` keeps the overrides visible in the recorded command line,
	// which is the point: an assertion about a doctored environment has to show
	// the doctoring.
	full := append(append([]string{}, overrides...), append([]string{name}, args...)...)
	return s.run(what, timeout, "env", full...)
}

// ssh runs an OPERATOR command on the server host. The operator surface is
// server-local by design, so reaching it over ssh is the shape the spec
// describes rather than a shortcut around an API.
func (s *stage) ssh(what string, timeout time.Duration, script string) result {
	s.t.Helper()
	return s.run(what, timeout, "ssh", "-o", "BatchMode=yes", s.env.sshHost, script)
}

// --- the server's audit log --------------------------------------------------

// auditRow mirrors store.AuditEvent as the admin CLI encodes it (no JSON tags
// there, so the keys are the Go field names).
type auditRow struct {
	ID               int64             `json:"ID"`
	TS               time.Time         `json:"TS"`
	Event            string            `json:"Event"`
	ActorKind        string            `json:"ActorKind"`
	ObservedNodeID   string            `json:"ObservedNodeID"`
	ObservedNodeName string            `json:"ObservedNodeName"`
	AuthMachineID    string            `json:"AuthMachineID"`
	Harness          string            `json:"Harness"`
	GrantID          string            `json:"GrantID"`
	ActionClass      string            `json:"ActionClass"`
	Tool             string            `json:"Tool"`
	ArtifactID       string            `json:"ArtifactID"`
	Outcome          string            `json:"Outcome"`
	Reason           string            `json:"Reason"`
	TokenFingerprint string            `json:"TokenFingerprint"`
	Detail           map[string]string `json:"Detail"`
}

// audit reads the authoritative log through the operator CLI on the server.
//
// Reading it over ssh rather than from a copy is the point: the rows the
// acceptance gate reads are the rows the running server wrote.
func (s *stage) audit(what string, since time.Time) []auditRow {
	s.t.Helper()
	script := fmt.Sprintf("%s/bin/homeplane-server admin audit -state-dir %s -json -since %s -limit 2000",
		serverPrefix(s.env), s.env.serverStateDir, since.UTC().Format(time.RFC3339))
	res := s.run(what, 60*time.Second, "ssh", "-o", "BatchMode=yes", s.env.sshHost, script)
	if res.ExitCode != 0 {
		s.t.Fatalf("reading the server audit log failed: exit %d\n%s", res.ExitCode, res.Stderr)
	}
	var rows []auditRow
	dec := json.NewDecoder(strings.NewReader(res.full))
	for {
		var r auditRow
		if err := dec.Decode(&r); err != nil {
			break
		}
		rows = append(rows, r)
	}
	return rows
}

func serverPrefix(e env) string {
	if v := os.Getenv("HOMEPLANE_E2E_SERVER_PREFIX"); v != "" {
		return v
	}
	return "homeplane"
}

// --- evidence ----------------------------------------------------------------

// assertion is one acceptance-bearing claim, with the observation that settles
// it. The acceptance gate in task .14 reads these; prose in a log does not
// travel, and a claim with no observation attached is an opinion.
type assertion struct {
	Claim  string `json:"claim"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type stageRecord struct {
	Stage      string      `json:"stage"`
	Status     string      `json:"status"` // pass | fail | skipped | partial
	Reason     string      `json:"reason,omitempty"`
	StartedAt  string      `json:"started_at"`
	FinishedAt string      `json:"finished_at"`
	Steps      []result    `json:"steps"`
	Assertions []assertion `json:"assertions"`
}

// recorder accumulates the whole run. It is written after EVERY stage, so a run
// that is interrupted (a human who never consents, a laptop that sleeps) still
// leaves the record of what did happen.
type recorder struct {
	mu     sync.Mutex
	path   string
	doc    map[string]any
	stages []stageRecord
}

func newRecorder(t *testing.T, e env, meta map[string]any) *recorder {
	t.Helper()
	r := &recorder{path: e.evidencePath, doc: meta}
	// A previous run's stages are carried forward so an interactive proof can be
	// completed in sittings: a stage runs again and REPLACES its earlier record,
	// and one that is not re-run keeps the result it earned.
	if raw, err := os.ReadFile(e.evidencePath); err == nil {
		var prev struct {
			Stages []stageRecord `json:"stages"`
		}
		if json.Unmarshal(raw, &prev) == nil {
			r.stages = prev.Stages
			t.Logf("carrying %d stage record(s) forward from %s", len(prev.Stages), e.evidencePath)
		}
	}
	return r
}

func (r *recorder) put(rec stageRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	replaced := false
	for i := range r.stages {
		if r.stages[i].Stage == rec.Stage {
			r.stages[i], replaced = rec, true
			break
		}
	}
	if !replaced {
		r.stages = append(r.stages, rec)
	}
	r.flush()
}

// flush writes the evidence file. Callers hold the lock.
func (r *recorder) flush() {
	doc := map[string]any{}
	for k, v := range r.doc {
		doc[k] = v
	}
	doc["stages"] = r.stages
	doc["updated_at"] = time.Now().UTC().Format(time.RFC3339)

	passed, failed, partial, skipped := 0, 0, 0, 0
	for _, s := range r.stages {
		switch s.Status {
		case "pass":
			passed++
		case "fail":
			failed++
		case "partial":
			partial++
		default:
			skipped++
		}
	}
	doc["summary"] = map[string]int{
		"stages_passed": passed, "stages_failed": failed,
		"stages_partial": partial, "stages_skipped": skipped,
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		panic(err)
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o644); err != nil {
		panic(err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		panic(err)
	}
}

// --- stages ------------------------------------------------------------------

// stage is one leg of the proof. It records everything it runs and everything it
// concludes, and its record is written even when it fails — a proof that only
// reports its successes is a demo.
type stage struct {
	t          *testing.T
	env        env
	rec        *recorder
	name       string
	started    time.Time
	steps      []result
	assertions []assertion
	failed     bool
	partial    bool
	reason     string
}

func (s *stage) assert(claim string, ok bool, format string, args ...any) bool {
	s.t.Helper()
	detail := fmt.Sprintf(format, args...)
	s.assertions = append(s.assertions, assertion{Claim: claim, OK: ok, Detail: detail})
	if ok {
		s.t.Logf("  ✓ %s — %s", claim, detail)
	} else {
		s.failed = true
		s.t.Errorf("  ✗ %s — %s", claim, detail)
	}
	return ok
}

// record marks a leg that genuinely could not run here, with an owner. It is
// the one honest alternative to a silent skip.
func (s *stage) recordLimitation(claim, detail string) {
	s.t.Helper()
	s.partial = true
	s.assertions = append(s.assertions, assertion{Claim: claim, OK: false, Detail: "LIMITATION: " + detail})
	s.t.Logf("  ! %s — LIMITATION: %s", claim, detail)
}

func (s *stage) finish() {
	status := "pass"
	switch {
	case s.failed:
		status = "fail"
	case s.partial:
		status = "partial"
	}
	s.rec.put(stageRecord{
		Stage: s.name, Status: status, Reason: s.reason,
		StartedAt:  s.started.Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Steps:      s.steps, Assertions: s.assertions,
	})
}

// runStage runs one leg unless the selection excludes it. A skipped stage is
// recorded as skipped with its reason — never dropped.
func runStage(t *testing.T, e env, rec *recorder, name string, fn func(*stage)) {
	t.Helper()
	if e.stages != nil && !e.stages[name] {
		t.Logf("== stage %s: not selected", name)
		return
	}
	t.Run(name, func(t *testing.T) {
		s := &stage{t: t, env: e, rec: rec, name: name, started: time.Now().UTC()}
		defer s.finish()
		t.Logf("== stage %s", name)
		fn(s)
	})
}
