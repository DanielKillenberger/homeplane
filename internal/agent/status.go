package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/gno"
	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// Component states. `unknown` is the load-bearing one: it is what the agent
// reports when it could not establish a fact, and it is deliberately distinct
// from both `ok` and `degraded` so a server it cannot reach is never rendered
// as a working capability (R10).
const (
	// grantStateActive is the server-side wire value for a live grant.
	grantStateActive = "active"

	StateOK            = "ok"
	StateDegraded      = "degraded"
	StateUnknown       = "unknown"
	StateNotConfigured = "not_configured"
)

// Canonical machine-side component names reported by status.
const (
	ComponentEnrolment = "enrolment"
	ComponentVault     = "vault"
	ComponentSync      = "sync"
	ComponentGNO       = "gno"
	ComponentHarnesses = "harnesses"
	ComponentSkills    = "skills"
	ComponentGrants    = "grants"
	ComponentServer    = "server"
)

// Overall status values.
const (
	OverallOK          = "ok"
	OverallDegraded    = "degraded"
	OverallNotEnrolled = "not_enrolled"
)

// Exit codes. Distinguishing "not enrolled" from "degraded" lets a script tell
// a machine that was never set up from one that was and has since broken.
const (
	ExitOK          = 0
	ExitDegraded    = 1
	ExitNotEnrolled = 2
)

// ComponentReport is one machine-side component's reported state.
type ComponentReport struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// GrantReport is a grant as the SERVER currently sees it. There is no cached
// copy on the machine: every field here came from this call's `GET /grants`.
type GrantReport struct {
	GrantID      string   `json:"grant_id"`
	Harness      string   `json:"harness"`
	Capabilities []string `json:"capabilities"`
	State        string   `json:"state"`
	RevokedAt    string   `json:"revoked_at,omitempty"`
}

// Report is the whole machine-side picture.
type Report struct {
	Status      string            `json:"status"`
	StateDir    string            `json:"state_dir"`
	Enroled     bool              `json:"enroled"`
	ServerURL   string            `json:"server_url,omitempty"`
	MachineID   string            `json:"machine_id,omitempty"`
	MachineOS   string            `json:"os,omitempty"`
	MachineName string            `json:"machine_name,omitempty"`
	CheckedAt   time.Time         `json:"checked_at"`
	Components  []ComponentReport `json:"components"`
	Grants      []GrantReport     `json:"grants"`
	Server      *HealthReport     `json:"server,omitempty"`
}

// ExitCode maps the report onto a process exit status.
func (r Report) ExitCode() int {
	switch r.Status {
	case OverallOK:
		return ExitOK
	case OverallNotEnrolled:
		return ExitNotEnrolled
	default:
		return ExitDegraded
	}
}

// Degraded names every component that is not ok.
func (r Report) Degraded() []ComponentReport {
	var out []ComponentReport
	for _, c := range r.Components {
		if c.State != StateOK {
			out = append(out, c)
		}
	}
	return out
}

// StatusOptions describes one status check.
type StatusOptions struct {
	StateDir string
	Timeout  time.Duration
	// SkipServer suppresses the two control-plane calls. Offline callers get a
	// report whose server-dependent components read `unknown`, never `ok`.
	SkipServer bool
	// SyncLiveness observes whether the supervised sync process is ACTUALLY
	// running. Nil means supervise.ProcessProbe. It is injectable because a
	// SIGKILLed process records no exit, so the ledger alone cannot answer the
	// question — and a test must be able to stage "the pid is gone" without
	// killing a real process.
	SyncLiveness supervise.Probe
	// GNOLiveness observes the supervised retrieval engine, for the same reason
	// and with the same default (supervise.ProcessProbe).
	GNOLiveness supervise.Probe
}

// Status inspects the machine and reports what is actually true right now.
//
// The method is: read local state, then reconcile everything the server owns
// against the server. Nothing that depends on the server is answered from
// disk, because a machine's belief about its own grants is exactly the belief
// a revocation is designed to invalidate.
func Status(ctx context.Context, opts StatusOptions) (Report, error) {
	dir := opts.StateDir
	if dir == "" {
		return Report{}, errors.New("agent: state directory is required")
	}

	report := Report{
		StateDir:  dir,
		CheckedAt: time.Now().UTC(),
		Grants:    []GrantReport{},
	}

	state, hasState, err := PeekState(dir)
	if err != nil {
		// An unreadable or corrupt state file is a machine-side failure, and
		// status is the surface whose job that is.
		report.Status = OverallDegraded
		report.Components = []ComponentReport{{
			Name: ComponentEnrolment, State: StateDegraded,
			Detail: "agent state is unreadable: " + err.Error(),
		}}
		return report, nil
	}

	credential := ""
	if hasState {
		store := &Store{dir: dir}
		credential, err = store.Credential()
		if err != nil && !errors.Is(err, ErrNotEnroled) {
			credential = ""
		}
	}

	report.Enroled = hasState && state.Enroled() && credential != ""
	report.ServerURL = state.ServerURL
	report.MachineID = state.MachineID
	report.MachineName = state.MachineName
	report.MachineOS = state.OS

	report.Components = append(report.Components, enrolmentComponent(hasState, state, credential))
	report.Components = append(report.Components, vaultComponent(state))
	report.Components = append(report.Components, syncComponent(dir, state, opts.SyncLiveness))
	report.Components = append(report.Components, gnoComponent(dir, state, opts.GNOLiveness))
	report.Components = append(report.Components, listComponent(ComponentHarnesses, state.Harnesses, "no harness is configured yet"))
	report.Components = append(report.Components, listComponent(ComponentSkills, state.Skills, "no skills are provisioned yet"))

	grants, server := serverComponents(ctx, opts, report.Enroled, state, credential)
	report.Components = append(report.Components, grants.component, server.component)
	report.Grants = grants.grants
	report.Server = server.health

	switch {
	case !report.Enroled:
		report.Status = OverallNotEnrolled
	case len(report.Degraded()) > 0:
		report.Status = OverallDegraded
	default:
		report.Status = OverallOK
	}
	return report, nil
}

func enrolmentComponent(hasState bool, state State, credential string) ComponentReport {
	c := ComponentReport{Name: ComponentEnrolment}
	switch {
	case !hasState || !state.Enroled():
		c.State = StateDegraded
		c.Detail = "machine is not enrolled — run `homeplane-agent enrol -server <url>`"
	case credential == "":
		// State says enrolled but the secret is gone: the machine cannot
		// authenticate, and saying "enrolled" here would be a lie with an exit
		// code of zero attached to it.
		c.State = StateDegraded
		c.Detail = "machine credential is missing or unreadable — re-run `homeplane-agent enrol`"
	default:
		c.State = StateOK
		c.Detail = fmt.Sprintf("machine %s (%s) enrolled at %s, credential version %d",
			state.MachineID, state.MachineName, state.ServerURL, state.CredentialVersion)
	}
	return c
}

func vaultComponent(state State) ComponentReport {
	c := ComponentReport{Name: ComponentVault}
	if strings.TrimSpace(state.VaultPath) == "" {
		// No path. The recorded reason is what distinguishes "no vault on this
		// machine" from "retrieval failed because the sync credential was
		// rejected" — both leave VaultPath empty, and R3 requires status to
		// name which one happened.
		if state.Vault != nil && strings.TrimSpace(state.Vault.State) != "" {
			c.State = state.Vault.State
			c.Detail = state.Vault.Detail
			return c
		}
		c.State = StateNotConfigured
		c.Detail = "no vault path recorded yet"
		return c
	}
	info, err := os.Stat(state.VaultPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.State = StateDegraded
		c.Detail = "vault path " + state.VaultPath + " does not exist"
	case err != nil:
		c.State = StateDegraded
		c.Detail = "vault path " + state.VaultPath + " is unreadable: " + err.Error()
	case !info.IsDir():
		c.State = StateDegraded
		c.Detail = "vault path " + state.VaultPath + " is not a directory"
	default:
		c.State = StateOK
		c.Detail = state.VaultPath
	}
	return c
}

// Sync component states beyond the shared vocabulary.
const (
	// StateInstalled means the supervision unit exists on disk but has not been
	// loaded into launchd/systemd. The vault is NOT syncing, and saying `ok`
	// here would be the exact lie R14 forbids.
	StateInstalled = "installed"
)

// syncComponent reports whether the vault is ACTUALLY syncing.
//
// The recorded state in state.json is a claim made at activation time; the
// restart ledger is what the supervised process has done since. A machine can
// record `ok` and then be SIGKILLed, crash-loop, or exit — and a status that
// only echoed the recorded claim would keep reporting a healthy sync through
// all three. So the ledger is authoritative for liveness, and the recorded
// state only supplies the reason when there is nothing running to ask.
func syncComponent(stateDir string, state State, probe supervise.Probe) ComponentReport {
	c := localComponent(ComponentSync, state.Sync, "vault sync is not configured yet")
	if state.Sync == nil || strings.TrimSpace(state.Sync.State) == "" {
		return c
	}
	// A recorded failure (bad pin, destructive diff, auth failure) is the whole
	// story: nothing was supervised, so there is no ledger to consult.
	if c.State != StateOK && c.State != StateInstalled {
		return c
	}
	ledger, live, err := (supervise.Tracker{Dir: stateDir, Label: supervise.VaultSyncLabel}).Observe(probe)
	if err != nil {
		return ComponentReport{Name: ComponentSync, State: StateUnknown,
			Detail: "restart history unreadable: " + err.Error()}
	}
	now := time.Now()
	switch {
	case c.State == StateInstalled:
		// Installed but never loaded. If the ledger shows starts anyway, the
		// supervisor did pick it up and the recorded claim is simply stale.
		if ledger.TotalStarts == 0 {
			c.State = StateDegraded
			c.Detail = "supervision unit installed but not loaded — vault is NOT syncing; " + c.Detail
			return c
		}
	case ledger.TotalStarts == 0:
		c.State = StateDegraded
		c.Detail = "supervised but never started — vault is NOT syncing; " + c.Detail
		return c
	}
	// Liveness comes from the PROBE, never from the ledger's last event. A
	// SIGKILLed process records no exit, so a ledger ending on a start is
	// exactly what a dead-and-never-restarted sync looks like.
	switch {
	case ledger.CrashLooping(now, supervise.DefaultCrashLoopWindow, supervise.DefaultCrashLoopThreshold):
		c.State = StateDegraded
		c.Detail = "crash-looping (retryable; the vault remains readable locally) — " + ledger.Summary(now)
	case !live.Known:
		// Truthfulness beats optimism: an unobservable process is `unknown`,
		// which is the same rule the server-dependent components follow.
		c.State = StateUnknown
		c.Detail = "cannot tell whether sync is running (" + live.Detail + ") — " + ledger.Summary(now)
	case !live.Alive:
		c.State = StateDegraded
		c.Detail = "not running: " + live.Detail +
			" (retryable; the vault remains readable locally) — " + ledger.Summary(now)
	default:
		c.State = StateOK
		c.Detail = live.Detail + "; " + ledger.Summary(now) + "; " + c.Detail
	}
	return c
}

// gnoComponent reports whether the retrieval engine is ACTUALLY running.
//
// R4 names two lifecycles and forbids conflating them, so this reports both and
// keeps them labelled:
//
//	the DAEMON is supervised — pid, restart count, crash-loop, all from the
//	  shared ledger and an external liveness probe, exactly like vault sync;
//	the STDIO endpoint is launched per client — it has no pid, so what is
//	  reported is the LAST PROBE of the launch template, with its timestamp.
//
// The engine also has a hard precondition: no vault, no engine. A machine whose
// vault is missing must report the engine as degraded and SAY why, rather than
// leaving a not_configured that reads like "nobody got round to it yet".
func gnoComponent(stateDir string, state State, probe supervise.Probe) ComponentReport {
	// The vault is checked FIRST, and unconditionally.
	//
	// R4 makes the engine's dependency explicit: no vault, no engine, and the
	// state is named. That has to be evaluated before anything else, because the
	// dangerous case is not the fresh machine — it is the machine that activated
	// successfully weeks ago and whose vault directory has since vanished. Its
	// recorded state still says `ok` and its daemon pid is still alive (GNO keeps
	// serving a stale index), so consulting the recorded state first would report
	// a healthy retrieval engine over a vault that is gone.
	if degraded, ok := vaultBlocker(state); ok {
		return degraded
	}

	c := localComponent(ComponentGNO, state.GNO, "the retrieval engine is not configured yet")
	if state.GNO == nil || strings.TrimSpace(state.GNO.State) == "" {
		return c
	}
	// A recorded failure is the whole story: nothing was supervised, so there is
	// no ledger to consult.
	if c.State != StateOK && c.State != StateInstalled {
		return c
	}
	ledger, live, err := (supervise.Tracker{Dir: stateDir, Label: supervise.GNOLabel}).Observe(probe)
	if err != nil {
		return ComponentReport{Name: ComponentGNO, State: StateUnknown,
			Detail: "restart history unreadable: " + err.Error()}
	}
	now := time.Now()
	switch {
	case c.State == StateInstalled:
		if ledger.TotalStarts == 0 {
			c.State = StateDegraded
			c.Detail = "supervision unit installed but not loaded — the index is NOT being kept current; " + c.Detail
			return c
		}
	case ledger.TotalStarts == 0:
		c.State = StateDegraded
		c.Detail = "supervised but never started — the index is NOT being kept current; " + c.Detail
		return c
	}
	switch {
	case ledger.CrashLooping(now, supervise.DefaultCrashLoopWindow, supervise.DefaultCrashLoopThreshold):
		c.State = StateDegraded
		c.Detail = "crash-looping (retryable; the vault remains readable locally) — " + ledger.Summary(now)
	case !live.Known:
		c.State = StateUnknown
		c.Detail = "cannot tell whether the retrieval engine is running (" + live.Detail + ") — " + ledger.Summary(now)
	case !live.Alive:
		c.State = StateDegraded
		c.Detail = "not running: " + live.Detail +
			" (retryable; the vault remains readable locally) — " + ledger.Summary(now)
	default:
		c.State = StateOK
		c.Detail = live.Detail + "; " + ledger.Summary(now) + "; " + c.Detail
	}
	return withStdioLaunches(stateDir, c)
}

// vaultBlocker reports the engine's state when the vault cannot support it.
//
// Every branch names both the blocker and the fix, because "not_configured" on
// its own is indistinguishable from "nobody has got round to it" — and R4 asks
// for a named degraded state, not a shrug.
func vaultBlocker(state State) (ComponentReport, bool) {
	report := func(s, detail string) (ComponentReport, bool) {
		return ComponentReport{Name: ComponentGNO, State: s, Detail: detail}, true
	}
	path := strings.TrimSpace(state.VaultPath)
	if path == "" {
		return report(StateDegraded,
			"not started: no vault on this machine — run `homeplane-agent vault detect -record` or `vault retrieve` first (retryable)")
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return report(StateDegraded,
			"not started: the vault at "+path+" no longer exists — the engine cannot index what is not there (retryable)")
	case err != nil:
		return report(StateDegraded,
			"not started: the vault at "+path+" is unreadable: "+err.Error()+" (retryable)")
	case !info.IsDir():
		return report(StateDegraded,
			"not started: the vault path "+path+" is not a directory (retryable)")
	}
	return ComponentReport{}, false
}

// withStdioLaunches folds the harness-launch history into the engine's report.
//
// The daemon and the stdio endpoint fail independently: the indexer can be
// perfectly healthy while every harness launch dies on a missing runtime. A
// report that only described the daemon would call that machine `ok`.
func withStdioLaunches(stateDir string, c ComponentReport) ComponentReport {
	launches, err := gno.LoadLaunchLedger(stateDir)
	if err != nil {
		return c
	}
	// Never launched is not a fault: harnesses start the endpoint on demand, and
	// a machine configured this morning has legitimately never seen one.
	if launches.TotalLaunches == 0 {
		return c
	}
	c.Detail += "; " + launches.Summary()
	if launches.ConsecutiveFailures() > 0 && c.State == StateOK {
		// The daemon is fine, so this is specifically the harness path failing —
		// say which half is broken rather than degrading the whole thing namelessly.
		c.State = StateDegraded
		c.Detail = "the indexing daemon is healthy but harness launches are FAILING — " + c.Detail
	}
	return c
}

// localComponent reports a component whose state a later task records in
// state.json. Absent means "not configured", never "ok".
func localComponent(name string, recorded *ComponentState, absentDetail string) ComponentReport {
	if recorded == nil || strings.TrimSpace(recorded.State) == "" {
		return ComponentReport{Name: name, State: StateNotConfigured, Detail: absentDetail}
	}
	return ComponentReport{Name: name, State: recorded.State, Detail: recorded.Detail}
}

func listComponent(name string, values []string, absentDetail string) ComponentReport {
	if len(values) == 0 {
		return ComponentReport{Name: name, State: StateNotConfigured, Detail: absentDetail}
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return ComponentReport{Name: name, State: StateOK, Detail: strings.Join(sorted, ", ")}
}

type grantsResult struct {
	component ComponentReport
	grants    []GrantReport
}

type serverResult struct {
	component ComponentReport
	health    *HealthReport
}

// serverComponents performs the live reconcile.
//
// Every failure path here lands on `unknown` with the reason attached. The one
// thing this function will never do is fall back to a remembered answer.
func serverComponents(ctx context.Context, opts StatusOptions, enroled bool, state State, credential string) (grantsResult, serverResult) {
	grants := grantsResult{
		component: ComponentReport{Name: ComponentGrants, State: StateUnknown},
		grants:    []GrantReport{},
	}
	server := serverResult{component: ComponentReport{Name: ComponentServer, State: StateUnknown}}

	if !enroled {
		grants.component.Detail = "unknown (machine is not enrolled)"
		server.component.Detail = "unknown (machine is not enrolled)"
		return grants, server
	}
	if opts.SkipServer {
		grants.component.Detail = "unknown (server not contacted)"
		server.component.Detail = "unknown (server not contacted)"
		return grants, server
	}

	client, err := NewClient(state.ServerURL, opts.Timeout)
	if err != nil {
		detail := "unknown (" + err.Error() + ")"
		grants.component.Detail = detail
		server.component.Detail = detail
		return grants, server
	}
	authed := client.WithCredential(credential)

	if report, err := client.Health(ctx); err != nil {
		server.component.Detail = "unknown (" + serverFailureDetail(err) + ")"
	} else {
		server.health = &report
		if report.Status == StateOK {
			server.component.State = StateOK
			server.component.Detail = state.ServerURL
		} else {
			server.component.State = StateDegraded
			server.component.Detail = state.ServerURL + ": " + strings.Join(degradedComponentNames(report), ", ")
		}
	}

	live, err := authed.ListGrants(ctx)
	if err != nil {
		grants.component.Detail = "unknown (" + serverFailureDetail(err) + ")"
		return grants, server
	}

	var active, revoked []string
	for _, g := range live {
		grants.grants = append(grants.grants, GrantReport{
			GrantID:      g.GrantID,
			Harness:      g.Harness,
			Capabilities: g.Capabilities,
			State:        g.State,
			RevokedAt:    g.RevokedAt,
		})
		if g.State == grantStateActive {
			active = append(active, g.Harness)
		} else {
			revoked = append(revoked, g.Harness+"/"+g.GrantID)
		}
	}
	sort.Strings(active)
	sort.Strings(revoked)

	switch {
	case len(live) == 0:
		grants.component.State = StateNotConfigured
		grants.component.Detail = "no grants issued to this machine"
	case len(active) == 0:
		// Every grant this machine holds has been revoked server-side. The
		// machine keeps working locally, but its plane access is gone, and
		// that is a degraded machine however healthy the server is.
		grants.component.State = StateDegraded
		grants.component.Detail = "no active grants; revoked: " + strings.Join(revoked, ", ")
	case len(revoked) > 0:
		grants.component.State = StateOK
		grants.component.Detail = fmt.Sprintf("active: %s (revoked: %s)",
			strings.Join(active, ", "), strings.Join(revoked, ", "))
	default:
		grants.component.State = StateOK
		grants.component.Detail = "active: " + strings.Join(active, ", ")
	}
	return grants, server
}

// serverFailureDetail phrases a failed control-plane call for a human reading
// `status`, keeping "unreachable" distinct from "refused".
func serverFailureDetail(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("server refused: %d %s", apiErr.Status, apiErr.Code)
	}
	if Unreachable(err) {
		return "server unreachable"
	}
	return err.Error()
}

func degradedComponentNames(report HealthReport) []string {
	var names []string
	for _, c := range report.Components {
		if c.Status != StateOK {
			names = append(names, c.Name+" "+c.Status)
		}
	}
	if len(names) == 0 {
		names = append(names, report.Status)
	}
	return names
}
