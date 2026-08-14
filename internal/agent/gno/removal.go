package gno

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/agent/supervise"
)

// Uninstall-hook registration.
//
// `homeplane-agent uninstall` is deferred hardening (spec Boundaries, D17), and
// this task does not build it. What it DOES do is make the deferral survivable:
// every side effect activation produces is written down, at the moment it is
// produced, in a machine-readable plan. Without that, a future uninstall would
// have to re-derive what a past agent version did — from a machine whose agent
// has since been upgraded — and a supervised daemon nobody can find is exactly
// how a "removed" component keeps running.
//
// The plan is registered, not executed. `homeplane-agent gno deactivate` runs
// the component's own half of it; the deferred global uninstall reads the same
// file.

// RemovalSchemaVersion is bumped when the plan's shape changes.
const RemovalSchemaVersion = 1

// RemovalDir holds one plan per component role.
func RemovalDir(stateDir string) string { return filepath.Join(stateDir, "removal") }

// RemovalPlanPath is the retrieval engine's removal plan.
func RemovalPlanPath(stateDir string) string {
	return filepath.Join(RemovalDir(stateDir), ComponentRetrievalEngine+".json")
}

// RemovalPlan is everything activation created, and how to undo it.
type RemovalPlan struct {
	SchemaVersion int       `json:"schema_version"`
	Component     string    `json:"component"`
	Engine        string    `json:"engine"`
	RegisteredAt  time.Time `json:"registered_at"`

	// Deactivate stops and unloads the supervised unit. Run FIRST: deleting a
	// unit file that launchd still has loaded leaves a running daemon with no
	// unit behind it.
	Deactivate []supervise.Command `json:"deactivate_commands"`
	// UnitPath is the supervision unit file to delete after deactivation.
	UnitPath string `json:"unit_path"`
	// HarnessCleanup removes GNO's entries from each harness's MCP config. Task
	// .6 owns writing them; upstream owns removing them, and these are its own
	// commands rather than an edit Homeplane would have to reimplement.
	HarnessCleanup []RemovalCommand `json:"harness_cleanup_commands"`
	// Paths are the machine-local directories and files to delete. They are
	// listed deepest-first so a partial run never orphans a child.
	Paths []string `json:"paths"`
	// Keep names what removal must NOT touch. The vault is the whole point: an
	// uninstall that deleted synchronized content would propagate that deletion
	// to every other machine.
	Keep []string `json:"keep"`
}

// RemovalCommand is one external command with its argv.
type RemovalCommand struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Reason  string   `json:"reason"`
}

// ErrNoRemovalPlan means nothing was ever registered for this component.
var ErrNoRemovalPlan = errors.New("gno: no removal plan registered for the retrieval engine")

// RegisterRemoval records how to undo this activation.
func RegisterRemoval(stateDir string, cfg Config, installer supervise.Installer, uid string, now time.Time) error {
	unit, err := DaemonUnit(orSelf(cfg.UnitPath), stateDir, cfg.DaemonHost, cfg.DaemonPort, cfg.GatewayToken)
	if err != nil {
		return err
	}
	deactivate, err := installer.DeactivationCommands(unit, uid)
	if err != nil {
		return err
	}
	plan := RemovalPlan{
		SchemaVersion: RemovalSchemaVersion,
		Component:     ComponentRetrievalEngine,
		Engine:        "gno",
		RegisteredAt:  now.UTC(),
		Deactivate:    deactivate,
		UnitPath:      cfg.UnitPath,
		Paths: []string{
			cfg.Paths.Data,
			LaunchLedgerPath(stateDir),
			cfg.Paths.Cache,
			cfg.Paths.Config,
			DescriptorPath(stateDir),
			ConfigPath(stateDir),
		},
		Keep: []string{cfg.VaultPath},
	}
	for _, target := range []string{TargetClaudeCode, TargetCodex} {
		plan.HarnessCleanup = append(plan.HarnessCleanup, RemovalCommand{
			Command: cfg.Bin,
			Args:    MCPUninstallArgs(target, ScopeUser),
			Reason:  "remove the retrieval engine's MCP entry from " + target,
		})
	}
	return SaveRemovalPlan(stateDir, plan)
}

// SaveRemovalPlan writes the plan atomically.
func SaveRemovalPlan(stateDir string, plan RemovalPlan) error {
	plan.SchemaVersion = RemovalSchemaVersion
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("gno: encode removal plan: %w", err)
	}
	if err := os.MkdirAll(RemovalDir(stateDir), dirPerm); err != nil {
		return fmt.Errorf("gno: create removal directory: %w", err)
	}
	return writeFileAtomic(RemovalPlanPath(stateDir), append(raw, '\n'), filePerm)
}

// LoadRemovalPlan reads the registered plan.
func LoadRemovalPlan(stateDir string) (RemovalPlan, error) {
	raw, err := os.ReadFile(RemovalPlanPath(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RemovalPlan{}, ErrNoRemovalPlan
		}
		return RemovalPlan{}, fmt.Errorf("gno: read removal plan: %w", err)
	}
	var plan RemovalPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return RemovalPlan{}, fmt.Errorf("gno: parse %s: %w", RemovalPlanPath(stateDir), err)
	}
	return plan, nil
}

// DeactivateResult reports what a deactivation actually did.
type DeactivateResult struct {
	Commands  []supervise.Command `json:"commands"`
	Executed  bool                `json:"executed"`
	Removed   []string            `json:"removed"`
	Kept      []string            `json:"kept"`
	Remaining []string            `json:"remaining,omitempty"`
}

// Deactivate stops the supervised engine and removes its machine-local state.
//
// It refuses to delete anything under a path the plan says to KEEP, which is
// how "the vault is never touched" is enforced rather than promised. Without a
// runner it reports what it WOULD run and deletes nothing, matching the rest of
// the supervision framework's stance on mutating a live session.
func Deactivate(stateDir string, run func(name string, args ...string) error, deleteState bool) (DeactivateResult, error) {
	plan, err := LoadRemovalPlan(stateDir)
	if err != nil {
		return DeactivateResult{}, err
	}
	res := DeactivateResult{Commands: plan.Deactivate, Kept: plan.Keep}
	if run == nil {
		return res, nil
	}
	res.Executed = true
	for _, c := range plan.Deactivate {
		if err := run(c.Name, c.Args...); err != nil {
			// A unit that was never loaded makes `bootout`/`disable` fail, and
			// that is not a deactivation failure — it is the desired end state.
			res.Remaining = append(res.Remaining, c.String()+": "+err.Error())
		}
	}
	if plan.UnitPath != "" {
		if err := os.Remove(plan.UnitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Remaining = append(res.Remaining, "remove "+plan.UnitPath+": "+err.Error())
		} else {
			res.Removed = append(res.Removed, plan.UnitPath)
		}
	}
	if !deleteState {
		return res, nil
	}
	for _, path := range plan.Paths {
		if path == "" {
			continue
		}
		if protected, why := plan.protects(path); protected {
			res.Remaining = append(res.Remaining, "refused to delete "+path+": "+why)
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			res.Remaining = append(res.Remaining, "remove "+path+": "+err.Error())
			continue
		}
		res.Removed = append(res.Removed, path)
	}
	return res, nil
}

// protects reports whether a path is inside anything the plan must keep.
func (p RemovalPlan) protects(path string) (bool, string) {
	abs, err := absClean(path)
	if err != nil {
		return true, err.Error()
	}
	for _, keep := range p.Keep {
		if strings.TrimSpace(keep) == "" {
			continue
		}
		inside, err := withinRoot(abs, keep)
		if err != nil {
			return true, err.Error()
		}
		if inside {
			return true, "it is inside " + keep + ", which removal must never touch"
		}
	}
	return false, ""
}

func orSelf(fallback string) string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return fallback
}
