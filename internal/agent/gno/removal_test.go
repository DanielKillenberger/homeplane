package gno

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeactivateWithoutARunnerChangesNothing(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	res, err := Deactivate(f.stateDir, nil, true)
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if res.Executed {
		t.Fatal("deactivate claimed to have run without a runner")
	}
	if len(res.Commands) == 0 {
		t.Fatal("deactivate reported no steps")
	}
	if _, err := os.Stat(cfg.UnitPath); err != nil {
		t.Fatalf("the unit was removed by a dry run: %v", err)
	}
	if !IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the index was removed by a dry run")
	}
}

func TestDeactivateStopsTheUnitAndOptionallyDropsState(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	var ran []string
	runner := func(name string, args ...string) error {
		ran = append(ran, name+" "+strings.Join(args, " "))
		return nil
	}

	// Stop only: state survives, so a re-activation does not have to re-index.
	res, err := Deactivate(f.stateDir, runner, false)
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if len(ran) == 0 {
		t.Fatal("no supervisor command was executed")
	}
	if _, err := os.Stat(cfg.UnitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unit file survived deactivation: %v", err)
	}
	if !IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("a stop-only deactivation deleted the index")
	}
	if !res.Executed {
		t.Fatal("the result does not record that it ran")
	}

	// With -delete-state the machine-local state goes too.
	if _, err := Deactivate(f.stateDir, runner, true); err != nil {
		t.Fatalf("deactivate with state: %v", err)
	}
	if IndexExists(cfg.Paths, cfg.Index) {
		t.Fatal("the index survived a state-dropping deactivation")
	}
	if _, err := os.Stat(DescriptorPath(f.stateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the endpoint descriptor survived: %v", err)
	}
}

// The vault is the whole point: an uninstall that deleted synchronized content
// would propagate the deletion to every other machine.
func TestDeactivateRefusesToDeleteAnythingInsideTheVault(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	cfg, _ := f.install(t, prepared)

	plan, err := LoadRemovalPlan(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	// A plan that has drifted to name a path inside the vault must be refused at
	// execution time, not trusted because it is written down.
	inVault := filepath.Join(cfg.VaultPath, "notes")
	if err := os.MkdirAll(inVault, 0o755); err != nil {
		t.Fatal(err)
	}
	plan.Paths = append(plan.Paths, inVault)
	if err := SaveRemovalPlan(f.stateDir, plan); err != nil {
		t.Fatal(err)
	}

	res, err := Deactivate(f.stateDir, func(string, ...string) error { return nil }, true)
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := os.Stat(inVault); err != nil {
		t.Fatalf("removal deleted vault content: %v", err)
	}
	found := false
	for _, note := range res.Remaining {
		if strings.Contains(note, inVault) && strings.Contains(note, "refused") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the refusal was not reported: %+v", res.Remaining)
	}
}

// A unit that was never loaded makes `bootout` fail. That is the desired end
// state, not a deactivation failure — but it must still be surfaced.
func TestDeactivateSurvivesAnUnloadedUnit(t *testing.T) {
	f := newFixture(t)
	prepared := f.prepare(t)
	f.install(t, prepared)

	res, err := Deactivate(f.stateDir, func(string, ...string) error {
		return errors.New("Boot-out failed: 3: No such process")
	}, false)
	if err != nil {
		t.Fatalf("an unloaded unit turned deactivation into a failure: %v", err)
	}
	if len(res.Remaining) == 0 {
		t.Fatal("the failed supervisor call was not surfaced")
	}
}

func TestLoadRemovalPlanReportsAbsenceHonestly(t *testing.T) {
	if _, err := LoadRemovalPlan(t.TempDir()); !errors.Is(err, ErrNoRemovalPlan) {
		t.Fatalf("expected ErrNoRemovalPlan, got %v", err)
	}
}
