package vault

import (
	"errors"
	"strings"
	"testing"
)

func manifest(files map[string]string) Manifest {
	m := Manifest{SchemaVersion: ManifestSchemaVersion, Files: map[string]FileEntry{}}
	for name, content := range files {
		m.Files[name] = FileEntry{Size: int64(len(content)), SHA256: content}
	}
	return m
}

func TestCompare(t *testing.T) {
	before := manifest(map[string]string{"a": "1", "b": "2", "c": "3"})
	after := manifest(map[string]string{"a": "1", "b": "CHANGED", "d": "4"})
	d := Compare(before, after)

	if strings.Join(d.Deleted, ",") != "c" {
		t.Fatalf("deleted = %v, want [c]", d.Deleted)
	}
	if strings.Join(d.Modified, ",") != "b" {
		t.Fatalf("modified = %v, want [b]", d.Modified)
	}
	if strings.Join(d.Added, ",") != "d" {
		t.Fatalf("added = %v, want [d]", d.Added)
	}
	if d.Empty() {
		t.Fatal("a non-empty diff reported itself empty")
	}
	if !Compare(before, before).Empty() {
		t.Fatal("an identical manifest produced a diff")
	}
}

// Receiving notes from another machine is the point of sync; additions must
// never trip the guard.
func TestGuardAllowsUnlimitedAdditions(t *testing.T) {
	before := manifest(map[string]string{"a": "1"})
	files := map[string]string{"a": "1"}
	for i := 0; i < 500; i++ {
		files["new"+itoa(i)] = "x"
	}
	after := manifest(files)
	if err := DefaultGuardPolicy().Check(before, Compare(before, after), ""); err != nil {
		t.Fatalf("additions were refused: %v", err)
	}
}

func TestGuardRefusesMassDeletion(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 100; i++ {
		files["n"+itoa(i)] = "x"
	}
	before := manifest(files)
	after := manifest(map[string]string{"n0": "x"}) // 99 of 100 gone

	err := DefaultGuardPolicy().Check(before, Compare(before, after), "/snap")
	var destructive *DestructiveDiffError
	if !errors.As(err, &destructive) {
		t.Fatalf("err = %v, want *DestructiveDiffError", err)
	}
	if len(destructive.Diff.Deleted) != 99 {
		t.Fatalf("recorded %d deletions, want 99", len(destructive.Diff.Deleted))
	}
	// The error must point at the undo, or the guard is only half useful.
	if !strings.Contains(err.Error(), "/snap") {
		t.Fatalf("error does not name the snapshot: %v", err)
	}
}

// The absolute floor matters: a 6-file vault losing 6 files is 100% gone, but a
// fraction-only rule tuned for large vaults could wave it through.
func TestGuardRefusesSmallVaultWipe(t *testing.T) {
	before := manifest(map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"})
	after := manifest(map[string]string{})
	if err := DefaultGuardPolicy().Check(before, Compare(before, after), ""); err == nil {
		t.Fatal("wiping a small vault was allowed")
	}
}

func TestGuardRefusesMassRewrite(t *testing.T) {
	files := map[string]string{}
	rewritten := map[string]string{}
	for i := 0; i < 200; i++ {
		files["n"+itoa(i)] = "original"
		rewritten["n"+itoa(i)] = "clobbered"
	}
	err := DefaultGuardPolicy().Check(manifest(files), Compare(manifest(files), manifest(rewritten)), "")
	var destructive *DestructiveDiffError
	if !errors.As(err, &destructive) {
		t.Fatalf("err = %v, want *DestructiveDiffError", err)
	}
}

// A handful of legitimately deleted notes must not block activation forever.
func TestGuardAllowsSmallDeletionsInALargeVault(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 400; i++ {
		files["n"+itoa(i)] = "x"
	}
	before := manifest(files)
	delete(files, "n0")
	delete(files, "n1")
	after := manifest(files)
	if err := DefaultGuardPolicy().Check(before, Compare(before, after), ""); err != nil {
		t.Fatalf("two deletions in a 400-file vault were refused: %v", err)
	}
}

func TestGuardEmptyVaultIsNotADivideByZero(t *testing.T) {
	if err := DefaultGuardPolicy().Check(manifest(nil), Diff{}, ""); err != nil {
		t.Fatalf("empty vault: %v", err)
	}
}

func TestDestructiveErrorSamplesWithoutDumpingTheVault(t *testing.T) {
	e := &DestructiveDiffError{
		Reason: "too many",
		Diff:   Diff{Deleted: []string{"a", "b", "c", "d", "e"}},
	}
	sample := e.Sample()
	if !strings.HasSuffix(sample, "…") {
		t.Fatalf("sample = %q, want a truncated list", sample)
	}
	if strings.Count(sample, ",") > 3 {
		t.Fatalf("sample lists too many paths: %q", sample)
	}
}
