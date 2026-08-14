package vault

import (
	"fmt"
	"sort"
	"strings"
)

// The destructive-diff guard.
//
// Obsidian Sync reconciles two sides. If the remote side is empty, stale, or
// pointing at the wrong vault, "reconcile" means "delete Daniel's notes". The
// guard's job is to notice that BEFORE continuous sync is activated, and to
// stop rather than to sync through it. It is deliberately a policy over a
// content diff, not a heuristic over log lines: the manifest either says 400
// files vanished or it does not.

// Diff is what changed between two manifests of the same vault.
type Diff struct {
	Added    []string `json:"added"`
	Modified []string `json:"modified"`
	Deleted  []string `json:"deleted"`
}

// Empty reports whether nothing changed at all.
func (d Diff) Empty() bool { return len(d.Added)+len(d.Modified)+len(d.Deleted) == 0 }

// Summary is a one-line, path-free description for logs and status detail.
func (d Diff) Summary() string {
	return fmt.Sprintf("%d added, %d modified, %d deleted", len(d.Added), len(d.Modified), len(d.Deleted))
}

// Compare diffs `after` against `before`.
func Compare(before, after Manifest) Diff {
	var d Diff
	for path, b := range before.Files {
		a, ok := after.Files[path]
		switch {
		case !ok:
			d.Deleted = append(d.Deleted, path)
		case a.SHA256 != b.SHA256:
			d.Modified = append(d.Modified, path)
		}
	}
	for path := range after.Files {
		if _, ok := before.Files[path]; !ok {
			d.Added = append(d.Added, path)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Modified)
	sort.Strings(d.Deleted)
	return d
}

// GuardPolicy bounds how much destruction a single sync pass may perform
// before activation is refused.
//
// Two dimensions, because they fail differently: an absolute floor so a small
// vault cannot be wiped by a "only 10%" rule, and a fraction so a large vault
// is not judged by a count tuned for a small one. Additions are unbounded —
// receiving notes from another machine is the point.
type GuardPolicy struct {
	// MaxDeleted is the absolute number of deletions allowed.
	MaxDeleted int `json:"max_deleted"`
	// MaxDeletedFraction is the share of the vault allowed to disappear.
	MaxDeletedFraction float64 `json:"max_deleted_fraction"`
	// MaxModified is the absolute number of in-place rewrites allowed.
	MaxModified int `json:"max_modified"`
	// MaxModifiedFraction is the share of the vault allowed to be rewritten.
	MaxModifiedFraction float64 `json:"max_modified_fraction"`
}

// DefaultGuardPolicy is tuned for a first activation, where the expected diff
// is "nothing changed" or "a few files arrived". Anything that deletes more
// than a handful of notes, or rewrites a quarter of the vault, is the failure
// mode this guard exists for.
func DefaultGuardPolicy() GuardPolicy {
	return GuardPolicy{
		MaxDeleted:          5,
		MaxDeletedFraction:  0.05,
		MaxModified:         50,
		MaxModifiedFraction: 0.25,
	}
}

// DestructiveDiffError is returned when a sync pass exceeded the policy. It
// carries the diff so `status` and the operator can see exactly what would have
// been destroyed, and it names the snapshot that can restore it.
type DestructiveDiffError struct {
	Reason       string
	Diff         Diff
	SnapshotPath string
}

func (e *DestructiveDiffError) Error() string {
	msg := "vault: destructive sync diff refused — " + e.Reason + " (" + e.Diff.Summary() + ")"
	if e.SnapshotPath != "" {
		msg += "; the pre-sync snapshot is at " + e.SnapshotPath
	}
	if sample := e.Sample(); sample != "" {
		msg += "; e.g. " + sample
	}
	return msg
}

// Sample names a few affected paths without dumping the whole vault into a log.
func (e *DestructiveDiffError) Sample() string {
	pick := e.Diff.Deleted
	if len(pick) == 0 {
		pick = e.Diff.Modified
	}
	if len(pick) == 0 {
		return ""
	}
	if len(pick) > 3 {
		return strings.Join(pick[:3], ", ") + ", …"
	}
	return strings.Join(pick, ", ")
}

// Check applies the policy to a diff taken against `before`.
func (p GuardPolicy) Check(before Manifest, d Diff, snapshotPath string) error {
	total := len(before.Files)
	fail := func(reason string) error {
		return &DestructiveDiffError{Reason: reason, Diff: d, SnapshotPath: snapshotPath}
	}
	if len(d.Deleted) > p.MaxDeleted {
		return fail(fmt.Sprintf("%d deletions exceed the limit of %d", len(d.Deleted), p.MaxDeleted))
	}
	if total > 0 && p.MaxDeletedFraction > 0 {
		if frac := float64(len(d.Deleted)) / float64(total); frac > p.MaxDeletedFraction {
			return fail(fmt.Sprintf("%.0f%% of the vault was deleted, above the %.0f%% limit",
				frac*100, p.MaxDeletedFraction*100))
		}
	}
	if p.MaxModified > 0 && len(d.Modified) > p.MaxModified {
		return fail(fmt.Sprintf("%d in-place rewrites exceed the limit of %d", len(d.Modified), p.MaxModified))
	}
	if total > 0 && p.MaxModifiedFraction > 0 {
		if frac := float64(len(d.Modified)) / float64(total); frac > p.MaxModifiedFraction {
			return fail(fmt.Sprintf("%.0f%% of the vault was rewritten, above the %.0f%% limit",
				frac*100, p.MaxModifiedFraction*100))
		}
	}
	return nil
}
