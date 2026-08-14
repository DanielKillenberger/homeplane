package harness

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// The semantic-preservation check (R5, as amended).
//
// The contract is stated as an equation, so it is checked as one:
//
//	parse(after) − managed  ==  parse(before) − managed
//
// Both sides are produced by a REAL parser for the format — not by the
// span-scanner or the order-preserving editor that performed the write. That
// separation is the point: an editing bug shows up here as an inequality
// instead of as a corrupted config, and the write is rolled back.
//
// "− managed" removes the Homeplane-owned entries from the container they live
// in, and then removes the container itself if it has become empty. The second
// half matters for the one asymmetric case: a config with no MCP servers at all
// has no container BEFORE and an all-managed container AFTER, and treating an
// emptied container as absent is what makes "we added only managed entries" and
// "we changed nothing else" the same statement.

// parseFn parses a config file into a comparable tree.
type parseFn func([]byte) (map[string]any, error)

func parseJSONTree(raw []byte) (map[string]any, error) {
	out := map[string]any{}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func parseTOMLTree(raw []byte) (map[string]any, error) {
	out := map[string]any{}
	if err := toml.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// stripManaged removes the named entries from the container key, and the
// container itself when nothing is left in it.
func stripManaged(tree map[string]any, container string, names []string) map[string]any {
	sub, ok := tree[container]
	if !ok {
		return tree
	}
	m, ok := sub.(map[string]any)
	if !ok {
		// The container is not an object. Nothing managed can be in it, and it
		// must compare as-is — a config where `mcpServers` is a string is
		// exactly the kind of thing this check exists to notice.
		return tree
	}
	for _, n := range names {
		delete(m, n)
	}
	if len(m) == 0 {
		delete(tree, container)
	} else {
		tree[container] = m
	}
	return tree
}

// stripPath removes one dotted key path from the tree, and then prunes every
// ancestor table the removal left empty.
//
// The pruning is the same asymmetry stripManaged handles for the container: a
// config with no `[compat]` table at all has nothing before and a
// Homeplane-created `compat.claude = {mcps: false}` after, and treating an
// emptied ancestor as absent is what makes "we set only our own cell" and "we
// changed nothing else" the same statement. A table the USER already had stays,
// because removing our key from it leaves their other keys behind.
func stripPath(tree map[string]any, path []string) map[string]any {
	if len(path) == 0 {
		return tree
	}
	if len(path) == 1 {
		delete(tree, path[0])
		return tree
	}
	sub, ok := tree[path[0]]
	if !ok {
		return tree
	}
	m, ok := sub.(map[string]any)
	if !ok {
		// Not a table: nothing of ours can be inside it, and it must compare
		// as-is rather than be quietly dropped.
		return tree
	}
	m = stripPath(m, path[1:])
	if len(m) == 0 {
		delete(tree, path[0])
	} else {
		tree[path[0]] = m
	}
	return tree
}

// preservationCheck compares before and after under the managed-entry
// subtraction, and returns a message naming the first difference it finds.
type preservationCheck struct {
	parse     parseFn
	container string
	managed   []string
	// exempt are Homeplane-managed key paths outside the container (grok's
	// compat cells). They are subtracted from BOTH sides — an edit we meant to
	// make is not a preservation failure — and assertAfter proves the value.
	exempt [][]string
	// assertAfter checks the parsed result. Nil means nothing to prove.
	assertAfter func(tree map[string]any) error
}

func (p preservationCheck) verify(before, after []byte) error {
	beforeTree, err := p.parse(before)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedConfig, err)
	}
	afterTree, err := p.parse(after)
	if err != nil {
		// The bytes WE produced do not parse. That is our bug, and it must
		// never reach the user's file.
		return fmt.Errorf("%w: the rewritten configuration does not parse: %v", ErrPreservationFailed, err)
	}
	if p.assertAfter != nil {
		// Proven before the comparison, so a subtracted key can never be
		// subtracted without also being checked.
		if err := p.assertAfter(afterTree); err != nil {
			return err
		}
	}

	residualBefore := stripManaged(beforeTree, p.container, p.managed)
	residualAfter := stripManaged(afterTree, p.container, p.managed)
	for _, path := range p.exempt {
		residualBefore = stripPath(residualBefore, path)
		residualAfter = stripPath(residualAfter, path)
	}
	if reflect.DeepEqual(residualBefore, residualAfter) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrPreservationFailed, describeDiff(residualBefore, residualAfter))
}

// describeDiff names the first divergence in operator-readable terms. It is
// deliberately shallow-but-specific: the operator needs to know WHAT moved, and
// a full structural diff of a config file would bury that.
func describeDiff(before, after map[string]any) string {
	return strings.Join(diffPaths(before, after, ""), "; ")
}

func diffPaths(before, after map[string]any, prefix string) []string {
	var out []string
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, k := range names {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		b, hasB := before[k]
		a, hasA := after[k]
		switch {
		case hasB && !hasA:
			out = append(out, "lost "+path)
		case !hasB && hasA:
			out = append(out, "added "+path)
		case reflect.DeepEqual(a, b):
			// unchanged
		default:
			bm, bok := b.(map[string]any)
			am, aok := a.(map[string]any)
			if bok && aok {
				out = append(out, diffPaths(bm, am, path)...)
				continue
			}
			out = append(out, "changed "+path)
		}
		if len(out) >= 8 {
			return append(out, "…")
		}
	}
	return out
}
