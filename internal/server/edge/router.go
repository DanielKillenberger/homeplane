package edge

import (
	"fmt"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/server/connectors"
)

// UnroutedProvider is the provider name recorded for a tool call the edge could
// not attribute to any declared connector.
//
// It is not a fallback that grants anything: the engine has no connector by
// this name, so the call is denied `unknown_provider` and audited as a policy
// violation like any other unroutable call. What it buys is an audit row that
// says plainly "this tool belongs to no connector we declare" instead of an
// empty provider column.
const UnroutedProvider = "unrouted"

// QualifierSeparator is how a composed gateway namespaces a tool it re-exports
// (`<provider>__<tool>`). A qualified name routes on its prefix when that
// prefix is a declared connector; anything else falls through to the
// unqualified index, so a tool whose own name contains the separator still
// routes correctly.
const QualifierSeparator = "__"

// toolRouter maps a wire tool name onto the (provider, tool) pair the manifest
// authorizes. Routing decides WHICH connector's rules apply — it never decides
// whether a call is allowed; that is the engine's job, and an unroutable name
// is handed to it as an unknown provider so the refusal is audited by the same
// code path as every other refusal.
type toolRouter struct {
	// providers is the set of declared connector names.
	providers map[string]bool
	// unqualified maps a bare tool name to its sole declaring connector.
	unqualified map[string]string
}

// newToolRouter indexes a manifest, refusing two configurations that would make
// routing ambiguous or spoofable:
//
//   - a connector literally named `unrouted`, which would turn the marker for
//     "belongs to nothing" into a real, reachable connector;
//   - the same bare tool name declared by two connectors, which would leave the
//     edge guessing whose policy applies to an unqualified call.
//
// Both are refused at construction. A gateway composition the edge cannot route
// deterministically must not serve traffic.
func newToolRouter(m connectors.Manifest) (*toolRouter, error) {
	r := &toolRouter{
		providers:   make(map[string]bool, len(m.Connectors)),
		unqualified: make(map[string]string),
	}
	for _, c := range m.Connectors {
		if c.Provider == UnroutedProvider {
			return nil, fmt.Errorf("edge: connector %q uses the reserved provider name", c.Provider)
		}
		r.providers[c.Provider] = true
	}
	for _, c := range m.Connectors {
		// Every name the connector claims is routable, not only the authorized
		// ones: an EXCLUDED tool must reach its own connector's rules so the
		// denial is audited as the deliberate exclusion it is
		// (`excluded_tool`), rather than degrading into "belongs to nothing".
		names := make([]string, 0, len(c.Tools)+len(c.Excluded)+len(c.ToolInventory))
		for _, t := range c.Tools {
			names = append(names, t.Tool)
		}
		for _, x := range c.Excluded {
			names = append(names, x.Tool)
		}
		names = append(names, c.ToolInventory...)

		for _, name := range names {
			owner, seen := r.unqualified[name]
			if seen && owner != c.Provider {
				return nil, fmt.Errorf(
					"edge: tool %q is declared by both %q and %q; qualify it as <provider>%s<tool> in the gateway composition",
					name, owner, c.Provider, QualifierSeparator)
			}
			r.unqualified[name] = c.Provider
		}
	}
	return r, nil
}

// route resolves a wire tool name to the provider and tool the engine judges.
// An unroutable name yields UnroutedProvider and the name as received, so the
// denial that follows names what was actually attempted.
func (r *toolRouter) route(wire string) (provider, tool string) {
	if prefix, rest, ok := strings.Cut(wire, QualifierSeparator); ok && rest != "" && r.providers[prefix] {
		return prefix, rest
	}
	if p, ok := r.unqualified[wire]; ok {
		return p, wire
	}
	return UnroutedProvider, wire
}
