package edge

import (
	"fmt"
	"sort"
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

// AmbiguousProvider is the provider name recorded when a BARE tool name is
// claimed by more than one declared connector.
//
// Like UnroutedProvider it names no connector, so the call is denied and
// audited; it exists so the row distinguishes "no connector claims this tool"
// from "two do, and the caller did not say which". The qualified form
// (`<provider>__<tool>`) of the same tool keeps working — a composition that
// namespaces its tools is exactly the case this must not break (R12).
const AmbiguousProvider = "ambiguous"

// reservedProviderNames are the markers above. A connector may not take one:
// that would turn "belongs to no connector" into a reachable connector.
var reservedProviderNames = map[string]bool{
	UnroutedProvider:  true,
	AmbiguousProvider: true,
}

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
	// ambiguous holds the bare names more than one connector claims. Their
	// UNQUALIFIED form is denied; their qualified form still routes.
	ambiguous map[string]bool
}

// newToolRouter indexes a manifest.
//
// Only one configuration is refused outright: a connector using a reserved
// provider name, which would make the marker for "belongs to no connector" a
// reachable connector.
//
// A bare tool name claimed by two connectors is NOT a startup failure — a
// composed gateway that namespaces its tools (`<provider>__<tool>`) is a normal
// and supported deployment, and refusing it would mean common multi-connector
// manifests could not run at all (R12). Such a name is marked ambiguous
// instead: the unqualified form is denied, because guessing whose policy
// applies is how one connector's read-only rules end up applied to another's
// delete tool, while the qualified form routes deterministically.
func newToolRouter(m connectors.Manifest) (*toolRouter, error) {
	r := &toolRouter{
		providers:   make(map[string]bool, len(m.Connectors)),
		unqualified: make(map[string]string),
		ambiguous:   make(map[string]bool),
	}
	for _, c := range m.Connectors {
		if reservedProviderNames[c.Provider] {
			return nil, fmt.Errorf("edge: connector %q uses a reserved provider name", c.Provider)
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
				delete(r.unqualified, name)
				r.ambiguous[name] = true
				continue
			}
			if r.ambiguous[name] {
				continue
			}
			r.unqualified[name] = c.Provider
		}
	}
	return r, nil
}

// route resolves a wire tool name to the provider and tool the engine judges.
// A name that routes nowhere yields a marker provider and the name as
// received, so the denial that follows names what was actually attempted and
// says which kind of unroutable it was.
func (r *toolRouter) route(wire string) (provider, tool string) {
	if prefix, rest, ok := strings.Cut(wire, QualifierSeparator); ok && rest != "" && r.providers[prefix] {
		return prefix, rest
	}
	if p, ok := r.unqualified[wire]; ok {
		return p, wire
	}
	if r.ambiguous[wire] {
		return AmbiguousProvider, wire
	}
	return UnroutedProvider, wire
}

// ambiguousTools lists the bare names whose unqualified form is denied. The
// edge logs it at startup: an operator must be able to see that a tool is only
// reachable by its qualified name without discovering it from a denial.
func (r *toolRouter) ambiguousTools() []string {
	if len(r.ambiguous) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.ambiguous))
	for name := range r.ambiguous {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
