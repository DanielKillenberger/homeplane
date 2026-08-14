// Package policy holds the SERVER-SIDE per-harness capability policy.
//
// The invariant it exists to enforce: a client never self-selects its own
// authority. A grant request names a harness and (optionally) the capabilities
// it wants; what it may actually receive is decided here, from server-held
// policy, and a request reaching outside that policy is refused — never
// silently downgraded into something the caller did not ask for and never
// silently widened.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Capability is a coarse authority label carried by a grant. Capabilities map
// onto the connector manifest's action classes (task .3): the edge admits a
// tool call only when the grant carries the capability its action class needs.
type Capability string

// The skeleton's capability vocabulary. Deliberately connector-agnostic: adding
// a connector adds manifest entries, never a capability (R12).
const (
	// ConnectorRead permits read-class connector tools.
	ConnectorRead Capability = "connector.read"
	// ConnectorWrite permits write-class connector tools.
	ConnectorWrite Capability = "connector.write"
	// ConnectorDelete permits delete-class connector tools (needed by R8's
	// reversible-write proof, which deletes the event it created).
	ConnectorDelete Capability = "connector.delete"
	// ConnectorSend permits send-class tools (mail and the like). No harness
	// policy grants it in the skeleton — it exists so that an over-policy
	// request is a real, testable case rather than a hypothetical one.
	ConnectorSend Capability = "connector.send"
)

// Known harness identifiers (D1: Claude Code + Codex).
const (
	HarnessClaudeCode = "claude-code"
	HarnessCodex      = "codex"
)

// Errors returned by Resolve. Callers map these onto HTTP status codes.
var (
	// ErrUnknownHarness means the harness has no server-side policy entry.
	ErrUnknownHarness = errors.New("policy: unknown harness")
	// ErrNotPermitted means the request asked for capabilities the harness's
	// policy does not allow.
	ErrNotPermitted = errors.New("policy: capability not permitted for harness")
)

// HarnessPolicy is what one harness may hold.
type HarnessPolicy struct {
	// Allowed is the maximum authority this harness may ever be granted.
	Allowed []Capability
	// Default is issued when a request names no capabilities. It must be a
	// subset of Allowed (enforced by Validate).
	Default []Capability
}

// Policy is the whole server-side capability policy, keyed by harness.
type Policy struct {
	Harnesses map[string]HarnessPolicy
}

// Default is the skeleton's policy: both harnesses may read, write, and delete
// through connectors; neither may send. It is intentionally identical for the
// two harnesses — per-harness DIFFERENCE is a product decision, while the
// mechanism (server decides, client asks) is the architectural invariant.
func Default() Policy {
	caps := []Capability{ConnectorRead, ConnectorWrite, ConnectorDelete}
	return Policy{Harnesses: map[string]HarnessPolicy{
		HarnessClaudeCode: {Allowed: caps, Default: caps},
		HarnessCodex:      {Allowed: caps, Default: caps},
	}}
}

// Validate reports whether the policy is internally consistent (every Default
// is within its own Allowed set). It guards against a misconfigured policy
// handing out authority the policy itself says is out of bounds.
func (p Policy) Validate() error {
	for harness, hp := range p.Harnesses {
		allowed := make(map[Capability]bool, len(hp.Allowed))
		for _, c := range hp.Allowed {
			allowed[c] = true
		}
		for _, c := range hp.Default {
			if !allowed[c] {
				return fmt.Errorf("policy: harness %q default capability %q is not in its allowed set", harness, c)
			}
		}
	}
	return nil
}

// KnownHarnesses returns the configured harness identifiers, sorted — useful
// for error messages that tell a caller what it could have asked for.
func (p Policy) KnownHarnesses() []string {
	out := make([]string, 0, len(p.Harnesses))
	for h := range p.Harnesses {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Resolve decides the capability set a grant for harness may carry.
//
//   - unknown harness            -> ErrUnknownHarness
//   - no capabilities requested  -> the harness's policy default
//   - requested ⊆ allowed        -> the requested set, normalized
//   - anything else              -> ErrNotPermitted, naming the offending
//     capabilities (the refusal is explicit; the request is never quietly
//     clamped down to a smaller set the caller did not ask for)
func (p Policy) Resolve(harness string, requested []string) ([]string, error) {
	hp, ok := p.Harnesses[normalize(harness)]
	if !ok {
		return nil, fmt.Errorf("%w: %q (known: %s)", ErrUnknownHarness, harness, strings.Join(p.KnownHarnesses(), ", "))
	}

	if len(requested) == 0 {
		return capsToStrings(hp.Default), nil
	}

	allowed := make(map[Capability]bool, len(hp.Allowed))
	for _, c := range hp.Allowed {
		allowed[c] = true
	}

	seen := make(map[Capability]bool, len(requested))
	var granted []Capability
	var refused []string
	for _, raw := range requested {
		c := Capability(normalize(raw))
		if c == "" {
			continue
		}
		if !allowed[c] {
			refused = append(refused, string(c))
			continue
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		granted = append(granted, c)
	}
	if len(refused) > 0 {
		sort.Strings(refused)
		return nil, fmt.Errorf("%w: harness %q may not hold %s", ErrNotPermitted, harness, strings.Join(refused, ", "))
	}
	if len(granted) == 0 {
		return nil, fmt.Errorf("%w: harness %q was asked for no usable capability", ErrNotPermitted, harness)
	}
	return capsToStrings(granted), nil
}

func capsToStrings(caps []Capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
