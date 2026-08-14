// Package health reports the liveness of SERVER-SIDE components only: the
// store, the connector/gateway runtime, the tsnet listener, and the credential
// store.
//
// The scope boundary is deliberate and load-bearing (R10): machine-side state —
// enrolment, vault, sync, GNO supervision, harness config — is
// `homeplane-agent status`'s job. A machine whose GNO is down must never make
// the server look unhealthy, and a healthy-looking server must never mask a
// broken machine.
package health

import (
	"context"
	"sort"
	"sync"
)

// Status is a component's or the system's health state.
type Status string

const (
	// StatusOK means every probed component answered.
	StatusOK Status = "ok"
	// StatusDegraded means at least one component failed its probe.
	StatusDegraded Status = "degraded"
)

// Canonical server component names.
const (
	ComponentStore           = "store"
	ComponentGatewayRuntime  = "gateway_runtime"
	ComponentTsnet           = "tsnet"
	ComponentCredentialStore = "credential_store"
	// ComponentWorkloadCredential is the delivery of a brokered credential into
	// the connector workload's own directory. It is a SERVER component: the
	// credential is stored here, materialized here, and read by a workload
	// running here.
	ComponentWorkloadCredential = "workload_credential"
)

// Probe is a component liveness check. A nil error means healthy.
type Probe func(ctx context.Context) error

// Component pairs a canonical name with its probe.
type Component struct {
	Name  string
	Probe Probe
}

// ComponentReport is one component's outcome. Detail carries the probe's error
// text so a degraded response NAMES what broke rather than saying "degraded".
type ComponentReport struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report is the whole server-side health picture.
type Report struct {
	Status     Status            `json:"status"`
	Components []ComponentReport `json:"components"`
}

// Degraded reports whether any component failed.
func (r Report) Degraded() bool { return r.Status != StatusOK }

// Checker runs a fixed set of component probes.
type Checker struct {
	mu         sync.RWMutex
	components []Component
}

// New builds a Checker over the given components.
func New(components ...Component) *Checker {
	c := &Checker{}
	c.Set(components...)
	return c
}

// Set replaces the component set. Components are sorted by name so the report
// order is stable across calls.
func (c *Checker) Set(components ...Component) {
	sorted := make([]Component, len(components))
	copy(sorted, components)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	c.mu.Lock()
	defer c.mu.Unlock()
	c.components = sorted
}

// Check probes every component and aggregates the result. A component with a
// nil probe is reported degraded rather than silently assumed healthy —
// "unprobed" must never render as "ok".
func (c *Checker) Check(ctx context.Context) Report {
	c.mu.RLock()
	components := make([]Component, len(c.components))
	copy(components, c.components)
	c.mu.RUnlock()

	report := Report{Status: StatusOK, Components: make([]ComponentReport, 0, len(components))}
	for _, comp := range components {
		cr := ComponentReport{Name: comp.Name, Status: StatusOK}
		switch {
		case comp.Probe == nil:
			cr.Status = StatusDegraded
			cr.Detail = "no probe configured"
		default:
			if err := comp.Probe(ctx); err != nil {
				cr.Status = StatusDegraded
				cr.Detail = err.Error()
			}
		}
		if cr.Status != StatusOK {
			report.Status = StatusDegraded
		}
		report.Components = append(report.Components, cr)
	}
	return report
}
