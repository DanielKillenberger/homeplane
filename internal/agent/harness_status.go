package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/DanielKillenberger/homeplane/internal/agent/harness"
)

// Per-harness status, reconciled from three sources that can all disagree.
//
// The persisted list of configured harnesses cannot answer this on its own, and
// the ways it is wrong are the ways an operator gets misled:
//
//   - a harness that was configured and has since been UNINSTALLED still
//     appears in the list;
//   - a harness that is installed and was never configured does not appear at
//     all, which is indistinguishable from "not installed";
//   - a harness whose grant the server REVOKED still appears configured,
//     because revocation happens server-side and touches nothing on the
//     machine. That is precisely the state a revocation is designed to create,
//     so a status surface that reads only local state reports the one thing
//     revocation was supposed to make false.
//
// So each harness is reconciled from live detection, the local configuration
// record, and the grants the SERVER currently lists, and lands in exactly one of
// five states.
const (
	// HarnessNotDetected means neither the CLI nor a configuration file is on
	// this machine. Not a fault: a machine without grok is healthy.
	HarnessNotDetected = "not_detected"
	// HarnessDetectedUnconfigured means the harness is here and Homeplane has
	// not wired it. Actionable, and invisible in the persisted list.
	HarnessDetectedUnconfigured = "detected_unconfigured"
	// HarnessDetectedUnsupported means the harness is here and running a
	// version whose configuration surface this build has not verified. It is
	// deliberately distinct from unconfigured: re-running configure will not fix
	// it, and the fix is a re-captured contract, not a retry.
	HarnessDetectedUnsupported = "detected_unsupported"
	// HarnessConfigured means the harness is wired and its grant is live
	// server-side.
	HarnessConfigured = "configured"
	// HarnessRevoked means the machine holds a configuration whose grant the
	// server no longer honours. The config file still contains a token; it just
	// does not work. Saying "configured" here would be the single most
	// misleading thing this surface could do.
	HarnessRevoked = "revoked"
)

// HarnessStatus is one harness's reconciled state.
type HarnessStatus struct {
	Harness string `json:"harness"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
	// ConfigPath is the user-scope file this harness is (or would be)
	// configured through.
	ConfigPath string `json:"config_path,omitempty"`
	// Version is the harness CLI's self-declared version, when observed.
	Version string `json:"version,omitempty"`
	// Support is the version verdict that produced (or did not produce) the
	// unsupported state.
	Support string `json:"support,omitempty"`
	// GrantID is the grant the local record names.
	GrantID string `json:"grant_id,omitempty"`
	// CompatSources names the other vendors' configurations this harness would
	// still inherit MCP servers from. Present for grok, whose compat merge
	// Homeplane closes for the two user-config sources and cannot close for the
	// project-scope one — so the residual is reported rather than assumed away.
	CompatSources []string `json:"compat_sources,omitempty"`
}

// reconcileHarnesses folds detection, records and live grants into one row per
// known harness, in Known() order.
//
// grantsKnown is false when the server was not reached. A machine that is
// locally configured is still locally configured — that is a fact about this
// disk — so the row keeps `configured` and SAYS the grant could not be checked,
// rather than inventing a revocation from a network failure. The overall report
// already carries the grants component as `unknown` for exactly this case.
func reconcileHarnesses(detections []harness.Detection, records []harness.Record, grants []GrantReport, grantsKnown bool) []HarnessStatus {
	byHarness := map[string]harness.Detection{}
	for _, d := range detections {
		byHarness[d.Harness] = d
	}
	recorded := map[string]harness.Record{}
	for _, r := range records {
		recorded[r.Harness] = r
	}
	grantByID := map[string]GrantReport{}
	for _, g := range grants {
		grantByID[g.GrantID] = g
	}

	out := make([]HarnessStatus, 0, len(harness.Known()))
	for _, name := range harness.Known() {
		d, detected := byHarness[name]
		row := HarnessStatus{
			Harness:       name,
			ConfigPath:    d.ConfigPath,
			Version:       d.Version,
			Support:       d.Support,
			CompatSources: d.CompatSources,
		}
		switch {
		case !detected || !d.Installed:
			row.State = HarnessNotDetected
			row.Detail = d.Reason
			if row.Detail == "" {
				row.Detail = name + " is not installed on this machine"
			}
		case !d.Usable():
			row.State = HarnessDetectedUnsupported
			row.Detail = d.SupportReason
		default:
			rec, hasRecord := recorded[name]
			if !hasRecord || strings.TrimSpace(rec.GrantID) == "" {
				row.State = HarnessDetectedUnconfigured
				row.Detail = name + " is installed but Homeplane has not configured it — run `homeplane-agent configure-harnesses`"
				break
			}
			row.GrantID = rec.GrantID
			switch {
			case !grantsKnown:
				row.State = HarnessConfigured
				row.Detail = "configured at " + rec.ConfigPath + "; the grant could not be checked (the server was not reached)"
			case isLiveGrant(grantByID, rec.GrantID):
				row.State = HarnessConfigured
				row.Detail = "configured at " + rec.ConfigPath
			default:
				row.State = HarnessRevoked
				row.Detail = fmt.Sprintf("%s holds a configuration whose grant %s is no longer live server-side — "+
					"re-run `homeplane-agent configure-harnesses` to mint a new one", rec.ConfigPath, rec.GrantID)
			}
		}
		if len(row.CompatSources) > 0 && row.State != HarnessNotDetected {
			row.Detail = strings.TrimRight(row.Detail, " ") +
				"; still inherits MCP servers from: " + strings.Join(row.CompatSources, ", ")
		}
		out = append(out, row)
	}
	return out
}

// isLiveGrant reports whether the server currently lists this grant as active.
// A grant the server does not list at all counts as not live: forgetting is a
// perfectly good way to revoke.
func isLiveGrant(grants map[string]GrantReport, id string) bool {
	g, ok := grants[id]
	return ok && g.State == grantStateActive
}

// DegradedHarnesses names the harnesses whose row an operator has to act on:
// installed but unwired, unsupported, or holding a dead grant. Sorted.
func DegradedHarnesses(rows []HarnessStatus) []string {
	var out []string
	for _, r := range rows {
		switch r.State {
		case HarnessDetectedUnconfigured, HarnessDetectedUnsupported, HarnessRevoked:
			out = append(out, r.Harness)
		}
	}
	sort.Strings(out)
	return out
}
