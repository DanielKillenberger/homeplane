package credflow

import (
	"context"
	"errors"
)

// Test-only handles on the broker's internals. This file is compiled only for
// tests, so nothing here widens the package's real surface.
//
// They exist for one reason: the expiry/relay race is decided inside a single
// lock, and the interleaving that used to break it — an eligibility check that
// passed, then a relay, then the expiry transition — cannot be scheduled
// reliably from outside. A test that cannot force that ordering can only fail
// occasionally, which is no better than not having it.

// SetExpiryClaimBarrier installs a function that runs between an expiry's
// eligibility check and its atomic claim. Passing nil removes it.
func SetExpiryClaimBarrier(fn func()) {
	expiryBarrierMu.Lock()
	defer expiryBarrierMu.Unlock()
	expiryBarrierFn = fn
}

// RelayForTest consumes a relay WITHOUT the settle step the HTTP handler runs
// first — standing in for a relay whose own settle passed a moment earlier,
// which is exactly the caller that can land inside the expiry window.
func (s *Service) RelayForTest(ctx context.Context, flowID, machineID, oauthState, code string) error {
	f, ok := s.lookup(flowID, machineID)
	if !ok {
		return errors.New("credflow: no such flow for this machine")
	}
	return s.relay(ctx, f, relayOutcome{Code: code, State: oauthState})
}
