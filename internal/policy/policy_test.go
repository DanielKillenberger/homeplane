package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestDefaultPolicyIsInternallyConsistent(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
}

func TestValidateCatchesDefaultOutsideAllowed(t *testing.T) {
	p := Policy{Harnesses: map[string]HarnessPolicy{
		"codex": {Allowed: []Capability{ConnectorRead}, Default: []Capability{ConnectorWrite}},
	}}
	if err := p.Validate(); err == nil {
		t.Fatal("a default capability outside the allowed set was accepted")
	}
}

func TestResolveDefaultsWhenNothingRequested(t *testing.T) {
	got, err := Default().Resolve(HarnessCodex, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := []string{"connector.delete", "connector.read", "connector.write"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("default capabilities = %v, want %v", got, want)
	}
}

func TestResolveRefusesOverPolicyRequests(t *testing.T) {
	_, err := Default().Resolve(HarnessClaudeCode, []string{string(ConnectorRead), string(ConnectorSend)})
	if !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("err = %v, want ErrNotPermitted", err)
	}
	// The refusal must name what was refused — an operator reading the audit
	// row should not have to guess which capability was out of bounds.
	if !strings.Contains(err.Error(), string(ConnectorSend)) {
		t.Errorf("error %q does not name the refused capability", err)
	}
	// And it must not leak the permitted set back as a hint of what to ask for
	// next; the point is that authority is server-decided, not negotiated.
	if strings.Contains(err.Error(), string(ConnectorDelete)) {
		t.Errorf("error %q enumerates capabilities the caller did not ask about", err)
	}
}

func TestResolveRefusesUnknownHarness(t *testing.T) {
	_, err := Default().Resolve("hermes", nil)
	if !errors.Is(err, ErrUnknownHarness) {
		t.Fatalf("err = %v, want ErrUnknownHarness", err)
	}
	if !strings.Contains(err.Error(), HarnessCodex) {
		t.Errorf("error %q does not list the known harnesses", err)
	}
}

func TestResolveNormalizesInput(t *testing.T) {
	got, err := Default().Resolve("  Codex  ", []string{" Connector.Read ", "connector.read"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != 1 || got[0] != string(ConnectorRead) {
		t.Errorf("capabilities = %v, want a single deduplicated connector.read", got)
	}
}

func TestResolveRefusesAnEmptyRequestedSet(t *testing.T) {
	// A request that names only blanks is not the same as naming nothing: it is
	// a malformed ask, and silently substituting the default would grant more
	// than the caller expressed.
	if _, err := Default().Resolve(HarnessCodex, []string{"", "   "}); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("err = %v, want ErrNotPermitted", err)
	}
}

func TestNoHarnessMaySendInTheSkeleton(t *testing.T) {
	for harness := range Default().Harnesses {
		if _, err := Default().Resolve(harness, []string{string(ConnectorSend)}); err == nil {
			t.Errorf("harness %q was granted connector.send", harness)
		}
	}
}
