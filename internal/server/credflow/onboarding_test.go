package credflow_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DanielKillenberger/homeplane/internal/server/credflow"
)

// R12 for credentials: onboarding another provider must be a manifest entry and
// its client credentials — nothing else.
//
// The claim is proven two ways, because either alone is weak. The behavioural
// half runs a complete flow for a second provider through the identical code
// path. The structural half reads this package's own source and asserts it
// contains no provider-specific knowledge at all — which is what stops the
// behavioural half from being satisfied by a hidden `if provider == …`.

func TestSecondProviderOnboardsThroughTheManifestAlone(t *testing.T) {
	alpha := newFakeProvider(t, "alpha")
	beta := newFakeProvider(t, "beta")

	// One server, one manifest, two entries. The second entry differs only in
	// its endpoints, its secret refs and its name.
	h := newHarness(t, harnessOptions{providers: []*fakeProvider{alpha, beta}})

	for _, p := range []*fakeProvider{alpha, beta} {
		t.Run(p.name, func(t *testing.T) {
			_, relay := h.runFlow(machineA, p, false)
			if relay.status != http.StatusAccepted || relay.str("state") != string(credflow.StateCompleted) {
				t.Fatalf("flow for %s: status %d body %s", p.name, relay.status, relay.raw)
			}
			cred, generation, err := h.credential(p.name)
			if err != nil {
				t.Fatalf("read %s credential: %v", p.name, err)
			}
			if cred.Access != p.name+"-access-token" {
				t.Errorf("%s credential = %q, want its own token", p.name, cred.Access)
			}
			if generation != 1 {
				t.Errorf("%s generation = %d, want 1", p.name, generation)
			}
		})
	}

	// The two providers are genuinely independent: each has its own credential
	// at its own ref, and neither flow disturbed the other.
	alphaCred, _, err := h.credential(alpha.name)
	if err != nil {
		t.Fatalf("read alpha credential after beta's flow: %v", err)
	}
	if alphaCred.Access != "alpha-access-token" {
		t.Fatalf("alpha's credential = %q after beta onboarded; the two share storage", alphaCred.Access)
	}
}

// TestBrokerSourceHasNoProviderSpecificKnowledge is the structural half of R12.
// If onboarding a provider ever requires a code change, the first symptom is a
// provider's name appearing in this package's CODE — in a string literal it
// compares against, or in an identifier named after it.
//
// Comments are deliberately not searched: prose may (and does) explain which
// real provider's requirement a rule exists for, and forbidding that would only
// buy a passing test at the cost of losing the reason.
func TestBrokerSourceHasNoProviderSpecificKnowledge(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	// Provider names, and the endpoints a hard-coded provider would need.
	forbidden := []string{"google", "gmail", "drive", "calendar", "fabrikam", "rize", "oura", "ticktick",
		"googleapis", "alpha", "beta"}

	fset := token.NewFileSet()
	checked := 0
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		// Comments are dropped: only what the compiler sees is examined.
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				// Whole words only: "driver" is not "drive", and "authorize"
				// is not "rize". A hard-coded provider would appear as its own
				// word — "google", "accounts.google.com" — every time.
				for _, word := range wordsIn(node.Value) {
					for _, term := range forbidden {
						if word == term {
							t.Errorf("%s: string literal %s names provider %q; the broker must know nothing "+
								"about individual providers", fset.Position(node.Pos()), node.Value, term)
						}
					}
				}
			case *ast.Ident:
				lowered := strings.ToLower(node.Name)
				for _, term := range forbidden {
					if lowered == term {
						t.Errorf("%s: identifier %q is named after a provider", fset.Position(node.Pos()), node.Name)
					}
				}
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no package sources were checked; the glob is wrong")
	}
}

// wordsIn splits text into lowercase alphanumeric words.
func wordsIn(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

// TestUnsupportedCredentialDriverIsRefused — a connector whose credentials come
// from somewhere else entirely (a future driver) must be refused clearly rather
// than run through the OAuth path by default.
func TestUnsupportedCredentialDriverIsRefused(t *testing.T) {
	// The manifest validator only admits drivers this build ships, so an
	// unshipped driver cannot even be registered — which is the refusal, one
	// layer earlier and stronger than a runtime check.
	const manifest = `{"version":1,"connectors":[{
		"provider":"someservice",
		"credential_ref":"someservice/session",
		"credential_acquisition":{"driver":"device-code","params":{},"scopes":["x"]},
		"mcp_server":{"name":"someservice","transport":"streamable-http","source":"stub://in-process"},
		"tools":[{"tool":"list_things","action_class":"read"}]}]}`

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	// newHarness fails the test on an invalid manifest, so the refusal is
	// asserted directly against the parser instead.
	if err := parseManifestErr(manifest); err == nil {
		t.Fatal("a manifest naming an unshipped credential driver was accepted")
	} else if !strings.Contains(err.Error(), "unknown credential driver") {
		t.Fatalf("refusal = %v, want it to name the unknown driver", err)
	}
}
