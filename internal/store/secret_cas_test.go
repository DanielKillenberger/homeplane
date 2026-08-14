package store

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// PutSecretCAS is what makes R13's credential replacement an atomic swap. The
// property these tests hold it to: a write either lands on exactly the
// generation its caller observed, or it does not happen at all.

func TestPutSecretCASRequiresTheObservedGeneration(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const ref = "provider/oauth-session"

	// Generation 0 means "nothing stored yet".
	gen, err := st.PutSecretCAS(ctx, ref, []byte("cipher-1"), 0, noAuditSecret)
	if err != nil || gen != 1 {
		t.Fatalf("first write: gen=%d err=%v, want gen 1", gen, err)
	}

	// A second caller that also observed "nothing stored" must lose.
	if _, err := st.PutSecretCAS(ctx, ref, []byte("cipher-loser"), 0, noAuditSecret); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("stale create: err=%v, want ErrGenerationConflict", err)
	}
	// So must one that observed a generation that never existed.
	if _, err := st.PutSecretCAS(ctx, ref, []byte("cipher-loser"), 7, noAuditSecret); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("wrong generation: err=%v, want ErrGenerationConflict", err)
	}

	// The loser changed nothing.
	sec, err := st.GetSecret(ctx, ref)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(sec.Ciphertext) != "cipher-1" || sec.Generation != 1 {
		t.Fatalf("secret = %q gen %d, want the original at generation 1", sec.Ciphertext, sec.Generation)
	}

	// The caller holding the current generation succeeds and moves it on.
	gen, err = st.PutSecretCAS(ctx, ref, []byte("cipher-2"), 1, noAuditSecret)
	if err != nil || gen != 2 {
		t.Fatalf("replacement: gen=%d err=%v, want gen 2", gen, err)
	}
}

// TestPutSecretCASUnderConcurrencyAdmitsExactlyOneWriter — the same-observed
// generation race, run for real.
func TestPutSecretCASUnderConcurrencyAdmitsExactlyOneWriter(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const ref = "provider/oauth-session"
	if _, err := st.PutSecret(ctx, ref, []byte("cipher-0"), noAuditSecret); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const writers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
	)
	wg.Add(writers)
	for i := range writers {
		go func() {
			defer wg.Done()
			// Every writer observed generation 1.
			_, err := st.PutSecretCAS(ctx, ref, []byte{byte(i)}, 1, noAuditSecret)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrGenerationConflict):
				conflicts++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 || conflicts != writers-1 {
		t.Fatalf("succeeded=%d conflicts=%d, want 1 and %d", succeeded, conflicts, writers-1)
	}
	sec, err := st.GetSecret(ctx, ref)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if sec.Generation != 2 {
		t.Fatalf("generation = %d, want 2 (exactly one write landed)", sec.Generation)
	}
}

// TestPutSecretCASRollsBackWhenItsAuditRowCannotBeWritten — the store's audit
// atomicity rule applies to the compare-and-swap path too: a credential that
// replaced another with no record of it would be exactly the untraceable swap
// the audit log exists to prevent.
func TestPutSecretCASRollsBackWhenItsAuditRowCannotBeWritten(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	const ref = "provider/oauth-session"
	if _, err := st.PutSecretCAS(ctx, ref, []byte("cipher-1"), 0, noAuditSecret); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := st.PutSecretCAS(ctx, ref, []byte("cipher-2"), 1, func(int64) []AuditEvent {
		// A key outside the allowlist is rejected by the audit writer.
		return []AuditEvent{{Event: "credential_flow_committed", ActorKind: ActorMachine,
			Outcome: OutcomeAllowed, Detail: map[string]string{"unwritable_key": "x"}}}
	})
	if err == nil {
		t.Fatal("a replacement committed despite an unwritable audit row")
	}
	sec, err := st.GetSecret(ctx, ref)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(sec.Ciphertext) != "cipher-1" || sec.Generation != 1 {
		t.Fatalf("secret = %q gen %d, want the original untouched", sec.Ciphertext, sec.Generation)
	}
}

func TestPutSecretCASRequiresAnAuditCallback(t *testing.T) {
	if _, err := newTestStore(t).PutSecretCAS(context.Background(), "ref", []byte("c"), 0, nil); err == nil {
		t.Error("PutSecretCAS accepted a nil audit callback")
	}
}
