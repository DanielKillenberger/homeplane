package health

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/secrets"
)

// Pinger is anything whose liveness is a round trip — in practice, the store.
type Pinger interface {
	Ping(ctx context.Context) error
}

// StoreProbe reports whether the control-plane database answers.
func StoreProbe(p Pinger) Probe {
	return func(ctx context.Context) error {
		if p == nil {
			return errors.New("store not configured")
		}
		return p.Ping(ctx)
	}
}

// CredentialStoreProbe re-validates the age key file on every check, so a
// deleted key or loosened permissions surfaces as a degraded component rather
// than as a surprise at the next credential operation.
func CredentialStoreProbe(keyPath string) Probe {
	return func(ctx context.Context) error {
		if keyPath == "" {
			return errors.New("credential key file not configured")
		}
		if _, err := secrets.LoadKeyFile(keyPath); err != nil {
			return err
		}
		return nil
	}
}

// GatewayProbe checks the composed gateway runtime (ToolHive). An unconfigured
// URL reports degraded rather than healthy: an unwired component must never
// render as "ok".
func GatewayProbe(url string, timeout time.Duration) Probe {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context) error {
		if url == "" {
			return errors.New("gateway health URL not configured")
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("gateway probe: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("gateway unreachable: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("gateway returned %s", resp.Status)
		}
		return nil
	}
}
