package health_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/health"
)

func okProbe(context.Context) error  { return nil }
func badProbe(context.Context) error { return errors.New("component exploded") }

func TestCheckAggregatesComponents(t *testing.T) {
	c := health.New(
		health.Component{Name: health.ComponentStore, Probe: okProbe},
		health.Component{Name: health.ComponentTsnet, Probe: okProbe},
	)
	report := c.Check(context.Background())
	if report.Degraded() || report.Status != health.StatusOK {
		t.Fatalf("report = %+v, want ok", report)
	}

	c.Set(
		health.Component{Name: health.ComponentStore, Probe: okProbe},
		health.Component{Name: health.ComponentTsnet, Probe: badProbe},
	)
	report = c.Check(context.Background())
	if !report.Degraded() {
		t.Fatal("one failing component did not degrade the report")
	}
	for _, comp := range report.Components {
		if comp.Name == health.ComponentTsnet {
			if comp.Status != health.StatusDegraded || comp.Detail == "" {
				t.Errorf("degraded component lacks a named detail: %+v", comp)
			}
		}
	}
}

// TestUnprobedComponentIsDegraded pins the safe default: a component nobody
// checks must never be reported as healthy.
func TestUnprobedComponentIsDegraded(t *testing.T) {
	report := health.New(health.Component{Name: health.ComponentGatewayRuntime}).Check(context.Background())
	if !report.Degraded() {
		t.Fatal("a component with no probe was reported healthy")
	}
}

func TestComponentOrderIsStable(t *testing.T) {
	c := health.New(
		health.Component{Name: health.ComponentTsnet, Probe: okProbe},
		health.Component{Name: health.ComponentStore, Probe: okProbe},
		health.Component{Name: health.ComponentGatewayRuntime, Probe: okProbe},
	)
	first := c.Check(context.Background())
	second := c.Check(context.Background())
	for i := range first.Components {
		if first.Components[i].Name != second.Components[i].Name {
			t.Fatalf("component order is unstable: %v vs %v", first.Components, second.Components)
		}
	}
}

func TestGatewayProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := health.GatewayProbe(srv.URL, time.Second)(context.Background()); err != nil {
		t.Fatalf("healthy gateway probe failed: %v", err)
	}
	if err := health.GatewayProbe("", time.Second)(context.Background()); err == nil {
		t.Error("unconfigured gateway URL reported healthy")
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := health.GatewayProbe(bad.URL, time.Second)(context.Background()); err == nil {
		t.Error("a 500 from the gateway reported healthy")
	}

	srv.Close()
	if err := health.GatewayProbe(srv.URL, time.Second)(context.Background()); err == nil {
		t.Error("an unreachable gateway reported healthy")
	}
}

type failingPinger struct{}

func (failingPinger) Ping(context.Context) error { return errors.New("database is closed") }

func TestStoreProbe(t *testing.T) {
	if err := health.StoreProbe(nil)(context.Background()); err == nil {
		t.Error("a nil store reported healthy")
	}
	if err := health.StoreProbe(failingPinger{})(context.Background()); err == nil {
		t.Error("a failing store reported healthy")
	}
}
