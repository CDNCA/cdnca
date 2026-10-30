package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/signerrevocationconsumer"
)

func TestSignerRevocationShutdownPeriodCoversConsumer(t *testing.T) {
	config := signerrevocationconsumer.Config{Enabled: true, ShutdownTimeout: 10 * time.Second}
	if err := validateSignerRevocationShutdownPeriod(10*time.Second, config); err != nil {
		t.Fatalf("equal shutdown periods rejected: %v", err)
	}
	if err := validateSignerRevocationShutdownPeriod(9*time.Second, config); err == nil {
		t.Fatal("shorter shared shutdown period was accepted")
	}
	config.Enabled = false
	if err := validateSignerRevocationShutdownPeriod(time.Second, config); err != nil {
		t.Fatalf("disabled consumer affected shared shutdown: %v", err)
	}
}

func TestRequiredSignerRevocationRuntimeReportsTerminalExit(t *testing.T) {
	tests := []struct {
		name   string
		worker runtimeWorker
	}{
		{name: "missing"},
		{name: "nil exit", worker: fakeRuntimeWorker{run: func(context.Context) error { return nil }}},
		{name: "canceled exit", worker: fakeRuntimeWorker{run: func(context.Context) error { return context.Canceled }}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failures := make(chan error, 1)
			runRequiredSignerRevocationRuntime(t.Context(), test.worker, failures)
			select {
			case err := <-failures:
				if err == nil {
					t.Fatal("terminal exit reported nil")
				}
			default:
				t.Fatal("terminal exit was not reported")
			}
		})
	}

	terminal := errors.New("audit persistence failed")
	failures := make(chan error, 1)
	runRequiredSignerRevocationRuntime(t.Context(), fakeRuntimeWorker{
		run: func(context.Context) error { return terminal },
	}, failures)
	if err := <-failures; !errors.Is(err, terminal) {
		t.Fatalf("terminal cause = %v", err)
	}
}

func TestRequiredSignerRevocationRuntimeIgnoresParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	failures := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runRequiredSignerRevocationRuntime(ctx, fakeRuntimeWorker{
			run: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		}, failures)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("required runtime did not stop after parent cancellation")
	}
	select {
	case err := <-failures:
		t.Fatalf("parent cancellation reported terminal failure: %v", err)
	default:
	}
}

func TestSignerRevocationProbeIsRequiredForReadiness(t *testing.T) {
	probe := &fakeReadinessProbe{err: signerrevocationconsumer.ErrProductionNotReady}
	handler := requireReadiness(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}), probe)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready signer consumer status = %d", response.Code)
	}
	probe.err = nil
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("ready signer consumer status = %d", response.Code)
	}
}

func TestInstallSignerRevocationGateWithoutConsumerKeepsTrustBehavior(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: "lineage-1", PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	installSignerRevocationGate(trust, nil)
	installSignerRevocationGate(nil, nil)
	if err := trust.CheckSignerRevocation(entitlementguard.SignerArtifactLease, "lineage-1"); err != nil {
		t.Fatalf("disabled consumer changed trust decisions: %v", err)
	}
}
