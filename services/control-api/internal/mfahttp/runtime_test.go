package mfahttp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimeCipher struct{}

func (*runtimeCipher) Encrypt(value []byte) (string, []byte, error) {
	return "runtime-key", append([]byte("0123456789abcdef"), value...), nil
}

func (*runtimeCipher) Decrypt(string, []byte) ([]byte, error) {
	return bytes.Repeat([]byte{1}, 20), nil
}

type panickingRuntimeCipher struct{ runtimeCipher }

func (*panickingRuntimeCipher) Configured() bool { panic("cipher readiness failure") }

type unconfiguredRuntimeCipher struct{ runtimeCipher }

func (*unconfiguredRuntimeCipher) Configured() bool { return false }

func TestDisabledRuntimeIsClosedAndDoesNotTouchDependencies(t *testing.T) {
	config := RuntimeConfig{Core: mfa.Config{Clock: func() time.Time {
		t.Fatal("disabled runtime touched clock")
		return time.Time{}
	}}}
	runtime, err := NewRuntime(config, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.StepUpConsumer() != nil {
		t.Fatal("disabled runtime exposed a step-up consumer")
	}
	response := httptest.NewRecorder()
	runtime.ServeHTTP(response, httptest.NewRequest(http.MethodPost, apiPrefix+"/enrollments", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	waitRunning(t, runtime)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("disabled Ready=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFactoryOwnsProductionAssemblyAndFailsClosed(t *testing.T) {
	dependencies := runtimeDependencies(t)
	config := validRuntimeConfig()
	runtime, err := NewRuntimeHandler(config, dependencies)
	if err != nil || runtime == nil || runtime.Handler() == nil || runtime.StepUpConsumer() == nil {
		t.Fatalf("NewRuntimeHandler=(%#v,%v)", runtime, err)
	}

	var typedNilCipher *runtimeCipher
	tests := map[string]func(*RuntimeDependencies){
		"nil pool":         func(value *RuntimeDependencies) { value.Pool = nil },
		"zero pool":        func(value *RuntimeDependencies) { value.Pool = new(pgxpool.Pool) },
		"nil identity":     func(value *RuntimeDependencies) { value.Identity = nil },
		"zero identity":    func(value *RuntimeDependencies) { value.Identity = new(identity.Service) },
		"nil IAM":          func(value *RuntimeDependencies) { value.IAM = nil },
		"zero IAM":         func(value *RuntimeDependencies) { value.IAM = new(iamlock.Authorizer) },
		"nil cipher":       func(value *RuntimeDependencies) { value.Cipher = nil },
		"typed nil cipher": func(value *RuntimeDependencies) { value.Cipher = typedNilCipher },
		"unconfigured cipher": func(value *RuntimeDependencies) {
			value.Cipher = &unconfiguredRuntimeCipher{}
		},
		"panicking cipher": func(value *RuntimeDependencies) {
			value.Cipher = &panickingRuntimeCipher{}
		},
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			value := dependencies
			invalidate(&value)
			runtime, err := NewRuntime(config, value)
			if runtime != nil || !errors.Is(err, ErrInvalidService) {
				t.Fatalf("NewRuntime=(%#v,%v)", runtime, err)
			}
		})
	}
}

func TestRuntimeFactoryRejectsMissingCoreAndInvalidHandlerConfig(t *testing.T) {
	dependencies := runtimeDependencies(t)
	valid := validRuntimeConfig()
	tests := map[string]func(*RuntimeConfig){
		"missing clock":            func(value *RuntimeConfig) { value.Core.Clock = nil },
		"zero clock":               func(value *RuntimeConfig) { value.Core.Clock = func() time.Time { return time.Time{} } },
		"panicking clock":          func(value *RuntimeConfig) { value.Core.Clock = func() time.Time { panic("clock") } },
		"missing random":           func(value *RuntimeConfig) { value.Core.Random = nil },
		"missing issuer":           func(value *RuntimeConfig) { value.Core.Issuer = "" },
		"noncanonical issuer":      func(value *RuntimeConfig) { value.Core.Issuer = " CDNCA" },
		"missing enrollment TTL":   func(value *RuntimeConfig) { value.Core.EnrollmentTTL = 0 },
		"oversized enrollment TTL": func(value *RuntimeConfig) { value.Core.EnrollmentTTL = 16 * time.Minute },
		"invalid timeout":          func(value *RuntimeConfig) { value.Handler.CommandTimeout = time.Hour },
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			invalidate(&config)
			runtime, err := NewRuntime(config, dependencies)
			if runtime != nil || !errors.Is(err, ErrInvalidService) {
				t.Fatalf("NewRuntime=(%#v,%v)", runtime, err)
			}
		})
	}
}

func TestRuntimeRunReadyCloseLifecycle(t *testing.T) {
	runtime := newRuntime(http.NotFoundHandler(), true, func(context.Context) error { return nil })
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready before Run=%v", err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	waitReady(t, runtime)
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeAlreadyRunning) {
		t.Fatalf("second Run=%v", err)
	}
	closed := make(chan error, 2)
	go func() { closed <- runtime.Close() }()
	go func() { closed <- runtime.Close() }()
	for range 2 {
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready after Close=%v", err)
	}
	if err := runtime.Run(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatalf("Run after Close=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeContextCancellationClearsReadiness(t *testing.T) {
	runtime := newRuntime(http.NotFoundHandler(), true, func(context.Context) error { return nil })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitReady(t, runtime)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready after cancellation=%v", err)
	}
}

func TestRuntimeReadinessTracksPoolHealth(t *testing.T) {
	dependencies := runtimeDependencies(t)
	runtime, err := NewRuntime(validRuntimeConfig(), dependencies)
	if err != nil {
		t.Fatal(err)
	}
	dependencies.Pool.Close()
	done := make(chan error, 1)
	go func() { done <- runtime.Run(t.Context()) }()
	waitRunning(t, runtime)
	if err := runtime.Ready(); !errors.Is(err, ErrRuntimeNotReady) {
		t.Fatalf("Ready with closed pool=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func runtimeDependencies(t *testing.T) RuntimeDependencies {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager(strings.Repeat("mfa-runtime-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x4d}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{Pool: pool, Identity: identityService, IAM: authorizer,
		Cipher: &runtimeCipher{}}
}

func validRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{Enabled: true, Core: mfa.Config{
		Clock: time.Now, Random: bytes.NewReader(bytes.Repeat([]byte{1}, 256)),
		Issuer: "CDNCA", EnrollmentTTL: 10 * time.Minute,
	}}
}

func waitRunning(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		runtime.mu.Lock()
		running := runtime.running
		runtime.mu.Unlock()
		if running {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("runtime did not start")
		case <-time.After(time.Millisecond):
		}
	}
}

func waitReady(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		if runtime.Ready() == nil {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("runtime did not become ready")
		case <-time.After(time.Millisecond):
		}
	}
}
