package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestIAM12IdentitySessionRuntimeLifecycle(t *testing.T) {
	dependencies := configuredRuntimeTestDependencies(t)
	runtime, err := openIdentitySessionRuntime(dependencies.Pool, dependencies.Identity)
	if err != nil || runtime == nil {
		t.Fatalf("openIdentitySessionRuntime() = (%T, %v)", runtime, err)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready() before close = %v", err)
	}
	factory := runtime.HandlerFactory()
	if factory == nil {
		t.Fatal("enabled identity session runtime returned nil factory")
	}
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("factory() = (%T, %v)", handler, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/identity/sessions", nil)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated production handler status=%d body=%s", response.Code, response.Body.String())
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("closed identity session runtime remained ready")
	}
	if handler, err := factory(); err == nil || handler != nil {
		t.Fatalf("closed factory() = (%T, %v), want nil,error", handler, err)
	}
}

func TestIAM12IdentitySessionRuntimeFailsClosed(t *testing.T) {
	dependencies := configuredRuntimeTestDependencies(t)
	for name, present := range map[string]struct {
		pool     bool
		identity bool
	}{
		"missing pool":     {identity: true},
		"missing identity": {pool: true},
	} {
		t.Run(name, func(t *testing.T) {
			var configuredPool = dependencies.Pool
			var configuredIdentity = dependencies.Identity
			if !present.pool {
				configuredPool = nil
			}
			if !present.identity {
				configuredIdentity = nil
			}
			if runtime, err := openIdentitySessionRuntime(configuredPool, configuredIdentity); err == nil || runtime != nil {
				t.Fatalf("openIdentitySessionRuntime() = (%T, %v), want nil,error", runtime, err)
			}
		})
	}
}
