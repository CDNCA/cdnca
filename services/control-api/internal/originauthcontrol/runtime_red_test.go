package originauthcontrol

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimeNilVerifier struct{}

func (*runtimeNilVerifier) Verify(context.Context, VerificationRequest) error { return nil }

type runtimeNilAuditor struct{}

func (*runtimeNilAuditor) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

type runtimeNilEntitlement struct{}

func (*runtimeNilEntitlement) Check(context.Context, pgx.Tx, EntitlementCheck) error { return nil }

func TestRuntimeHandlerDisabledIsClosed(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/018f9d7e-4a1b-7a2c-8d3e-111111111111/origin-auth/credentials", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled runtime status = %d", response.Code)
	}
}

func TestRuntimeAuthorizationErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid credential", err: iamlock.ErrInvalidCredential, want: ErrUnauthenticated},
		{name: "permission denied", err: iamlock.ErrPermissionDenied, want: ErrPermissionDenied},
		{name: "unavailable", err: iamlock.ErrUnavailable, want: ErrUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := (runtimeTxAuthorizer{}).mapAuthorizationError(context.Background(), test.err)
			if !errors.Is(got, test.want) {
				t.Fatalf("authorization error=%v want=%v", got, test.want)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := (runtimeTxAuthorizer{}).mapAuthorizationError(ctx, iamlock.ErrInvalidCredential); !errors.Is(got, context.Canceled) {
		t.Fatalf("canceled authorization error=%v want=%v", got, context.Canceled)
	}
}

func TestRuntimeHandlerEnabledRejectsMissingAndTypedNilDependencies(t *testing.T) {
	valid := runtimeTestDependencies(t)
	tests := map[string]func(*RuntimeDependencies){
		"postgres": func(value *RuntimeDependencies) { value.Pool = nil },
		"identity": func(value *RuntimeDependencies) { value.Identity = nil },
		"iam":      func(value *RuntimeDependencies) { value.IAM = nil },
		"keyring":  func(value *RuntimeDependencies) { value.Keyring = nil },
		"verifier": func(value *RuntimeDependencies) {
			var verifier *runtimeNilVerifier
			value.Service.Verifier = verifier
		},
		"auditor": func(value *RuntimeDependencies) {
			var auditor *runtimeNilAuditor
			value.Service.Auditor = auditor
		},
		"entitlement": func(value *RuntimeDependencies) {
			var entitlement *runtimeNilEntitlement
			value.Service.Entitlement = entitlement
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			mutate(&dependencies)
			if handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies); err == nil || handler != nil {
				t.Fatalf("NewRuntimeHandler() = (%T, %v), want nil error", handler, err)
			}
		})
	}
}

func TestRuntimeHandlerEnabledRejectsUnconfiguredNestedDependencies(t *testing.T) {
	valid := runtimeTestDependencies(t)
	tests := map[string]func(*RuntimeDependencies){
		"postgres_zero": func(value *RuntimeDependencies) { value.Pool = new(pgxpool.Pool) },
		"identity_zero": func(value *RuntimeDependencies) { value.Identity = new(identity.Service) },
		"iam_zero":      func(value *RuntimeDependencies) { value.IAM = new(iamlock.Authorizer) },
		"keyring_zero":  func(value *RuntimeDependencies) { value.Keyring = new(Keyring) },
		"clock_missing": func(value *RuntimeDependencies) { value.Service.Clock = nil },
		"trust_missing": func(value *RuntimeDependencies) {
			value.Service.Entitlement = nil
			value.Service.TrustStore = nil
		},
		"trust_zero": func(value *RuntimeDependencies) {
			value.Service.Entitlement = nil
			value.Service.TrustStore = new(entitlementguard.TrustStore)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			mutate(&dependencies)
			if handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies); err == nil || handler != nil {
				t.Fatalf("NewRuntimeHandler() = (%T, %v), want nil error", handler, err)
			}
		})
	}
}

func TestRuntimeHandlerBearerMetadataAndRouteBoundaries(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, runtimeTestDependencies(t))
	if err != nil {
		t.Fatal(err)
	}
	tenant := "018f9d7e-4a1b-7a2c-8d3e-111111111111"

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+tenant+"/origin-auth/credentials", nil))
	if response.Code != http.StatusUnauthorized || response.Header().Get("X-Request-ID") == "" ||
		response.Header().Get("X-Trace-ID") != response.Header().Get("X-Request-ID") {
		t.Fatalf("missing bearer response = %d headers=%v body=%s", response.Code, response.Header(), response.Body)
	}

	request := httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+tenant+"/origin-auth/credentials", nil)
	request.Header.Add("X-Request-ID", "request-one")
	request.Header.Add("X-Request-ID", "request-two")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate request ID status = %d body=%s", response.Code, response.Body)
	}

	request = httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+tenant+"/origin-auth/credentials", nil)
	request.Header.Add("Authorization", "Bearer one")
	request.Header.Add("Authorization", "Bearer two")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("duplicate bearer status = %d body=%s", response.Code, response.Body)
	}

	for _, route := range []string{
		"/v1/tenant-scopes/" + tenant + "/origin-auth/credential",
		"/v1/tenant-scopes/" + tenant + "/origin-auth//credentials",
		"/v1/tenant-scopes/" + tenant + "/origin-auth/credentials/",
		"/v1/tenant-scopes/" + tenant + "/origin-auth/rules/../credentials",
		"/v1/tenant-scopes/" + tenant + "/origin-auth/%63redentials",
	} {
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("non-canonical route %q status = %d body=%s", route, response.Code, response.Body)
		}
	}
}

func runtimeTestDependencies(t *testing.T) RuntimeDependencies {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("origin-auth-runtime-test-token-secret", time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x41}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := NewKeyring("runtime", map[string][]byte{"runtime": bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{
		Pool: pool, Identity: identityService, IAM: authorizer, Keyring: keyring,
		Service: Config{
			Clock:       time.Now,
			Verifier:    CredentialVerifierFunc(func(context.Context, VerificationRequest) error { return nil }),
			Entitlement: allowEntitlement{},
		},
	}
}
