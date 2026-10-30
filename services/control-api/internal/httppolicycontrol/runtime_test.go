package httppolicycontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimeTestGate struct{}

func (runtimeTestGate) Check(context.Context, pgx.Tx, entitlementCheck) error { return nil }

type typedNilRuntimeGate struct{}

func (*typedNilRuntimeGate) Check(context.Context, pgx.Tx, entitlementCheck) error { return nil }

type typedNilRuntimeAuditor struct{}

func (*typedNilRuntimeAuditor) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

type typedNilRuntimeAuthorizer struct{}

func (*typedNilRuntimeAuthorizer) AuthorizeWrite(
	context.Context,
	pgx.Tx,
	Actor,
	uuid.UUID,
	string,
) (uuid.UUID, error) {
	return uuid.Nil, ErrPermissionDenied
}

type typedNilRuntimeAuthenticator struct{}

func (*typedNilRuntimeAuthenticator) Authenticate(*http.Request) (Actor, error) {
	return Actor{}, ErrUnauthenticated
}

func TestHTTPPolicyRuntimeHandlerDisabledIsClosed(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/ignored/http-policies", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled runtime status = %d, want 404", response.Code)
	}
}

func TestHTTPPolicyRuntimeHandlerRequiresProductionDependencies(t *testing.T) {
	valid := runtimeUnitDependencies(t)
	if handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, valid); err != nil || handler == nil {
		t.Fatalf("valid runtime = (%T, %v), want handler", handler, err)
	}
	nestedTokens, err := identity.NewTokenManager("http-policy-nested-runtime-secret-2026", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityWithoutPool, err := identity.NewService(identity.NewStore(nil), nestedTokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	nestedSessions, err := sessioncredential.NewVerifier(nestedTokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	nestedAPIKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x73}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iamWithoutSessions, err := iamlock.NewAuthorizer(new(sessioncredential.Verifier), nestedAPIKeys)
	if err != nil {
		t.Fatal(err)
	}
	iamWithoutAPIKeys, err := iamlock.NewAuthorizer(nestedSessions, new(apikeycredential.Verifier))
	if err != nil {
		t.Fatal(err)
	}
	for name, invalidate := range map[string]func(*RuntimeDependencies){
		"postgres":          func(value *RuntimeDependencies) { value.Pool = nil },
		"identity":          func(value *RuntimeDependencies) { value.Identity = nil },
		"iam":               func(value *RuntimeDependencies) { value.IAM = nil },
		"entitlement trust": func(value *RuntimeDependencies) { value.EntitlementTrust = nil },
		"clock":             func(value *RuntimeDependencies) { value.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			invalidate(&dependencies)
			handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidHandlerConfig) {
				t.Fatalf("invalid runtime = (%T, %v), want nil ErrInvalidHandlerConfig", handler, err)
			}
		})
	}
	for name, invalidate := range map[string]func(*RuntimeDependencies){
		"zero postgres":          func(value *RuntimeDependencies) { value.Pool = new(pgxpool.Pool) },
		"zero identity":          func(value *RuntimeDependencies) { value.Identity = new(identity.Service) },
		"identity without pool":  func(value *RuntimeDependencies) { value.Identity = identityWithoutPool },
		"zero iam":               func(value *RuntimeDependencies) { value.IAM = new(iamlock.Authorizer) },
		"iam without sessions":   func(value *RuntimeDependencies) { value.IAM = iamWithoutSessions },
		"iam without api keys":   func(value *RuntimeDependencies) { value.IAM = iamWithoutAPIKeys },
		"zero entitlement trust": func(value *RuntimeDependencies) { value.EntitlementTrust = new(entitlementguard.TrustStore) },
	} {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			invalidate(&dependencies)
			handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidHandlerConfig) {
				t.Fatalf("zero-value runtime = (%T, %v), want nil ErrInvalidHandlerConfig", handler, err)
			}
		})
	}
}

func TestHTTPPolicyTypedNilDependenciesFailClosed(t *testing.T) {
	pool := new(pgxpool.Pool)
	var gate *typedNilRuntimeGate
	var auditor *typedNilRuntimeAuditor
	var authorizer *typedNilRuntimeAuthorizer
	for name, candidate := range map[string]func() (*Store, error){
		"gate": func() (*Store, error) {
			return newStoreWithDependencies(pool, time.Now, gate, nil, allowTxAuthorizer{})
		},
		"auditor": func() (*Store, error) {
			return newStoreWithDependencies(pool, time.Now, runtimeTestGate{}, auditor, allowTxAuthorizer{})
		},
		"authorizer": func() (*Store, error) {
			return newStoreWithDependencies(pool, time.Now, runtimeTestGate{}, nil, authorizer)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := candidate()
			if store != nil || !errors.Is(err, ErrInvalidStoreConfig) {
				t.Fatalf("typed-nil %s = (%#v, %v), want nil ErrInvalidStoreConfig", name, store, err)
			}
		})
	}
	store, err := newStoreWithDependencies(pool, time.Now, runtimeTestGate{}, nil, allowTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	var authenticator *typedNilRuntimeAuthenticator
	if handler, err := NewHandler(NewService(store), authenticator); handler != nil || !errors.Is(err, ErrInvalidHandlerConfig) {
		t.Fatalf("typed-nil authenticator = (%T, %v), want nil ErrInvalidHandlerConfig", handler, err)
	}
}

func TestHTTPPolicyNilReceiversAndZeroStoreDoNotPanic(t *testing.T) {
	assertUnavailable := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s error = %v, want ErrUnavailable", name, err)
		}
	}
	ctx := context.Background()
	target, policyID := uuid.New(), uuid.New()
	metadata := WriteMetadata{IdempotencyKey: "zero-store", RequestID: "zero-store-request", TraceID: "zero-store-trace"}
	create := CreateRequest{TargetScopeID: target, SiteID: uuid.New(), Config: validTestConfig(), WriteMetadata: metadata}
	update := UpdateRequest{TargetScopeID: target, ID: policyID, ExpectedRevision: 1, Config: validTestConfig(), WriteMetadata: metadata}
	state := StateRequest{TargetScopeID: target, ID: policyID, ExpectedRevision: 1, WriteMetadata: metadata}
	remove := DeleteRequest{TargetScopeID: target, ID: policyID, ExpectedRevision: 1, WriteMetadata: metadata}
	list := ListFilter{TargetScopeID: target, Limit: 1}

	var nilService *Service
	_, err := nilService.Create(ctx, Actor{}, create)
	assertUnavailable("nil service Create", err)
	_, err = nilService.Update(ctx, Actor{}, update)
	assertUnavailable("nil service Update", err)
	_, err = nilService.SetEnabled(ctx, Actor{}, state)
	assertUnavailable("nil service SetEnabled", err)
	_, err = nilService.Delete(ctx, Actor{}, remove)
	assertUnavailable("nil service Delete", err)
	_, err = nilService.Get(ctx, Actor{}, target, policyID)
	assertUnavailable("nil service Get", err)
	_, err = nilService.List(ctx, Actor{}, list)
	assertUnavailable("nil service List", err)
	_, err = nilService.PublicationPreview(ctx, Actor{}, target)
	assertUnavailable("nil service PublicationPreview", err)

	for name, store := range map[string]*Store{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			_, err := store.Create(ctx, Actor{}, create, [32]byte{})
			assertUnavailable("Store.Create", err)
			_, err = store.Update(ctx, Actor{}, update, [32]byte{})
			assertUnavailable("Store.Update", err)
			_, err = store.SetEnabled(ctx, Actor{}, state, [32]byte{})
			assertUnavailable("Store.SetEnabled", err)
			_, err = store.Delete(ctx, Actor{}, remove, [32]byte{})
			assertUnavailable("Store.Delete", err)
			_, err = store.Get(ctx, Actor{}, target, policyID)
			assertUnavailable("Store.Get", err)
			_, err = store.List(ctx, Actor{}, list)
			assertUnavailable("Store.List", err)
			_, err = store.PublicationPreview(ctx, Actor{}, target)
			assertUnavailable("Store.PublicationPreview", err)
		})
	}
	for name, handler := range map[string]*Handler{"nil": nil, "zero": {}} {
		t.Run("handler "+name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("Handler.ServeHTTP status=%d, want 503", response.Code)
			}
		})
	}
}

func TestHTTPPolicyRuntimeAuthenticatorRequiresOneBearerSession(t *testing.T) {
	authenticator := runtimeAuthenticator{identity: new(identity.Service)}
	for name, values := range map[string][]string{
		"missing":    nil,
		"duplicate":  {"Bearer one", "Bearer two"},
		"basic":      {"Basic token"},
		"empty":      {"Bearer "},
		"whitespace": {"Bearer one two"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, value := range values {
				request.Header.Add("Authorization", value)
			}
			if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("Authenticate(%q) error = %v, want ErrUnauthenticated", values, err)
			}
		})
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer opaque-session")
	if _, err := authenticator.Authenticate(request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("zero identity Authenticate error = %v, want ErrUnavailable", err)
	}
}

func runtimeUnitDependencies(t *testing.T) RuntimeDependencies {
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
	tokens, err := identity.NewTokenManager("http-policy-runtime-unit-secret-2026", time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x71}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "http-policy-runtime-unit", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{
		Pool: pool, Identity: identityService, IAM: iam, EntitlementTrust: trust, Now: time.Now,
	}
}
