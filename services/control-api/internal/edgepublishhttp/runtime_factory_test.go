package edgepublishhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimeFactorySigner struct{}

func (*runtimeFactorySigner) KeyID() string { return "runtime-factory-test" }
func (*runtimeFactorySigner) PublicKey() ed25519.PublicKey {
	return make(ed25519.PublicKey, ed25519.PublicKeySize)
}
func (*runtimeFactorySigner) Sign(context.Context, []byte) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

type runtimeFactoryEntitlement struct{}

func (runtimeFactoryEntitlement) AuthorizePublication(
	context.Context,
	pgx.Tx,
	edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	return edgepublish.EntitlementDecision{}, nil
}

func TestRuntimeHandlerDisabledIsClosedNotFoundSurface(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"/v1/admin/site-publications",
		"/v1/site-publications",
		"/v1/admin/site-publications/neighbor",
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled %s status = %d, want 404", target, response.Code)
		}
	}
}

func TestRuntimeHandlerEnabledFailsClosedWithoutDependencies(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, RuntimeDependencies{})
	if handler != nil || !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("NewRuntimeHandler() = (%T, %v), want nil invalid runtime config", handler, err)
	}
}

func TestRuntimeHandlerAcceptsCompleteDependencySet(t *testing.T) {
	handler, err := NewRuntimeHandler(validRuntimeConfig(), validRuntimeDependencies(t))
	if err != nil || handler == nil {
		t.Fatalf("NewRuntimeHandler() = (%T, %v)", handler, err)
	}
}

func TestRuntimeHandlerRejectsTypedNilDependencies(t *testing.T) {
	t.Run("publisher", func(t *testing.T) {
		dependencies := validRuntimeDependencies(t)
		var publisher *edgepublish.Runtime
		dependencies.Publisher = publisher
		handler, err := NewRuntimeHandler(validRuntimeConfig(), dependencies)
		if handler != nil || !errors.Is(err, ErrInvalidRuntimeConfig) {
			t.Fatalf("typed-nil publisher = (%T, %v)", handler, err)
		}
	})
}

func TestRuntimeHandlerRejectsTypedNilAPIKeyDependency(t *testing.T) {
	dependencies := validRuntimeDependencies(t)
	var apiKeys *apikey.Service
	dependencies.APIKeys = apiKeys

	handler, err := NewRuntimeHandler(validRuntimeConfig(), dependencies)
	if handler != nil || !errors.Is(err, ErrInvalidRuntimeConfig) {
		t.Fatalf("typed-nil API keys = (%T, %v)", handler, err)
	}
}

func TestServiceConstructorsRejectTypedNilPorts(t *testing.T) {
	validDomain := &fakeDomain{}
	validCursor := newTestCursorCodec(t)

	var nilDomain *fakeDomain
	var nilCursor *HMACCursorCodec
	for name, construct := range map[string]func() (*Service, error){
		"publications": func() (*Service, error) {
			return NewService(nilDomain, validDomain, validCursor)
		},
		"rollouts": func() (*Service, error) {
			return NewService(validDomain, nilDomain, validCursor)
		},
		"cursor": func() (*Service, error) {
			return NewService(validDomain, validDomain, nilCursor)
		},
		"commands": func() (*Service, error) {
			return newRuntimeService(validDomain, validDomain, nilDomain, validCursor)
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, err := construct()
			if service != nil || !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("constructor = (%T, %v), want nil invalid request", service, err)
			}
		})
	}
}

func TestRuntimeHandlerRejectsUnconfiguredDependenciesAndPublisher(t *testing.T) {
	tests := map[string]func(*RuntimeConfig, *RuntimeDependencies){
		"postgres":  func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Pool = new(pgxpool.Pool) },
		"identity":  func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Identity = new(identity.Service) },
		"api keys":  func(_ *RuntimeConfig, value *RuntimeDependencies) { value.APIKeys = nil },
		"iam":       func(_ *RuntimeConfig, value *RuntimeDependencies) { value.IAM = new(iamlock.Authorizer) },
		"publisher": func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Publisher = nil },
		"cursor": func(config *RuntimeConfig, _ *RuntimeDependencies) {
			config.CursorActiveKey.Secret = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config, dependencies := validRuntimeConfig(), validRuntimeDependencies(t)
			mutate(&config, &dependencies)
			handler, err := NewRuntimeHandler(config, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidRuntimeConfig) {
				t.Fatalf("NewRuntimeHandler() = (%T, %v), want nil invalid runtime config", handler, err)
			}
		})
	}
}

func validRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Enabled: true, CursorActiveKey: CursorKey{ID: "runtime-active", Secret: make([]byte, 32)},
	}
}

func validRuntimeDependencies(t *testing.T) RuntimeDependencies {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("edgepublish-runtime-test-token-secret", time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x51}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	publisherConfig := edgepublish.DefaultConfig()
	publisherConfig.Clock = func() time.Time { return testClock }
	publisherConfig.EntitlementAuthorizer = runtimeFactoryEntitlement{}
	publisher, err := edgepublish.NewRuntime(edgepublish.RuntimeConfig{Publisher: publisherConfig},
		edgepublish.RuntimeDependencies{Pool: pool, Signer: &runtimeFactorySigner{}, IAM: authorizer})
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{
		Pool: pool, Identity: identityService, APIKeys: apikey.NewService(pool, bytes.Repeat([]byte{0x51}, 32), time.Now),
		IAM: authorizer, Publisher: publisher,
	}
}
