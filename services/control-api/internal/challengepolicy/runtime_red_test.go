package challengepolicy

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
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeHandlerDisabledIsClosed(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, collectionPath(testUUID(1)), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled runtime status=%d body=%s", response.Code, response.Body)
	}
}

func TestRuntimeHandlerEnabledBuildsPackageHandler(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{
		Enabled:        true,
		CursorAudience: "challenge-policy-runtime",
		CursorKeyID:    "challenge-policy-key-2026-07",
	}, runtimeTestDependencies(t))
	if err != nil || handler == nil {
		t.Fatalf("NewRuntimeHandler()=(%T,%v), want package handler", handler, err)
	}
}

func TestRuntimeHandlerEnabledRequiresProductionDependencies(t *testing.T) {
	validConfig := RuntimeConfig{
		Enabled:        true,
		CursorAudience: "challenge-policy-runtime",
		CursorKeyID:    "challenge-policy-key-2026-07",
	}
	validDependencies := runtimeTestDependencies(t)
	tokens, err := identity.NewTokenManager("challenge-policy-runtime-invalid-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityWithoutPool, err := identity.NewService(identity.NewStore(nil), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityWithZeroTokens, err := identity.NewService(identity.NewStore(validDependencies.Pool), new(identity.TokenManager), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x73}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iamWithoutSessions, err := iamlock.NewAuthorizer(new(sessioncredential.Verifier), apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	iamWithoutAPIKeys, err := iamlock.NewAuthorizer(sessions, new(apikeycredential.Verifier))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*RuntimeConfig, *RuntimeDependencies){
		"postgres":          func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Pool = nil },
		"identity":          func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Identity = nil },
		"iam":               func(_ *RuntimeConfig, value *RuntimeDependencies) { value.IAM = nil },
		"entitlement trust": func(_ *RuntimeConfig, value *RuntimeDependencies) { value.EntitlementTrust = nil },
		"clock":             func(_ *RuntimeConfig, value *RuntimeDependencies) { value.Now = nil },
		"cursor key":        func(_ *RuntimeConfig, value *RuntimeDependencies) { value.CursorKey = nil },
		"short cursor key": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.CursorKey = []byte("short")
		},
		"cursor audience": func(config *RuntimeConfig, _ *RuntimeDependencies) { config.CursorAudience = "" },
		"cursor key id":   func(config *RuntimeConfig, _ *RuntimeDependencies) { config.CursorKeyID = "" },
		"zero postgres": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Pool = new(pgxpool.Pool)
		},
		"zero identity": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Identity = new(identity.Service)
		},
		"identity without pool": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Identity = identityWithoutPool
		},
		"identity with zero tokens": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.Identity = identityWithZeroTokens
		},
		"zero iam": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.IAM = new(iamlock.Authorizer)
		},
		"iam without sessions": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.IAM = iamWithoutSessions
		},
		"iam without api keys": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.IAM = iamWithoutAPIKeys
		},
		"zero entitlement trust": func(_ *RuntimeConfig, value *RuntimeDependencies) {
			value.EntitlementTrust = new(entitlementguard.TrustStore)
		},
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validConfig
			dependencies := validDependencies
			invalidate(&config, &dependencies)
			handler, err := NewRuntimeHandler(config, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidHandlerConfig) {
				t.Fatalf("NewRuntimeHandler()=(%T,%v), want nil ErrInvalidHandlerConfig", handler, err)
			}
		})
	}
}

func runtimeTestDependencies(t *testing.T) RuntimeDependencies {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgresql://challenge:challenge@127.0.0.1:1/challenge?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("challenge-policy-runtime-identity-secret", time.Hour)
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
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x61}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "challenge-runtime-test-key", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return RuntimeDependencies{
		Pool: pool, Identity: identityService, IAM: iam, EntitlementTrust: trust,
		Now: time.Now, CursorKey: bytes.Repeat([]byte{0x41}, minCursorKeyBytes),
	}
}
