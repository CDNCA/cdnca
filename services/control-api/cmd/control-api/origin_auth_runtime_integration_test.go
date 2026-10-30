package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthverifier"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const originAuthRuntimeSecretMarker = "origin-auth-production-secret-marker"

type originAuthRuntimeTypedNilVerifier struct{}

func (*originAuthRuntimeTypedNilVerifier) Verify(
	context.Context,
	originauthcontrol.VerificationRequest,
) error {
	return nil
}

type originAuthRuntimeTypedNilAuditor struct{}

func (*originAuthRuntimeTypedNilAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return nil
}

func TestOriginAuthProductionRuntimeConfigurationIsStrictAndClearsSecrets(t *testing.T) {
	config, err := loadOriginAuthRuntimeConfigFromEnvEntries(originAuthRuntimeEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.ActiveKeyID != "active" || len(config.Keys) != 2 {
		t.Fatalf("origin auth config enabled=%t active=%q keys=%d",
			config.Enabled, config.ActiveKeyID, len(config.Keys))
	}
	if _, err := originauthverifier.New(config.Verifier); err != nil {
		t.Fatalf("production verifier config is invalid: %v", err)
	}
	retained := [][]byte{config.Keys["active"], config.Keys["previous"]}
	config.clearSecrets()
	if config.Keys != nil {
		t.Fatalf("cleared config retained key references: key_count=%d", len(config.Keys))
	}
	assertOriginAuthRuntimeSecretsCleared(t, retained)
}

func TestOriginAuthProductionRuntimeDisabledNeedsNoSecretsAndIsExact404(t *testing.T) {
	config, err := loadOriginAuthRuntimeConfigFromEnvEntries([]string{
		"ORIGIN_AUTH_RUNTIME_ENABLED=false",
	})
	if err != nil || config.Enabled {
		t.Fatalf("disabled config enabled=%t err=%v", config.Enabled, err)
	}
	factory, err := buildAndClearOriginAuthHandlerFactory(&config, originAuthRuntimeDependencies{})
	if err != nil || factory != nil {
		t.Fatalf("disabled factory=(%v, %v), want nil", factory, err)
	}
	assertOriginAuthRuntimeStatus(t, http.NotFoundHandler(), http.MethodGet,
		"/v1/tenant-scopes/018f9d7e-4a1b-7a2c-8d3e-111111111111/origin-auth/credentials",
		http.StatusNotFound)
}

func TestOriginAuthProductionRuntimeRejectsMalformedAndPartialEnvironment(t *testing.T) {
	secret32 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	secret31 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 31))
	valid := originAuthRuntimeEnvironment()
	for _, test := range []struct {
		name        string
		environment []string
	}{
		{name: "empty enabled", environment: []string{"ORIGIN_AUTH_RUNTIME_ENABLED="}},
		{name: "invalid enabled", environment: []string{"ORIGIN_AUTH_RUNTIME_ENABLED=1"}},
		{name: "duplicate enabled", environment: append(append([]string(nil), valid...), "ORIGIN_AUTH_RUNTIME_ENABLED=true")},
		{name: "unknown runtime variable", environment: append(append([]string(nil), valid...), "ORIGIN_AUTH_RUNTIME_ENABLD=true")},
		{name: "missing active key", environment: originAuthRuntimeWithout("ORIGIN_AUTH_ENCRYPTION_ACTIVE_KEY_ID")},
		{name: "missing keyring", environment: originAuthRuntimeWithout("ORIGIN_AUTH_ENCRYPTION_KEYS_JSON")},
		{name: "missing probes", environment: originAuthRuntimeWithout("ORIGIN_AUTH_PROVIDER_PROBES_JSON")},
		{name: "invalid key base64", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_ENCRYPTION_KEYS_JSON", `{"active":"not-base64"}`)},
		{name: "short key", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_ENCRYPTION_KEYS_JSON", `{"active":"`+secret31+`"}`)},
		{name: "unknown active key", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_ENCRYPTION_ACTIVE_KEY_ID", "missing")},
		{name: "duplicate key", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_ENCRYPTION_KEYS_JSON", `{"active":"`+secret32+`","active":"`+secret32+`"}`)},
		{name: "no enabled probe", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_PROVIDER_PROBES_JSON", `{"s3":{"enabled":false}}`)},
		{name: "partial enabled probe", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_PROVIDER_PROBES_JSON", `{"s3":{"enabled":true,"endpoint":"https://s3.example.com"}}`)},
		{name: "duplicate provider", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_PROVIDER_PROBES_JSON", `{"s3":{"enabled":false},"s3":{"enabled":false}}`)},
		{name: "unknown provider field", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_PROVIDER_PROBES_JSON", `{"s3":{"enabled":false,"credential":"secret"}}`)},
		{name: "trailing provider document", environment: originAuthRuntimeReplace(
			"ORIGIN_AUTH_PROVIDER_PROBES_JSON", `{"s3":{"enabled":false}}{}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadOriginAuthRuntimeConfigFromEnvEntries(test.environment)
			if err == nil || config.Enabled || config.Keys != nil {
				t.Fatalf("invalid environment accepted: enabled=%t key_count=%d",
					config.Enabled, len(config.Keys))
			}
			if strings.Contains(err.Error(), originAuthRuntimeSecretMarker) ||
				strings.Contains(err.Error(), secret32) {
				t.Fatal("configuration error leaked secret material")
			}
		})
	}
}

func TestOriginAuthProductionRuntimeFactoryFailsClosedAndClearsSecrets(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*originAuthRuntimeConfig, *originAuthRuntimeDependencies)
	}{
		{name: "missing pool", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Pool = nil }},
		{name: "unconfigured pool", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Pool = new(pgxpool.Pool) }},
		{name: "missing identity", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Identity = nil }},
		{name: "unconfigured identity", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) {
			value.Identity = new(identity.Service)
		}},
		{name: "missing IAM", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.IAM = nil }},
		{name: "unconfigured IAM", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) {
			value.IAM = new(iamlock.Authorizer)
		}},
		{name: "missing trust", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Trust = nil }},
		{name: "unconfigured trust", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) {
			value.Trust = new(entitlementguard.TrustStore)
		}},
		{name: "missing verifier", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Verifier = nil }},
		{name: "typed nil verifier", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) {
			var verifier *originAuthRuntimeTypedNilVerifier
			value.Verifier = verifier
		}},
		{name: "missing auditor", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Auditor = nil }},
		{name: "typed nil auditor", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) {
			var auditor *originAuthRuntimeTypedNilAuditor
			value.Auditor = auditor
		}},
		{name: "missing clock", mutate: func(_ *originAuthRuntimeConfig, value *originAuthRuntimeDependencies) { value.Clock = nil }},
		{name: "missing active key", mutate: func(value *originAuthRuntimeConfig, _ *originAuthRuntimeDependencies) { value.ActiveKeyID = "" }},
		{name: "missing keyring", mutate: func(value *originAuthRuntimeConfig, _ *originAuthRuntimeDependencies) { value.Keys = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadOriginAuthRuntimeConfigFromEnvEntries(originAuthRuntimeEnvironment())
			if err != nil {
				t.Fatal(err)
			}
			retained := originAuthRuntimeRetainedSecrets(config)
			dependencies := originAuthRuntimeValidDependencies(t, config)
			test.mutate(&config, &dependencies)
			factory, err := buildAndClearOriginAuthHandlerFactory(&config, dependencies)
			if err == nil || factory != nil {
				t.Fatalf("factory_present=%t error_present=%t, want false/true", factory != nil, err != nil)
			}
			if strings.Contains(err.Error(), originAuthRuntimeSecretMarker) {
				t.Fatal("factory error leaked secret material")
			}
			assertOriginAuthRuntimeSecretsCleared(t, retained)
		})
	}
}

func TestOriginAuthProductionRuntimeFactoryBuildsFrozenHandler(t *testing.T) {
	config, err := loadOriginAuthRuntimeConfigFromEnvEntries(originAuthRuntimeEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	retained := originAuthRuntimeRetainedSecrets(config)
	dependencies := originAuthRuntimeValidDependencies(t, config)
	factory, err := buildAndClearOriginAuthHandlerFactory(&config, dependencies)
	if err != nil || factory == nil {
		t.Fatalf("factory=(%v, %v)", factory, err)
	}
	assertOriginAuthRuntimeSecretsCleared(t, retained)
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("handler=(%T, %v)", handler, err)
	}
	base := "/v1/tenant-scopes/018f9d7e-4a1b-7a2c-8d3e-111111111111/origin-auth"
	assertOriginAuthRuntimeStatus(t, handler, http.MethodGet, base+"/credentials", http.StatusUnauthorized)
	assertOriginAuthRuntimeStatus(t, handler, http.MethodGet, base+"/credential", http.StatusNotFound)
	for _, authorization := range []string{"Bearer not-a-token", "CdncaKey not-supported"} {
		request := httptest.NewRequest(http.MethodGet, base+"/credentials", nil)
		request.Header.Set("Authorization", authorization)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("authorization %q status=%d body=%s", authorization, response.Code, response.Body)
		}
	}
}

func originAuthRuntimeValidDependencies(
	t *testing.T,
	config originAuthRuntimeConfig,
) originAuthRuntimeDependencies {
	t.Helper()
	pool := originAuthRuntimeConfiguredPool(t)
	tokens, err := identity.NewTokenManager("origin-auth-production-runtime-token-secret", time.Hour)
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
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := originauthverifier.New(config.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "origin-auth-production-trust", PublicKey: privateKey.Public().(ed25519.PublicKey),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return originAuthRuntimeDependencies{
		Pool: pool, Identity: identityService, IAM: iam, Trust: trust,
		Verifier: verifier, Auditor: audit.New(pool), Clock: time.Now,
	}
}

func originAuthRuntimeConfiguredPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgresql://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func originAuthRuntimeEnvironment() []string {
	active := bytes.Repeat([]byte(originAuthRuntimeSecretMarker), 2)[:32]
	previous := bytes.Repeat([]byte{0x42}, 32)
	return []string{
		"ORIGIN_AUTH_RUNTIME_ENABLED=true",
		"ORIGIN_AUTH_ENCRYPTION_ACTIVE_KEY_ID=active",
		"ORIGIN_AUTH_ENCRYPTION_KEYS_JSON={\"active\":\"" + base64.StdEncoding.EncodeToString(active) +
			"\",\"previous\":\"" + base64.StdEncoding.EncodeToString(previous) + "\"}",
		"ORIGIN_AUTH_PROVIDER_PROBES_JSON={\"s3\":{\"enabled\":true,\"endpoint\":\"https://s3.us-east-1.amazonaws.com\",\"region\":\"us-east-1\",\"bucket\":\"runtime-probe\",\"object\":\"health/check\"}}",
	}
}

func originAuthRuntimeWithout(name string) []string {
	result := make([]string, 0, len(originAuthRuntimeEnvironment()))
	for _, entry := range originAuthRuntimeEnvironment() {
		if !strings.HasPrefix(entry, name+"=") {
			result = append(result, entry)
		}
	}
	return result
}

func originAuthRuntimeReplace(name, value string) []string {
	result := originAuthRuntimeWithout(name)
	return append(result, name+"="+value)
}

func originAuthRuntimeRetainedSecrets(config originAuthRuntimeConfig) [][]byte {
	result := make([][]byte, 0, len(config.Keys))
	for _, secret := range config.Keys {
		result = append(result, secret)
	}
	return result
}

func assertOriginAuthRuntimeSecretsCleared(t *testing.T, retained [][]byte) {
	t.Helper()
	for index, secret := range retained {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("origin auth secret %d was not cleared", index)
		}
	}
}

func assertOriginAuthRuntimeStatus(t *testing.T, handler http.Handler, method, target string, want int) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, target, nil))
	if response.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, target, response.Code, want, response.Body)
	}
}
