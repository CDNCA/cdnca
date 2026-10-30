package analyticslog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPrincipalFormattingRedactsCredential(t *testing.T) {
	const credential = "cdnca-sensitive-runtime-credential"
	principal := Principal{ID: "user", ScopeID: "scope", ScopeKind: "tenant",
		credentialKind: credentialSession, rawCredential: credential}
	encoded, err := json.Marshal(principal)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		fmt.Sprintf("%v", principal), fmt.Sprintf("%+v", principal), fmt.Sprintf("%#v", principal),
		principal.String(), principal.GoString(), string(encoded),
	} {
		if strings.Contains(output, credential) {
			t.Fatalf("credential leaked through %q", output)
		}
	}
}

func TestRuntimeHandlerDisabledReturnsOnlyNotFound(t *testing.T) {
	handler, err := NewRuntimeHandler(RuntimeConfig{}, HTTPDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/analytics/logs/access",
		"/v1/admin/analytics/logs/access",
		"/v1/analytics/logs/access/neighbor",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestRuntimeHandlerEnabledFailsClosedWithoutOfficialDependencies(t *testing.T) {
	poolConfig, err := pgxpool.ParseConfig("postgres://runtime:runtime@127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tokens, err := identity.NewTokenManager("01234567890123456789012345678901", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{1}, 32)
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(pepper, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	complete := HTTPDependencies{
		Identity: identityService,
		APIKeys:  apikey.NewService(pool, pepper, time.Now),
		Pool:     pool,
		IAM:      iam,
	}
	config := RuntimeConfig{Enabled: true, HTTP: HTTPConfig{
		Client: ClientConfig{Endpoint: "http://127.0.0.1:8123", Database: "analyticslog", CursorKeyring: testLogCursorKeyring()},
	}}
	if handler, err := NewRuntimeHandler(config, complete); err != nil || handler == nil {
		t.Fatalf("complete NewRuntimeHandler() = (%T, %v)", handler, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*HTTPDependencies)
	}{
		{name: "identity_missing", mutate: func(value *HTTPDependencies) { value.Identity = nil }},
		{name: "identity_unconfigured", mutate: func(value *HTTPDependencies) { value.Identity = new(identity.Service) }},
		{name: "api_key_missing", mutate: func(value *HTTPDependencies) { value.APIKeys = nil }},
		{name: "pool_missing", mutate: func(value *HTTPDependencies) { value.Pool = nil }},
		{name: "pool_unconfigured", mutate: func(value *HTTPDependencies) { value.Pool = new(pgxpool.Pool) }},
		{name: "iam_missing", mutate: func(value *HTTPDependencies) { value.IAM = nil }},
		{name: "iam_unconfigured", mutate: func(value *HTTPDependencies) { value.IAM = new(iamlock.Authorizer) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := complete
			test.mutate(&dependencies)
			handler, err := NewRuntimeHandler(config, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewRuntimeHandler() = (%T, %v), want nil invalid configuration", handler, err)
			}
		})
	}
}
