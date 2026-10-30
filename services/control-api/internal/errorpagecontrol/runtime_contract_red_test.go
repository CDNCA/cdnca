package errorpagecontrol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRuntimeMetadataRejectsDuplicateSensitiveHeadersBeforeAuthentication(t *testing.T) {
	assetBody := `{"scope_id":"` + uuid.NewString() + `","mime_type":"text/plain","size_bytes":4,"sha256":"` +
		strings.Repeat("a", 64) + `"}`
	tests := []struct {
		name   string
		method string
		path   string
		body   string
		header string
		value  string
	}{
		{name: "idempotency key", method: http.MethodPost, path: apiPrefix + "/assets/initiate", body: assetBody,
			header: "Idempotency-Key", value: "duplicate-idempotency"},
		{name: "if match", method: http.MethodDelete, path: apiPrefix + "/rules/" + uuid.NewString(),
			header: "If-Match", value: `"1"`},
		{name: "content type", method: http.MethodPost, path: apiPrefix + "/assets/initiate", body: assetBody,
			header: "Content-Type", value: "application/json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &reviewAuthenticator{actor: tenantRuntimeActor()}
			domain := &reviewPublicationDomain{fakeHTTPDomain: &fakeHTTPDomain{}}
			inner, err := NewHandler(domain, auth)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, "http://control.test"+test.path, strings.NewReader(test.body))
			setWriteHeaders(request)
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			request.Header.Set(test.header, test.value)
			request.Header.Add(test.header, test.value)
			response := httptest.NewRecorder()
			runtimeMetadataHandler{inner: inner}.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest ||
				!strings.Contains(response.Body.String(), `"code":"invalid_request"`) ||
				auth.calls != 0 || domain.initiateCalls != 0 || domain.uploadCalls != 0 || domain.calls != 0 {
				t.Fatalf("status=%d body=%s auth_calls=%d initiate_calls=%d upload_calls=%d publication_calls=%d",
					response.Code, response.Body.String(), auth.calls, domain.initiateCalls,
					domain.uploadCalls, domain.calls)
			}
		})
	}
}

func TestRuntimeMetadataRejectsRawPathBeforeAuthentication(t *testing.T) {
	auth := &reviewAuthenticator{actor: tenantRuntimeActor()}
	domain := &reviewPublicationDomain{fakeHTTPDomain: &fakeHTTPDomain{}}
	inner, err := NewHandler(domain, auth)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://control.test"+apiPrefix+"/assets", nil)
	request.URL.RawPath = apiPrefix + "/%61ssets"
	response := httptest.NewRecorder()
	runtimeMetadataHandler{inner: inner}.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || auth.calls != 0 || domain.initiateCalls != 0 ||
		domain.uploadCalls != 0 || domain.calls != 0 {
		t.Fatalf("status=%d auth_calls=%d initiate_calls=%d upload_calls=%d publication_calls=%d",
			response.Code, auth.calls, domain.initiateCalls, domain.uploadCalls, domain.calls)
	}
}

func TestRuntimeMetadataDoesNotGenerateRequiredWriteCorrelation(t *testing.T) {
	assetBody := `{"scope_id":"` + uuid.NewString() + `","mime_type":"text/plain","size_bytes":4,"sha256":"` +
		strings.Repeat("a", 64) + `"}`
	for _, missing := range []string{"X-Request-ID", "X-Trace-ID"} {
		t.Run(missing, func(t *testing.T) {
			auth := &reviewAuthenticator{actor: tenantRuntimeActor()}
			domain := &reviewPublicationDomain{fakeHTTPDomain: &fakeHTTPDomain{}}
			inner, err := NewHandler(domain, auth)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "http://control.test"+apiPrefix+"/assets/initiate",
				strings.NewReader(assetBody))
			setWriteHeaders(request)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Del(missing)
			response := httptest.NewRecorder()
			runtimeMetadataHandler{inner: inner}.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest ||
				!strings.Contains(response.Body.String(), `"code":"invalid_request"`) ||
				auth.calls != 1 || domain.initiateCalls != 0 {
				t.Fatalf("status=%d body=%s auth_calls=%d initiate_calls=%d",
					response.Code, response.Body.String(), auth.calls, domain.initiateCalls)
			}
		})
	}
}

func TestRuntimeHandlerUsesSealedIAMAndServicePublicationCapability(t *testing.T) {
	dependencies := runtimeFactoryDependencies(t, "runtime-contract")
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	runtimeHandler, ok := handler.Handler().(runtimeMetadataHandler)
	if !ok {
		t.Fatalf("runtime handler type=%T", handler.Handler())
	}
	httpHandler, ok := runtimeHandler.inner.(*Handler)
	if !ok {
		t.Fatalf("inner handler type=%T", runtimeHandler.inner)
	}
	service, ok := httpHandler.domain.(*Service)
	if !ok || service.pool != dependencies.Pool {
		t.Fatalf("domain=%T pool_matches=%t", httpHandler.domain, ok && service.pool == dependencies.Pool)
	}
	authenticator, ok := httpHandler.auth.(runtimeAuthenticator)
	if !ok || authenticator.identity != dependencies.Identity {
		t.Fatalf("authenticator=%T identity_matches=%t", httpHandler.auth,
			ok && authenticator.identity == dependencies.Identity)
	}
	authorizer, ok := service.authorizer.(runtimeTxAuthorizer)
	if !ok || authorizer.identity != dependencies.Identity || authorizer.iam != dependencies.IAM {
		t.Fatalf("authorizer=%T production_dependencies=%t", service.authorizer,
			ok && authorizer.identity == dependencies.Identity && authorizer.iam == dependencies.IAM)
	}
	if _, legacy := service.authorizer.(tenantSessionTxAuthorizer); legacy {
		t.Fatalf("production factory reached legacy authorizer %T", service.authorizer)
	}
}

func TestRuntimeHandlerRejectsTypedNilProductionInterfaces(t *testing.T) {
	var content *typedNilContentStore
	var scanner *typedNilScanner
	var limits *typedNilLimits
	valid := runtimeFactoryDependencies(t, "runtime-typed-nil")
	tests := map[string]func(*RuntimeDependencies){
		"content": func(dependencies *RuntimeDependencies) { dependencies.ContentStore = content },
		"scanner": func(dependencies *RuntimeDependencies) { dependencies.Scanner = scanner },
		"limits":  func(dependencies *RuntimeDependencies) { dependencies.Limits = limits },
	}
	for name, makeTypedNil := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := valid
			makeTypedNil(&dependencies)
			handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, dependencies)
			if handler != nil || !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("NewRuntimeHandler() = (%T,%v), want nil ErrInvalidStore", handler, err)
			}
		})
	}
}

func TestRuntimeAuthenticatorRejectsOversizedBearerBeforeIdentity(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://control.test"+apiPrefix+"/assets", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 8193))

	// A zero service panics if invoked, so it proves the identity dependency was not reached.
	actor, err := (runtimeAuthenticator{identity: new(identity.Service)}).Authenticate(request)
	if actor != (Actor{}) || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Authenticate() = (%+v,%v), want zero actor ErrUnauthenticated", actor, err)
	}
}

func TestRuntimeAuthenticatorRejectsUnconfiguredIdentityBeforeAuthentication(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://control.test"+apiPrefix+"/assets", nil)
	tokens, err := identity.NewTokenManager(strings.Repeat("unconfigured-identity-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rawToken, _, err := tokens.Mint(uuid.New(), uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+rawToken)

	actor, err := (runtimeAuthenticator{identity: new(identity.Service)}).Authenticate(request)
	if actor != (Actor{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Authenticate() = (%+v,%v), want zero actor ErrUnavailable", actor, err)
	}
}

type typedNilTenantSessionAuthorizer struct{}

func (*typedNilTenantSessionAuthorizer) AuthorizeTenantSessionTx(
	context.Context,
	pgx.Tx,
	rbacmanager.AuthenticatedSessionReference,
	string,
) (uuid.UUID, error) {
	return uuid.Nil, nil
}

func TestTenantSessionAuthorizerRejectsTypedNilCompatibilityDependency(t *testing.T) {
	var sessions *typedNilTenantSessionAuthorizer
	authorizer, err := NewTenantSessionTxAuthorizer(sessions)
	if authorizer != nil || !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewTenantSessionTxAuthorizer() = (%T,%v), want nil ErrInvalidStore", authorizer, err)
	}
}
