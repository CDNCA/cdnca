package urlauthpolicyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
)

type stubService struct {
	createRequest urlauthpolicy.CreateRequest
	updateRequest urlauthpolicy.UpdateRequest
	rotateRequest urlauthpolicy.RotateRequest
	revokeRequest urlauthpolicy.RevokeRequest
	stateRequest  urlauthpolicy.StateRequest
	listFilter    urlauthpolicy.ListFilter
	item          urlauthpolicy.Policy
	err           error
}

func (service *stubService) Create(_ context.Context, _ urlauthpolicy.Actor, request urlauthpolicy.CreateRequest) (urlauthpolicy.SecretWriteResult, error) {
	service.createRequest = request
	return urlauthpolicy.SecretWriteResult{Policy: service.item, Secret: "one-time-secret"}, service.err
}

func (service *stubService) Update(_ context.Context, _ urlauthpolicy.Actor, request urlauthpolicy.UpdateRequest) (urlauthpolicy.WriteResult, error) {
	service.updateRequest = request
	return urlauthpolicy.WriteResult{Policy: service.item}, service.err
}

func (service *stubService) Rotate(_ context.Context, _ urlauthpolicy.Actor, request urlauthpolicy.RotateRequest) (urlauthpolicy.SecretWriteResult, error) {
	service.rotateRequest = request
	return urlauthpolicy.SecretWriteResult{Policy: service.item, Secret: "rotated-secret"}, service.err
}

func (service *stubService) Revoke(_ context.Context, _ urlauthpolicy.Actor, request urlauthpolicy.RevokeRequest) (urlauthpolicy.WriteResult, error) {
	service.revokeRequest = request
	return urlauthpolicy.WriteResult{Policy: service.item}, service.err
}

func (service *stubService) SetEnabled(_ context.Context, _ urlauthpolicy.Actor, request urlauthpolicy.StateRequest) (urlauthpolicy.WriteResult, error) {
	service.stateRequest = request
	service.item.Enabled = request.Enabled
	return urlauthpolicy.WriteResult{Policy: service.item}, service.err
}

func (service *stubService) Get(_ context.Context, _ urlauthpolicy.Actor, _ uuid.UUID) (urlauthpolicy.Policy, error) {
	return service.item, service.err
}

func (service *stubService) List(_ context.Context, _ urlauthpolicy.Actor, filter urlauthpolicy.ListFilter) (urlauthpolicy.ListResult, error) {
	service.listFilter = filter
	return urlauthpolicy.ListResult{Items: []urlauthpolicy.Policy{service.item}, Total: 1, Page: filter.Page, Limit: filter.Limit}, service.err
}

func (service *stubService) Snapshot(_ context.Context, _ urlauthpolicy.Actor, id uuid.UUID) (urlauthpolicy.SnapshotResult, error) {
	return urlauthpolicy.SnapshotResult{
		PolicyID: id, Revision: service.item.Revision, SHA256: strings.Repeat("a", 64),
		Document: urlauthpolicy.EdgePolicy{SchemaVersion: urlauthpolicy.SchemaVersion},
	}, service.err
}

func principal(permissions ...string) identity.Principal {
	tenantID := uuid.New()
	return identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID,
		Roles: []string{"tenant_owner"}, Permissions: permissions,
	}
}

func testPolicy() urlauthpolicy.Policy {
	now := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	return urlauthpolicy.Policy{
		ID: uuid.New(), ScopeID: uuid.New(), Site: urlauthpolicy.SiteReference{ID: uuid.New(), Domain: "download.example"},
		Name: "Downloads", Enabled: true, Algorithm: urlauthpolicy.AlgorithmHMACSHA256,
		SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
		MaxClockSkewSeconds: 30, MaxValiditySeconds: 600, MaxSignatureUses: 1,
		ExcludedQueryParameters: []string{}, TrustedProxyCIDRs: []string{},
		CurrentKey: urlauthpolicy.KeyMetadata{KeyID: "k-current", CreatedAt: now}, Revision: 3,
		CreatedAt: now, UpdatedAt: now,
	}
}

func validBody(item urlauthpolicy.Policy) string {
	value := urlauthpolicy.PolicyFields{
		SiteID: item.Site.ID, Name: item.Name, Enabled: item.Enabled, Algorithm: item.Algorithm,
		SignatureParameter: item.SignatureParameter, ExpirationParameter: item.ExpirationParameter,
		KeyIDParameter: item.KeyIDParameter, BindClientIP: item.BindClientIP,
		MaxClockSkewSeconds: item.MaxClockSkewSeconds, MaxValiditySeconds: item.MaxValiditySeconds,
		MaxSignatureUses: item.MaxSignatureUses, ExcludedQueryParameters: []string{}, TrustedProxyCIDRs: []string{},
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func newTestHandler(t *testing.T, service *stubService, authenticated identity.Principal, config HandlerConfig) http.Handler {
	t.Helper()
	handler, err := NewHandler(service, AuthenticateFunc(func(*http.Request) (authenticatedPrincipal, error) {
		if authenticated.UserID == uuid.Nil {
			return authenticatedPrincipal{}, ErrUnauthenticated
		}
		return authenticatedPrincipal{Principal: authenticated}, nil
	}), config)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

func request(method, target, body string) *http.Request {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer test-session")
	req.Header.Set("X-Request-ID", "url-auth-test-request")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func TestHandlerCollectionAndDetail(t *testing.T) {
	item := testPolicy()
	service := &stubService{item: item}
	handler := newTestHandler(t, service, principal("url_auth_policies.read", "url_auth_policies.manage"), HandlerConfig{})

	list := request(http.MethodGet, "/v1/url-auth-policies?page=2&limit=50&name=down&status=enabled&site_id="+item.Site.ID.String(), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, list)
	if response.Code != http.StatusOK || service.listFilter.Page != 2 || service.listFilter.Limit != 50 || service.listFilter.SiteID != item.Site.ID {
		t.Fatalf("list status=%d filter=%+v body=%s", response.Code, service.listFilter, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") != "url-auth-test-request" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list headers = %v", response.Header())
	}

	detail := request(http.MethodGet, "/v1/url-auth-policies/"+item.ID.String(), "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, detail)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"3"` || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("detail status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}

	snapshot := request(http.MethodGet, "/v1/url-auth-policies/"+item.ID.String()+"/edge-snapshot", "")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, snapshot)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"sha256:`+strings.Repeat("a", 64)+`"` ||
		!strings.Contains(response.Body.String(), urlauthpolicy.SchemaVersion) {
		t.Fatalf("snapshot status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestHandlerWritesCarryExactMetadata(t *testing.T) {
	item := testPolicy()
	service := &stubService{item: item}
	handler := newTestHandler(t, service, principal("url_auth_policies.read", "url_auth_policies.manage"), HandlerConfig{})

	create := request(http.MethodPost, "/v1/url-auth-policies", validBody(item))
	create.Header.Set("Idempotency-Key", "create-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, create)
	if response.Code != http.StatusCreated || service.createRequest.IdempotencyKey != "create-key" ||
		service.createRequest.RequestID != "url-auth-test-request" || !strings.Contains(response.Body.String(), "one-time-secret") {
		t.Fatalf("create status=%d request=%+v body=%s", response.Code, service.createRequest, response.Body.String())
	}

	update := request(http.MethodPatch, "/v1/url-auth-policies/"+item.ID.String(), validBody(item))
	update.Header.Set("Idempotency-Key", "update-key")
	update.Header.Set("If-Match", `"3"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, update)
	if response.Code != http.StatusOK || service.updateRequest.ExpectedRevision != 3 || service.updateRequest.IdempotencyKey != "update-key" {
		t.Fatalf("update status=%d request=%+v body=%s", response.Code, service.updateRequest, response.Body.String())
	}

	disable := request(http.MethodPost, "/v1/url-auth-policies/"+item.ID.String()+"/disable", `{}`)
	disable.Header.Set("Idempotency-Key", "disable-key")
	disable.Header.Set("If-Match", `"3"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, disable)
	if response.Code != http.StatusOK || service.stateRequest.Enabled || service.stateRequest.ExpectedRevision != 3 || service.stateRequest.IdempotencyKey != "disable-key" {
		t.Fatalf("disable status=%d request=%+v body=%s", response.Code, service.stateRequest, response.Body.String())
	}

	enable := request(http.MethodPost, "/v1/url-auth-policies/"+item.ID.String()+"/enable", `{}`)
	enable.Header.Set("Idempotency-Key", "enable-key")
	enable.Header.Set("If-Match", `"3"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, enable)
	if response.Code != http.StatusOK || !service.stateRequest.Enabled || service.stateRequest.ExpectedRevision != 3 || service.stateRequest.IdempotencyKey != "enable-key" {
		t.Fatalf("enable status=%d request=%+v body=%s", response.Code, service.stateRequest, response.Body.String())
	}

	rotate := request(http.MethodPost, "/v1/url-auth-policies/"+item.ID.String()+"/rotate", `{}`)
	rotate.Header.Set("Idempotency-Key", "rotate-key")
	rotate.Header.Set("If-Match", `"3"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, rotate)
	if response.Code != http.StatusOK || service.rotateRequest.ExpectedRevision != 3 || !strings.Contains(response.Body.String(), "rotated-secret") {
		t.Fatalf("rotate status=%d request=%+v body=%s", response.Code, service.rotateRequest, response.Body.String())
	}

	previous := item.CurrentKey
	previous.KeyID = "k-previous"
	service.item.PreviousKey = &previous
	revoke := request(http.MethodPost, "/v1/url-auth-policies/"+item.ID.String()+"/revoke", `{"key_id":"k-previous"}`)
	revoke.Header.Set("Idempotency-Key", "revoke-key")
	revoke.Header.Set("If-Match", `"3"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, revoke)
	if response.Code != http.StatusOK || service.revokeRequest.KeyID != "k-previous" || service.revokeRequest.ExpectedRevision != 3 {
		t.Fatalf("revoke status=%d request=%+v body=%s", response.Code, service.revokeRequest, response.Body.String())
	}
}

func TestHandlerRejectsUntrustedOrAmbiguousInput(t *testing.T) {
	item := testPolicy()
	service := &stubService{item: item}
	handler := newTestHandler(t, service, principal("url_auth_policies.read"), HandlerConfig{MaxRequestBytes: 1024, MaxResponseBytes: 4096, MaxHeaderBytes: 1024})

	tests := []struct {
		name    string
		request *http.Request
		status  int
	}{
		{name: "unknown query", request: request(http.MethodGet, "/v1/url-auth-policies?page=1&limit=20&unknown=x", ""), status: http.StatusBadRequest},
		{name: "write permission", request: func() *http.Request {
			r := request(http.MethodPost, "/v1/url-auth-policies", validBody(item))
			r.Header.Set("Idempotency-Key", "write-key")
			return r
		}(), status: http.StatusForbidden},
		{name: "unknown field", request: func() *http.Request {
			r := request(http.MethodPost, "/v1/url-auth-policies", `{"unknown":true}`)
			r.Header.Set("Idempotency-Key", "unknown-key")
			return r
		}(), status: http.StatusForbidden},
		{name: "oversized body", request: func() *http.Request {
			r := request(http.MethodPost, "/v1/url-auth-policies", `{"padding":"`+strings.Repeat("x", 2048)+`"}`)
			r.Header.Set("Idempotency-Key", "large-key")
			return r
		}(), status: http.StatusForbidden},
		{name: "bad revision", request: func() *http.Request {
			r := request(http.MethodPatch, "/v1/url-auth-policies/"+item.ID.String(), validBody(item))
			r.Header.Set("Idempotency-Key", "update-key")
			r.Header.Set("If-Match", "3")
			return r
		}(), status: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, test.request)
			if response.Code != test.status || strings.Contains(response.Body.String(), "test-session") {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}

	manageHandler := newTestHandler(t, service, principal("url_auth_policies.manage"), HandlerConfig{MaxRequestBytes: 1024, MaxResponseBytes: 4096, MaxHeaderBytes: 1024})
	duplicate := request(http.MethodPost, "/v1/url-auth-policies", strings.Replace(validBody(item), `"name":"Downloads"`, `"name":"Downloads","name":"Again"`, 1))
	duplicate.Header.Set("Idempotency-Key", "duplicate-key")
	response := httptest.NewRecorder()
	manageHandler.ServeHTTP(response, duplicate)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate status=%d body=%s", response.Code, response.Body.String())
	}

	ambiguous := request(http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", "")
	ambiguous.Header.Add("Authorization", "CdncaKey untrusted")
	response = httptest.NewRecorder()
	manageHandler.ServeHTTP(response, ambiguous)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous authorization status=%d body=%s", response.Code, response.Body.String())
	}

	ambiguousRequestID := request(http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", "")
	ambiguousRequestID.Header.Add("X-Request-ID", "second-request")
	response = httptest.NewRecorder()
	manageHandler.ServeHTTP(response, ambiguousRequestID)
	if response.Code != http.StatusBadRequest || response.Header().Get("X-Request-ID") == "second-request" {
		t.Fatalf("ambiguous request ID status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestHandlerResponseLimitAndErrorRedaction(t *testing.T) {
	item := testPolicy()
	item.Name = strings.Repeat("x", 128)
	service := &stubService{item: item}
	handler := newTestHandler(t, service, principal("url_auth_policies.read"), HandlerConfig{MaxResponseBytes: 128})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request(http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", ""))
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() > 128 {
		t.Fatalf("response status=%d bytes=%d body=%s", response.Code, response.Body.Len(), response.Body.String())
	}

	service.err = errors.New("private database detail")
	handler = newTestHandler(t, service, principal("url_auth_policies.read"), HandlerConfig{})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request(http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", ""))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private database detail") {
		t.Fatalf("error status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsOversizedHeaderBeforeAuthentication(t *testing.T) {
	called := false
	handler, err := NewHandler(&stubService{item: testPolicy()}, AuthenticateFunc(func(*http.Request) (authenticatedPrincipal, error) {
		called = true
		return authenticatedPrincipal{Principal: principal("url_auth_policies.read")}, nil
	}), HandlerConfig{MaxHeaderBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	req := request(http.MethodGet, "/v1/url-auth-policies?page=1&limit=20", "")
	req.Header.Set("X-Large", string(bytes.Repeat([]byte{'x'}, 2048)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusRequestHeaderFieldsTooLarge || called {
		t.Fatalf("status=%d authenticate_called=%t", response.Code, called)
	}
}
