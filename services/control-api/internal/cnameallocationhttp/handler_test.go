package cnameallocationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type readerStub struct {
	listScope     uuid.UUID
	getScope      uuid.UUID
	diagnoseScope uuid.UUID
	list          []AllocationView
	get           AllocationView
	diagnosis     DiagnosisView
	err           error
	panicRead     bool
}

func (stub *readerStub) List(_ context.Context, scopeID uuid.UUID, _ ListQuery) ([]AllocationView, error) {
	stub.listScope = scopeID
	if stub.panicRead {
		panic("reader panic")
	}
	return stub.list, stub.err
}

func (stub *readerStub) Get(_ context.Context, scopeID, _ uuid.UUID) (AllocationView, error) {
	stub.getScope = scopeID
	return stub.get, stub.err
}

func (stub *readerStub) Diagnose(_ context.Context, scopeID uuid.UUID, _ DiagnoseQuery) (DiagnosisView, error) {
	stub.diagnoseScope = scopeID
	return stub.diagnosis, stub.err
}

func TestHandlerTenantAndAdminScopesAreAuthoritative(t *testing.T) {
	tenantScope, adminScope := uuid.New(), uuid.New()
	allocationID, siteID := uuid.New(), uuid.New()
	stub := &readerStub{
		list:      []AllocationView{{ID: allocationID, Mode: "site", OwnerID: siteID, State: "done"}},
		get:       AllocationView{ID: allocationID, Mode: "site", OwnerID: siteID, State: "done"},
		diagnosis: DiagnosisView{SiteID: siteID, Ready: true, ReasonCodes: []string{"ready"}},
	}
	handler := testHandler(t, stub, tenantScope, adminScope)

	assertStatus(t, handler, http.MethodGet, "/v1/cname-allocations?limit=20", "tenant", http.StatusOK)
	if stub.listScope != tenantScope {
		t.Fatalf("tenant list scope=%s want=%s", stub.listScope, tenantScope)
	}
	assertStatus(t, handler, http.MethodGet, "/v1/cname-allocations/"+allocationID.String(), "tenant", http.StatusOK)
	if stub.getScope != tenantScope {
		t.Fatalf("tenant get scope=%s want=%s", stub.getScope, tenantScope)
	}
	assertStatus(t, handler, http.MethodGet, "/v1/cname-allocations/diagnose?site_id="+siteID.String(), "tenant", http.StatusOK)
	if stub.diagnoseScope != tenantScope {
		t.Fatalf("tenant diagnose scope=%s want=%s", stub.diagnoseScope, tenantScope)
	}

	adminQuery := "?scope_id=" + adminScope.String()
	assertStatus(t, handler, http.MethodGet, "/v1/admin/cname-allocations"+adminQuery, "admin", http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/v1/admin/cname-allocations/"+allocationID.String()+adminQuery, "admin", http.StatusOK)
	assertStatus(t, handler, http.MethodGet, "/v1/admin/cname-allocations/diagnose"+adminQuery+"&site_id="+siteID.String(), "admin", http.StatusOK)
	if stub.listScope != adminScope || stub.getScope != adminScope || stub.diagnoseScope != adminScope {
		t.Fatalf("admin scopes list=%s get=%s diagnose=%s want=%s", stub.listScope, stub.getScope, stub.diagnoseScope, adminScope)
	}
}

func TestHandlerFailClosedAuthenticationQueriesAndMethods(t *testing.T) {
	tenantScope, targetScope := uuid.New(), uuid.New()
	allocationID, siteID := uuid.New(), uuid.New()
	stub := &readerStub{}
	handler := testHandler(t, stub, tenantScope, targetScope)

	tests := []struct {
		method, path, token string
		status              int
	}{
		{http.MethodGet, "/v1/cname-allocations", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/cname-allocations", "denied", http.StatusForbidden},
		{http.MethodGet, "/v1/cname-allocations?scope_id=" + targetScope.String(), "tenant", http.StatusBadRequest},
		{http.MethodGet, "/v1/admin/cname-allocations", "admin", http.StatusBadRequest},
		{http.MethodGet, "/v1/admin/cname-allocations?scope_id=" + strings.ToUpper(targetScope.String()), "admin", http.StatusBadRequest},
		{http.MethodGet, "/v1/admin/cname-allocations?scope_id=" + targetScope.String(), "tenant", http.StatusForbidden},
		{http.MethodGet, "/v1/cname-allocations/" + strings.ToUpper(allocationID.String()), "tenant", http.StatusBadRequest},
		{http.MethodGet, "/v1/cname-allocations/diagnose?site_id=" + strings.ToUpper(siteID.String()), "tenant", http.StatusBadRequest},
		{http.MethodGet, "/v1/cname-allocations?limit=01", "tenant", http.StatusBadRequest},
		{http.MethodGet, "/v1/cname-allocations?unknown=x", "tenant", http.StatusBadRequest},
		{http.MethodPost, "/v1/cname-allocations", "tenant", http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		response := serve(handler, test.method, test.path, test.token)
		if response.Code != test.status {
			t.Errorf("%s %s token=%q status=%d want=%d body=%s", test.method, test.path, test.token, response.Code, test.status, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Request-ID") == "" {
			t.Errorf("%s %s security headers=%v", test.method, test.path, response.Header())
		}
		if test.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != http.MethodGet {
			t.Errorf("method Allow=%q want GET", response.Header().Get("Allow"))
		}
	}
}

func TestHandlerErrorsPaginationRedactionAndPanicBoundary(t *testing.T) {
	scopeID, allocationID := uuid.New(), uuid.New()
	now := time.Date(2026, 8, 7, 1, 2, 3, 0, time.UTC)
	stub := &readerStub{list: []AllocationView{
		{ID: allocationID, Mode: "site", OwnerID: uuid.New(), ProviderID: uuid.New(), ZoneID: uuid.New(), Domain: "example.test", Hostname: "x.example.test", State: "done", CurrentRevision: 2, LKGRevision: 2, CreatedAt: now, UpdatedAt: now},
		{ID: uuid.New(), Mode: "site", OwnerID: uuid.New(), State: "pending"},
	}}
	handler := testHandler(t, stub, scopeID, uuid.New())
	response := serve(handler, http.MethodGet, "/v1/cname-allocations?limit=1", "tenant")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"next_cursor"`) {
		t.Fatalf("page status=%d body=%s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"hmac_key", "request_digest", "idempotency", "credential", "secret"} {
		if strings.Contains(strings.ToLower(response.Body.String()), forbidden) {
			t.Errorf("response exposed %q: %s", forbidden, response.Body.String())
		}
	}
	var page AllocationPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Items) != 1 || page.NextCursor != allocationID.String() {
		t.Fatalf("page=%+v err=%v", page, err)
	}

	for _, subject := range []struct {
		err    error
		status int
	}{
		{ErrNotFound, http.StatusNotFound},
		{ErrInvalidRequest, http.StatusBadRequest},
		{context.DeadlineExceeded, http.StatusRequestTimeout},
		{errors.New("database offline"), http.StatusServiceUnavailable},
	} {
		stub.err = subject.err
		response = serve(handler, http.MethodGet, "/v1/cname-allocations/"+allocationID.String(), "tenant")
		if response.Code != subject.status {
			t.Errorf("error=%v status=%d want=%d body=%s", subject.err, response.Code, subject.status, response.Body.String())
		}
	}

	stub.err, stub.panicRead = nil, true
	response = serve(handler, http.MethodGet, "/v1/cname-allocations", "tenant")
	if response.Code != http.StatusInternalServerError || response.Body.Len() != 0 {
		t.Fatalf("panic response status=%d body=%q", response.Code, response.Body.String())
	}
}

func testHandler(t *testing.T, reader Reader, tenantScope, adminTarget uuid.UUID) http.Handler {
	t.Helper()
	tenantID := uuid.New()
	authenticate := func(request *http.Request) (identity.Principal, error) {
		switch request.Header.Get("Authorization") {
		case "Bearer tenant":
			return identity.Principal{UserID: uuid.New(), ScopeID: tenantScope, ScopeKind: "tenant", TenantID: &tenantID, Permissions: []string{"dns.read"}}, nil
		case "Bearer admin":
			return identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"platform.admin"}}, nil
		case "Bearer denied":
			return identity.Principal{UserID: uuid.New(), ScopeID: tenantScope, ScopeKind: "tenant", TenantID: &tenantID}, nil
		default:
			return identity.Principal{}, identity.ErrInvalidSession
		}
	}
	handler, err := NewHandler(reader, authenticate, HandlerConfig{QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = adminTarget
	return handler
}

func serve(handler http.Handler, method, path, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("X-Request-ID", "cname-query-test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertStatus(t *testing.T, handler http.Handler, method, path, token string, status int) {
	t.Helper()
	response := serve(handler, method, path, token)
	if response.Code != status {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, response.Code, status, response.Body.String())
	}
}
