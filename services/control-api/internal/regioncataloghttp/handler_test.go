package regioncataloghttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/regioncatalog"
	"github.com/google/uuid"
)

type catalogStub struct {
	request regioncatalog.ListRequest
	page    regioncatalog.Page
	err     error
}

func (stub *catalogStub) List(_ context.Context, _ regioncatalog.Actor, request regioncatalog.ListRequest) (regioncatalog.Page, error) {
	stub.request = request
	return stub.page, stub.err
}

func (stub *catalogStub) Get(context.Context, regioncatalog.Actor, string) (regioncatalog.Region, error) {
	return regioncatalog.Region{}, stub.err
}

func (stub *catalogStub) Create(context.Context, regioncatalog.Actor, regioncatalog.CreateRequest) (regioncatalog.Region, bool, error) {
	return regioncatalog.Region{}, false, stub.err
}

func (stub *catalogStub) Update(context.Context, regioncatalog.Actor, regioncatalog.UpdateRequest) (regioncatalog.Region, bool, error) {
	return regioncatalog.Region{}, false, stub.err
}

func (stub *catalogStub) Delete(context.Context, regioncatalog.Actor, regioncatalog.DeleteRequest) (bool, error) {
	return false, stub.err
}

func regionFixture(id, name string) regioncatalog.Region {
	created := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	return regioncatalog.Region{
		ID: id, Name: name, Code: "r" + id, L2CheckPort: 80, Sort: 100, Revision: 1,
		CreatedAt: created, UpdatedAt: created,
	}
}

func platformSession(permissions ...string) identity.AuthenticatedSession {
	return identity.AuthenticatedSession{
		SessionID: uuid.New(),
		Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: permissions,
		},
	}
}

func TestHandlerListsPlatformRegionsWithoutTenantInput(t *testing.T) {
	stub := &catalogStub{page: regioncatalog.Page{
		Count: 2,
		Data:  []regioncatalog.Region{regionFixture("1", "默认"), regionFixture("2", "华东")},
	}}
	handler, err := NewHandler(stub, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return platformSession(regioncatalog.PermissionRead), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, Route+"?limit=0&search=%E5%8D%8E", nil)
	request.Header.Set("Authorization", "Bearer live-session")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body.String())
	}
	if stub.request.Limit != 0 || stub.request.Search != "华" {
		t.Fatalf("request=%+v", stub.request)
	}
	if got := response.Body.String(); !strings.Contains(got, `"count":2`) ||
		!strings.Contains(got, `"id":"1","name":"默认","code":"r1","country_code":"","province_code":"","description":"","l2_check_port":80,"sort":100,"revision":1`) ||
		!strings.Contains(got, `"id":"2","name":"华东"`) {
		t.Fatalf("body=%s", got)
	}
}

func TestHandlerPreservesTotalCountForLimitedPages(t *testing.T) {
	stub := &catalogStub{page: regioncatalog.Page{
		Count: 3,
		Data:  []regioncatalog.Region{regionFixture("2", "华东")},
	}}
	handler, err := NewHandler(stub, func(context.Context, string) (identity.AuthenticatedSession, error) {
		return platformSession(regioncatalog.PermissionRead), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, Route+"?limit=1", nil)
	request.Header.Set("Authorization", "Bearer live-session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || stub.request.Limit != 1 ||
		!strings.Contains(response.Body.String(), `"count":3`) ||
		!strings.Contains(response.Body.String(), `"id":"2","name":"华东"`) {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, stub.request, response.Body.String())
	}
}

func TestHandlerRejectsTenantScopeAndMissingRegionPermission(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		session identity.AuthenticatedSession
		status  int
		code    string
	}{
		{name: "tenant query", query: "?limit=0&tenant_id=7", session: platformSession(regioncatalog.PermissionRead), status: 400, code: "regions_validation_error"},
		{name: "duplicate limit", query: "?limit=0&limit=1", session: platformSession(regioncatalog.PermissionRead), status: 400, code: "regions_validation_error"},
		{name: "invalid limit", query: "?limit=-1", session: platformSession(regioncatalog.PermissionRead), status: 400, code: "regions_validation_error"},
		{name: "tenant principal", query: "?limit=0", session: func() identity.AuthenticatedSession {
			value := platformSession(regioncatalog.PermissionRead)
			value.Principal.ScopeKind = "tenant"
			tenant := uuid.New()
			value.Principal.TenantID = &tenant
			return value
		}(), status: 403, code: "regions_permission_denied"},
		{name: "missing permission", query: "?limit=0", session: platformSession("system_configuration.read"), status: 403, code: "regions_permission_denied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(&catalogStub{}, func(context.Context, string) (identity.AuthenticatedSession, error) {
				return test.session, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, Route+test.query, nil)
			request.Header.Set("Authorization", "Bearer live-session")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !containsErrorCode(response.Body.String(), test.code) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandlerRejectsUnauthenticatedAndMapsUnavailable(t *testing.T) {
	for _, test := range []struct {
		name   string
		auth   AuthenticateFunc
		store  *catalogStub
		status int
		code   string
	}{
		{name: "missing bearer", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{}, nil
		}, store: &catalogStub{}, status: 401, code: "regions_unauthenticated"},
		{name: "invalid bearer", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return identity.AuthenticatedSession{}, errors.New("invalid")
		}, store: &catalogStub{}, status: 401, code: "regions_unauthenticated"},
		{name: "unavailable", auth: func(context.Context, string) (identity.AuthenticatedSession, error) {
			return platformSession(regioncatalog.PermissionRead), nil
		}, store: &catalogStub{err: regioncatalog.ErrUnavailable}, status: 503, code: "regions_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(test.store, test.auth)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, Route+"?limit=0", nil)
			if test.name != "missing bearer" {
				request.Header.Set("Authorization", "Bearer live-session")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !containsErrorCode(response.Body.String(), test.code) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func containsErrorCode(body, code string) bool {
	return strings.Contains(body, code)
}
