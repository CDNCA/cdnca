package analytics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerRejectsInvalidRawQueryEnvelopeBeforeAuthentication(t *testing.T) {
	const validWindow = "from=2099-01-01T00%3A00%3A00Z&to=2099-01-01T02%3A00%3A00Z"
	tests := []struct {
		name     string
		path     string
		rawQuery string
	}{
		{name: "tenant summary malformed percent", path: "/v1/analytics/summary", rawQuery: validWindow + "&site_id=%zz"},
		{name: "admin summary duplicate tenant", path: "/v1/admin/analytics/summary", rawQuery: validWindow + "&tenant_id=" + testTenantID + "&tenant_id=" + testTenantID},
		{name: "tenant trend duplicate site", path: "/v1/analytics/hourly-trend", rawQuery: validWindow + "&site_id=" + testSiteID + "&site_id=" + testSiteID},
		{name: "admin trend malformed percent", path: "/v1/admin/analytics/hourly-trend", rawQuery: validWindow + "&node_id=%zz"},
		{name: "tenant rank duplicate cursor", path: "/v1/analytics/top/url", rawQuery: validWindow + "&cursor=one&cursor=two"},
		{name: "admin rank malformed percent", path: "/v1/admin/analytics/top/domain", rawQuery: validWindow + "&cursor=%zz"},
		{name: "unescaped semicolon", path: "/v1/analytics/summary", rawQuery: validWindow + "&site_id=a;b=c"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingQueryStore{}
			handler, authCalls := handlerWithRejectedAuthentication(t, store)
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.URL.RawQuery = test.rawQuery
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertHandlerError(t, response, http.StatusBadRequest, "analytics_invalid_request")
			if *authCalls != 0 {
				t.Fatalf("authenticate calls = %d, want 0", *authCalls)
			}
			if store.queryCalled {
				t.Fatal("store was called for an invalid raw query envelope")
			}
		})
	}
}

func TestHandlerKeepsSingletonQuerySemanticsAfterAuthentication(t *testing.T) {
	const validWindow = "from=2099-01-01T00%3A00%3A00Z&to=2099-01-01T02%3A00%3A00Z"
	for _, test := range []struct {
		name     string
		rawQuery string
	}{
		{name: "empty raw query"},
		{name: "allowed singleton", rawQuery: validWindow + "&site_id="},
		{name: "unknown singleton", rawQuery: validWindow + "&unknown=value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingQueryStore{}
			handler, authCalls := handlerWithRejectedAuthentication(t, store)
			request := httptest.NewRequest(http.MethodGet, "/v1/analytics/summary", nil)
			request.URL.RawQuery = test.rawQuery
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertHandlerError(t, response, http.StatusUnauthorized, "analytics_authentication_required")
			if *authCalls != 1 {
				t.Fatalf("authenticate calls = %d, want 1", *authCalls)
			}
			if store.queryCalled {
				t.Fatal("store was called after authentication rejection")
			}
		})
	}
}

func TestHandlerPreservesRawQueryEnvelopePrecedence(t *testing.T) {
	const malformedQuery = "from=%zz"
	tests := []struct {
		name       string
		method     string
		path       string
		rawQuery   string
		nilURL     bool
		wantStatus int
		wantCode   string
	}{
		{name: "nil URL", method: http.MethodGet, path: "/v1/analytics/summary", nilURL: true, wantStatus: http.StatusBadRequest, wantCode: "analytics_invalid_request"},
		{name: "raw capacity before route", method: http.MethodGet, path: "/v1/analytics/missing", rawQuery: strings.Repeat("x", maximumHandlerRawQuery+1), wantStatus: http.StatusBadRequest, wantCode: "analytics_invalid_request"},
		{name: "route before envelope", method: http.MethodGet, path: "/v1/analytics/missing", rawQuery: malformedQuery, wantStatus: http.StatusNotFound, wantCode: "analytics_route_not_found"},
		{name: "method before envelope", method: http.MethodPost, path: "/v1/analytics/summary", rawQuery: malformedQuery, wantStatus: http.StatusMethodNotAllowed, wantCode: "analytics_method_not_allowed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingQueryStore{}
			handler, authCalls := handlerWithRejectedAuthentication(t, store)
			request := httptest.NewRequest(test.method, test.path, nil)
			request.URL.RawQuery = test.rawQuery
			if test.nilURL {
				request.URL = nil
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertHandlerError(t, response, test.wantStatus, test.wantCode)
			if *authCalls != 0 {
				t.Fatalf("authenticate calls = %d, want 0", *authCalls)
			}
			if store.queryCalled {
				t.Fatal("store was called before request envelope checks completed")
			}
		})
	}
}

func handlerWithRejectedAuthentication(t *testing.T, store QueryStore) (*Handler, *int) {
	t.Helper()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	authCalls := 0
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
		authCalls++
		return Actor{}, errors.New("authentication rejected")
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return handler, &authCalls
}
