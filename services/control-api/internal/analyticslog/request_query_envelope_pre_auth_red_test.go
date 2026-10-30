package analyticslog

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuntimeHandlerRejectsMalformedOrDuplicateQueryBeforeDependencies(t *testing.T) {
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer server.Close()

	var authenticationCalls atomic.Int64
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		authenticationCalls.Add(1)
		return Principal{}, errors.New("invalid credentials")
	}, authorizer, time.Second)

	routes := []struct {
		name      string
		path      string
		duplicate string
		singleton string
	}{
		{name: "access", path: "/v1/analytics/logs/access", duplicate: "from=a&from=b", singleton: "from=a"},
		{name: "block_events", path: "/v1/analytics/logs/block-events", duplicate: "from=a&from=b", singleton: "from=a"},
		{name: "blocks_current", path: "/v1/analytics/logs/blocks/current", duplicate: "tenant_id=" + tenantA + "&tenant_id=" + tenantA, singleton: "tenant_id=" + tenantA},
		{name: "blocks_history", path: "/v1/analytics/logs/blocks/history", duplicate: "tenant_id=" + tenantA + "&tenant_id=" + tenantA, singleton: "tenant_id=" + tenantA},
	}

	for _, route := range routes {
		for _, invalid := range []struct {
			name     string
			rawQuery string
		}{
			{name: "malformed_percent", rawQuery: "from=%zz"},
			{name: "duplicate_scalar", rawQuery: route.duplicate},
		} {
			t.Run(route.name+"_"+invalid.name, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, route.path, nil)
				request.URL.RawQuery = invalid.rawQuery
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)

				assertHandlerError(t, response, http.StatusBadRequest, "analytics_logs_invalid_request")
			})
		}
	}

	if authenticationCalls.Load() != 0 || len(authorizer.calls()) != 0 || storageCalls.Load() != 0 {
		t.Fatalf("invalid query reached dependencies: authentication=%d authorization=%d storage=%d",
			authenticationCalls.Load(), len(authorizer.calls()), storageCalls.Load())
	}

	for _, route := range routes {
		t.Run(route.name+"_singleton", func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, route.path, nil)
			request.URL.RawQuery = route.singleton
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assertHandlerError(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
		})
	}

	if authenticationCalls.Load() != int64(len(routes)) || len(authorizer.calls()) != 0 || storageCalls.Load() != 0 {
		t.Fatalf("singleton query dependency calls: authentication=%d authorization=%d storage=%d",
			authenticationCalls.Load(), len(authorizer.calls()), storageCalls.Load())
	}
}
