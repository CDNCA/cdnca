package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type observabilityLogMountTypedNil struct{}

func (*observabilityLogMountTypedNil) ServeHTTP(http.ResponseWriter, *http.Request) {}

type observabilityLogMountProbe struct {
	mu       sync.Mutex
	requests []string
	headers  []http.Header
}

func (probe *observabilityLogMountProbe) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	probe.mu.Lock()
	probe.requests = append(probe.requests, request.Method+" "+request.URL.Path)
	probe.headers = append(probe.headers, request.Header.Clone())
	probe.mu.Unlock()
	response.WriteHeader(http.StatusNoContent)
}

func (probe *observabilityLogMountProbe) snapshot() ([]string, []http.Header) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return append([]string(nil), probe.requests...), append([]http.Header(nil), probe.headers...)
}

func TestOBS09ObservabilityLogMountIsExactAndFailClosed(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/v1/observability/logs"},
		{method: http.MethodGet, path: "/v1/observability/logs/export"},
		{method: http.MethodPost, path: "/v1/observability/frontend-events"},
	}

	disabled := httpapi.New(nil, nil, httpapi.Config{}).Handler()
	for _, route := range routes {
		response := httptest.NewRecorder()
		disabled.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled %s %s status = %d, want 404", route.method, route.path, response.Code)
		}
	}

	var typedNil *observabilityLogMountTypedNil
	rejected := httpapi.New(nil, nil, httpapi.Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ObservabilityLogHandler: typedNil})
	if rejected.InitializationError() == nil {
		t.Fatal("typed-nil observability log handler was accepted")
	}
	response := httptest.NewRecorder()
	rejected.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, routes[0].path, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("rejected mount status = %d, want 404", response.Code)
	}

	probe := new(observabilityLogMountProbe)
	api := httpapi.New(nil, nil, httpapi.Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ObservabilityLogHandler: probe})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	handler := api.Handler()
	for _, route := range routes {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer preserved-session")
		request.Header.Set("X-Request-ID", "obs09-mount-request")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent || response.Header().Get("X-Request-ID") != "obs09-mount-request" {
			t.Errorf("%s %s status=%d request_id=%q", route.method, route.path, response.Code, response.Header().Get("X-Request-ID"))
		}
	}
	requests, headers := probe.snapshot()
	if len(requests) != len(routes) {
		t.Fatalf("forwarded requests = %#v", requests)
	}
	for index := range headers {
		if headers[index].Get("Authorization") != "Bearer preserved-session" || headers[index].Get("X-Request-ID") != "obs09-mount-request" {
			t.Errorf("forwarded headers[%d] = %#v", index, headers[index])
		}
	}

	for _, request := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/v1/observability/logs"},
		{method: http.MethodGet, path: "/v1/observability/frontend-events"},
		{method: http.MethodGet, path: "/v1/observability/logs/"},
		{method: http.MethodGet, path: "/v1/observability/logs/export/next"},
		{method: http.MethodPost, path: "/v1/observability/frontend-events/extra"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(request.method, request.path, nil))
		if response.Code == http.StatusNoContent {
			t.Errorf("adjacent %s %s reached observability log handler", request.method, request.path)
		}
	}
	after, _ := probe.snapshot()
	if len(after) != len(requests) {
		t.Fatalf("adjacent routes were forwarded: %#v", after[len(requests):])
	}
}

func TestOBS09ObservabilityLogBuilderRejectsMissingAuthority(t *testing.T) {
	key := make([]byte, 32)
	for _, test := range []struct {
		name         string
		pool         *pgxpool.Pool
		identity     *identity.Service
		key          []byte
		trustedCIDRs []string
		maxProxyHops int
	}{
		{name: "database", identity: &identity.Service{}, key: key},
		{name: "identity", pool: &pgxpool.Pool{}, key: key},
		{name: "cursor key", pool: &pgxpool.Pool{}, identity: &identity.Service{}, key: key[:31]},
		{name: "trusted proxy", pool: &pgxpool.Pool{}, identity: &identity.Service{}, key: key, trustedCIDRs: []string{"0.0.0.0/0"}},
		{name: "proxy hops", pool: &pgxpool.Pool{}, identity: &identity.Service{}, key: key, maxProxyHops: 65},
	} {
		t.Run(test.name, func(t *testing.T) {
			if handler, err := buildObservabilityLogHandler(test.pool, test.identity, test.key, test.trustedCIDRs, test.maxProxyHops); err == nil || handler != nil {
				t.Fatalf("buildObservabilityLogHandler() = (%T, %v), want rejection", handler, err)
			}
		})
	}
}
