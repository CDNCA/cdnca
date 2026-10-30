package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

type ccCoordinationMountProbe struct {
	calls []struct{ method, path, stateID, requestID string }
}

func (probe *ccCoordinationMountProbe) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	probe.calls = append(probe.calls, struct{ method, path, stateID, requestID string }{
		method: request.Method, path: request.URL.Path, stateID: request.PathValue("state_id"),
		requestID: request.Header.Get("X-Request-ID"),
	})
	response.WriteHeader(http.StatusNoContent)
}

type ccCoordinationMountTypedNil struct{}

func (*ccCoordinationMountTypedNil) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestCCCoordinationMountForwardsOnlyFourCanonicalRoutes(t *testing.T) {
	probe := &ccCoordinationMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CCCoordinationHandler: probe})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	stateID := "11111111-1111-4111-8111-111111111111"
	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/analytics/logs/cc-coordination"},
		{http.MethodGet, "/v1/analytics/logs/cc-coordination"},
		{http.MethodPost, "/v1/admin/analytics/logs/cc-coordination/" + stateID + "/release"},
		{http.MethodPost, "/v1/analytics/logs/cc-coordination/" + stateID + "/release"},
	}
	for _, route := range routes {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("X-Request-ID", "cc-coordination-mount")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status=%d, want 204", route.method, route.path, response.Code)
		}
	}
	if len(probe.calls) != 4 {
		t.Fatalf("forwarded calls=%d, want 4", len(probe.calls))
	}
	for index, call := range probe.calls {
		if call.method != routes[index].method || call.path != routes[index].path || call.requestID != "cc-coordination-mount" {
			t.Errorf("forwarded call %d=%#v", index, call)
		}
		if index >= 2 && call.stateID != stateID {
			t.Errorf("release state_id=%q, want %q", call.stateID, stateID)
		}
	}

	before := len(probe.calls)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v1/analytics/logs/cc-coordination"},
		{http.MethodGet, "/v1/analytics/logs/cc-coordination/" + stateID + "/release"},
		{http.MethodGet, "/v1/analytics/logs/cc-coordination/"},
		{http.MethodPost, "/v1/analytics/logs/cc-coordination/" + stateID + "/release/neighbor"},
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		want := http.StatusNotFound
		if route.method == http.MethodPost && route.path == "/v1/analytics/logs/cc-coordination" ||
			route.method == http.MethodGet && route.path == "/v1/analytics/logs/cc-coordination/"+stateID+"/release" {
			want = http.StatusMethodNotAllowed
		}
		if response.Code != want {
			t.Errorf("non-canonical %s %s status=%d, want %d", route.method, route.path, response.Code, want)
		}
	}
	if len(probe.calls) != before {
		t.Fatalf("non-canonical routes reached handler: %#v", probe.calls[before:])
	}
}

func TestCCCoordinationMountDisabledAndTypedNilFailClosed(t *testing.T) {
	path := "/v1/analytics/logs/cc-coordination"
	response := httptest.NewRecorder()
	New(nil, nil, Config{}).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled route status=%d, want 404", response.Code)
	}

	var typedNil *ccCoordinationMountTypedNil
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CCCoordinationHandler: typedNil})
	if api.InitializationError() == nil {
		t.Fatal("typed-nil CC coordination handler did not fail startup")
	}
	response = httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("typed-nil handler exposed route: status=%d", response.Code)
	}
}
