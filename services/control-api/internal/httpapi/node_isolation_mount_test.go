package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type nodeIsolationMountTypedNilHandler struct{}

func (*nodeIsolationMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestNodeIsolationMountForwardsOnlyCanonicalRoutesAndRequestID(t *testing.T) {
	type observedCall struct {
		method, path, nodeID, requestID, authorization string
	}
	var calls []observedCall
	factoryCalls := 0
	api := New(nil, nil, Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		NodeIsolationHandlerFactory: func() (http.Handler, error) {
			factoryCalls++
			return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				calls = append(calls, observedCall{
					method: request.Method, path: request.URL.Path, nodeID: request.PathValue("node_id"),
					requestID: request.Header.Get("X-Request-ID"), authorization: request.Header.Get("Authorization"),
				})
				response.WriteHeader(http.StatusNoContent)
			}), nil
		},
	})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 1 {
		t.Fatalf("node isolation factory calls = %d, want 1", factoryCalls)
	}

	nodeID := "11111111-1111-4111-8111-111111111111"
	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/node-isolations?node_id=" + nodeID},
		{http.MethodPost, "/v1/internal/node-isolation/results/" + nodeID},
	}
	handler := api.Handler()
	for _, route := range routes {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("Authorization", "Bearer preserved-session")
		request.Header.Set("X-Request-ID", "node-isolation-mount")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
		if response.Header().Get("X-Request-ID") != "node-isolation-mount" {
			t.Errorf("%s %s response request ID = %q", route.method, route.path, response.Header().Get("X-Request-ID"))
		}
	}
	if len(calls) != 2 {
		t.Fatalf("forwarded calls = %#v", calls)
	}
	if calls[0].method != http.MethodGet || calls[0].path != "/v1/admin/node-isolations" || calls[0].nodeID != "" ||
		calls[1].method != http.MethodPost || calls[1].path != "/v1/internal/node-isolation/results/"+nodeID || calls[1].nodeID != nodeID {
		t.Fatalf("forwarded routes = %#v", calls)
	}
	for _, call := range calls {
		if call.requestID != "node-isolation-mount" || call.authorization != "Bearer preserved-session" {
			t.Errorf("forwarded headers = %#v", call)
		}
	}

	before := len(calls)
	for _, route := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodPost, "/v1/admin/node-isolations", http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/internal/node-isolation/results/" + nodeID, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/admin/node-isolations/", http.StatusNotFound},
		{http.MethodGet, "/v1/admin/node-isolations-extra", http.StatusNotFound},
		{http.MethodPost, "/v1/internal/node-isolation/results/", http.StatusNotFound},
		{http.MethodPost, "/v1/internal/node-isolation/results/" + nodeID + "/neighbor", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != route.status {
			t.Errorf("non-canonical %s %s status = %d, want %d", route.method, route.path, response.Code, route.status)
		}
	}
	if len(calls) != before {
		t.Fatalf("non-canonical routes reached node isolation handler: %#v", calls[before:])
	}
}

func TestNodeIsolationMountDisabledAndFactoryFailuresStayClosed(t *testing.T) {
	assertClosed := func(t *testing.T, api *Server) {
		t.Helper()
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/v1/admin/node-isolations"},
			{http.MethodPost, "/v1/internal/node-isolation/results/11111111-1111-4111-8111-111111111111"},
		} {
			response := httptest.NewRecorder()
			api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
			if response.Code != http.StatusNotFound {
				t.Errorf("closed %s %s status = %d, want 404", route.method, route.path, response.Code)
			}
		}
	}

	disabled := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	if err := disabled.InitializationError(); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, disabled)

	factoryErr := errors.New("node isolation dependencies unavailable")
	failed := New(nil, nil, Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		NodeIsolationHandlerFactory: func() (http.Handler, error) {
			return nil, factoryErr
		},
	})
	if !errors.Is(failed.InitializationError(), factoryErr) {
		t.Fatalf("factory error = %v, want %v", failed.InitializationError(), factoryErr)
	}
	assertClosed(t, failed)

	var typedNil *nodeIsolationMountTypedNilHandler
	typedNilAPI := New(nil, nil, Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		NodeIsolationHandlerFactory: func() (http.Handler, error) {
			return typedNil, nil
		},
	})
	if typedNilAPI.InitializationError() == nil {
		t.Fatal("typed-nil node isolation handler was accepted")
	}
	assertClosed(t, typedNilAPI)
}

func TestNodeIsolationCanonicalOpenAPIAggregatesFragment(t *testing.T) {
	fragmentBytes, err := os.ReadFile("../../../../api/control-node-isolation.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(fragmentBytes)
	for _, marker := range []string{
		"/v1/admin/node-isolations:",
		"operationId: listNodeIsolationStates",
		"/v1/internal/node-isolation/results/{node_id}:",
		"operationId: recordNodeIsolationSyncResult",
	} {
		if !strings.Contains(fragment, marker) {
			t.Errorf("node isolation fragment omits %q", marker)
		}
	}

	rootBytes, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root := string(rootBytes)
	for _, marker := range []string{
		"/v1/admin/node-isolations:",
		"../../control-node-isolation.openapi.yaml#/paths/~1v1~1admin~1node-isolations",
		"/v1/internal/node-isolation/results/{node_id}:",
		"../../control-node-isolation.openapi.yaml#/paths/~1v1~1internal~1node-isolation~1results~1{node_id}",
	} {
		if !strings.Contains(root, marker) {
			t.Errorf("canonical control OpenAPI omits %q", marker)
		}
	}
}
