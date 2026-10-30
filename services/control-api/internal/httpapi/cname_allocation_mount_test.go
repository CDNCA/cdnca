package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocationhttp"
)

func TestCNAMEAllocationQueryRoutesAreAbsentWhenDisabled(t *testing.T) {
	for _, path := range []string{"/v1/cname-allocations", "/v1/admin/cname-allocations", "/v1/cname-allocations/diagnose"} {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled route %s status=%d want=404", path, response.Code)
		}
	}
}

func TestCNAMEAllocationQueryMountForwardsOnlyFrozenRoutes(t *testing.T) {
	var paths []string
	probe := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.Method+" "+request.URL.Path)
		if request.Header.Get("X-Request-ID") != "cname-mount-test" {
			t.Errorf("forwarded request id=%q", request.Header.Get("X-Request-ID"))
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CNAMEAllocationHandlerFactory: func(cnameallocationhttp.AuthenticateFunc) (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/cname-allocations", "/v1/cname-allocations/example", "/v1/cname-allocations/diagnose",
		"/v1/admin/cname-allocations", "/v1/admin/cname-allocations/example", "/v1/admin/cname-allocations/diagnose",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("X-Request-ID", "cname-mount-test")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("route %s status=%d want=204", path, response.Code)
		}
	}
	before := len(paths)
	for _, path := range []string{"/v1/cname-allocation", "/v1/cname-allocations-extra", "/v1/admin/cname-allocation"} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusNoContent {
			t.Errorf("adjacent route %s reached CNAME handler", path)
		}
	}
	if len(paths) != before {
		t.Fatalf("adjacent routes forwarded: %#v", paths[before:])
	}
}

func TestCNAMEAllocationQueryMountFailsClosed(t *testing.T) {
	factoryErr := errors.New("CNAME allocation reader unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CNAMEAllocationHandlerFactory: func(cnameallocationhttp.AuthenticateFunc) (http.Handler, error) { return nil, factoryErr }})
	if !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("initialization error=%v want=%v", api.InitializationError(), factoryErr)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/cname-allocations", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("failed mount exposed route: status=%d", response.Code)
	}
}
