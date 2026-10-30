package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestIAM12IdentitySessionRoutesAreAbsentWithoutFactory(t *testing.T) {
	api := New(nil, nil, Config{})
	for _, route := range identitySessionMountRoutes() {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled %s %s status=%d, want 404", route.method, route.path, response.Code)
		}
	}
}

func TestIAM12IdentitySessionMountForwardsOnlyExactRoutes(t *testing.T) {
	requestID := uuid.NewString()
	var forwarded []string
	probe := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Request-ID") != requestID {
			t.Fatalf("forwarded request ID=%q, want %q", request.Header.Get("X-Request-ID"), requestID)
		}
		forwarded = append(forwarded, request.Method+" "+request.URL.Path)
		writer.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x12}, 32), IdentitySessionHandlerFactory: func() (http.Handler, error) {
		return probe, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, route := range identitySessionMountRoutes() {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("X-Request-ID", requestID)
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("mounted %s %s status=%d", route.method, route.path, response.Code)
		}
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v1/identity/sessions"},
		{http.MethodGet, "/v1/identity/sessions/"},
		{http.MethodDelete, "/v1/identity/session-families/"},
		{http.MethodGet, "/v1/identity/session-families/11111111-1111-4111-8111-111111111111"},
		{http.MethodDelete, "/v1/identity/session-families/11111111-1111-4111-8111-111111111111/extra"},
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code == http.StatusNoContent {
			t.Fatalf("adjacent %s %s reached identity session handler", route.method, route.path)
		}
	}
	if len(forwarded) != len(identitySessionMountRoutes()) {
		t.Fatalf("forwarded routes=%v", forwarded)
	}
}

func TestIAM12IdentitySessionFactoryFailsClosed(t *testing.T) {
	want := errors.New("identity session dependency unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x12}, 32), IdentitySessionHandlerFactory: func() (http.Handler, error) {
		return nil, want
	}})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("initialization error=%v, want %v", api.InitializationError(), want)
	}
	var typedNil *identitySessionMountHandler
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x12}, 32), IdentitySessionHandlerFactory: func() (http.Handler, error) {
		return typedNil, nil
	}})
	if api.InitializationError() == nil {
		t.Fatal("typed-nil identity session handler was accepted")
	}
}

type identitySessionMountHandler struct{}

func (*identitySessionMountHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func identitySessionMountRoutes() []struct{ method, path string } {
	return []struct{ method, path string }{
		{http.MethodGet, "/v1/identity/sessions"},
		{http.MethodDelete, "/v1/identity/session-families/11111111-1111-4111-8111-111111111111"},
	}
}
