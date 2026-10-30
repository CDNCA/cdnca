package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolhttp"
)

func TestCacheControlHandlerMountForwardsAuthenticationAndRequestID(t *testing.T) {
	t.Parallel()
	called := false
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CacheControlHandlerFactory: func(authenticate cachecontrolhttp.AuthenticateFunc) (http.Handler, error) {
		if authenticate == nil {
			t.Fatal("cache control authenticator is nil")
		}
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			called = true
			if request.Header.Get("X-Request-ID") != "cache-mount-request" {
				t.Fatalf("request id = %q", request.Header.Get("X-Request-ID"))
			}
			response.WriteHeader(http.StatusNoContent)
		}), nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/cache-operations", nil)
	request.Header.Set("X-Request-ID", "cache-mount-request")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("mounted cache handler = (%d,%v)", response.Code, called)
	}
}

func TestCacheControlHandlerFactoryFailsClosed(t *testing.T) {
	t.Parallel()
	want := errors.New("cache factory failed")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CacheControlHandlerFactory: func(cachecontrolhttp.AuthenticateFunc) (http.Handler, error) {
		return nil, want
	}})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("initialization error = %v, want %v", api.InitializationError(), want)
	}
}
