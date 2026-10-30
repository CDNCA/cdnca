package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

type systemConfigurationMountProbe struct {
	calls     int
	requestID string
	requests  []string
}

func (probe *systemConfigurationMountProbe) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	probe.calls++
	probe.requestID = request.Header.Get("X-Request-ID")
	probe.requests = append(probe.requests, request.Method+" "+request.URL.Path)
	writer.WriteHeader(http.StatusNoContent)
}

func TestSystemConfigurationMountForwardsCategoryAndRevisionRoutesWithoutRewritingHeaders(t *testing.T) {
	probe := &systemConfigurationMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), SystemConfigurationHandlerFactory: func() (http.Handler, error) {
		return probe, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}

	wantRequests := []string{
		"PUT /v1/admin/system-configuration/categories/nginx",
		"POST /v1/admin/system-configuration/revisions/7/preflight",
		"POST /v1/admin/system-configuration/revisions/7/activate",
		"GET /v1/admin/system-configuration/revisions/7/publications",
	}
	for _, requestLine := range wantRequests {
		method, path, _ := strings.Cut(requestLine, " ")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if response.Code != http.StatusNoContent || probe.requestID != "" {
			t.Fatalf("mounted %s response=(status=%d request_id=%q)", requestLine, response.Code, probe.requestID)
		}
	}
	if probe.calls != len(wantRequests) || !slices.Equal(probe.requests, wantRequests) {
		t.Fatalf("mounted requests=(calls=%d requests=%q), want %q", probe.calls, probe.requests, wantRequests)
	}

	unrelated := httptest.NewRecorder()
	api.Handler().ServeHTTP(unrelated, httptest.NewRequest(http.MethodGet,
		"/v1/admin/system-configuration/private", nil))
	if unrelated.Code != http.StatusNotFound || probe.calls != len(wantRequests) {
		t.Fatalf("unrelated response=(status=%d calls=%d)", unrelated.Code, probe.calls)
	}
}

func TestSystemConfigurationMountFactoryFailuresBlockInitialization(t *testing.T) {
	want := errors.New("system configuration unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), SystemConfigurationHandlerFactory: func() (http.Handler, error) {
		return nil, want
	}})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("factory error = %v, want wrapping %v", api.InitializationError(), want)
	}

	var typedNil *systemConfigurationMountProbe
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), SystemConfigurationHandlerFactory: func() (http.Handler, error) {
		return typedNil, nil
	}})
	if err := api.InitializationError(); err == nil || !strings.Contains(err.Error(), "factory returned nil handler") {
		t.Fatalf("typed-nil factory error = %v", err)
	}
}
