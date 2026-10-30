package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type l4LineSwitchMountProbe struct {
	calls         int
	authorization string
	requestID     string
}

func (probe *l4LineSwitchMountProbe) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	probe.calls++
	probe.authorization = request.Header.Get("Authorization")
	probe.requestID = request.Header.Get("X-Request-ID")
	writer.WriteHeader(http.StatusNoContent)
}

func TestL4LineSwitchMountForwardsExactRouteFamily(t *testing.T) {
	probe := &l4LineSwitchMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), L4LineSwitchHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	scopeID := "11111111-1111-4111-8111-111111111111"
	switchID := "22222222-2222-4222-8222-222222222222"
	paths := []string{
		"/v1/tenant-scopes/" + scopeID + "/l4-line-switches",
		"/v1/tenant-scopes/" + scopeID + "/l4-line-switches/current",
		"/v1/tenant-scopes/" + scopeID + "/l4-line-switches/" + switchID,
		"/v1/tenant-scopes/" + scopeID + "/l4-line-switches/" + switchID + "/reconcile",
	}
	for _, path := range paths {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer preserved-session")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("GET %s status = %d, want 204", path, response.Code)
		}
	}
	if probe.calls != len(paths) || probe.authorization != "Bearer preserved-session" || probe.requestID == "" {
		t.Fatalf("mounted probe = %+v", probe)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/"+scopeID+"/l4-line-switches-neighbor", nil))
	if response.Code != http.StatusNotFound || probe.calls != len(paths) {
		t.Fatalf("neighbor status=%d calls=%d", response.Code, probe.calls)
	}
}

func TestL4LineSwitchMountFactoryFailuresBlockInitialization(t *testing.T) {
	want := errors.New("L4 line switch unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), L4LineSwitchHandlerFactory: func() (http.Handler, error) { return nil, want }})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("factory error = %v, want wrapping %v", api.InitializationError(), want)
	}
	var typedNil *l4LineSwitchMountProbe
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), L4LineSwitchHandlerFactory: func() (http.Handler, error) { return typedNil, nil }})
	if err := api.InitializationError(); err == nil || !strings.Contains(err.Error(), "factory returned nil handler") {
		t.Fatalf("typed-nil factory error = %v", err)
	}
}

func TestL4LineSwitchCanonicalContractAggregatesFrozenFragment(t *testing.T) {
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-l4-line-switch.openapi.yaml", []string{
		"/v1/tenant-scopes/{scope_id}/l4-line-switches",
		"/v1/tenant-scopes/{scope_id}/l4-line-switches/current",
		"/v1/tenant-scopes/{scope_id}/l4-line-switches/{switch_id}",
		"/v1/tenant-scopes/{scope_id}/l4-line-switches/{switch_id}/reconcile",
	})
	fragment := string(sharedRuntimeIIReadFile(t, "../../../../api/control-l4-line-switch.openapi.yaml"))
	if strings.Count(fragment, "- bearerAuth: []") != 1 || strings.Contains(fragment, "cdncaApiKey") {
		t.Fatal("L4 line switch contract must use one global Bearer-only security declaration")
	}
}
