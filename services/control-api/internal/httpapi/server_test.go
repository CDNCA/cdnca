package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type nodeSchedulerMountProbe struct{ calls int }

func (probe *nodeSchedulerMountProbe) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	probe.calls++
	writer.WriteHeader(http.StatusNoContent)
}

type nodeSchedulerMountTypedNilHandler struct{}

func (*nodeSchedulerMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestNodeSchedulerHandlerFactoryMountsCanonicalRouteFamily(t *testing.T) {
	probe := &nodeSchedulerMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NodeSchedulerHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/node-line-groups",
		"/v1/node-line-groups/11111111-1111-4111-8111-111111111111/decisions",
		"/v1/l2-configs",
		"/v1/l2-configs/11111111-1111-4111-8111-111111111111",
		"/v1/l2-conds",
		"/v1/l2-conds/11111111-1111-4111-8111-111111111111",
		"/v1/l2-nodes?config_id=11111111-1111-4111-8111-111111111111",
		"/v1/l2-nodes/11111111-1111-4111-8111-111111111111",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("GET %s status = %d, want 204", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups-neighbor", nil))
	if response.Code != http.StatusNotFound || probe.calls != 8 {
		t.Fatalf("neighbor route status = %d, calls = %d", response.Code, probe.calls)
	}
}

func TestNodeSchedulerHandlerFactoryFailsClosed(t *testing.T) {
	want := errors.New("node scheduler unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NodeSchedulerHandlerFactory: func() (http.Handler, error) { return nil, want }})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("initialization error = %v, want %v", api.InitializationError(), want)
	}
	for name, factory := range map[string]MountedHandlerFactory{
		"nil": func() (http.Handler, error) { return nil, nil },
		"typed nil": func() (http.Handler, error) {
			var handler *nodeSchedulerMountTypedNilHandler
			return handler, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NodeSchedulerHandlerFactory: factory})
			if api.InitializationError() == nil {
				t.Fatal("nil node scheduler handler did not fail startup")
			}
		})
	}
}

func TestCertificateAssetHandlerFactoryMountsExactRoutePartition(t *testing.T) {
	probe := &nodeSchedulerMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CertificateAssetHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/certificate-assets",
		"/v1/certificate-assets/11111111-1111-4111-8111-111111111111",
		"/v1/sites/11111111-1111-4111-8111-111111111111/certificate-binding",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("GET %s status = %d, want 204", path, response.Code)
		}
	}
	for _, path := range []string{"/v1/certificate-assets-neighbor", "/v1/certificate-asset"} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, response.Code)
		}
	}
	if probe.calls != 3 {
		t.Fatalf("certificate asset probe calls = %d, want 3", probe.calls)
	}

	disabled := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	for _, path := range []string{"/v1/certificate-assets", "/v1/certificate-assets/11111111-1111-4111-8111-111111111111"} {
		response := httptest.NewRecorder()
		disabled.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled GET %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestCertificatePublicationStatusHandlerFactoryMountsExactRoutePartition(t *testing.T) {
	probe := &nodeSchedulerMountProbe{}
	api := New(nil, nil, Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CertificatePublicationStatusHandlerFactory: func() (http.Handler, error) { return probe, nil },
	})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/certificate-publications",
		"/v1/certificate-publications/11111111-1111-4111-8111-111111111111/revisions/1",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("GET %s status = %d, want 204", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/certificate-publications-neighbor", nil))
	if response.Code != http.StatusNotFound || probe.calls != 2 {
		t.Fatalf("neighbor status = %d, calls = %d", response.Code, probe.calls)
	}
}

func TestCertificateAssetHandlerFactoryFailsClosed(t *testing.T) {
	want := errors.New("certificate asset unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CertificateAssetHandlerFactory: func() (http.Handler, error) { return nil, want }})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("initialization error = %v, want %v", api.InitializationError(), want)
	}
	for name, factory := range map[string]MountedHandlerFactory{
		"nil": func() (http.Handler, error) { return nil, nil },
		"typed nil": func() (http.Handler, error) {
			var handler *nodeSchedulerMountTypedNilHandler
			return handler, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CertificateAssetHandlerFactory: factory})
			if api.InitializationError() == nil {
				t.Fatal("nil certificate asset handler did not fail startup")
			}
		})
	}
}
