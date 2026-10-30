package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenRestySecurityMountRoutesOnlyCanonicalPaths(t *testing.T) {
	security := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Handler", "security")
		writer.WriteHeader(http.StatusNoContent)
	})
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Handler", "next")
		writer.WriteHeader(http.StatusNotFound)
	})
	handler := withOpenRestySecurityRoutes(next, security)

	canonical := []string{
		"/v1/openresty-security/configs/global",
		"/v1/openresty-security/overrides",
		"/v1/openresty-security/overrides/018f22f2-0c3b-7b91-95d4-4ac177175736",
		"/v1/openresty-security/targets",
		"/v1/openresty-security/effective",
		"/v1/openresty-security/actions/download-cc-image",
		"/v1/cc-rule-groups",
	}
	for _, path := range canonical {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusNoContent || response.Header().Get("X-Handler") != "security" {
				t.Fatalf("canonical path %q was not mounted: status=%d handler=%q", path, response.Code, response.Header().Get("X-Handler"))
			}
		})
	}

	neighbors := []string{
		"/v1/openresty-security/configs/global/extra",
		"/v1/openresty-security/overrides/",
		"/v1/openresty-security/overrides/id/extra",
		"/v1/openresty-security/targets-extra",
		"/v1/openresty-security/effective-extra",
		"/v1/openresty-security/actions/download-cc-image/extra",
		"/v1/cc-rule-groups-extra",
	}
	for _, path := range neighbors {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusNotFound || response.Header().Get("X-Handler") != "next" {
				t.Fatalf("neighbor path %q leaked into security handler: status=%d handler=%q", path, response.Code, response.Header().Get("X-Handler"))
			}
		})
	}
}

func TestOpenRestySecurityMountFallsThroughWhenDisabled(t *testing.T) {
	next := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
	})
	response := httptest.NewRecorder()
	withOpenRestySecurityRoutes(next, nil).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/v1/openresty-security/configs/global", nil),
	)
	if response.Code != http.StatusTeapot {
		t.Fatalf("disabled mount status=%d, want %d", response.Code, http.StatusTeapot)
	}
}
