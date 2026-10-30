package httpapi

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestErrorPageMountOwnsOnlyCanonicalPathsAndPreservesCredentials(t *testing.T) {
	assetID := uuid.NewString()
	ruleID := uuid.NewString()
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/error-pages/assets/initiate"},
		{http.MethodGet, "/v1/error-pages/assets"},
		{http.MethodGet, "/v1/error-pages/assets/" + assetID},
		{http.MethodDelete, "/v1/error-pages/assets/" + assetID},
		{http.MethodPut, "/v1/error-pages/assets/" + assetID + "/content"},
		{http.MethodPost, "/v1/error-pages/assets/" + assetID + "/finalize"},
		{http.MethodGet, "/v1/error-pages/rules"},
		{http.MethodPost, "/v1/error-pages/rules"},
		{http.MethodGet, "/v1/error-pages/rules/" + ruleID},
		{http.MethodPatch, "/v1/error-pages/rules/" + ruleID},
		{http.MethodDelete, "/v1/error-pages/rules/" + ruleID},
		{http.MethodPost, "/v1/error-pages/rules/" + ruleID + "/enable"},
		{http.MethodPost, "/v1/error-pages/rules/" + ruleID + "/disable"},
		{http.MethodGet, "/v1/error-pages/slots"},
		{http.MethodGet, "/v1/error-pages/slots/blacklist"},
		{http.MethodPut, "/v1/error-pages/slots/blacklist"},
		{http.MethodDelete, "/v1/error-pages/slots/blacklist"},
		{http.MethodGet, "/v1/error-pages/scope-overrides"},
		{http.MethodPost, "/v1/error-pages/scope-overrides"},
		{http.MethodGet, "/v1/error-pages/scope-overrides/3"},
		{http.MethodPatch, "/v1/error-pages/scope-overrides/3"},
		{http.MethodDelete, "/v1/error-pages/scope-overrides/3"},
		{http.MethodGet, "/v1/error-pages/publication-snapshot"},
	}
	observed := 0
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observed++
		if got := request.Header.Values("Authorization"); !slices.Equal(got, []string{"Bearer session-one", "Bearer session-two"}) {
			t.Fatalf("Authorization changed at mount: %#v", got)
		}
		if got := request.Header.Values("X-Request-ID"); !slices.Equal(got, []string{"request-one", "request-two"}) {
			t.Fatalf("X-Request-ID changed at mount: %#v", got)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	server := (&Server{errorPageHandler: handler}).Handler()
	for _, route := range routes {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Add("Authorization", "Bearer session-one")
		request.Header.Add("Authorization", "Bearer session-two")
		request.Header.Add("X-Request-ID", "request-one")
		request.Header.Add("X-Request-ID", "request-two")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/error-pages",
		"/v1/error-pages/",
		"/v1/error-pages-neighbor/assets",
		"/v1/error-pages/assets/" + assetID + "/content/extra",
		"/v1/error-pages/rules/" + ruleID + "/enable/extra",
		"/v1/error-pages/slots/blacklist/extra",
		"/v1/error-pages/scope-overrides/3/extra",
	} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("neighbor path %s status = %d, want 404", path, response.Code)
		}
	}
	if observed != len(routes) {
		t.Fatalf("mounted handler calls = %d, want %d", observed, len(routes))
	}
}

func TestErrorPageCanonicalContractAggregatesFrozenFragment(t *testing.T) {
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-error-pages.openapi.yaml", []string{
		"/v1/error-pages/assets/initiate",
		"/v1/error-pages/assets",
		"/v1/error-pages/assets/{asset_id}",
		"/v1/error-pages/assets/{asset_id}/content",
		"/v1/error-pages/assets/{asset_id}/finalize",
		"/v1/error-pages/rules",
		"/v1/error-pages/rules/{rule_id}",
		"/v1/error-pages/rules/{rule_id}/enable",
		"/v1/error-pages/rules/{rule_id}/disable",
		"/v1/error-pages/slots",
		"/v1/error-pages/slots/{slot_key}",
		"/v1/error-pages/scope-overrides",
		"/v1/error-pages/scope-overrides/{override_display_id}",
		"/v1/error-pages/publication-snapshot",
	})
	fragment := string(sharedRuntimeIIReadFile(t, "../../../../api/control-error-pages.openapi.yaml"))
	if !strings.Contains(fragment, "security:\n  - bearerAuth: []\n  - cdncaApiKey: []") {
		t.Fatal("error page fragment does not preserve Bearer and CdncaKey security")
	}
	sharedRuntimeIIRequireUniqueOperationIDs(t, []string{
		"initiateErrorPageAsset", "listErrorPageAssets", "getErrorPageAsset", "deleteErrorPageAsset",
		"uploadErrorPageAssetContent", "finalizeErrorPageAsset", "listErrorPageRules", "createErrorPageRule",
		"getErrorPageRule", "updateErrorPageRule", "deleteErrorPageRule", "enableErrorPageRule",
		"disableErrorPageRule", "listErrorPageSlots", "getErrorPageSlot", "bindErrorPageSlot",
		"unbindErrorPageSlot", "listErrorPageScopeOverrides", "createErrorPageScopeOverride",
		"getErrorPageScopeOverride", "updateErrorPageScopeOverride", "deleteErrorPageScopeOverride",
		"getErrorPagePublicationSnapshot",
	})
}
