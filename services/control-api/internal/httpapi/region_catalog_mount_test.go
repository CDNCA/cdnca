package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegionCatalogMountIsExactAndPreservesMethodPathAndQuery(t *testing.T) {
	calls := 0
	wantURL := ""
	wantMethod := ""
	api := &Server{regionCatalogHandler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != wantMethod || request.URL.String() != wantURL {
			t.Fatalf("forwarded method=%s URL=%s, want %s %s", request.Method, request.URL.String(), wantMethod, wantURL)
		}
		response.WriteHeader(http.StatusNoContent)
	})}

	for _, test := range []struct {
		method string
		url    string
	}{
		{http.MethodGet, "/v1/regions?limit=0&search=east"},
		{http.MethodPost, "/v1/regions"},
		{http.MethodPatch, "/v1/regions/7"},
		{http.MethodDelete, "/v1/regions/7"},
	} {
		wantMethod, wantURL = test.method, test.url
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(test.method, test.url, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status=%d", test.method, test.url, response.Code)
		}
	}

	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/regions-extra", nil))
	if response.Code != http.StatusNotFound || calls != 4 {
		t.Fatalf("sibling status=%d calls=%d", response.Code, calls)
	}
}
