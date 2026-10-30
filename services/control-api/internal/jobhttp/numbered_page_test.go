package jobhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestHandlerNumberedPageAndEmptyKindCatalog(t *testing.T) {
	reader := &fixtureReader{}
	handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		return platformPrincipal(uuid.MustParse("10000000-0000-4000-8000-000000000031")), nil
	}, HandlerConfig{})
	for _, path := range []string{listURL("/v1/admin/jobs") + "&page=1", "/v1/admin/jobs/kinds"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if path == "/v1/admin/jobs/kinds" {
				var kinds []map[string]string
				if err := json.Unmarshal(body["data"], &kinds); err != nil || len(kinds) != 10 {
					t.Fatalf("catalog=%s err=%v", body["data"], err)
				}
				return
			}
			var page map[string]any
			if err := json.Unmarshal(body["page"], &page); err != nil {
				t.Fatal(err)
			}
			if page["total"] != float64(0) || page["number"] != float64(1) || page["consistency"] != "request_snapshot" {
				t.Fatalf("page=%s", body["page"])
			}
		})
	}
}

func TestHandlerKindCatalogAuthenticationScopeAndStrictQueries(t *testing.T) {
	reader := &fixtureReader{}
	handler := fixtureHandler(t, reader, func(request *http.Request) (Principal, error) {
		switch request.Header.Get("X-Test-Principal") {
		case "platform":
			return platformPrincipal(uuid.New()), nil
		case "tenant":
			return tenantPrincipal(uuid.New()), nil
		case "denied":
			principal := tenantPrincipal(uuid.New())
			principal.Permissions = nil
			return principal, nil
		default:
			return Principal{}, errors.New("no session")
		}
	}, HandlerConfig{})
	for _, test := range []struct {
		path, principal string
		status          int
	}{
		{"/v1/admin/jobs/kinds", "", http.StatusUnauthorized},
		{"/v1/jobs/kinds", "", http.StatusUnauthorized},
		{"/v1/admin/jobs/kinds", "platform", http.StatusOK},
		{"/v1/jobs/kinds", "tenant", http.StatusOK},
		{"/v1/jobs/kinds", "denied", http.StatusForbidden},
		{"/v1/jobs/kinds", "platform", http.StatusForbidden},
		{"/v1/admin/jobs/kinds", "tenant", http.StatusForbidden},
		{"/v1/jobs/kinds?tenant_id=" + uuid.NewString(), "tenant", http.StatusBadRequest},
		{"/v1/admin/jobs/kinds?page=1", "platform", http.StatusBadRequest},
	} {
		t.Run(test.path+"/"+test.principal, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Header.Set("X-Test-Principal", test.principal)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || reader.calls != 0 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, reader.calls, response.Body.String())
			}
		})
	}
}
