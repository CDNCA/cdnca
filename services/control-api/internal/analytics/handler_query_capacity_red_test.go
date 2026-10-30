package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerEnforcesAggregateRawQueryCapacityBeforeAuthentication(t *testing.T) {
	const queryCapacity = 16 << 10

	tests := []struct {
		name          string
		rawQuery      string
		nilURL        bool
		wantAuthCalls int
	}{
		{name: "exact capacity reaches validation", rawQuery: handlerRawQueryOfSize(t, queryCapacity), wantAuthCalls: 1},
		{name: "capacity plus one is rejected", rawQuery: handlerRawQueryOfSize(t, queryCapacity+1)},
		{name: "nil URL is rejected", nilURL: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingQueryStore{}
			service, err := NewService(store)
			if err != nil {
				t.Fatal(err)
			}
			authCalls := 0
			handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
				authCalls++
				return Actor{
					ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
				}, nil
			}, HandlerConfig{})
			if err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodGet, "/v1/analytics/summary", nil)
			request.URL.RawQuery = test.rawQuery
			if test.nilURL {
				request.URL = nil
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assertHandlerError(t, response, http.StatusBadRequest, "analytics_invalid_request")
			if authCalls != test.wantAuthCalls {
				t.Fatalf("authenticate calls = %d, want %d", authCalls, test.wantAuthCalls)
			}
			if store.queryCalled {
				t.Fatal("store was called for a rejected query")
			}
		})
	}
}

func handlerRawQueryOfSize(t *testing.T, size int) string {
	t.Helper()
	const prefix = "from=2099-01-01T00%3A00%3A00Z&to=2099-01-01T02%3A00%3A00Z&site_id="
	if size < len(prefix) {
		t.Fatalf("query size %d is smaller than prefix %d", size, len(prefix))
	}
	return prefix + strings.Repeat("a", size-len(prefix))
}
