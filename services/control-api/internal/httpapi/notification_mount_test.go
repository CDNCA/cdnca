package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notificationhttp"
)

func TestNotificationRoutesMountThroughIndependentFactory(t *testing.T) {
	forwarded := 0
	unsupported := map[string]string{
		http.MethodPost + " /v1/admin/notifications/channels":                                                   "GET, PUT",
		http.MethodPost + " /v1/admin/notifications/policy":                                                     "GET, PUT",
		http.MethodDelete + " /v1/admin/notifications/templates":                                                "GET",
		http.MethodGet + " /v1/admin/notifications/templates/announcement_published/versions/1/email":           "PUT",
		http.MethodPost + " /v1/admin/notifications/deliveries":                                                 "GET",
		http.MethodDelete + " /v1/admin/notifications/deliveries/11111111-1111-4111-8111-111111111111/attempts": "GET",
		http.MethodPost + " /v1/admin/notifications/messages":                                                   "GET",
		http.MethodDelete + " /v1/account/notification-subscriptions/announcement.published":                    "GET, PUT",
	}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NotificationHandlerFactory: func(notificationhttp.AuthenticateFunc) (http.Handler, error) {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			forwarded++
			if strings.Contains(request.URL.Path, "/deliveries/") && request.PathValue("outbox_id") == "" {
				t.Error("notification delivery outbox path value was not preserved")
			}
			if allow, exists := unsupported[request.Method+" "+request.URL.Path]; exists {
				response.Header().Set("Allow", allow)
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(http.StatusMethodNotAllowed)
				_ = json.NewEncoder(response).Encode(map[string]any{"error": map[string]string{"code": "method_not_allowed"}})
				return
			}
			response.WriteHeader(http.StatusNoContent)
		}), nil
	}})
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/notifications/channels"},
		{http.MethodPut, "/v1/admin/notifications/channels"},
		{http.MethodGet, "/v1/admin/notifications/policy"},
		{http.MethodPut, "/v1/admin/notifications/policy"},
		{http.MethodGet, "/v1/admin/notifications/templates"},
		{http.MethodPut, "/v1/admin/notifications/templates/announcement_published/versions/1/email"},
		{http.MethodGet, "/v1/admin/notifications/deliveries"},
		{http.MethodGet, "/v1/admin/notifications/deliveries/11111111-1111-4111-8111-111111111111/attempts"},
		{http.MethodGet, "/v1/admin/notifications/messages"},
		{http.MethodGet, "/v1/account/notification-subscriptions/announcement.published"},
		{http.MethodPut, "/v1/account/notification-subscriptions/announcement.published"},
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status=%d", route.method, route.path, response.Code)
		}
	}
	if forwarded != 11 {
		t.Fatalf("forwarded=%d", forwarded)
	}
	for route, allow := range unsupported {
		method, path := route[:strings.IndexByte(route, ' ')], route[strings.IndexByte(route, ' ')+1:]
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Content-Type") != "application/json" ||
			response.Header().Get("Allow") != allow || !strings.Contains(response.Body.String(), `"code":"method_not_allowed"`) {
			t.Fatalf("%s response status=%d allow=%q content-type=%q body=%q", route, response.Code,
				response.Header().Get("Allow"), response.Header().Get("Content-Type"), response.Body.String())
		}
	}
	if forwarded != 19 {
		t.Fatalf("forwarded with unsupported methods=%d", forwarded)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/notifications/templates-extra", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("neighbor status=%d", response.Code)
	}
}
