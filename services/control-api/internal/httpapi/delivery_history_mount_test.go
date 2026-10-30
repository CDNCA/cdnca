package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notificationhttp"
)

func TestNotificationDeliveryHistoryAggregateMount(t *testing.T) {
	forwarded := 0
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), NotificationHandlerFactory: func(notificationhttp.AuthenticateFunc) (http.Handler, error) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forwarded++
			if r.URL.Query().Get("user_id") != "123" {
				t.Error("delivery history query was not forwarded")
			}
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}), nil
	}})
	for _, test := range []struct {
		method, path string
		status       int
	}{{"GET", "/v1/admin/notifications/delivery-history?user_id=123", 204},
		{"POST", "/v1/admin/notifications/delivery-history?user_id=123", 405},
		{"GET", "/v1/admin/notifications/delivery-history-extra", 404}} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("%s %s status=%d want=%d", test.method, test.path, response.Code, test.status)
		}
	}
	if forwarded != 2 {
		t.Fatalf("forwarded=%d want=2", forwarded)
	}
}
