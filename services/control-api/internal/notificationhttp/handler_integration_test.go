package notificationhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
)

func TestHandlerRequiresARealSessionEnvelope(t *testing.T) {
	handler, err := New(&stubService{}, func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/notifications/channels", nil))
	if response.Code != http.StatusUnauthorized || response.Body.String() == identity.ErrInvalidSession.Error() {
		t.Fatalf("unauthenticated response status=%d body=%q", response.Code, response.Body.String())
	}
	_ = notificationcontrol.EventTypeAnnouncementPublished
}
