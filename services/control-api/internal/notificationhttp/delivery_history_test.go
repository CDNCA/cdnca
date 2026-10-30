package notificationhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
)

type historyStubService struct {
	*stubService
	query notificationcontrol.DeliveryHistoryQuery
	err   error
}

func (s *historyStubService) ListDeliveryHistory(_ context.Context, _ notificationcontrol.Actor, query notificationcontrol.DeliveryHistoryQuery) (notificationcontrol.DeliveryHistoryPage, error) {
	s.query = query
	if query.Invalid {
		return notificationcontrol.DeliveryHistoryPage{}, notificationcontrol.ErrInvalidInput
	}
	return notificationcontrol.DeliveryHistoryPage{Schema: "cdnca.notification-delivery-history/v1", Items: []notificationcontrol.DeliveryHistoryFact{}}, s.err
}

func TestDeliveryHistoryHTTPQueryErrorsAndMethods(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &historyStubService{stubService: &stubService{}}
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	path := "/v1/admin/notifications/delivery-history?scope_id=" + id + "&user_id=123&message_id=" + id +
		"&channel=email&state=retry_wait&result=failure&event_type=announcement.published&from=2026-09-28T00:00:00Z&to=2026-09-28T01:00:00Z&limit=30&cursor=" + id + ":2"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"schema":"cdnca.notification-delivery-history/v1"`) ||
		!strings.Contains(response.Body.String(), `"total_count":0`) || strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	if service.query != (notificationcontrol.DeliveryHistoryQuery{ScopeID: id, UserID: "123", MessageID: id,
		Channel: "email", State: "retry_wait", Result: "failure", EventType: "announcement.published",
		From: "2026-09-28T00:00:00Z", To: "2026-09-28T01:00:00Z", Limit: "30", Cursor: id + ":2"}) {
		t.Fatalf("query=%+v", service.query)
	}
	for _, query := range []string{"?unknown=1", "?limit=1&limit=2", "?state=", "?user_id=%zz", "?channel=email;state=accepted"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/notifications/delivery-history"+query, nil))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "validation_error") {
			t.Fatalf("query=%s response=%d %s", query, response.Code, response.Body.String())
		}
	}
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{{notificationcontrol.ErrUnauthenticated, 401, "authentication_required"},
		{notificationcontrol.ErrPermissionDenied, 403, "permission_denied"},
		{errors.New("private-database-detail"), 500, "internal_error"}} {
		service.err = test.err
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/notifications/delivery-history", nil))
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) || strings.Contains(response.Body.String(), "private") {
			t.Fatalf("domain error response=%d %s", response.Code, response.Body.String())
		}
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/admin/notifications/delivery-history", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET" {
		t.Fatalf("unsupported method=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/notifications/delivery-history-extra", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("neighbor route=%d", response.Code)
	}
}
