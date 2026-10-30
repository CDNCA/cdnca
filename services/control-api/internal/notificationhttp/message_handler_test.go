package notificationhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
)

type messageStubService struct {
	*stubService
	page  notificationcontrol.MessagePage
	query notificationcontrol.MessageQuery
	err   error
}

func (s *messageStubService) ListMessages(_ context.Context, _ notificationcontrol.Actor, query notificationcontrol.MessageQuery) (notificationcontrol.MessagePage, error) {
	s.query = query
	if query.Invalid {
		return notificationcontrol.MessagePage{}, notificationcontrol.ErrInvalidInput
	}
	if query.UserID != "" {
		value, err := uuid.Parse(query.UserID)
		if err != nil || value == uuid.Nil || value.String() != query.UserID {
			return notificationcontrol.MessagePage{}, notificationcontrol.ErrInvalidInput
		}
	}
	return s.page, s.err
}

func newMessageHandler(t *testing.T, service *messageStubService, session identity.AuthenticatedSession) http.Handler {
	t.Helper()
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestListMessagesHTTPVersionedProjectionAndFilters(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	userID := uuid.New()
	service := &messageStubService{
		stubService: &stubService{},
		page: notificationcontrol.MessagePage{
			Schema: "cdnca.notification-message-query/v1", Total: 1,
			Items: []notificationcontrol.Message{{
				ID: uuid.New(), UserID: &userID, Type: "announcement.published", CreatedAt: time.Now(),
			}},
		},
	}
	handler := newMessageHandler(t, service, session)
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/notifications/messages?type=announcement.published&user_id="+userID.String()+"&package_id=pkg-1&site_id=site-1&limit=30&cursor="+uuid.NewString(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if service.query.Type != "announcement.published" || service.query.UserID != userID.String() ||
		service.query.PackageID != "pkg-1" || service.query.SiteID != "site-1" || service.query.Limit != "30" || service.query.Cursor == "" {
		t.Fatalf("query=%+v", service.query)
	}
	body := response.Body.String()
	var envelope notificationcontrol.MessagePage
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil || envelope.Schema != "cdnca.notification-message-query/v1" || envelope.Total != 1 {
		t.Fatalf("envelope=%+v err=%v", envelope, err)
	}
	// L1：可读名称字段固定出现（缺失对象为 null），前端按精确键校验。
	for _, key := range []string{`"user_display_id":null`, `"username":null`, `"user_display_name":null`, `"site_domain":null`, `"package_name":null`} {
		if !strings.Contains(body, key) {
			t.Fatalf("response lacks %s: %s", key, body)
		}
	}
}

func TestListMessagesHTTPRejectsMalformedQueryAndMethods(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &messageStubService{stubService: &stubService{}}
	handler := newMessageHandler(t, service, session)
	for _, path := range []string{
		"/v1/admin/notifications/messages?unknown=1",
		"/v1/admin/notifications/messages?limit=1&limit=2",
		"/v1/admin/notifications/messages?user_id=bad",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "validation_error") {
			t.Fatalf("path=%s status=%d body=%q", path, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/admin/notifications/messages", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET" {
		t.Fatalf("method status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
}

type ownMessageStubService struct {
	*stubService
	actor notificationcontrol.Actor
	query notificationcontrol.OwnMessageQuery
}

func (s *ownMessageStubService) ListOwnMessages(_ context.Context, actor notificationcontrol.Actor, query notificationcontrol.OwnMessageQuery) (notificationcontrol.OwnMessagePage, error) {
	s.actor, s.query = actor, query
	if query.Invalid {
		return notificationcontrol.OwnMessagePage{}, notificationcontrol.ErrInvalidInput
	}
	return notificationcontrol.OwnMessagePage{Schema: "cdnca.notification-own-messages/v1", Items: []notificationcontrol.OwnMessage{}}, nil
}

// SEC-ACCOUNT-07: the own-message list takes scope and recipient from the
// session and rejects any attempt to name another scope or user.
func TestListOwnMessagesHTTPUsesSessionIdentityOnly(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
	}}
	service := &ownMessageStubService{stubService: &stubService{}}
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	siteID := uuid.NewString()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/account/notification-messages?type=security.attack.detected&site_id="+siteID+"&limit=20&offset=40", nil))
	if response.Code != http.StatusOK || service.actor.UserID != session.Principal.UserID || service.actor.ScopeID != session.Principal.ScopeID ||
		service.query.Type != "security.attack.detected" || service.query.SiteID != siteID || service.query.Limit != "20" || service.query.Offset != "40" {
		t.Fatalf("status=%d actor=%+v query=%+v body=%q", response.Code, service.actor, service.query, response.Body.String())
	}
	for _, path := range []string{
		"/v1/account/notification-messages?user_id=" + uuid.NewString(),
		"/v1/account/notification-messages?scope_id=" + uuid.NewString(),
		"/v1/account/notification-messages?offset=1&offset=2",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("path=%s status=%d", path, response.Code)
		}
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/account/notification-messages", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET" {
		t.Fatalf("method status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
}
