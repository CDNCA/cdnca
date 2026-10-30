package notificationhttp

import (
	"bytes"
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

func TestHandlerStrictJSONIfMatchErrorsAndNeighbor404(t *testing.T) {
	actor := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &stubService{channels: notificationcontrol.ChannelSettings{
		Revision: 7, SMSSupported: true, EmailSupported: true,
	}}
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return actor, nil })
	if err != nil {
		t.Fatal(err)
	}

	assertStatusCode(t, handler, http.MethodPut, "/v1/admin/notifications/channels", `{"sms_enabled":false,"email_enabled":true,"extra":1}`, `"7"`, http.StatusBadRequest, "validation_error")
	assertStatusCode(t, handler, http.MethodPut, "/v1/admin/notifications/channels", `{"sms_enabled":false,"email_enabled":true}`, "7", http.StatusBadRequest, "validation_error")
	assertStatusCode(t, handler, http.MethodPut, "/v1/admin/notifications/channels", `{"sms_enabled":false,"email_enabled":true}`, `"7"`, http.StatusOK, "")
	if service.channelWrite.ExpectedRevision != 7 || service.channelWrite.RequestID == "" {
		t.Fatalf("channel write = %+v", service.channelWrite)
	}

	assertStatusCode(t, handler, http.MethodPut, "/v1/admin/notifications/channels", `{"sms_enabled":true,"email_enabled":false}`, `"7"`, http.StatusOK, "")
	if !service.channelWrite.SMSEnabled || service.channelWrite.EmailEnabled {
		t.Fatalf("SMS channel write = %+v", service.channelWrite)
	}
	service.updateErr = notificationcontrol.ErrVersionConflict
	assertStatusCode(t, handler, http.MethodPut, "/v1/admin/notifications/channels", `{"sms_enabled":false,"email_enabled":false}`, `"7"`, http.StatusConflict, "version_conflict")

	service.updateErr = nil
	assertStatusCode(t, handler, http.MethodPut, "/v1/account/notification-subscriptions/announcement.published", `{"sms_enabled":true,"email_enabled":true}`, `"0"`, http.StatusOK, "")
	if !service.subscriptionWrite.SMSEnabled || !service.subscriptionWrite.EmailEnabled {
		t.Fatalf("SMS subscription write = %+v", service.subscriptionWrite)
	}
	assertStatusCode(t, handler, http.MethodGet, "/v1/account/notification-subscriptions/other.event", "", "", http.StatusNotFound, "notification_not_found")

	for _, path := range []string{
		"/v1/admin/notifications/channels-extra",
		"/v1/admin/notifications/templates/announcement_published/versions/1/email/extra",
		"/v1/account/notification-subscriptions/announcement.published/extra",
	} {
		assertStatusCode(t, handler, http.MethodGet, path, "", "", http.StatusNotFound, "")
	}
}

func TestHandlerTemplateReplayAndStablePrivateError(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &stubService{template: notificationcontrol.Template{
		TemplateID: "announcement_published", Version: 1, Channel: notificationcontrol.ChannelEmail,
		Subject: "subject", Body: "body", Variables: []string{}, CreatedAt: time.Now(),
	}}
	handler, _ := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/v1/admin/notifications/templates/announcement_published/versions/1/email", strings.NewReader(`{"subject":"subject","body":"body","variables":[]}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != "" {
		t.Fatalf("template response status=%d etag=%q body=%q", response.Code, response.Header().Get("ETag"), response.Body.String())
	}

	service.templateErr = notificationcontrol.ErrTemplateVersionConflict
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPut, "/v1/admin/notifications/templates/announcement_published/versions/1/email", strings.NewReader(`{"subject":"private subject","body":"private body","variables":[]}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), "private") || !strings.Contains(response.Body.String(), "template_version_conflict") {
		t.Fatalf("template conflict status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestHandlerListsRedactedDeliveryLogsAndAttempts(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	outboxID := uuid.New()
	scopeID := uuid.New()
	failureCode := "smtp_temporary_failure"
	service := &stubService{
		deliveries: notificationcontrol.DeliveryLogPage{
			Items: []notificationcontrol.DeliveryLog{{
				ScopeID: scopeID, OutboxID: outboxID, EventType: notificationcontrol.EventTypeAnnouncementPublished,
				Channel: notificationcontrol.ChannelEmail, TemplateID: "announcement_published", TemplateVersion: 3,
				Generation: 1, State: "retry_wait", Revision: 2, AttemptCount: 1,
				FailureCode: &failureCode, CreatedAt: time.Now(), UpdatedAt: time.Now(),
			}},
			NextCursor: outboxID.String(),
		},
		attempts: notificationcontrol.DeliveryAttemptPage{
			OutboxID: outboxID,
			Items: []notificationcontrol.DeliveryAttempt{{
				AttemptNumber: 1, Outcome: "temporary_failure", FailureCode: &failureCode,
				ClaimedAt: time.Now(), CompletedAt: timePointer(time.Now()),
			}},
		},
	}
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet,
		"/v1/admin/notifications/deliveries?scope_id="+scopeID.String()+"&channel=email&state=retry_wait&limit=25&cursor="+outboxID.String(), nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("delivery log status=%d body=%q", response.Code, response.Body.String())
	}
	if service.deliveryQuery != (notificationcontrol.DeliveryLogQuery{
		ScopeID: scopeID.String(), Channel: "email", State: "retry_wait", Limit: "25", Cursor: outboxID.String(),
	}) {
		t.Fatalf("delivery query=%+v", service.deliveryQuery)
	}
	for _, secret := range []string{"subject", "body", "dedup_key", "lease_token", "provider_response"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("delivery response leaked %q: %s", secret, response.Body.String())
		}
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/admin/notifications/deliveries/"+outboxID.String()+"/attempts", nil))
	if response.Code != http.StatusOK || service.attemptOutboxID != outboxID.String() {
		t.Fatalf("attempt response status=%d outbox=%q body=%q", response.Code, service.attemptOutboxID, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "lease_token") {
		t.Fatalf("attempt response leaked lease token: %s", response.Body.String())
	}

	assertStatusCode(t, handler, http.MethodGet, "/v1/admin/notifications/deliveries?unknown=1", "", "", http.StatusBadRequest, "validation_error")
	assertStatusCode(t, handler, http.MethodGet, "/v1/admin/notifications/deliveries?limit=10&limit=20", "", "", http.StatusBadRequest, "validation_error")
	assertStatusCode(t, handler, http.MethodPost, "/v1/admin/notifications/deliveries", "", "", http.StatusMethodNotAllowed, "method_not_allowed")
	assertStatusCode(t, handler, http.MethodDelete, "/v1/admin/notifications/deliveries/"+outboxID.String()+"/attempts", "", "", http.StatusMethodNotAllowed, "method_not_allowed")
}

func timePointer(value time.Time) *time.Time { return &value }

func TestHandlerForwardsSMSTemplateChannel(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &stubService{template: notificationcontrol.Template{
		TemplateID: "announcement_published", Version: 2, Channel: notificationcontrol.ChannelSMS,
		Body: "{{.title}}", Variables: []string{"title", "body"}, CreatedAt: time.Now(),
	}}
	handler, _ := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut,
		"/v1/admin/notifications/templates/announcement_published/versions/2/sms",
		strings.NewReader(`{"subject":"","body":"{{.title}}","variables":["title","body"]}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.templateChannel != notificationcontrol.ChannelSMS ||
		service.templateInput.Subject != "" {
		t.Fatalf("SMS template status=%d template=%+v body=%q", response.Code, service.template, response.Body.String())
	}
}

func TestHandlerRejectsMalformedUTF8BeforeTemplateWrite(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &stubService{template: notificationcontrol.Template{
		TemplateID: "announcement_published", Version: 1, Channel: notificationcontrol.ChannelEmail,
		Subject: "subject", Body: "body", Variables: []string{}, CreatedAt: time.Now(),
	}}
	handler, _ := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	payload := append([]byte(`{"subject":"subject","body":"`), 0xff)
	payload = append(payload, []byte(`","variables":[]}`)...)
	request := httptest.NewRequest(http.MethodPut,
		"/v1/admin/notifications/templates/announcement_published/versions/1/email", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertErrorEnvelope(t, response, http.StatusBadRequest, "validation_error")
	if service.templateWrites != 0 {
		t.Fatalf("template service writes = %d, want 0", service.templateWrites)
	}
}

func TestHandlerPreservesValidUTF8ReplacementRuneInTemplateWrite(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &stubService{template: notificationcontrol.Template{
		TemplateID: "announcement_published", Version: 1, Channel: notificationcontrol.ChannelEmail,
		Subject: "subject", Body: "body", Variables: []string{}, CreatedAt: time.Now(),
	}}
	handler, _ := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	replacement := []byte{0xef, 0xbf, 0xbd}
	payload := append([]byte(`{"subject":"subject","body":"`), replacement...)
	payload = append(payload, []byte(`","variables":[]}`)...)
	request := httptest.NewRequest(http.MethodPut,
		"/v1/admin/notifications/templates/announcement_published/versions/1/email", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("template response status=%d body=%q", response.Code, response.Body.String())
	}
	if service.templateWrites != 1 || !bytes.Equal([]byte(service.templateInput.Body), replacement) {
		t.Fatalf("template writes=%d body=%x", service.templateWrites, []byte(service.templateInput.Body))
	}
}

func TestHandlerStrictJSONWritesAndContractMethodErrors(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	service := &stubService{channels: notificationcontrol.ChannelSettings{Revision: 7, EmailSupported: true}, unchanged: true}
	handler, _ := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })

	valid := httptest.NewRequest(http.MethodPut, "/v1/admin/notifications/channels", strings.NewReader(`{"sms_enabled":false,"email_enabled":false}`))
	valid.Header.Set("Content-Type", "application/json; charset=utf-8")
	valid.Header.Set("If-Match", `"7"`)
	valid.Header.Set("X-Request-ID", "strict-json-valid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, valid)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"changed":false`) {
		t.Fatalf("unchanged response status=%d body=%q", response.Code, response.Body.String())
	}

	invalidWrites := []struct {
		name        string
		contentType []string
		body        string
		wantStatus  int
		wantCode    string
	}{
		{name: "missing content type", body: `{"sms_enabled":false,"email_enabled":false}`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type"},
		{name: "wrong content type", contentType: []string{"text/plain"}, body: `{"sms_enabled":false,"email_enabled":false}`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type"},
		{name: "duplicate content type", contentType: []string{"application/json", "application/json"}, body: `{"sms_enabled":false,"email_enabled":false}`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type"},
		{name: "duplicate key", contentType: []string{"application/json"}, body: `{"sms_enabled":false,"sms_enabled":false,"email_enabled":false}`, wantStatus: http.StatusBadRequest, wantCode: "validation_error"},
		{name: "unknown field", contentType: []string{"application/json"}, body: `{"sms_enabled":false,"email_enabled":false,"extra":true}`, wantStatus: http.StatusBadRequest, wantCode: "validation_error"},
		{name: "trailing value", contentType: []string{"application/json"}, body: `{"sms_enabled":false,"email_enabled":false} {}`, wantStatus: http.StatusBadRequest, wantCode: "validation_error"},
	}
	for _, test := range invalidWrites {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/v1/admin/notifications/channels", strings.NewReader(test.body))
			for _, contentType := range test.contentType {
				request.Header.Add("Content-Type", contentType)
			}
			request.Header.Set("If-Match", `"7"`)
			request.Header.Set("X-Request-ID", "strict-json-invalid")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorEnvelope(t, response, test.wantStatus, test.wantCode)
		})
	}

	methodCases := []struct{ method, path, allow string }{
		{http.MethodPost, "/v1/admin/notifications/channels", "GET, PUT"},
		{http.MethodPost, "/v1/admin/notifications/templates", "GET"},
		{http.MethodGet, "/v1/admin/notifications/templates/announcement_published/versions/1/email", "PUT"},
		{http.MethodDelete, "/v1/account/notification-subscriptions/announcement.published", "GET, PUT"},
	}
	for _, test := range methodCases {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		assertErrorEnvelope(t, response, http.StatusMethodNotAllowed, "method_not_allowed")
		if response.Header().Get("Allow") != test.allow {
			t.Fatalf("%s %s Allow=%q", test.method, test.path, response.Header().Get("Allow"))
		}
	}
}

type stubService struct {
	channels          notificationcontrol.ChannelSettings
	policy            notificationcontrol.DeliveryPolicySettings
	channelWrite      notificationcontrol.UpdateChannelsRequest
	updateErr         error
	template          notificationcontrol.Template
	templateErr       error
	templateChannel   string
	templateInput     notificationcontrol.TemplateInput
	templateWrites    int
	subscriptionWrite notificationcontrol.UpdateSubscriptionRequest
	unchanged         bool
	deliveries        notificationcontrol.DeliveryLogPage
	deliveryQuery     notificationcontrol.DeliveryLogQuery
	attempts          notificationcontrol.DeliveryAttemptPage
	attemptOutboxID   string
}

func (s *stubService) GetChannels(context.Context, notificationcontrol.Actor) (notificationcontrol.ChannelSettings, error) {
	return s.channels, nil
}
func (s *stubService) GetDeliveryPolicy(context.Context, notificationcontrol.Actor) (notificationcontrol.DeliveryPolicySettings, error) {
	return s.policy, nil
}
func (s *stubService) UpdateDeliveryPolicy(_ context.Context, _ notificationcontrol.Actor, request notificationcontrol.UpdateDeliveryPolicyRequest) (notificationcontrol.DeliveryPolicySettings, error) {
	result := s.policy
	result.Changed = true
	return result, s.updateErr
}
func (s *stubService) UpdateChannels(_ context.Context, _ notificationcontrol.Actor, request notificationcontrol.UpdateChannelsRequest) (notificationcontrol.ChannelSettings, error) {
	s.channelWrite = request
	result := s.channels
	result.Changed = !s.unchanged
	return result, s.updateErr
}
func (s *stubService) ListTemplates(context.Context, notificationcontrol.Actor) ([]notificationcontrol.Template, error) {
	return []notificationcontrol.Template{s.template}, nil
}
func (s *stubService) PutTemplate(_ context.Context, _ notificationcontrol.Actor, _ string, _ int64, channel string, input notificationcontrol.TemplateInput, _ string) (notificationcontrol.Template, error) {
	s.templateChannel = channel
	s.templateInput = input
	s.templateWrites++
	return s.template, s.templateErr
}
func (s *stubService) GetSubscription(_ context.Context, _ notificationcontrol.Actor, eventType string) (notificationcontrol.Subscription, error) {
	if eventType != notificationcontrol.EventTypeAnnouncementPublished {
		return notificationcontrol.Subscription{}, notificationcontrol.ErrNotFound
	}
	return notificationcontrol.Subscription{EventType: eventType, SMSSupported: true, EmailSupported: true}, nil
}
func (s *stubService) UpdateSubscription(_ context.Context, _ notificationcontrol.Actor, eventType string, request notificationcontrol.UpdateSubscriptionRequest) (notificationcontrol.Subscription, error) {
	s.subscriptionWrite = request
	return notificationcontrol.Subscription{EventType: eventType, SMSSupported: true, EmailSupported: true, SMSEnabled: request.SMSEnabled, EmailEnabled: request.EmailEnabled, Revision: 1, Changed: true}, s.updateErr
}
func (s *stubService) ListDeliveryLogs(_ context.Context, _ notificationcontrol.Actor, query notificationcontrol.DeliveryLogQuery) (notificationcontrol.DeliveryLogPage, error) {
	s.deliveryQuery = query
	if query.Invalid {
		return notificationcontrol.DeliveryLogPage{}, notificationcontrol.ErrInvalidInput
	}
	return s.deliveries, nil
}
func (s *stubService) ListDeliveryAttempts(_ context.Context, _ notificationcontrol.Actor, outboxID string) (notificationcontrol.DeliveryAttemptPage, error) {
	s.attemptOutboxID = outboxID
	return s.attempts, nil
}

func assertStatusCode(t *testing.T, handler http.Handler, method, path, body, ifMatch string, status int, code string) {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test")
	request.Header.Set("X-Request-ID", "notification-http-test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("%s %s status=%d body=%q", method, path, response.Code, response.Body.String())
	}
	if code == "" {
		return
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil || envelope.Error.Code != code {
		t.Fatalf("%s %s error=%+v decode=%v", method, path, envelope, err)
	}
}

func assertErrorEnvelope(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d content-type=%q body=%q", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil || envelope.Error.Code != code {
		t.Fatalf("error=%+v decode=%v body=%q", envelope, err, response.Body.String())
	}
}
