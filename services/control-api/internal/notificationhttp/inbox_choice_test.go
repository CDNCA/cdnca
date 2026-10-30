package notificationhttp

import (
	"net/http"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
)

// fix-ticket2 (546): a subscription write may carry the in-app choice;
// leaving it out keeps the stored one (older consoles send only sms/email).
func TestSubscriptionInboxChoice(t *testing.T) {
	actor := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
	}}
	service := &stubService{}
	handler, err := New(service, func(*http.Request) (identity.AuthenticatedSession, error) { return actor, nil })
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/account/notification-subscriptions/" + notificationcontrol.EventTypeAnnouncementPublished
	assertStatusCode(t, handler, http.MethodPut, path, `{"sms_enabled":false,"email_enabled":true,"inbox_enabled":false}`, `"0"`, http.StatusOK, "")
	if service.subscriptionWrite.InboxEnabled == nil || *service.subscriptionWrite.InboxEnabled {
		t.Fatalf("inbox choice = %+v", service.subscriptionWrite)
	}
	assertStatusCode(t, handler, http.MethodPut, path, `{"sms_enabled":false,"email_enabled":true}`, `"0"`, http.StatusOK, "")
	if service.subscriptionWrite.InboxEnabled != nil {
		t.Fatalf("absent inbox choice = %+v", service.subscriptionWrite)
	}
	assertStatusCode(t, handler, http.MethodPut, path, `{"sms_enabled":false,"email_enabled":true,"inbox_enabled":null}`, `"0"`, http.StatusBadRequest, "validation_error")
}
