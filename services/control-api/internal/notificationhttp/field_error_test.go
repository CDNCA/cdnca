package notificationhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/google/uuid"
)

// fix-fielderr-be5: a located notification refusal keeps 400 validation_error
// and adds error.details {field, reason}; an unlocated one has no details.
func TestDomainErrorCarriesLocatedField(t *testing.T) {
	for name, check := range map[string]struct {
		err           error
		field, reason string
	}{
		"policy":    {fmt.Errorf("update: %w", fielderr.New(notificationcontrol.ErrInvalidInput, "events[2].interval_hours", fielderr.OutOfRange)), "events[2].interval_hours", fielderr.OutOfRange},
		"template":  {fielderr.New(notificationcontrol.ErrInvalidInput, "variables[0]", fielderr.InvalidFormat), "variables[0]", fielderr.InvalidFormat},
		"unlocated": {notificationcontrol.ErrInvalidInput, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeDomainError(recorder, httptest.NewRequest(http.MethodPut, "/v1/admin/notifications/policy", nil), check.err)
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Details *struct {
						Field  string `json:"field"`
						Reason string `json:"reason"`
					} `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_error" {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if check.field == "" {
				if body.Error.Details != nil {
					t.Fatalf("unlocated has details: %s", recorder.Body.String())
				}
				return
			}
			if body.Error.Details == nil || body.Error.Details.Field != check.field || body.Error.Details.Reason != check.reason {
				t.Fatalf("details: %s", recorder.Body.String())
			}
		})
	}
}

// The handler's own body checks name the missing field too.
func TestHandlerMissingBodyFieldIsLocated(t *testing.T) {
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform",
	}}
	handler, err := New(&stubService{}, func(*http.Request) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ method, path, body, ifMatch, field string }{
		{http.MethodPut, "/v1/admin/notifications/channels", `{"sms_enabled":true}`, `"7"`, "email_enabled"},
		{http.MethodPut, "/v1/admin/notifications/policy", `{"window_mode":"all_day","window_start":"00:00","window_end":"23:59","events":[]}`, `"7"`, "timezone"},
		{http.MethodPut, "/v1/admin/notifications/templates/site_ready/versions/1/email", `{"subject":"s","variables":[]}`, "", "body"},
		{http.MethodPut, "/v1/account/notification-subscriptions/announcement.published", `{"email_enabled":true}`, `"0"`, "sms_enabled"},
		{http.MethodPut, "/v1/account/notification-subscriptions/announcement.published", `{"sms_enabled":true,"email_enabled":true,"inbox_enabled":null}`, `"0"`, "inbox_enabled"},
	} {
		request := httptest.NewRequest(check.method, check.path, strings.NewReader(check.body))
		request.Header.Set("Content-Type", "application/json")
		if check.ifMatch != "" {
			request.Header.Set("If-Match", check.ifMatch)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Details struct {
					Field  string `json:"field"`
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		if recorder.Code != http.StatusBadRequest || body.Error.Code != "validation_error" || body.Error.Details.Field != check.field {
			t.Fatalf("%s %s: status=%d body=%s", check.method, check.path, recorder.Code, recorder.Body.String())
		}
	}
}
