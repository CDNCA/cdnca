package accountregistration

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

func TestRegistrationSuccessEnqueueRequestUsesPublishedTemplateAndPublicUsername(t *testing.T) {
	record := RegistrationRecord{
		RegistrationID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		ScopeID:        uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		UserID:         uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
		Username:       "new-user",
		RequestID:      "registration-request-1",
	}
	ref := notification.TemplateRef{
		ID: "platform_user_registration_success", Version: 7, Channel: notification.ChannelEmail,
	}

	request, err := registrationSuccessEnqueueRequest(record, ref, []string{"username"})
	if err != nil {
		t.Fatal(err)
	}
	if request.ScopeID != record.ScopeID || request.RecipientID != record.UserID ||
		request.SourceEventID != "account-registration-success:"+record.RegistrationID.String() ||
		request.EventType != notification.EventTypeAccountRegistrationSuccess ||
		request.Policy != notification.DeliverySystemRequired {
		t.Fatalf("registration success identity = %#v", request)
	}
	if got := request.Templates[notification.ChannelEmail]; got != ref {
		t.Fatalf("template = %#v, want %#v", got, ref)
	}
	value, ok := request.Contexts[notification.ChannelEmail]["username"]
	if !ok || value == (notification.ContextValue{}) {
		t.Fatalf("username context missing: %#v", request.Contexts)
	}
}

func TestRegistrationSuccessEnqueueRequestAllowsTemplateWithoutVariables(t *testing.T) {
	record := RegistrationRecord{
		RegistrationID: uuid.New(), ScopeID: uuid.New(), UserID: uuid.New(),
		Username: "new-user", RequestID: "registration-request-2",
	}
	request, err := registrationSuccessEnqueueRequest(record, notification.TemplateRef{
		ID: "platform_user_registration_success", Version: 8, Channel: notification.ChannelEmail,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Contexts[notification.ChannelEmail]) != 0 {
		t.Fatalf("unexpected context for static template: %#v", request.Contexts)
	}
}

func TestRegistrationSuccessEnqueueRequestRejectsUnknownVariables(t *testing.T) {
	_, err := registrationSuccessEnqueueRequest(RegistrationRecord{Username: "new-user"}, notification.TemplateRef{
		ID: "platform_user_registration_success", Version: 1, Channel: notification.ChannelEmail,
	}, []string{"password"})
	if err == nil {
		t.Fatal("unknown registration success variable was accepted")
	}
}
