package notification

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestRegistrationVerificationDispatchIsExplicitAndNarrow(t *testing.T) {
	t.Parallel()

	smsTemplate := TemplateRef{ID: "registration-otp-sms", Version: 1, Channel: ChannelSMS}
	request := DispatchEnqueueRequest{
		ScopeID: uuid.New(), SourceEventID: uuid.NewString(),
		AnonymousDispatchReference: uuid.New(), AuditRequestID: "registration-challenge-1",
		EventType: EventTypeAccountRegistrationVerification, SelectedChannel: ChannelSMS,
		Templates: map[Channel]TemplateRef{ChannelSMS: smsTemplate},
	}
	if err := validateDispatchEnqueueRequest(request); err != nil {
		t.Fatalf("valid registration dispatch: %v", err)
	}

	unknown := request
	unknown.EventType = "identity.arbitrary_anonymous"
	if err := validateDispatchEnqueueRequest(unknown); !errors.Is(err, ErrInvalidDispatch) {
		t.Fatalf("unknown event error = %v, want ErrInvalidDispatch", err)
	}

	mixed := request
	mixed.Templates = map[Channel]TemplateRef{
		ChannelSMS:   smsTemplate,
		ChannelEmail: {ID: "registration-otp-email", Version: 1, Channel: ChannelEmail},
	}
	if err := validateDispatchEnqueueRequest(mixed); !errors.Is(err, ErrInvalidDispatch) {
		t.Fatalf("mixed channel error = %v, want ErrInvalidDispatch", err)
	}

	recovery := request
	recovery.EventType = EventTypeAccountRecovery
	recovery.SelectedChannel = ""
	if dispatchEnqueueRequestDigest(recovery) == dispatchEnqueueRequestDigest(request) {
		t.Fatal("registration and recovery dispatch digests collide")
	}
	if !validAnonymousEventType(EventTypeAccountRecovery) ||
		!validAnonymousEventType(EventTypeAccountRegistrationVerification) ||
		!validAnonymousEventType(EventTypeAccountLoginVerification) ||
		validAnonymousEventType("identity.arbitrary_anonymous") {
		t.Fatal("anonymous event whitelist is not exact")
	}

	login := request
	login.EventType = EventTypeAccountLoginVerification
	if err := validateDispatchEnqueueRequest(login); err != nil {
		t.Fatalf("valid login dispatch: %v", err)
	}
	memberLogin := EnqueueRequest{
		ScopeID: uuid.New(), RecipientID: uuid.New(), SourceEventID: uuid.NewString(),
		EventType: EventTypeAccountLoginVerification, Policy: DeliverySystemRequired,
		AuditRequestID: "login-verification-member-denied",
	}
	if err := validateEnqueueRequest(memberLogin); !errors.Is(err, ErrInvalidEnqueue) {
		t.Fatalf("member login verification error = %v, want ErrInvalidEnqueue", err)
	}
}

func TestRegistrationSuccessIsARecipientNotificationEvent(t *testing.T) {
	ref := TemplateRef{ID: "platform_user_registration_success", Version: 1, Channel: ChannelEmail}
	request := EnqueueRequest{
		ScopeID:        uuid.New(),
		RecipientID:    uuid.New(),
		SourceEventID:  "account-registration-success:1",
		EventType:      EventTypeAccountRegistrationSuccess,
		Policy:         DeliverySystemRequired,
		Templates:      map[Channel]TemplateRef{ChannelEmail: ref},
		Contexts:       map[Channel]TemplateContext{ChannelEmail: {"username": PublicValue("new-user")}},
		AuditRequestID: "registration-success-test",
	}
	if err := validateEnqueueRequest(request); err != nil {
		t.Fatalf("registration success event rejected: %v", err)
	}
	if validAnonymousEventType(EventTypeAccountRegistrationSuccess) {
		t.Fatal("registration success event was classified as anonymous")
	}
}
