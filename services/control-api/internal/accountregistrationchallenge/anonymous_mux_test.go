package accountregistrationchallenge

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

type muxTestDispatcher struct {
	calls int
}

func (dispatcher *muxTestDispatcher) Dispatch(context.Context, notification.AnonymousDeliveryAttempt) notification.AnonymousDispatchResult {
	dispatcher.calls++
	return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchAccepted}
}

func TestAnonymousDispatchMuxRoutesAllAccountEventsExactly(t *testing.T) {
	t.Parallel()

	recovery, registration, login := new(muxTestDispatcher), new(muxTestDispatcher), new(muxTestDispatcher)
	mux, err := NewAnonymousDispatchMux(recovery, registration, login)
	if err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{
		notification.EventTypeAccountRecovery,
		notification.EventTypeAccountRegistrationVerification,
		notification.EventTypeAccountLoginVerification,
	} {
		result := mux.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{EventType: eventType})
		if result.Disposition != notification.AnonymousDispatchAccepted || result.Failure != nil {
			t.Fatalf("dispatch %q result=%+v", eventType, result)
		}
	}
	if recovery.calls != 1 || registration.calls != 1 || login.calls != 1 {
		t.Fatalf("dispatch calls recovery=%d registration=%d login=%d", recovery.calls, registration.calls, login.calls)
	}
	result := mux.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{EventType: "identity.unknown"})
	if result.Failure == nil || result.Failure.Class != notification.FailurePermanent ||
		result.Failure.Code != "anonymous_dispatch_event_invalid" {
		t.Fatalf("unknown dispatch result=%+v", result)
	}
}

func TestAnonymousDispatchMuxAllowsLoginWithoutRegistration(t *testing.T) {
	t.Parallel()

	recovery, login := new(muxTestDispatcher), new(muxTestDispatcher)
	mux, err := NewAnonymousDispatchMux(recovery, nil, login)
	if err != nil {
		t.Fatal(err)
	}
	loginResult := mux.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{
		EventType: notification.EventTypeAccountLoginVerification,
	})
	registrationResult := mux.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{
		EventType: notification.EventTypeAccountRegistrationVerification,
	})
	if loginResult.Disposition != notification.AnonymousDispatchAccepted || login.calls != 1 ||
		registrationResult.Failure == nil || registrationResult.Failure.Class != notification.FailureTemporary {
		t.Fatalf("login=%+v registration=%+v calls=%d", loginResult, registrationResult, login.calls)
	}
}
