package notificationruntime

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestDispatcherRegistryRoutesLoginThroughRegisteredAnonymousMux(t *testing.T) {
	t.Parallel()

	registry := NewDispatcherRegistry()
	dispatcher := &registryDispatcher{}
	if _, err := registry.Register(context.Background(), notification.EventTypeAccountRecovery, dispatcher); err != nil {
		t.Fatal(err)
	}
	result := registry.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{
		EventType: notification.EventTypeAccountLoginVerification,
	})
	if result.Disposition != notification.AnonymousDispatchDelivered || result.Failure != nil || dispatcher.calls.Load() != 1 {
		t.Fatalf("login dispatch result=%+v calls=%d", result, dispatcher.calls.Load())
	}
}
