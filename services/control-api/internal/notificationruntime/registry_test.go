package notificationruntime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

type registryDispatcher struct {
	calls atomic.Int32
}

type panicOnceRegistryDispatcher struct {
	calls atomic.Int32
}

func (d *registryDispatcher) Dispatch(
	context.Context,
	notification.AnonymousDeliveryAttempt,
) notification.AnonymousDispatchResult {
	d.calls.Add(1)
	return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchDelivered}
}

func (d *panicOnceRegistryDispatcher) Dispatch(
	context.Context,
	notification.AnonymousDeliveryAttempt,
) notification.AnonymousDispatchResult {
	if d.calls.Add(1) == 1 {
		panic("dispatcher secret must not escape")
	}
	return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchDelivered}
}

func TestDispatcherRegistryContainsDispatcherPanicAndPreservesRegistration(t *testing.T) {
	registry := NewDispatcherRegistry()
	dispatcher := &panicOnceRegistryDispatcher{}
	if _, err := registry.Register(
		context.Background(), notification.EventTypeAccountRecovery, dispatcher,
	); err != nil {
		t.Fatal(err)
	}
	attempt := notification.AnonymousDeliveryAttempt{EventType: notification.EventTypeAccountRecovery}

	first, panicValue := dispatchCapturingPanic(registry, context.Background(), attempt)
	if panicValue != nil {
		t.Fatalf("dispatcher panic escaped: %v", panicValue)
	}
	if first.Disposition != "" || first.Failure == nil ||
		first.Failure.Class != notification.FailureTemporary || first.Failure.Code != "dispatch_unavailable" {
		t.Fatalf("panic result = %+v", first)
	}
	second := registry.Dispatch(context.Background(), attempt)
	if second.Disposition != notification.AnonymousDispatchDelivered || second.Failure != nil ||
		dispatcher.calls.Load() != 2 {
		t.Fatalf("second result=%+v calls=%d", second, dispatcher.calls.Load())
	}
}

func dispatchCapturingPanic(
	registry *DispatcherRegistry,
	ctx context.Context,
	attempt notification.AnonymousDeliveryAttempt,
) (result notification.AnonymousDispatchResult, panicValue any) {
	defer func() { panicValue = recover() }()
	result = registry.Dispatch(ctx, attempt)
	return result, nil
}

func TestDispatcherRegistryConcurrentRegistrationHasOneWinner(t *testing.T) {
	registry := NewDispatcherRegistry()
	const contenders = 64
	start := make(chan struct{})
	registrations := make(chan *DispatcherRegistration, contenders)
	errorsSeen := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			registration, err := registry.Register(
				context.Background(), notification.EventTypeAccountRecovery, &registryDispatcher{},
			)
			if err != nil {
				errorsSeen <- err
				return
			}
			registrations <- registration
		}()
	}
	close(start)
	wait.Wait()
	close(registrations)
	close(errorsSeen)
	if len(registrations) != 1 || len(errorsSeen) != contenders-1 {
		t.Fatalf("registrations=%d errors=%d", len(registrations), len(errorsSeen))
	}
	for err := range errorsSeen {
		if !errors.Is(err, ErrDispatcherRegistered) {
			t.Fatalf("registration error = %v", err)
		}
	}
}

func TestDispatcherRegistrationIsABAAndCloseSafe(t *testing.T) {
	registry := NewDispatcherRegistry()
	firstDispatcher := &registryDispatcher{}
	first, err := registry.Register(
		context.Background(), notification.EventTypeAccountRecovery, firstDispatcher,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	secondDispatcher := &registryDispatcher{}
	second, err := registry.Register(
		context.Background(), notification.EventTypeAccountRecovery, secondDispatcher,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatalf("idempotent stale close: %v", err)
	}
	result := registry.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{
		EventType: notification.EventTypeAccountRecovery,
	})
	if result.Disposition != notification.AnonymousDispatchDelivered ||
		firstDispatcher.calls.Load() != 0 || secondDispatcher.calls.Load() != 1 {
		t.Fatalf("dispatch result=%+v first=%d second=%d", result,
			firstDispatcher.calls.Load(), secondDispatcher.calls.Load())
	}
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDispatcherRegistryFailsClosedForUnsupportedAndUnavailableEvents(t *testing.T) {
	registry := NewDispatcherRegistry()
	if _, err := registry.Register(context.Background(), "tenant.message", &registryDispatcher{}); !errors.Is(err, ErrEventTypeDenied) {
		t.Fatalf("unsupported registration error = %v", err)
	}
	for _, eventType := range []string{notification.EventTypeAccountRecovery, "tenant.message"} {
		result := registry.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{EventType: eventType})
		if result.Disposition != "" || result.Failure == nil ||
			result.Failure.Class != notification.FailureTemporary || result.Failure.Code != "dispatch_unregistered" {
			t.Fatalf("unregistered %q result = %+v", eventType, result)
		}
	}
	if err := registry.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(
		context.Background(), notification.EventTypeAccountRecovery, &registryDispatcher{},
	); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("closed registry registration error = %v", err)
	}
}

func TestDispatcherRegistryRoutesRegistrationThroughRegisteredAnonymousMux(t *testing.T) {
	registry := NewDispatcherRegistry()
	dispatcher := &registryDispatcher{}
	if _, err := registry.Register(
		context.Background(), notification.EventTypeAccountRecovery, dispatcher,
	); err != nil {
		t.Fatal(err)
	}
	result := registry.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{
		EventType: notification.EventTypeAccountRegistrationVerification,
	})
	if result.Disposition != notification.AnonymousDispatchDelivered || result.Failure != nil ||
		dispatcher.calls.Load() != 1 {
		t.Fatalf("registration dispatch result=%+v calls=%d", result, dispatcher.calls.Load())
	}
}
