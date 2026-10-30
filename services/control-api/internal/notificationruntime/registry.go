package notificationruntime

import (
	"context"
	"sync"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

type dispatcherSlot struct {
	token      uint64
	dispatcher notification.AnonymousDispatcher
}

type DispatcherRegistry struct {
	mu        sync.RWMutex
	closed    bool
	nextToken uint64
	slots     map[string]dispatcherSlot
}

type DispatcherRegistration struct {
	mu        sync.Mutex
	registry  *DispatcherRegistry
	eventType string
	token     uint64
	closed    bool
}

func NewDispatcherRegistry() *DispatcherRegistry {
	return &DispatcherRegistry{slots: make(map[string]dispatcherSlot)}
}

func (r *DispatcherRegistry) Register(
	ctx context.Context,
	eventType string,
	dispatcher notification.AnonymousDispatcher,
) (*DispatcherRegistration, error) {
	if r == nil || ctx == nil || dispatcher == nil {
		return nil, ErrDispatcherInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if eventType != notification.EventTypeAccountRecovery {
		return nil, ErrEventTypeDenied
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrRegistryClosed
	}
	if _, exists := r.slots[eventType]; exists {
		return nil, ErrDispatcherRegistered
	}
	r.nextToken++
	slot := dispatcherSlot{token: r.nextToken, dispatcher: dispatcher}
	r.slots[eventType] = slot
	return &DispatcherRegistration{registry: r, eventType: eventType, token: slot.token}, nil
}

func (r *DispatcherRegistry) Dispatch(
	ctx context.Context,
	attempt notification.AnonymousDeliveryAttempt,
) notification.AnonymousDispatchResult {
	if r == nil || ctx == nil {
		return unavailableDispatch("dispatch_unavailable")
	}
	r.mu.RLock()
	slot, registered := r.slots[attempt.EventType]
	if !registered && (attempt.EventType == notification.EventTypeAccountRegistrationVerification ||
		attempt.EventType == notification.EventTypeAccountLoginVerification) {
		slot, registered = r.slots[notification.EventTypeAccountRecovery]
	}
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return unavailableDispatch("dispatch_unavailable")
	}
	if !registered {
		return unavailableDispatch("dispatch_unregistered")
	}
	result, panicked := callDispatcher(ctx, slot.dispatcher, attempt)
	if panicked {
		return unavailableDispatch("dispatch_unavailable")
	}
	return result
}

func callDispatcher(
	ctx context.Context,
	dispatcher notification.AnonymousDispatcher,
	attempt notification.AnonymousDeliveryAttempt,
) (result notification.AnonymousDispatchResult, panicked bool) {
	defer func() {
		if recover() != nil {
			result = notification.AnonymousDispatchResult{}
			panicked = true
		}
	}()
	result = dispatcher.Dispatch(ctx, attempt)
	return result, false
}

func (r *DispatcherRegistry) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return ErrDispatcherInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.closed = true
	clear(r.slots)
	r.mu.Unlock()
	return nil
}

func (r *DispatcherRegistry) unregister(ctx context.Context, eventType string, token uint64) error {
	if ctx == nil {
		return ErrDispatcherInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	slot, exists := r.slots[eventType]
	if exists && slot.token == token {
		delete(r.slots, eventType)
	}
	return nil
}

func (r *DispatcherRegistration) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if err := r.registry.unregister(ctx, r.eventType, r.token); err != nil {
		return err
	}
	r.closed = true
	return nil
}

func unavailableDispatch(code string) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Failure: &notification.Failure{
		Class: notification.FailureTemporary, Code: code,
	}}
}
