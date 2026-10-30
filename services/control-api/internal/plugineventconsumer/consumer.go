package plugineventconsumer

import (
	"context"
	"errors"
	"reflect"
	"regexp"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/google/uuid"
)

var ErrInvalidInput = errors.New("invalid plugin event consumer input")

var eventCodePattern = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)

type Verifier interface {
	Authorize(identityJSON, decisionJSON []byte,
		expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error)
}

type Dispatcher interface {
	Dispatch(context.Context, Event) error
}

type Event struct {
	EventID        string
	SubscriptionID string
	IdempotencyKey string
	Code           string
	Payload        []byte
}

type DispatchRequest struct {
	InstallationID uuid.UUID
	IdentityJSON   []byte
	DecisionJSON   []byte
	RequestID      string
	Event          Event
}

type Consumer struct {
	verifier   Verifier
	dispatcher Dispatcher
}

func NewConsumer(verifier Verifier, dispatcher Dispatcher) (*Consumer, error) {
	if nilDependency(verifier) || nilDependency(dispatcher) {
		return nil, ErrInvalidInput
	}
	return &Consumer{verifier: verifier, dispatcher: dispatcher}, nil
}

func (consumer *Consumer) Dispatch(ctx context.Context, request DispatchRequest) error {
	if consumer == nil || nilDependency(consumer.verifier) || nilDependency(consumer.dispatcher) ||
		ctx == nil || !validRequest(request) {
		return ErrInvalidInput
	}
	_, err := consumer.verifier.Authorize(
		append([]byte(nil), request.IdentityJSON...),
		append([]byte(nil), request.DecisionJSON...),
		pluginruntimeauth.ExpectedAction{
			InstallationID: request.InstallationID,
			RequestID:      request.RequestID, CapabilityKind: "event", CapabilityCode: request.Event.Code,
		},
	)
	if err != nil {
		return err
	}
	event := request.Event
	event.Payload = append([]byte(nil), request.Event.Payload...)
	return consumer.dispatcher.Dispatch(ctx, event)
}

func validRequest(request DispatchRequest) bool {
	return request.InstallationID != uuid.Nil && len(request.IdentityJSON) > 0 && len(request.DecisionJSON) > 0 &&
		validVisibleASCII(request.RequestID) && validVisibleASCII(request.Event.EventID) &&
		validVisibleASCII(request.Event.SubscriptionID) && validVisibleASCII(request.Event.IdempotencyKey) &&
		len(request.Event.Code) <= 160 && eventCodePattern.MatchString(request.Event.Code)
}

func validVisibleASCII(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range value {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
