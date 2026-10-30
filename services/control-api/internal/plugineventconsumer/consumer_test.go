package plugineventconsumer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/google/uuid"
)

var (
	errDenied          = errors.New("runtime authorization denied")
	errDispatchUnknown = errors.New("dispatch outcome unknown")
)

type verifierStub struct {
	mu        sync.Mutex
	calls     []pluginruntimeauth.ExpectedAction
	order     *[]string
	authorize func([]byte, []byte, pluginruntimeauth.ExpectedAction) error
}

func (stub *verifierStub) Authorize(identityJSON, decisionJSON []byte,
	expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls = append(stub.calls, expected)
	if stub.order != nil {
		*stub.order = append(*stub.order, "authorize")
	}
	if stub.authorize != nil {
		return pluginruntimeauth.Authorization{}, stub.authorize(identityJSON, decisionJSON, expected)
	}
	return pluginruntimeauth.Authorization{}, nil
}

type dispatcherStub struct {
	mu        sync.Mutex
	calls     []Event
	order     *[]string
	responses []error
}

func (stub *dispatcherStub) Dispatch(_ context.Context, event Event) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls = append(stub.calls, event)
	if stub.order != nil {
		*stub.order = append(*stub.order, "dispatch")
	}
	index := len(stub.calls) - 1
	if index < len(stub.responses) {
		return stub.responses[index]
	}
	return nil
}

func TestNewConsumerFailsClosedForMissingDependencies(t *testing.T) {
	verifier := &verifierStub{}
	dispatcher := &dispatcherStub{}
	for _, test := range []struct {
		name       string
		verifier   Verifier
		dispatcher Dispatcher
	}{{name: "verifier", dispatcher: dispatcher}, {name: "dispatcher", verifier: verifier}} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewConsumer(test.verifier, test.dispatcher); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("NewConsumer() error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestDispatchAuthorizesExactEventBeforeDownstreamAndIsolatesProofs(t *testing.T) {
	order := []string{}
	verifier := &verifierStub{order: &order}
	dispatcher := &dispatcherStub{order: &order}
	consumer, err := NewConsumer(verifier, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	request := testDispatchRequest()
	if err := consumer.Dispatch(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"authorize", "dispatch"}) {
		t.Fatalf("call order = %v", order)
	}
	if len(verifier.calls) != 1 || verifier.calls[0] != (pluginruntimeauth.ExpectedAction{
		InstallationID: request.InstallationID, RequestID: request.RequestID,
		CapabilityKind: "event", CapabilityCode: request.Event.Code,
	}) {
		t.Fatalf("expected action = %+v", verifier.calls)
	}
	if len(dispatcher.calls) != 1 || !reflect.DeepEqual(dispatcher.calls[0], request.Event) {
		t.Fatalf("downstream events = %+v", dispatcher.calls)
	}
	encoded, err := json.Marshal(dispatcher.calls[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, request.IdentityJSON) || bytes.Contains(encoded, request.DecisionJSON) {
		t.Fatalf("downstream event leaked authorization material: %s", encoded)
	}
}

func TestDispatchRejectsInvalidEventCodesBeforeAuthorization(t *testing.T) {
	for _, code := range []string{
		"", "io.cdnca.dns.changed", "io.cdnca.DNS.v1.changed", "io.cdnca.dns.v0.changed",
		"io.cdnca.dns.v1.changed.extra", "io.cdnca.dns.v01.changed", "io.cdnca.dns.v1.changed-unsafe",
	} {
		t.Run(code, func(t *testing.T) {
			verifier := &verifierStub{}
			dispatcher := &dispatcherStub{}
			consumer, err := NewConsumer(verifier, dispatcher)
			if err != nil {
				t.Fatal(err)
			}
			request := testDispatchRequest()
			request.Event.Code = code
			if err := consumer.Dispatch(t.Context(), request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Dispatch() error = %v, want ErrInvalidInput", err)
			}
			if len(verifier.calls) != 0 || len(dispatcher.calls) != 0 {
				t.Fatalf("invalid event reached verifier=%d dispatcher=%d", len(verifier.calls), len(dispatcher.calls))
			}
		})
	}
}

func TestDispatchDenialAndOldDecisionWithNewRequestIDNeverReachDownstream(t *testing.T) {
	verifier := &verifierStub{authorize: func(_ []byte, decisionJSON []byte,
		expected pluginruntimeauth.ExpectedAction) error {
		var decision struct {
			RequestID string `json:"request_id"`
			Decision  string `json:"decision"`
		}
		if json.Unmarshal(decisionJSON, &decision) != nil || decision.Decision != "allow" ||
			decision.RequestID != expected.RequestID {
			return errDenied
		}
		return nil
	}}
	dispatcher := &dispatcherStub{}
	consumer, err := NewConsumer(verifier, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	request := testDispatchRequest()
	request.RequestID = "request-new-after-revoke"
	request.DecisionJSON = []byte(`{"request_id":"request-old-before-revoke","decision":"allow"}`)
	if err := consumer.Dispatch(t.Context(), request); !errors.Is(err, errDenied) {
		t.Fatalf("Dispatch() error = %v, want authorization denial", err)
	}
	if len(dispatcher.calls) != 0 {
		t.Fatalf("old decision dispatched %d events", len(dispatcher.calls))
	}
}

func TestDispatchExactRetryPreservesDownstreamEventAndIdempotencyIdentity(t *testing.T) {
	verifier := &verifierStub{}
	dispatcher := &dispatcherStub{responses: []error{errDispatchUnknown, nil}}
	consumer, err := NewConsumer(verifier, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	request := testDispatchRequest()
	if err := consumer.Dispatch(t.Context(), request); !errors.Is(err, errDispatchUnknown) {
		t.Fatalf("first Dispatch() error = %v", err)
	}
	if err := consumer.Dispatch(t.Context(), request); err != nil {
		t.Fatalf("retry Dispatch() error = %v", err)
	}
	if len(verifier.calls) != 2 || len(dispatcher.calls) != 2 {
		t.Fatalf("authorize=%d dispatch=%d", len(verifier.calls), len(dispatcher.calls))
	}
	if !reflect.DeepEqual(dispatcher.calls[0], dispatcher.calls[1]) ||
		dispatcher.calls[0].EventID != request.Event.EventID ||
		dispatcher.calls[0].IdempotencyKey != request.Event.IdempotencyKey {
		t.Fatalf("retry identity drifted: first=%+v retry=%+v", dispatcher.calls[0], dispatcher.calls[1])
	}
}

func testDispatchRequest() DispatchRequest {
	return DispatchRequest{
		InstallationID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		IdentityJSON:   []byte(`{"schema":"identity","proof":"identity-secret"}`),
		DecisionJSON:   []byte(`{"request_id":"request-current","decision":"allow","signature":"decision-secret"}`),
		RequestID:      "request-current",
		Event: Event{
			EventID: "event-018cc251-f400-7def-8000-000000000001", SubscriptionID: "subscription-1",
			IdempotencyKey: "plugin-event-idempotency-1", Code: "io.cdnca.dns.v1.changed",
			Payload: []byte(`{"zone_id":"zone-1"}`),
		},
	}
}
