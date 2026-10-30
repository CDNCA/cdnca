package notificationruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

type observationProvider struct {
	ProviderTransport
	send func(context.Context, ProviderMessage) (ProviderResult, error)
}

func (provider observationProvider) Send(ctx context.Context, message ProviderMessage) (ProviderResult, error) {
	return provider.send(ctx, message)
}

func TestSenderObservesEveryActualProviderCall(t *testing.T) {
	started := time.Date(2026, 9, 28, 10, 0, 0, 123456000, time.UTC)
	for _, outcome := range []string{"accepted", "temporary", "permanent", "invalid", "error", "panic", "timeout"} {
		t.Run(outcome, func(t *testing.T) {
			clockCalls, providerCalls := 0, 0
			provider := observationProvider{send: func(ctx context.Context, message ProviderMessage) (ProviderResult, error) {
				providerCalls++
				if clockCalls != providerCalls || message.Contact != "member@example.test" {
					t.Fatal("observation was not sampled at the resolved provider call")
				}
				switch outcome {
				case "panic":
					panic("private-provider-response")
				case "timeout":
					<-ctx.Done()
					return ProviderResult{}, ctx.Err()
				case "error":
					return ProviderResult{}, errors.New("private-provider-response")
				case "temporary":
					return ProviderResult{Disposition: ProviderTemporaryFailure, Code: "provider_unavailable"}, nil
				case "permanent":
					return ProviderResult{Disposition: ProviderPermanentFailure, Code: "recipient_rejected"}, nil
				case "invalid":
					return ProviderResult{}, nil
				}
				return ProviderResult{Disposition: ProviderAccepted, ProviderDeliveryID: "provider-id"}, nil
			}}
			sender := newMemberSender(&testContactResolver{contact: "member@example.test"}, map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider}, time.Millisecond)
			sender.now = func() time.Time { clockCalls++; return started }
			result := sender.Send(t.Context(), notification.DeliveryAttempt{OutboxID: uuid.New(), ScopeID: uuid.New(), RecipientID: uuid.New(),
				Channel: notification.ChannelEmail, Subject: "private-title", Body: "private-body", DedupKey: "observation", AttemptNumber: 1})
			if providerCalls != 1 || !reflect.DeepEqual(result.Observation, notification.NewDispatchObservation(notification.ChannelEmail, "member@example.test", started)) {
				t.Fatalf("provider calls=%d observation=%+v", providerCalls, result.Observation)
			}
		})
	}
}

func TestSenderDoesNotInventUncalledProviderObservations(t *testing.T) {
	for _, mode := range []string{"missing provider", "resolver failure", "empty contact", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			provider := &testProvider{result: ProviderResult{Disposition: ProviderAccepted}}
			resolver := &testContactResolver{contact: "member@example.test"}
			providers := map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "missing provider":
				providers = nil
			case "resolver failure":
				resolver.contact = ""
				resolver.failure = &notification.Failure{Class: notification.FailureTemporary, Code: "contact_lookup_unavailable"}
			case "empty contact":
				resolver.contact = ""
			case "cancelled":
				cancel()
			}
			sender := newMemberSender(resolver, providers, time.Second)
			sender.now = func() time.Time { t.Fatal("clock sampled without a provider call"); return time.Time{} }
			result := sender.Send(ctx, notification.DeliveryAttempt{OutboxID: uuid.New(), ScopeID: uuid.New(), RecipientID: uuid.New(),
				Channel: notification.ChannelEmail, DedupKey: "observation", AttemptNumber: 1})
			messages, _ := provider.snapshot()
			if result.Observation != nil || len(messages) != 0 {
				t.Fatalf("invented observation=%+v calls=%d", result.Observation, len(messages))
			}
		})
	}
}

func TestRecoveryObservationExcludesContentAndRecoveryURL(t *testing.T) {
	started := time.Now().UTC().Truncate(time.Microsecond)
	provider := &testProvider{result: ProviderResult{Disposition: ProviderAccepted}}
	sender := newRecoverySender(map[notification.Channel]ProviderTransport{notification.ChannelSMS: provider}, time.Second)
	sender.now = func() time.Time { return started }
	result := sender.SendRecovery(t.Context(), accountrecovery.RecoveryDelivery{OutboxID: uuid.New(), Channel: notification.ChannelSMS,
		Contact: "+8613800001234", Subject: "private-title", Body: "private-body", RecoveryURL: "https://example.test/reset#token=private",
		IdempotencyKey: "recovery-observation", AttemptNumber: 1})
	if !reflect.DeepEqual(result.Observation, notification.NewDispatchObservation(notification.ChannelSMS, "+8613800001234", started)) {
		t.Fatalf("recovery observation=%+v", result.Observation)
	}
}
