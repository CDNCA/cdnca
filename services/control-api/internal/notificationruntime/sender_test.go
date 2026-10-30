package notificationruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

type testContactResolver struct {
	contact string
	failure *notification.Failure
	ready   error
}

func (r *testContactResolver) Ready(context.Context, notification.Channel) error {
	return r.ready
}

func (r *testContactResolver) Resolve(
	context.Context,
	uuid.UUID,
	uuid.UUID,
	notification.Channel,
) ContactResolution {
	return ContactResolution{Contact: r.contact, Failure: r.failure}
}

type testProvider struct {
	mu       sync.Mutex
	ready    error
	result   ProviderResult
	err      error
	messages []ProviderMessage
	closed   int
}

type panicOnceProvider struct {
	mu    sync.Mutex
	calls int
}

type panicOnIsError struct{}

func (panicOnIsError) Error() string { return "provider returned error" }

func (panicOnIsError) Is(error) bool { panic("post-provider classification panic") }

func (*panicOnceProvider) Ready(context.Context) error { return nil }

func (p *panicOnceProvider) Send(context.Context, ProviderMessage) (ProviderResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls == 1 {
		panic("provider secret must not escape")
	}
	return ProviderResult{Disposition: ProviderAccepted}, nil
}

func (*panicOnceProvider) Close(context.Context) error { return nil }

func (p *testProvider) Ready(context.Context) error { return p.ready }

func (p *testProvider) Send(_ context.Context, message ProviderMessage) (ProviderResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.messages = append(p.messages, message)
	return p.result, p.err
}

func (p *testProvider) Close(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed++
	return nil
}

func (p *testProvider) snapshot() ([]ProviderMessage, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]ProviderMessage(nil), p.messages...), p.closed
}

func TestMemberSenderClassifiesProviderOutcomesAndPreservesIdempotencyKey(t *testing.T) {
	tests := []struct {
		name            string
		result          ProviderResult
		err             error
		wantClass       notification.FailureClass
		wantCode        string
		wantAfter       time.Duration
		wantDisposition notification.SendDisposition
		wantProvider    string
		wantDeliveryID  string
	}{
		{
			name: "accepted", result: ProviderResult{
				Disposition: ProviderAccepted, ProviderDeliveryID: "provider-delivery-1",
			},
			wantDisposition: notification.SendAccepted, wantProvider: "configured_email",
			wantDeliveryID: "provider-delivery-1",
		},
		{
			name: "unknown", result: ProviderResult{Disposition: ProviderUnknown},
			wantDisposition: notification.SendUnknown, wantProvider: "configured_email",
		},
		{name: "temporary", result: ProviderResult{Disposition: ProviderTemporaryFailure, Code: "smtp_unavailable"}, wantClass: notification.FailureTemporary, wantCode: "smtp_unavailable"},
		{name: "permanent", result: ProviderResult{Disposition: ProviderPermanentFailure, Code: "recipient_rejected"}, wantClass: notification.FailurePermanent, wantCode: "recipient_rejected"},
		{name: "rate limited", result: ProviderResult{Disposition: ProviderRateLimited, Code: "provider_rate_limited", RetryAfter: 45 * time.Second}, wantClass: notification.FailureTemporary, wantCode: "provider_rate_limited", wantAfter: 45 * time.Second},
		{name: "timeout", err: context.DeadlineExceeded, wantDisposition: notification.SendUnknown, wantProvider: "configured_email"},
		{name: "transport", err: errors.New("credential=must-not-escape"), wantDisposition: notification.SendUnknown, wantProvider: "configured_email"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &testProvider{result: test.result, err: test.err}
			sender := newMemberSender(&testContactResolver{contact: "member@example.test"}, map[notification.Channel]ProviderTransport{
				notification.ChannelEmail: provider,
			}, time.Second)
			outboxID := uuid.New()
			result := sender.Send(context.Background(), notification.DeliveryAttempt{
				OutboxID: outboxID, ScopeID: uuid.New(), RecipientID: uuid.New(),
				Channel: notification.ChannelEmail, Subject: "subject", Body: "body",
				DedupKey: "notification-v1-stable", AttemptNumber: 2,
			})
			if test.wantDisposition != "" {
				if result.Failure != nil || result.Disposition != test.wantDisposition ||
					result.Provider != test.wantProvider || result.ProviderDeliveryID != test.wantDeliveryID {
					t.Fatalf("provider disposition = %+v", result)
				}
			} else if result.Failure == nil || result.Failure.Class != test.wantClass ||
				result.Failure.Code != test.wantCode || result.Failure.RetryAfter != test.wantAfter {
				t.Fatalf("failure = %+v", result.Failure)
			}
			messages, _ := provider.snapshot()
			if len(messages) != 1 || messages[0].IdempotencyKey != "notification-v1-stable" ||
				messages[0].OutboxID != outboxID || messages[0].AttemptNumber != 2 {
				t.Fatalf("provider messages = %+v", messages)
			}
		})
	}
}

func TestRecoverySenderUsesProviderBoundaryWithoutMemberResolution(t *testing.T) {
	provider := &testProvider{result: ProviderResult{Disposition: ProviderAccepted}}
	sender := newRecoverySender(map[notification.Channel]ProviderTransport{
		notification.ChannelSMS: provider,
	}, time.Second)
	result := sender.SendRecovery(context.Background(), accountrecovery.RecoveryDelivery{
		OutboxID: uuid.New(), Channel: notification.ChannelSMS, Contact: "+8613800000000",
		Body: "recovery", RecoveryURL: "https://control.example.test/reset#token=secret",
		IdempotencyKey: "notification-v1-recovery", AttemptNumber: 1,
	})
	if result.Failure != nil {
		t.Fatalf("recovery failure = %+v", result.Failure)
	}
	messages, _ := provider.snapshot()
	if len(messages) != 1 || messages[0].Contact != "+8613800000000" ||
		messages[0].ActionURL == "" || messages[0].IdempotencyKey != "notification-v1-recovery" {
		t.Fatalf("recovery provider message = %+v", messages)
	}
}

func TestProviderContractRejectsInvalidResults(t *testing.T) {
	for _, providerResult := range []ProviderResult{
		{Disposition: ProviderRateLimited, Code: "raw provider body: secret", RetryAfter: -time.Second},
		{Disposition: ProviderTemporaryFailure, Code: "provider_token_invalid"},
	} {
		provider := &testProvider{result: providerResult}
		sender := newRecoverySender(map[notification.Channel]ProviderTransport{
			notification.ChannelEmail: provider,
		}, time.Second)
		result := sender.SendRecovery(context.Background(), accountrecovery.RecoveryDelivery{
			OutboxID: uuid.New(), Channel: notification.ChannelEmail, Contact: "member@example.test",
			IdempotencyKey: "notification-v1-key", AttemptNumber: 1,
		})
		if result.Failure == nil || result.Failure.Class != notification.FailurePermanent ||
			result.Failure.Code != "provider_contract_invalid" {
			t.Fatalf("invalid provider result = %+v", result)
		}
	}
}

func TestProviderSendPanicIsUnknownAndDoesNotPoisonSubsequentDelivery(t *testing.T) {
	tests := []struct {
		name string
		send func(*panicOnceProvider) notification.SendResult
	}{
		{
			name: "member delivery",
			send: func(provider *panicOnceProvider) notification.SendResult {
				sender := newMemberSender(
					&testContactResolver{contact: "member@example.test"},
					map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider},
					time.Second,
				)
				return sender.Send(context.Background(), notification.DeliveryAttempt{
					OutboxID: uuid.New(), ScopeID: uuid.New(), RecipientID: uuid.New(),
					Channel: notification.ChannelEmail, DedupKey: "notification-v1-member-panic",
					AttemptNumber: 1,
				})
			},
		},
		{
			name: "recovery delivery",
			send: func(provider *panicOnceProvider) notification.SendResult {
				sender := newRecoverySender(
					map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider},
					time.Second,
				)
				return sender.SendRecovery(context.Background(), accountrecovery.RecoveryDelivery{
					OutboxID: uuid.New(), Channel: notification.ChannelEmail,
					Contact: "member@example.test", IdempotencyKey: "notification-v1-recovery-panic",
					AttemptNumber: 1,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := &panicOnceProvider{}
			first := test.send(provider)
			if first.Failure != nil || first.Disposition != notification.SendUnknown {
				t.Fatalf("panic result = %+v", first)
			}
			if second := test.send(provider); second.Failure != nil || second.Disposition != notification.SendAccepted {
				t.Fatalf("delivery after panic = %+v", second)
			}
		})
	}
}

func TestProviderPostSendErrorClassificationPanicPropagates(t *testing.T) {
	provider := &testProvider{err: panicOnIsError{}}
	sender := newRecoverySender(
		map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider},
		time.Second,
	)
	panicValue := capturePanic(func() {
		_ = sender.SendRecovery(context.Background(), accountrecovery.RecoveryDelivery{
			OutboxID: uuid.New(), Channel: notification.ChannelEmail,
			Contact: "member@example.test", IdempotencyKey: "notification-v1-post-send-panic",
			AttemptNumber: 1,
		})
	})
	if panicValue != "post-provider classification panic" {
		t.Fatalf("post-provider panic = %v", panicValue)
	}
}

func capturePanic(run func()) (panicValue any) {
	defer func() { panicValue = recover() }()
	run()
	return nil
}
