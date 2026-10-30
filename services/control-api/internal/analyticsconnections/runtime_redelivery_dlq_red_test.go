package analyticsconnections

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var errDeadLetterUnavailable = errors.New("dead letter unavailable")

type redeliveryTestSubscriber struct {
	delivery       Delivery
	publishErr     error
	actions        []string
	published      Delivery
	publishedState Receipt
	nextErrors     []error
	nextCalls      int
}

func (subscriber *redeliveryTestSubscriber) Next(context.Context) (Delivery, error) {
	if subscriber.nextCalls < len(subscriber.nextErrors) {
		err := subscriber.nextErrors[subscriber.nextCalls]
		subscriber.nextCalls++
		return Delivery{}, err
	}
	return subscriber.delivery, nil
}

func (subscriber *redeliveryTestSubscriber) PublishDeadLetter(_ context.Context, delivery Delivery, receipt Receipt) error {
	subscriber.actions = append(subscriber.actions, "publish")
	subscriber.published = delivery
	subscriber.publishedState = receipt
	return subscriber.publishErr
}

func (*redeliveryTestSubscriber) Close() error { return nil }

type redeliveryTestStore struct{ prepareErr error }

func (store *redeliveryTestStore) Prepare(context.Context, Receipt) error { return store.prepareErr }
func (*redeliveryTestStore) MarkBrokerAckObserved(context.Context, Receipt, PubAck) error {
	return nil
}

func TestRuntimeRetriesTransientFailureBeforeAuthoritativeMaxDeliver(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 2, 4)
	var actions []string
	delivery.Nak = func(_ context.Context, delay time.Duration) error {
		actions = append(actions, "nak")
		if delay < 100*time.Millisecond || delay > 5*time.Second {
			t.Fatalf("retry delay = %s, want bounded delay", delay)
		}
		return nil
	}
	delivery.Term = func(context.Context) error {
		actions = append(actions, "term")
		return nil
	}
	subscriber := &redeliveryTestSubscriber{delivery: delivery}
	runtime := &Runtime{subscriber: subscriber, store: &redeliveryTestStore{prepareErr: ErrClickHouseUnavailable}}

	if err := runtime.processDelivery(context.Background(), delivery); err != nil {
		t.Fatalf("process delivery: %v", err)
	}
	if strings.Join(actions, ",") != "nak" || len(subscriber.actions) != 0 {
		t.Fatalf("actions = delivery:%v subscriber:%v", actions, subscriber.actions)
	}
	if got := runtime.Metrics(); got.RetryScheduled != 1 || got.DeadLettered != 0 || got.DeadLetterFailures != 0 {
		t.Fatalf("metrics = %#v", got)
	}
}

func TestRuntimeDeadLettersExhaustedAndPermanentFailuresBeforeTerm(t *testing.T) {
	tests := []struct {
		name       string
		attempt    uint64
		maxDeliver uint64
		processErr error
		wantReason DeliveryFailureReason
	}{
		{name: "exhausted transient", attempt: 4, maxDeliver: 4, processErr: ErrClickHouseUnavailable, wantReason: DeliveryFailureMaxDeliver},
		{name: "permanent conflict", attempt: 1, maxDeliver: 4, processErr: ErrReceiptConflict, wantReason: DeliveryFailureReceiptConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivery := runtimeRedeliveryDelivery(t, test.attempt, test.maxDeliver)
			subscriber := &redeliveryTestSubscriber{delivery: delivery}
			delivery.Nak = func(context.Context, time.Duration) error {
				subscriber.actions = append(subscriber.actions, "nak")
				return nil
			}
			delivery.Term = func(context.Context) error {
				subscriber.actions = append(subscriber.actions, "term")
				return nil
			}
			subscriber.delivery = delivery
			runtime := &Runtime{subscriber: subscriber, store: &redeliveryTestStore{prepareErr: test.processErr}}

			if err := runtime.processDelivery(context.Background(), delivery); err != nil {
				t.Fatalf("process delivery: %v", err)
			}
			if got := strings.Join(subscriber.actions, ","); got != "publish,term" {
				t.Fatalf("actions = %q, want publish,term", got)
			}
			if subscriber.published.FailureReason != test.wantReason {
				t.Fatalf("failure reason = %q, want %q", subscriber.published.FailureReason, test.wantReason)
			}
			if subscriber.publishedState.StreamSequence != delivery.StreamSequence {
				t.Fatalf("published receipt lost broker identity: %#v", subscriber.publishedState)
			}
			if got := runtime.Metrics(); got.DeadLettered != 1 || got.RetryScheduled != 0 || got.DeadLetterFailures != 0 {
				t.Fatalf("metrics = %#v", got)
			}
		})
	}
}

func TestRuntimeDeadLetterUnknownOutcomeNeverTermsOrAcknowledges(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 4, 4)
	var acked, termed bool
	delivery.Ack = func(context.Context) error { acked = true; return nil }
	delivery.Term = func(context.Context) error { termed = true; return nil }
	nacked := false
	delivery.Nak = func(context.Context, time.Duration) error { nacked = true; return nil }
	subscriber := &redeliveryTestSubscriber{delivery: delivery, publishErr: errDeadLetterUnavailable}
	runtime := &Runtime{subscriber: subscriber, store: &redeliveryTestStore{prepareErr: ErrClickHouseUnavailable}}

	err := runtime.processDelivery(context.Background(), delivery)
	if !errors.Is(err, errDeadLetterUnavailable) {
		t.Fatalf("error = %v, want dead letter unavailable", err)
	}
	if acked || termed || !nacked {
		t.Fatalf("settlement = ack:%t term:%t nak:%t", acked, termed, nacked)
	}
	if got := runtime.Metrics(); got.DeadLetterFailures != 1 || got.DeadLettered != 0 {
		t.Fatalf("metrics = %#v", got)
	}
}

func TestRuntimeMetricsSnapshotNeverRetainsDeliveryData(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 2, 4)
	delivery.Payload = []byte("authorization=Bearer secret; cookie=session-secret")
	delivery.Nak = func(context.Context, time.Duration) error { return nil }
	runtime := &Runtime{subscriber: &redeliveryTestSubscriber{delivery: delivery}, store: &redeliveryTestStore{prepareErr: ErrClickHouseUnavailable}}
	if err := runtime.processDelivery(context.Background(), delivery); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(runtime.Metrics())
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "authorization", "cookie", "payload", "header"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("metrics leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestRuntimeRetriesBrokerUnavailableWithBoundedNonBusyDelay(t *testing.T) {
	subscriber := &redeliveryTestSubscriber{nextErrors: []error{
		ErrBrokerUnavailable,
		ErrBrokerUnavailable,
		context.Canceled,
	}}
	var delays []time.Duration
	runtime := &Runtime{
		subscriber: subscriber,
		store:      &redeliveryTestStore{},
		brokerWait: func(_ context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return nil
		},
	}

	if err := runtime.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v, want canceled", err)
	}
	if len(delays) != 2 {
		t.Fatalf("broker retry waits = %v", delays)
	}
	for index, delay := range delays {
		if delay < 100*time.Millisecond || delay > 5*time.Second {
			t.Fatalf("broker retry delay[%d] = %s", index, delay)
		}
		if index > 0 && delay < delays[index-1] {
			t.Fatalf("broker retry delay regressed: %v", delays)
		}
	}
	if subscriber.actions != nil {
		t.Fatalf("broker retry settled a nonexistent delivery: %v", subscriber.actions)
	}
	if got := runtime.Metrics(); got.BrokerRetries != 2 {
		t.Fatalf("metrics = %#v", got)
	}
}

func TestRuntimeBrokerErrorsPreserveCancellationAndFailClosedInvalidDelivery(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "invalid config", err: ErrInvalidConfiguration},
		{name: "invalid without metadata", err: ErrInvalidDelivery},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subscriber := &redeliveryTestSubscriber{nextErrors: []error{test.err}}
			waited := false
			runtime := &Runtime{
				subscriber: subscriber,
				store:      &redeliveryTestStore{},
				brokerWait: func(context.Context, time.Duration) error { waited = true; return nil },
			}
			if err := runtime.Run(context.Background()); !errors.Is(err, test.err) {
				t.Fatalf("run error = %v, want %v", err, test.err)
			}
			if waited || runtime.Metrics().BrokerRetries != 0 || subscriber.actions != nil {
				t.Fatalf("fail-closed path retried or settled: waited=%t metrics=%#v actions=%v", waited, runtime.Metrics(), subscriber.actions)
			}
		})
	}
}

func runtimeRedeliveryDelivery(t *testing.T, attempt, maxDeliver uint64) Delivery {
	t.Helper()
	delivery := validConnectionsDelivery()
	delivery.MetadataVersion = DeliveryMetadataVersion
	delivery.Attempt = attempt
	delivery.MaxDeliver = maxDeliver
	delivery.Nak = func(context.Context, time.Duration) error { return nil }
	delivery.Term = func(context.Context) error { return nil }
	return delivery
}
