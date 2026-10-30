package pluginwebhook

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type fakeQueueDelivery struct {
	data     []byte
	attempts uint64
	acked    bool
	naked    time.Duration
}

func (d *fakeQueueDelivery) Data() []byte              { return d.data }
func (d *fakeQueueDelivery) Attempts() uint64          { return d.attempts }
func (d *fakeQueueDelivery) StreamSequence() uint64    { return 42 }
func (d *fakeQueueDelivery) Ack(context.Context) error { d.acked = true; return nil }
func (d *fakeQueueDelivery) Nak(_ context.Context, delay time.Duration) error {
	d.naked = delay
	return nil
}

type fakeQueueConsumer struct{ delivery queueDelivery }

func (c *fakeQueueConsumer) Next(context.Context) (queueDelivery, error) {
	if c.delivery == nil {
		return nil, ErrNoDelivery
	}
	delivery := c.delivery
	c.delivery = nil
	return delivery, nil
}
func (*fakeQueueConsumer) Close() error { return nil }

type fakeDeliverer struct {
	result SendResult
	calls  int
}

func (d *fakeDeliverer) Deliver(context.Context, QueueItem, uint64) SendResult {
	d.calls++
	return d.result
}

type fakeDeadLetters struct{ records []DeadLetterRecord }

func (s *fakeDeadLetters) put(_ context.Context, record DeadLetterRecord) error {
	s.records = append(s.records, record)
	return nil
}

type fakeAttemptLogger struct {
	records        []AttemptRecord
	err            error
	hasDeadline    bool
	timeToDeadline time.Duration
}

func (l *fakeAttemptLogger) Record(ctx context.Context, record AttemptRecord) error {
	l.records = append(l.records, record)
	deadline, ok := ctx.Deadline()
	l.hasDeadline = ok
	if ok {
		l.timeToDeadline = time.Until(deadline)
	}
	return l.err
}

func TestWorkerSettlesSuccessRetryPermanentAndExhausted(t *testing.T) {
	t.Parallel()
	item, err := newQueueItem(PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID, EventID: "event-worker",
		EventType: "io.cdnca.site.v1.updated", TargetURL: "https://hooks.example.com/events",
		OccurredAt: time.Now().UTC(), Data: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		attempts uint64
		send     SendResult
		want     ProcessOutcome
		wantAck  bool
		wantNak  bool
		wantDLQ  bool
	}{
		{"success", 1, SendResult{Success: true, Code: "delivered", StatusCode: 204}, OutcomeDelivered, true, false, false},
		{"temporary", 1, SendResult{Retryable: true, Code: "remote_5xx", StatusCode: 503}, OutcomeRetryScheduled, false, true, false},
		{"permanent", 1, SendResult{Code: "remote_401", StatusCode: 401}, OutcomeDeadLettered, true, false, true},
		{"exhausted", 3, SendResult{Retryable: true, Code: "timeout"}, OutcomeDeadLettered, true, false, true},
		{"recovered after max", 4, SendResult{Success: true, Code: "delivered", StatusCode: 204}, OutcomeDeadLettered, true, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivery := &fakeQueueDelivery{data: payload, attempts: test.attempts}
			deliverer := &fakeDeliverer{result: test.send}
			deadLetters := &fakeDeadLetters{}
			worker, err := newWorker(&fakeQueueConsumer{delivery: delivery}, deliverer, deadLetters, WorkerConfig{
				MaxAttempts: 3, OperationTimeout: time.Second,
				Retry:        RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Minute, RetryAfterMax: 30 * time.Second},
				Now:          func() time.Time { return time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC) },
				RandomInt63n: func(int64) int64 { return 0 },
			}, &fakeAttemptLogger{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := worker.ProcessOne(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != test.want || delivery.acked != test.wantAck || (delivery.naked > 0) != test.wantNak ||
				(len(deadLetters.records) == 1) != test.wantDLQ {
				t.Fatalf("result=%#v delivery=%#v dead=%#v", result, delivery, deadLetters.records)
			}
			if test.name == "recovered after max" && deliverer.calls != 0 {
				t.Fatalf("plugin called %d times after max attempts", deliverer.calls)
			}
		})
	}
}

func TestWorkerDeadLettersMalformedMessagesWithoutCallingPlugin(t *testing.T) {
	t.Parallel()
	delivery := &fakeQueueDelivery{data: []byte(`{"schema":"bad"}`), attempts: 1}
	deliverer := &fakeDeliverer{}
	deadLetters := &fakeDeadLetters{}
	worker, err := newWorker(&fakeQueueConsumer{delivery: delivery}, deliverer, deadLetters, validTestWorkerConfig(), &fakeAttemptLogger{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeDeadLettered || !delivery.acked || deliverer.calls != 0 || len(deadLetters.records) != 1 ||
		deadLetters.records[0].ReasonCode != "invalid_message" {
		t.Fatalf("result=%#v calls=%d dead=%#v", result, deliverer.calls, deadLetters.records)
	}
}

func TestWorkerDoesNotAckWhenDeadLetterPersistenceFails(t *testing.T) {
	t.Parallel()
	delivery := &fakeQueueDelivery{data: []byte(`{"schema":"bad"}`), attempts: 1}
	worker, err := newWorker(&fakeQueueConsumer{delivery: delivery}, &fakeDeliverer{}, failingDeadLetters{}, validTestWorkerConfig(), &fakeAttemptLogger{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = worker.ProcessOne(context.Background())
	if err == nil || delivery.acked {
		t.Fatalf("error=%v acked=%v", err, delivery.acked)
	}
}

type failingDeadLetters struct{}

func (failingDeadLetters) put(context.Context, DeadLetterRecord) error {
	return errors.New("unavailable")
}

func TestWorkerDoesNotSettleWhenAttemptPersistenceFails(t *testing.T) {
	t.Parallel()
	item, err := newQueueItem(PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID, EventID: "event-attempt-store",
		EventType: "io.cdnca.site.v1.updated", TargetURL: "https://hooks.example.com/events",
		OccurredAt: time.Now().UTC(), Data: json.RawMessage(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	attemptStoreError := errors.New("attempt store unavailable")
	for _, test := range []struct {
		name string
		send SendResult
	}{
		{name: "success", send: SendResult{Success: true, Code: "delivered", StatusCode: 204}},
		{name: "retryable", send: SendResult{Retryable: true, Code: "remote_5xx", StatusCode: 503}},
		{name: "permanent", send: SendResult{Code: "remote_401", StatusCode: 401}},
	} {
		t.Run(test.name, func(t *testing.T) {
			delivery := &fakeQueueDelivery{data: payload, attempts: 1}
			deadLetters := &fakeDeadLetters{}
			logger := &fakeAttemptLogger{err: attemptStoreError}
			config := validTestWorkerConfig()
			worker, err := newWorker(
				&fakeQueueConsumer{delivery: delivery},
				&fakeDeliverer{result: test.send},
				deadLetters,
				config,
				logger,
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = worker.ProcessOne(context.Background())
			if !errors.Is(err, attemptStoreError) {
				t.Fatalf("error = %v, want attempt store error", err)
			}
			if delivery.acked || delivery.naked != 0 || len(deadLetters.records) != 0 {
				t.Fatalf("attempt persistence failure settled delivery: delivery=%#v dead=%#v", delivery, deadLetters.records)
			}
			if len(logger.records) != 1 || !logger.hasDeadline || logger.timeToDeadline <= 0 || logger.timeToDeadline > config.OperationTimeout {
				t.Fatalf("logger calls=%d deadline=%v remaining=%s", len(logger.records), logger.hasDeadline, logger.timeToDeadline)
			}
		})
	}
}

func TestWorkerRequiresAttemptLogger(t *testing.T) {
	t.Parallel()
	_, err := newWorker(
		&fakeQueueConsumer{},
		&fakeDeliverer{},
		&fakeDeadLetters{},
		validTestWorkerConfig(),
		nil,
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidConfig)
	}
}

func validTestWorkerConfig() WorkerConfig {
	return WorkerConfig{
		MaxAttempts: 3, OperationTimeout: time.Second,
		Retry: RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Minute, RetryAfterMax: 30 * time.Second},
		Now:   func() time.Time { return time.Now().UTC() }, RandomInt63n: func(int64) int64 { return 0 },
	}
}
