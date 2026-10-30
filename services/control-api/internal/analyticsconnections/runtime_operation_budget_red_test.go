package analyticsconnections

import (
	"context"
	"errors"
	"testing"
	"time"
)

var errRuntimeCapacityWorkReached = errors.New("runtime capacity work reached")

func TestRuntimeRejectsSubMillisecondBudgetsBeforeSubscriberOrStore(t *testing.T) {
	t.Run("sub-millisecond config", func(t *testing.T) {
		config := validRuntimeCapacityConfig()
		config.OperationTimeout = 500 * time.Microsecond
		runtime, err := NewRuntime(config, &runtimeCapacitySubscriber{}, &runtimeCapacityStore{})
		if !errors.Is(err, ErrInvalidConfiguration) || runtime != nil {
			t.Fatalf("NewRuntime() = (%#v, %v), want invalid configuration", runtime, err)
		}
	})

	t.Run("configured timeout floors to milliseconds", func(t *testing.T) {
		config := validRuntimeCapacityConfig()
		config.OperationTimeout = 1500 * time.Microsecond
		runtime, err := NewRuntime(config, &runtimeCapacitySubscriber{}, &runtimeCapacityStore{})
		if err != nil || runtime.operationTimeout != time.Millisecond {
			t.Fatalf("NewRuntime() timeout = %s, err=%v, want 1ms", runtime.operationTimeout, err)
		}
	})

	t.Run("caller budget stops before subscriber", func(t *testing.T) {
		subscriber := &runtimeCapacitySubscriber{}
		store := &runtimeCapacityStore{}
		runtime, err := NewRuntime(validRuntimeCapacityConfig(), subscriber, store)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Microsecond)
		defer cancel()
		if err := runtime.Run(ctx); !errors.Is(err, context.DeadlineExceeded) || subscriber.nextCalls != 0 || store.prepareCalls != 0 {
			t.Fatalf("Run() error=%v next=%d prepare=%d", err, subscriber.nextCalls, store.prepareCalls)
		}
	})

	t.Run("caller budget stops before store", func(t *testing.T) {
		store := &runtimeCapacityStore{}
		runtime, err := NewRuntime(validRuntimeCapacityConfig(), &runtimeCapacitySubscriber{}, store)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Microsecond)
		defer cancel()
		if err := runtime.processDelivery(ctx, runtimeRedeliveryDelivery(t, 1, 4)); !errors.Is(err, context.DeadlineExceeded) || store.prepareCalls != 0 {
			t.Fatalf("processDelivery() error=%v prepare=%d", err, store.prepareCalls)
		}
	})

	t.Run("configured timeout bounds store", func(t *testing.T) {
		config := validRuntimeCapacityConfig()
		config.OperationTimeout = 20 * time.Millisecond
		store := &runtimeCapacityStore{}
		runtime, err := NewRuntime(config, &runtimeCapacitySubscriber{}, store)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		callerDeadline, _ := ctx.Deadline()
		if err := runtime.processDelivery(ctx, runtimeRedeliveryDelivery(t, 1, 4)); !errors.Is(err, errRuntimeCapacityWorkReached) ||
			store.prepareCalls != 1 || store.deadline.IsZero() || !store.deadline.Before(callerDeadline) {
			t.Fatalf("processDelivery() error=%v prepare=%d store deadline=%v caller=%v", err, store.prepareCalls, store.deadline, callerDeadline)
		}
	})

	t.Run("smaller caller deadline is preserved", func(t *testing.T) {
		runtime, err := NewRuntime(validRuntimeCapacityConfig(), &runtimeCapacitySubscriber{}, &runtimeCapacityStore{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		callerDeadline, _ := ctx.Deadline()
		operationCtx, operationCancel := runtime.operationContext(ctx)
		defer operationCancel()
		operationDeadline, ok := operationCtx.Deadline()
		if !ok || operationDeadline.After(callerDeadline) {
			t.Fatalf("operation deadline=%v caller deadline=%v", operationDeadline, callerDeadline)
		}
	})
}

func TestRuntimeCapacityConfigRemainsFailClosed(t *testing.T) {
	config := validRuntimeCapacityConfig()
	config.MaxResponseBytes = 16<<20 + 1
	if runtime, err := NewRuntime(config, &runtimeCapacitySubscriber{}, &runtimeCapacityStore{}); !errors.Is(err, ErrInvalidConfiguration) || runtime != nil {
		t.Fatalf("over-limit response config = (%#v, %v)", runtime, err)
	}
}

func validRuntimeCapacityConfig() RuntimeConfig {
	return RuntimeConfig{
		Enabled: true, NATSURL: "nats://127.0.0.1:4222", Stream: "CONNECTIONS_INGEST_V1",
		Durable: "connections", Subject: ConnectionsSubject, Endpoint: "https://clickhouse.example.test",
		Database: "analytics", ConnectTimeout: time.Second, OperationTimeout: time.Second, MaxResponseBytes: 1 << 20,
	}
}

type runtimeCapacitySubscriber struct {
	nextCalls int
}

func (subscriber *runtimeCapacitySubscriber) Next(context.Context) (Delivery, error) {
	subscriber.nextCalls++
	return Delivery{}, errRuntimeCapacityWorkReached
}

func (*runtimeCapacitySubscriber) PublishDeadLetter(context.Context, Delivery, Receipt) error {
	return errRuntimeCapacityWorkReached
}

func (*runtimeCapacitySubscriber) Close() error { return nil }

type runtimeCapacityStore struct {
	prepareCalls int
	deadline     time.Time
}

func (store *runtimeCapacityStore) Prepare(ctx context.Context, _ Receipt) error {
	store.prepareCalls++
	store.deadline, _ = ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return err
	}
	return errRuntimeCapacityWorkReached
}

func (*runtimeCapacityStore) MarkBrokerAckObserved(context.Context, Receipt, PubAck) error {
	return errRuntimeCapacityWorkReached
}
