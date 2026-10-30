package analyticsconnections

import (
	"context"
	"errors"
	"testing"
	"time"
)

var (
	errDLQPublishRetryTest = errors.New("dead-letter publication outcome unknown")
	errDLQRetryLoopSeen    = errors.New("retry loop continued")
	errDLQNakFailed        = errors.New("dead-letter retry NAK failed")
)

type dlqPublishRetrySubscriber struct {
	delivery     Delivery
	nextErr      error
	publish      func(context.Context, Delivery, Receipt) error
	nextCalls    int
	publishCalls int
	published    Delivery
}

func (subscriber *dlqPublishRetrySubscriber) Next(context.Context) (Delivery, error) {
	subscriber.nextCalls++
	if subscriber.nextCalls == 1 {
		return subscriber.delivery, nil
	}
	return Delivery{}, subscriber.nextErr
}

func (subscriber *dlqPublishRetrySubscriber) PublishDeadLetter(
	ctx context.Context,
	delivery Delivery,
	receipt Receipt,
) error {
	subscriber.publishCalls++
	subscriber.published = delivery
	if subscriber.publish != nil {
		return subscriber.publish(ctx, delivery, receipt)
	}
	return errDLQPublishRetryTest
}

func (*dlqPublishRetrySubscriber) Close() error { return nil }

func TestRuntimeDLQPublishFailureContinuesOnlyAfterSuccessfulNak(t *testing.T) {
	t.Run("successful NAK preserves identity and continues", func(t *testing.T) {
		delivery := runtimeRedeliveryDelivery(t, 4, 4)
		var ackCalls, nakCalls, termCalls int
		delivery.Ack = func(context.Context) error {
			ackCalls++
			return nil
		}
		delivery.Nak = func(_ context.Context, delay time.Duration) error {
			nakCalls++
			if delay < 100*time.Millisecond || delay > 5*time.Second {
				t.Fatalf("NAK delay = %s, want bounded redelivery delay", delay)
			}
			return nil
		}
		delivery.Term = func(context.Context) error {
			termCalls++
			return nil
		}
		subscriber := &dlqPublishRetrySubscriber{delivery: delivery, nextErr: errDLQRetryLoopSeen}
		runtime := &Runtime{
			subscriber: subscriber,
			store:      &redeliveryTestStore{prepareErr: ErrClickHouseUnavailable},
		}

		if err := runtime.Run(context.Background()); !errors.Is(err, errDLQRetryLoopSeen) {
			t.Fatalf("Run error = %v, want evidence that the retry loop continued", err)
		}
		if subscriber.nextCalls != 2 || subscriber.publishCalls != 1 || nakCalls != 1 || ackCalls != 0 || termCalls != 0 {
			t.Fatalf("calls next=%d publish=%d nak=%d ack=%d term=%d",
				subscriber.nextCalls, subscriber.publishCalls, nakCalls, ackCalls, termCalls)
		}
		published := subscriber.published
		if published.BatchID != delivery.BatchID || published.ReceiptID != delivery.ReceiptID ||
			published.Stream != delivery.Stream || published.Durable != delivery.Durable ||
			published.StreamSequence != delivery.StreamSequence || published.ConsumerSequence != delivery.ConsumerSequence ||
			published.Attempt != delivery.Attempt || published.MaxDeliver != delivery.MaxDeliver ||
			published.FailureReason != DeliveryFailureMaxDeliver {
			t.Fatalf("published delivery identity drifted: %#v", published)
		}
		if metrics := runtime.Metrics(); metrics.DeadLetterFailures != 1 || metrics.DeadLettered != 0 {
			t.Fatalf("metrics = %#v", metrics)
		}
	})

	t.Run("NAK failure remains fail closed", func(t *testing.T) {
		delivery := runtimeRedeliveryDelivery(t, 4, 4)
		var ackCalls, termCalls int
		delivery.Ack = func(context.Context) error { ackCalls++; return nil }
		delivery.Nak = func(context.Context, time.Duration) error { return errDLQNakFailed }
		delivery.Term = func(context.Context) error { termCalls++; return nil }
		subscriber := &dlqPublishRetrySubscriber{delivery: delivery, nextErr: errDLQRetryLoopSeen}
		runtime := &Runtime{
			subscriber: subscriber,
			store:      &redeliveryTestStore{prepareErr: ErrClickHouseUnavailable},
		}

		if err := runtime.Run(context.Background()); !errors.Is(err, errDLQNakFailed) {
			t.Fatalf("Run error = %v, want NAK failure", err)
		}
		if subscriber.nextCalls != 1 || subscriber.publishCalls != 1 || ackCalls != 0 || termCalls != 0 {
			t.Fatalf("calls next=%d publish=%d ack=%d term=%d",
				subscriber.nextCalls, subscriber.publishCalls, ackCalls, termCalls)
		}
	})

	t.Run("caller cancellation remains fail closed", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		delivery := runtimeRedeliveryDelivery(t, 4, 4)
		var ackCalls, termCalls int
		delivery.Ack = func(context.Context) error { ackCalls++; return nil }
		delivery.Nak = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
		delivery.Term = func(context.Context) error { termCalls++; return nil }
		subscriber := &dlqPublishRetrySubscriber{
			delivery: delivery,
			nextErr:  errDLQRetryLoopSeen,
			publish: func(context.Context, Delivery, Receipt) error {
				cancel()
				return errDLQPublishRetryTest
			},
		}
		runtime := &Runtime{
			subscriber: subscriber,
			store:      &redeliveryTestStore{prepareErr: ErrClickHouseUnavailable},
		}

		if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want caller cancellation", err)
		}
		if subscriber.nextCalls != 1 || subscriber.publishCalls != 1 || ackCalls != 0 || termCalls != 0 {
			t.Fatalf("calls next=%d publish=%d ack=%d term=%d",
				subscriber.nextCalls, subscriber.publishCalls, ackCalls, termCalls)
		}
	})
}
