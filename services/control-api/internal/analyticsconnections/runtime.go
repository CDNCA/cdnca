package analyticsconnections

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

const ConnectionsSubject = ConnectionsSubjectPrefix + ".*.*"

var errDeliveryRetryScheduled = errors.New("connections delivery retry scheduled")

type RuntimeConfig struct {
	Enabled          bool
	NATSURL          string
	Stream           string
	Durable          string
	Subject          string
	Endpoint         string
	Database         string
	Username         string
	Password         string
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	MaxResponseBytes int64
}

func ValidateRuntimeConfig(config RuntimeConfig) error {
	if !config.Enabled {
		return nil
	}
	operationTimeout := config.OperationTimeout.Truncate(time.Millisecond)
	if !validID(config.NATSURL) || !validID(config.Stream) || !validID(config.Durable) || config.Subject != ConnectionsSubject || config.Endpoint == "" || !validID(config.Database) || config.ConnectTimeout <= 0 || operationTimeout < time.Millisecond || operationTimeout > 30*time.Second || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > 16<<20 {
		return ErrInvalidConfiguration
	}
	return nil
}

type Runtime struct {
	subscriber       Subscriber
	store            Store
	operationTimeout time.Duration
	brokerWait       func(context.Context, time.Duration) error
	metrics          runtimeMetrics
}

type RuntimeMetricsSnapshot struct {
	RetryScheduled     uint64 `json:"retry_scheduled"`
	BrokerRetries      uint64 `json:"broker_retries"`
	DeadLettered       uint64 `json:"dead_lettered"`
	DeadLetterFailures uint64 `json:"dead_letter_failures"`
}

type runtimeMetrics struct {
	retryScheduled     atomic.Uint64
	brokerRetries      atomic.Uint64
	deadLettered       atomic.Uint64
	deadLetterFailures atomic.Uint64
}

func NewRuntime(config RuntimeConfig, subscriber Subscriber, store Store) (*Runtime, error) {
	if err := ValidateRuntimeConfig(config); err != nil {
		return nil, err
	}
	if !config.Enabled {
		return nil, nil
	}
	if subscriber == nil || store == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Runtime{
		subscriber: subscriber, store: store, operationTimeout: config.OperationTimeout.Truncate(time.Millisecond), brokerWait: waitBrokerRetry,
	}, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || runtime.subscriber == nil || runtime.store == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	if err := validateRuntimeCallerBudget(ctx); err != nil {
		return err
	}
	var brokerAttempts uint64
	for {
		delivery, err := runtime.subscriber.Next(ctx)
		if err != nil {
			if errors.Is(err, ErrBrokerUnavailable) {
				brokerAttempts++
				runtime.metrics.brokerRetries.Add(1)
				if err := runtime.waitForBroker(ctx, brokerRetryDelay(brokerAttempts)); err != nil {
					return err
				}
				continue
			}
			if errors.Is(err, ErrInvalidDelivery) && ValidateDeliveryMetadata(delivery) == nil {
				if err := runtime.processDelivery(ctx, delivery); err != nil {
					if errors.Is(err, errDeliveryRetryScheduled) {
						continue
					}
					return err
				}
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}
		brokerAttempts = 0
		if err := runtime.processDelivery(ctx, delivery); err != nil {
			if errors.Is(err, errDeliveryRetryScheduled) {
				continue
			}
			return err
		}
	}
}

func (runtime *Runtime) processDelivery(ctx context.Context, delivery Delivery) error {
	if runtime == nil || runtime.subscriber == nil || runtime.store == nil || ctx == nil {
		return ErrInvalidConfiguration
	}
	if err := validateRuntimeCallerBudget(ctx); err != nil {
		return err
	}
	if err := ValidateDeliveryMetadata(delivery); err != nil {
		return err
	}
	operationCtx, cancel := runtime.operationContext(ctx)
	err := Process(operationCtx, delivery, runtime.store)
	cancel()
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return err
	}
	reason, permanent := classifyDeliveryFailure(err)
	if reason == DeliveryFailureNone {
		return err
	}
	if !permanent && delivery.Attempt < delivery.MaxDeliver {
		if err := runtime.nak(ctx, delivery); err != nil {
			return err
		}
		runtime.metrics.retryScheduled.Add(1)
		return nil
	}
	if !permanent {
		reason = DeliveryFailureMaxDeliver
	}
	delivery.FailureReason = reason
	receipt, receiptErr := ValidateDelivery(delivery)
	if receiptErr != nil && reason != DeliveryFailureInvalid {
		return receiptErr
	}
	if err := runtime.publishDeadLetter(ctx, delivery, receipt); err != nil {
		runtime.metrics.deadLetterFailures.Add(1)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if nakErr := runtime.nak(ctx, delivery); nakErr != nil {
			return nakErr
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		runtime.metrics.retryScheduled.Add(1)
		return errors.Join(errDeliveryRetryScheduled, err)
	}
	operationCtx, cancel = runtime.operationContext(ctx)
	err = delivery.Term(operationCtx)
	cancel()
	if err != nil {
		return err
	}
	runtime.metrics.deadLettered.Add(1)
	return nil
}

func (runtime *Runtime) publishDeadLetter(ctx context.Context, delivery Delivery, receipt Receipt) error {
	operationCtx, cancel := runtime.operationContext(ctx)
	defer cancel()
	return runtime.subscriber.PublishDeadLetter(operationCtx, delivery, receipt)
}

func (runtime *Runtime) nak(ctx context.Context, delivery Delivery) error {
	operationCtx, cancel := runtime.operationContext(ctx)
	defer cancel()
	return delivery.Nak(operationCtx, redeliveryDelay(delivery.Attempt))
}

func (runtime *Runtime) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := runtime.operationTimeout.Truncate(time.Millisecond)
	if timeout < time.Millisecond {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func validateRuntimeCallerBudget(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < time.Millisecond {
		return context.DeadlineExceeded
	}
	return nil
}

func (runtime *Runtime) Metrics() RuntimeMetricsSnapshot {
	if runtime == nil {
		return RuntimeMetricsSnapshot{}
	}
	return RuntimeMetricsSnapshot{
		RetryScheduled: runtime.metrics.retryScheduled.Load(), BrokerRetries: runtime.metrics.brokerRetries.Load(),
		DeadLettered:       runtime.metrics.deadLettered.Load(),
		DeadLetterFailures: runtime.metrics.deadLetterFailures.Load(),
	}
}

func (runtime *Runtime) waitForBroker(ctx context.Context, delay time.Duration) error {
	wait := runtime.brokerWait
	if wait == nil {
		wait = waitBrokerRetry
	}
	return wait(ctx, delay)
}

func waitBrokerRetry(ctx context.Context, delay time.Duration) error {
	if ctx == nil || delay <= 0 || delay > 5*time.Second {
		return ErrInvalidConfiguration
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func brokerRetryDelay(attempt uint64) time.Duration {
	return redeliveryDelay(attempt)
}

func classifyDeliveryFailure(err error) (DeliveryFailureReason, bool) {
	switch {
	case errors.Is(err, ErrInvalidDelivery):
		return DeliveryFailureInvalid, true
	case errors.Is(err, ErrReceiptConflict):
		return DeliveryFailureReceiptConflict, true
	case errors.Is(err, ErrClickHouseUnavailable):
		return DeliveryFailureClickHouseUnavailable, false
	case errors.Is(err, ErrClickHouseOutcomeUnknown):
		return DeliveryFailureOutcomeUnknown, false
	default:
		return DeliveryFailureNone, false
	}
}

func redeliveryDelay(attempt uint64) time.Duration {
	delay := 100 * time.Millisecond
	for remaining := attempt; remaining > 1 && delay < 5*time.Second; remaining-- {
		delay *= 2
	}
	if delay > 5*time.Second {
		return 5 * time.Second
	}
	return delay
}

func (runtime *Runtime) Close() error {
	if runtime == nil || runtime.subscriber == nil {
		return nil
	}
	return runtime.subscriber.Close()
}
