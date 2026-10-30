package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cccoord"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securitycoordmetrics"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type ccCoordinationConsumer interface {
	RunOnce(context.Context) (cccoord.ObserveResult, error)
	Close() error
}

type ccCoordinationRunner interface {
	RunOnce(context.Context) (cccoord.RunResult, error)
}

type ccCoordinationRuntime struct {
	store       *cccoord.Store
	consumer    ccCoordinationConsumer
	coordinator ccCoordinationRunner
	connection  *nats.Conn
	ready       atomic.Bool
	closeOnce   sync.Once
	closeErr    error
	metrics     *securitycoordmetrics.Registry
}

func openCCCoordinationRuntime(pool *pgxpool.Pool, connection *nats.Conn,
	activation *securityactivation.Store,
) (*ccCoordinationRuntime, error) {
	if !configuredRuntimePool(pool) || connection == nil || connection.IsClosed() || activation == nil {
		return nil, cccoord.ErrInvalidInput
	}
	config := cccoord.DefaultConfig()
	metrics := securitycoordmetrics.NewRegistry()
	store, err := cccoord.NewStoreWithMetrics(pool, time.Now, config, metrics)
	if err != nil {
		return nil, err
	}
	publisher, err := cccoord.NewPolicyPublisher(
		securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)), activation, store, time.Now,
	)
	if err != nil {
		return nil, err
	}
	coordinator, err := cccoord.NewCoordinator(store, publisher, "control-api-cccoord-"+uuid.NewString(), config)
	if err != nil {
		return nil, err
	}
	consumer, err := cccoord.NewNATSConsumer(connection, store, cccoord.DefaultNATSConfig())
	if err != nil {
		return nil, err
	}
	runtime := &ccCoordinationRuntime{store: store, consumer: consumer, coordinator: coordinator, connection: connection, metrics: metrics}
	runtime.ready.Store(true)
	return runtime, nil
}

func (runtime *ccCoordinationRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.consumer == nil || runtime.coordinator == nil || ctx == nil {
		return cccoord.ErrInvalidInput
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	finished := make(chan error, 2)
	go func() { finished <- runtime.consume(runCtx) }()
	go func() { finished <- runtime.coordinate(runCtx) }()
	err := <-finished
	cancel()
	<-finished
	runtime.ready.Store(false)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (runtime *ccCoordinationRuntime) consume(ctx context.Context) error {
	for {
		result, err := runtime.consumer.RunOnce(ctx)
		runtime.recordObserve(result, err)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil || errors.Is(err, nats.ErrTimeout) || errors.Is(err, cccoord.ErrInvalidInput) ||
			errors.Is(err, cccoord.ErrScopeMismatch) || errors.Is(err, cccoord.ErrCapacity) ||
			errors.Is(err, cccoord.ErrIdempotencyConflict) {
			continue
		}
		if err := waitCCCoordination(ctx, time.Second); err != nil {
			return err
		}
	}
}

func (runtime *ccCoordinationRuntime) coordinate(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		result, err := runtime.coordinator.RunOnce(ctx)
		runtime.recordCoordination(result, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitCCCoordination(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (runtime *ccCoordinationRuntime) Ready() error {
	if runtime == nil || !runtime.ready.Load() || runtime.connection == nil || !runtime.connection.IsConnected() {
		return cccoord.ErrUnavailable
	}
	return nil
}

func (runtime *ccCoordinationRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		runtime.ready.Store(false)
		if runtime.consumer != nil {
			runtime.closeErr = runtime.consumer.Close()
		}
	})
	return runtime.closeErr
}

func (runtime *ccCoordinationRuntime) Store() *cccoord.Store {
	if runtime == nil {
		return nil
	}
	return runtime.store
}

func (runtime *ccCoordinationRuntime) MetricsSnapshot() securitycoordmetrics.Snapshot {
	if runtime == nil || runtime.metrics == nil {
		return securitycoordmetrics.Snapshot{}
	}
	return runtime.metrics.Snapshot()
}

func (runtime *ccCoordinationRuntime) recordObserve(result cccoord.ObserveResult, err error) {
	if runtime == nil || runtime.metrics == nil || errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.Canceled) {
		return
	}
	reason := securitycoordmetrics.ReasonNone
	switch {
	case errors.Is(err, cccoord.ErrCapacity), err == nil && result.Rejected > 0:
		reason = securitycoordmetrics.ReasonCapacityRejected
	case errors.Is(err, cccoord.ErrScopeMismatch):
		reason = securitycoordmetrics.ReasonScopeRejected
	case errors.Is(err, cccoord.ErrInvalidInput):
		reason = securitycoordmetrics.ReasonInvalidInput
	case errors.Is(err, cccoord.ErrIdempotencyConflict), errors.Is(err, cccoord.ErrGenerationConflict):
		reason = securitycoordmetrics.ReasonConflict
	case err != nil:
		reason = securitycoordmetrics.ReasonDependencyUnavailable
	}
	runtime.metrics.RecordCCObserve(securitycoordmetrics.CCObserve{
		Accepted: result.Accepted, Duplicates: result.Duplicates, Rejected: result.Rejected,
		Queued: result.Queued, Reason: reason,
	})
}

func (runtime *ccCoordinationRuntime) recordCoordination(result cccoord.RunResult, err error) {
	if runtime == nil || runtime.metrics == nil || errors.Is(err, context.Canceled) {
		return
	}
	reason := securitycoordmetrics.ReasonNone
	if err != nil {
		reason = securitycoordmetrics.ReasonDependencyUnavailable
	}
	runtime.metrics.RecordCCCoordination(securitycoordmetrics.CCCoordination{
		Claimed: result.Claimed, Published: result.Published, Retryable: result.Retryable,
		ActivationActive: result.ActivationActive, ActivationFailed: result.ActivationFailed, Reason: reason,
	})
}
