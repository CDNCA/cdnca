package l4lineswitch

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type ReconcilerConfig struct {
	PollInterval     time.Duration
	ErrorBackoff     time.Duration
	OperationTimeout time.Duration
	BatchSize        int
}

func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{
		PollInterval: time.Second, ErrorBackoff: 3 * time.Second,
		OperationTimeout: 15 * time.Second, BatchSize: 32,
	}
}

type reconcileRunner interface {
	Reconcile(context.Context, Actor, uuid.UUID, uuid.UUID) (Switch, error)
}

type Reconciler struct {
	active ActiveSwitchReader
	runner reconcileRunner
	config ReconcilerConfig
}

func NewReconciler(active ActiveSwitchReader, runner reconcileRunner, config ReconcilerConfig) (*Reconciler, error) {
	if active == nil || runner == nil || config.PollInterval <= 0 || config.PollInterval > time.Minute ||
		config.ErrorBackoff <= 0 || config.ErrorBackoff > 5*time.Minute || config.OperationTimeout <= 0 ||
		config.OperationTimeout > 5*time.Minute || config.BatchSize < 1 || config.BatchSize > 100 {
		return nil, ErrInvalidInput
	}
	return &Reconciler{active: active, runner: runner, config: config}, nil
}

func (reconciler *Reconciler) RunOnce(ctx context.Context) error {
	if reconciler == nil || ctx == nil {
		return ErrInvalidInput
	}
	items, err := reconciler.active.ListActive(ctx, reconciler.config.BatchSize)
	if err != nil {
		return err
	}
	for _, item := range items {
		operationContext, cancel := context.WithTimeout(ctx, reconciler.config.OperationTimeout)
		_, err := reconciler.runner.Reconcile(
			operationContext, ReconcilerActor(), item.ConfigurationScopeID, item.SwitchID,
		)
		cancel()
		if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) &&
			!errors.Is(err, ErrUnsafeRollback) {
			return err
		}
	}
	return nil
}

func (reconciler *Reconciler) Run(ctx context.Context) error {
	if reconciler == nil || ctx == nil {
		return ErrInvalidInput
	}
	for {
		delay := reconciler.config.PollInterval
		if err := reconciler.RunOnce(ctx); err != nil {
			delay = reconciler.config.ErrorBackoff
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
