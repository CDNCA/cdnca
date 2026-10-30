package nodeserving

import (
	"context"
	"log/slog"
	"time"
)

// Evaluator is one hold source run by the worker each tick.
type Evaluator interface {
	Evaluate(context.Context) error
}

type Worker struct {
	interval   time.Duration
	evaluators []Evaluator
	store      *Store
	logger     *slog.Logger
}

func NewWorker(store *Store, interval time.Duration, logger *slog.Logger, evaluators ...Evaluator) (*Worker, error) {
	if store == nil || interval <= 0 {
		return nil, ErrInvalidInput
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{interval: interval, evaluators: evaluators, store: store, logger: logger}, nil
}

// RunOnce evaluates every source, then refreshes last-endpoint protection. One
// failing source does not stop the others; the first error is returned.
func (worker *Worker) RunOnce(ctx context.Context) error {
	var first error
	for _, evaluator := range worker.evaluators {
		if err := evaluator.Evaluate(ctx); err != nil && first == nil {
			first = err
		}
	}
	if err := worker.store.SyncProtection(ctx); err != nil && first == nil {
		first = err
	}
	return first
}

// Run never stops on a database error: holds are durable, so a missed tick
// only delays the next transition.
func (worker *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	for {
		if err := worker.RunOnce(ctx); err != nil && ctx.Err() == nil {
			worker.logger.Warn("node serving evaluation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// MonitorEvaluator applies the monitoring failure action "pause".
type MonitorEvaluator struct {
	store     *Store
	warmUntil time.Time
}

func NewMonitorEvaluator(store *Store) *MonitorEvaluator {
	return &MonitorEvaluator{store: store}
}

func (evaluator *MonitorEvaluator) Evaluate(ctx context.Context) error {
	candidates, now, err := evaluator.store.MonitorCandidates(ctx)
	if err != nil {
		return err
	}
	if evaluator.warmUntil.IsZero() {
		// One full stale window of observation before missing reports count.
		window := 390 * time.Second
		for _, candidate := range candidates {
			if candidate.Input.PolicyActive {
				window = StaleAfter(candidate.Input.Effective)
				break
			}
		}
		evaluator.warmUntil = now.Add(window)
	}
	var first error
	for _, candidate := range candidates {
		input := candidate.Input
		input.WarmUntil = evaluator.warmUntil
		if alert := DecideAlert(input, candidate.Alert); alert.Held != candidate.Alert.Offline {
			if _, err := evaluator.store.ApplyAlert(ctx, candidate.NodeID, candidate.ScopeID,
				candidate.Alert.Revision, alert); err != nil && first == nil {
				first = err
			}
		}
		decision := DecideMonitor(input)
		if decision.Held == input.Held {
			continue
		}
		if _, err := evaluator.store.Apply(ctx, candidate.NodeID, candidate.ScopeID, SourceAvailabilityMonitor,
			candidate.Revision, decision); err != nil && first == nil {
			first = err
		}
	}
	return first
}
