package acmeruntime

import (
	"context"
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
	"sync/atomic"
	"time"
)

type DispatchSource interface {
	DispatchOne(context.Context) (DispatchResult, error)
}

type RunnerConfig struct {
	PollInterval    time.Duration
	ErrorBackoffMin time.Duration
	ErrorBackoffMax time.Duration
}

func DefaultRunnerConfig() RunnerConfig {
	return RunnerConfig{
		PollInterval:    time.Second,
		ErrorBackoffMin: time.Second,
		ErrorBackoffMax: 30 * time.Second,
	}
}

type Runner struct {
	dispatcher DispatchSource
	config     RunnerConfig
	wait       func(context.Context, time.Duration) error
	running    atomic.Bool
}

func NewRunner(dispatcher DispatchSource, config RunnerConfig) (*Runner, error) {
	return newRunner(dispatcher, config, waitForContext)
}

func newRunner(
	dispatcher DispatchSource,
	config RunnerConfig,
	wait func(context.Context, time.Duration) error,
) (*Runner, error) {
	if dispatcher == nil || wait == nil || config.PollInterval <= 0 ||
		config.ErrorBackoffMin <= 0 || config.ErrorBackoffMax < config.ErrorBackoffMin ||
		config.PollInterval > time.Hour || config.ErrorBackoffMax > time.Hour {
		return nil, ErrInvalidInput
	}
	return &Runner{dispatcher: dispatcher, config: config, wait: wait}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidInput
	}
	if !r.running.CompareAndSwap(false, true) {
		return errors.New("ACME runtime is already running")
	}
	defer r.running.Store(false)

	errorBackoff := r.config.ErrorBackoffMin
	for {
		if installationlock.Skip("acme_dispatch") {
			if waitErr := r.wait(ctx, r.config.PollInterval); waitErr != nil {
				return waitErr
			}
			continue
		}
		result, err := r.dispatcher.DispatchOne(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if waitErr := r.wait(ctx, errorBackoff); waitErr != nil {
				return waitErr
			}
			errorBackoff = nextBackoff(errorBackoff, r.config.ErrorBackoffMax)
			continue
		}
		errorBackoff = r.config.ErrorBackoffMin

		switch result.Outcome {
		case OutcomeIdle:
			if waitErr := r.wait(ctx, r.config.PollInterval); waitErr != nil {
				return waitErr
			}
		case OutcomeCompleted, OutcomeRetry, OutcomeExhausted:
		default:
			return errors.New("ACME runtime dispatcher returned an invalid outcome")
		}
	}
}

func (r *Runner) Ready() error {
	if r == nil || !r.running.Load() {
		return errors.New("ACME runtime is unavailable")
	}
	return nil
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func waitForContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
