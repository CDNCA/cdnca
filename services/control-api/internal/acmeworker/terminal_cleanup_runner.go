package acmeworker

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

type TerminalCleanupRunnerConfig struct {
	BatchSize       int
	PollInterval    time.Duration
	ErrorBackoffMin time.Duration
	ErrorBackoffMax time.Duration
}

func DefaultTerminalCleanupRunnerConfig() TerminalCleanupRunnerConfig {
	return TerminalCleanupRunnerConfig{
		BatchSize: 16, PollInterval: time.Second,
		ErrorBackoffMin: time.Second, ErrorBackoffMax: 30 * time.Second,
	}
}

type terminalCleanupProcessor interface {
	CleanupTerminalChallengeOnce(context.Context) (bool, error)
}

type TerminalCleanupRunner struct {
	processor terminalCleanupProcessor
	config    TerminalCleanupRunnerConfig
	wait      func(context.Context, time.Duration) error
	running   atomic.Bool
}

func NewTerminalCleanupRunner(worker *Worker, config TerminalCleanupRunnerConfig) (*TerminalCleanupRunner, error) {
	if worker == nil {
		return nil, failure(CodeInvalidInput, nil)
	}
	if err := worker.TerminalCleanupReady(); err != nil {
		return nil, err
	}
	return newTerminalCleanupRunner(worker, config, waitForTerminalCleanupContext)
}

func newTerminalCleanupRunner(
	processor terminalCleanupProcessor,
	config TerminalCleanupRunnerConfig,
	wait func(context.Context, time.Duration) error,
) (*TerminalCleanupRunner, error) {
	if processor == nil || wait == nil || config.BatchSize < 1 || config.BatchSize > 1000 ||
		config.PollInterval <= 0 || config.PollInterval > time.Hour ||
		config.ErrorBackoffMin <= 0 || config.ErrorBackoffMax < config.ErrorBackoffMin ||
		config.ErrorBackoffMax > time.Hour {
		return nil, failure(CodeInvalidInput, nil)
	}
	return &TerminalCleanupRunner{processor: processor, config: config, wait: wait}, nil
}

func (runner *TerminalCleanupRunner) RunOnce(ctx context.Context) (int, error) {
	if runner == nil || ctx == nil {
		return 0, failure(CodeInvalidInput, nil)
	}
	processed := 0
	for processed < runner.config.BatchSize {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		found, err := runner.processor.CleanupTerminalChallengeOnce(ctx)
		if err != nil {
			return processed, err
		}
		if !found {
			return processed, nil
		}
		processed++
	}
	return processed, nil
}

func (runner *TerminalCleanupRunner) Run(ctx context.Context) error {
	if runner == nil || ctx == nil {
		return failure(CodeInvalidInput, nil)
	}
	if !runner.running.CompareAndSwap(false, true) {
		return errors.New("ACME terminal cleanup runner is already running")
	}
	defer runner.running.Store(false)

	errorBackoff := runner.config.ErrorBackoffMin
	for {
		_, err := runner.RunOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		delay := runner.config.PollInterval
		if err != nil {
			delay = errorBackoff
			errorBackoff = nextTerminalCleanupBackoff(errorBackoff, runner.config.ErrorBackoffMax)
		} else {
			errorBackoff = runner.config.ErrorBackoffMin
		}
		if err := runner.wait(ctx, delay); err != nil {
			return err
		}
	}
}

func (runner *TerminalCleanupRunner) Ready() error {
	if runner == nil || !runner.running.Load() {
		return errors.New("ACME terminal cleanup runner is unavailable")
	}
	return nil
}

func nextTerminalCleanupBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func waitForTerminalCleanupContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
