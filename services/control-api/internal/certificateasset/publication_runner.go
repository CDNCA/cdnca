package certificateasset

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	PublicationRunnerIdle            = "idle"
	PublicationRunnerProcessed       = "processed"
	PublicationRunnerDependencyError = "dependency_error"
	PublicationRunnerItemPanic       = "item_panic"
)

var (
	ErrPublicationRunnerAlreadyRunning = errors.New("certificate publication runner already running")
	ErrPublicationRunnerItemPanic      = errors.New("certificate publication runner item panic")
)

type PublicationRunnerMetric struct {
	Reason string
	Count  int
}

type PublicationRunnerConfig struct {
	BatchSize      int
	PollInterval   time.Duration
	IdleBackoffMin time.Duration
	IdleBackoffMax time.Duration
	ErrorBackoff   time.Duration
	Jitter         func(time.Duration) time.Duration
	Metrics        func(PublicationRunnerMetric)
}

func DefaultPublicationRunnerConfig() PublicationRunnerConfig {
	return PublicationRunnerConfig{
		BatchSize: 16, PollInterval: 100 * time.Millisecond,
		IdleBackoffMin: time.Second, IdleBackoffMax: 30 * time.Second,
		ErrorBackoff: time.Second, Jitter: securePublicationIntentJitter,
	}
}

type publicationRunnerProcessor interface {
	RunOnce(context.Context) (bool, error)
}

type PublicationRunner struct {
	processor publicationRunnerProcessor
	config    PublicationRunnerConfig
	wait      func(context.Context, time.Duration) error

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewPublicationRunner(
	worker *PublicationWorker,
	config PublicationRunnerConfig,
) (*PublicationRunner, error) {
	if worker == nil {
		return nil, ErrInvalidInput
	}
	return newPublicationRunner(worker, config, publicationRunnerWait)
}

func newPublicationRunner(
	processor publicationRunnerProcessor,
	config PublicationRunnerConfig,
	wait func(context.Context, time.Duration) error,
) (*PublicationRunner, error) {
	if nilPublicationDependency(processor) || wait == nil || config.BatchSize < 1 || config.BatchSize > 1000 ||
		config.PollInterval <= 0 || config.PollInterval > time.Minute || config.IdleBackoffMin <= 0 ||
		config.IdleBackoffMax < config.IdleBackoffMin || config.IdleBackoffMax > time.Hour ||
		config.ErrorBackoff <= 0 || config.ErrorBackoff > time.Hour || config.Jitter == nil {
		return nil, ErrInvalidInput
	}
	return &PublicationRunner{processor: processor, config: config, wait: wait}, nil
}

func (runner *PublicationRunner) Run(ctx context.Context) error {
	if runner == nil || ctx == nil {
		return ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runCtx, done, err := runner.start(ctx)
	if err != nil {
		return err
	}
	defer runner.finish(done)

	idleBackoff := runner.config.IdleBackoffMin
	for {
		processed, batchErr := runner.runBatch(runCtx)
		if err := runCtx.Err(); err != nil {
			return err
		}
		if processed > 0 {
			runner.observe(PublicationRunnerMetric{Reason: PublicationRunnerProcessed, Count: processed})
		}

		var delay time.Duration
		switch {
		case batchErr != nil:
			reason := PublicationRunnerDependencyError
			if errors.Is(batchErr, ErrPublicationRunnerItemPanic) {
				reason = PublicationRunnerItemPanic
			}
			runner.observe(PublicationRunnerMetric{Reason: reason, Count: 1})
			delay = runner.config.ErrorBackoff
		case processed > 0:
			idleBackoff = runner.config.IdleBackoffMin
			delay = runner.config.PollInterval
		default:
			runner.observe(PublicationRunnerMetric{Reason: PublicationRunnerIdle, Count: 1})
			delay, err = publicationIdleDelay(idleBackoff, runner.config.IdleBackoffMax, runner.config.Jitter)
			if err != nil {
				return err
			}
			idleBackoff = nextPublicationIdleBackoff(idleBackoff, runner.config.IdleBackoffMax)
		}
		if err := runner.wait(runCtx, delay); err != nil {
			return err
		}
	}
}

func (runner *PublicationRunner) Stop(ctx context.Context) error {
	if runner == nil || ctx == nil {
		return ErrInvalidInput
	}
	runner.mu.Lock()
	cancel, done := runner.cancel, runner.done
	runner.mu.Unlock()
	if done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runner *PublicationRunner) runBatch(ctx context.Context) (int, error) {
	if runner == nil || ctx == nil {
		return 0, ErrInvalidInput
	}
	processed := 0
	for processed < runner.config.BatchSize {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		found, err := runPublicationItem(ctx, runner.processor)
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

func (runner *PublicationRunner) start(ctx context.Context) (context.Context, chan struct{}, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.running {
		return nil, nil, ErrPublicationRunnerAlreadyRunning
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runner.running, runner.cancel, runner.done = true, cancel, done
	return runCtx, done, nil
}

func (runner *PublicationRunner) finish(done chan struct{}) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.done != done {
		return
	}
	runner.running, runner.cancel, runner.done = false, nil, nil
	close(done)
}

func (runner *PublicationRunner) observe(metric PublicationRunnerMetric) {
	if runner.config.Metrics == nil {
		return
	}
	defer func() { _ = recover() }()
	runner.config.Metrics(metric)
}

func runPublicationItem(
	ctx context.Context,
	processor publicationRunnerProcessor,
) (found bool, err error) {
	defer func() {
		if recover() != nil {
			found = false
			err = ErrPublicationRunnerItemPanic
		}
	}()
	return processor.RunOnce(ctx)
}

func publicationIdleDelay(
	current, maximum time.Duration,
	jitter func(time.Duration) time.Duration,
) (time.Duration, error) {
	if current <= 0 || maximum < current || jitter == nil {
		return 0, ErrInvalidInput
	}
	spread := min(current/2, maximum-current)
	offset := jitter(spread)
	if offset < 0 || offset > spread {
		return 0, ErrInvalidInput
	}
	return current + offset, nil
}

func nextPublicationIdleBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func publicationRunnerWait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
