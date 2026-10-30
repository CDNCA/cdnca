package certificateasset

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type publicationRunnerStep42 struct {
	found bool
	err   error
	panic bool
}

type publicationRunnerProcessor42 struct {
	mu        sync.Mutex
	steps     []publicationRunnerStep42
	calls     int
	active    int
	maxActive int
}

func (processor *publicationRunnerProcessor42) RunOnce(context.Context) (bool, error) {
	processor.mu.Lock()
	processor.calls++
	processor.active++
	if processor.active > processor.maxActive {
		processor.maxActive = processor.active
	}
	step := publicationRunnerStep42{}
	if len(processor.steps) > 0 {
		step = processor.steps[0]
		processor.steps = processor.steps[1:]
	}
	processor.mu.Unlock()
	defer func() {
		processor.mu.Lock()
		processor.active--
		processor.mu.Unlock()
	}()
	if step.panic {
		panic("sensitive publication panic")
	}
	return step.found, step.err
}

func TestPublicationRunnerBoundsBatchAndSerializesItems42(t *testing.T) {
	processor := &publicationRunnerProcessor42{steps: []publicationRunnerStep42{
		{found: true}, {found: true}, {found: true}, {found: true},
	}}
	config := publicationRunnerConfig42()
	config.BatchSize = 3
	runner, err := newPublicationRunner(processor, config, publicationRunnerWait)
	if err != nil {
		t.Fatal(err)
	}
	processed, err := runner.runBatch(t.Context())
	if err != nil || processed != 3 || processor.calls != 3 || processor.maxActive != 1 {
		t.Fatalf("runBatch()=(%d,%v) calls=%d maxActive=%d", processed, err, processor.calls, processor.maxActive)
	}
	processed, err = runner.runBatch(t.Context())
	if err != nil || processed != 1 || processor.calls != 5 || processor.maxActive != 1 {
		t.Fatalf("second runBatch()=(%d,%v) calls=%d maxActive=%d", processed, err, processor.calls, processor.maxActive)
	}
}

func TestPublicationRunnerIdleBackoffJitterCapsAndWorkResets42(t *testing.T) {
	processor := &publicationRunnerProcessor42{steps: []publicationRunnerStep42{
		{}, {}, {found: true}, {},
	}}
	config := publicationRunnerConfig42()
	config.BatchSize = 1
	config.PollInterval = 3 * time.Millisecond
	config.IdleBackoffMin = 10 * time.Millisecond
	config.IdleBackoffMax = 25 * time.Millisecond
	config.Jitter = func(maximum time.Duration) time.Duration { return maximum }
	var metrics []PublicationRunnerMetric
	config.Metrics = func(metric PublicationRunnerMetric) { metrics = append(metrics, metric) }
	ctx, cancel := context.WithCancel(t.Context())
	var waits []time.Duration
	runner, err := newPublicationRunner(processor, config, func(waitCtx context.Context, delay time.Duration) error {
		waits = append(waits, delay)
		if len(waits) == 4 {
			cancel()
			return waitCtx.Err()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error=%v", err)
	}
	want := []time.Duration{15 * time.Millisecond, 25 * time.Millisecond, 3 * time.Millisecond, 15 * time.Millisecond}
	if !reflect.DeepEqual(waits, want) {
		t.Fatalf("waits=%v want=%v", waits, want)
	}
	if !reflect.DeepEqual(metrics, []PublicationRunnerMetric{
		{Reason: PublicationRunnerIdle, Count: 1},
		{Reason: PublicationRunnerIdle, Count: 1},
		{Reason: PublicationRunnerProcessed, Count: 1},
		{Reason: PublicationRunnerIdle, Count: 1},
	}) {
		t.Fatalf("metrics=%+v", metrics)
	}
}

func TestPublicationRunnerIsolatesPanicAndBacksOffErrors42(t *testing.T) {
	dependencyErr := errors.New("sensitive dependency detail")
	for _, test := range []struct {
		name       string
		step       publicationRunnerStep42
		wantReason string
	}{
		{name: "panic", step: publicationRunnerStep42{panic: true}, wantReason: PublicationRunnerItemPanic},
		{name: "dependency error", step: publicationRunnerStep42{err: dependencyErr}, wantReason: PublicationRunnerDependencyError},
	} {
		t.Run(test.name, func(t *testing.T) {
			processor := &publicationRunnerProcessor42{steps: []publicationRunnerStep42{test.step}}
			config := publicationRunnerConfig42()
			var metrics []PublicationRunnerMetric
			config.Metrics = func(metric PublicationRunnerMetric) { metrics = append(metrics, metric) }
			ctx, cancel := context.WithCancel(t.Context())
			var waited time.Duration
			runner, err := newPublicationRunner(processor, config, func(waitCtx context.Context, delay time.Duration) error {
				waited = delay
				cancel()
				return waitCtx.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := runner.Run(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run() error=%v", err)
			}
			if waited != config.ErrorBackoff || processor.calls != 1 || len(metrics) != 1 ||
				metrics[0].Reason != test.wantReason || metrics[0].Count != 1 {
				t.Fatalf("wait=%s calls=%d metrics=%+v", waited, processor.calls, metrics)
			}
		})
	}
}

func TestPublicationRunnerSingleRunFenceAndConcurrentStop42(t *testing.T) {
	processor := &publicationRunnerProcessor42{}
	config := publicationRunnerConfig42()
	config.IdleBackoffMin = time.Hour
	config.IdleBackoffMax = time.Hour
	idle := make(chan struct{}, 1)
	config.Metrics = func(metric PublicationRunnerMetric) {
		if metric.Reason == PublicationRunnerIdle {
			idle <- struct{}{}
		}
	}
	runner, err := newPublicationRunner(processor, config, publicationRunnerWait)
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runner.Run(t.Context()) }()
	select {
	case <-idle:
	case <-time.After(time.Second):
		t.Fatal("runner did not enter idle wait")
	}
	if err := runner.Run(t.Context()); !errors.Is(err, ErrPublicationRunnerAlreadyRunning) {
		t.Fatalf("concurrent Run() error=%v", err)
	}
	stopCtx, cancelStop := context.WithTimeout(t.Context(), time.Second)
	defer cancelStop()
	stopResults := make(chan error, 2)
	go func() { stopResults <- runner.Stop(stopCtx) }()
	go func() { stopResults <- runner.Stop(stopCtx) }()
	for range 2 {
		if err := <-stopResults; err != nil {
			t.Fatalf("Stop() error=%v", err)
		}
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("stopped Run() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop() did not bound Run exit")
	}
	if err := runner.Stop(t.Context()); err != nil {
		t.Fatalf("idle Stop() error=%v", err)
	}
}

func TestPublicationRunnerMetricsContainOnlyStableReasonAndCount42(t *testing.T) {
	typeOfMetric := reflect.TypeOf(PublicationRunnerMetric{})
	if typeOfMetric.NumField() != 2 || typeOfMetric.Field(0).Name != "Reason" ||
		typeOfMetric.Field(1).Name != "Count" {
		t.Fatalf("metric fields=%v", typeOfMetric)
	}
	for _, reason := range []string{
		PublicationRunnerIdle, PublicationRunnerProcessed,
		PublicationRunnerDependencyError, PublicationRunnerItemPanic,
	} {
		if !validPublicationFailureCode(reason) {
			t.Fatalf("unstable metric reason %q", reason)
		}
	}
}

func TestPublicationRunnerValidatesConfiguration42(t *testing.T) {
	processor := &publicationRunnerProcessor42{}
	valid := publicationRunnerConfig42()
	for index, config := range []PublicationRunnerConfig{
		{},
		{BatchSize: valid.BatchSize, PollInterval: valid.PollInterval, IdleBackoffMin: valid.IdleBackoffMin,
			IdleBackoffMax: valid.IdleBackoffMax, ErrorBackoff: valid.ErrorBackoff},
		{BatchSize: 1001, PollInterval: valid.PollInterval, IdleBackoffMin: valid.IdleBackoffMin,
			IdleBackoffMax: valid.IdleBackoffMax, ErrorBackoff: valid.ErrorBackoff, Jitter: valid.Jitter},
	} {
		if _, err := newPublicationRunner(processor, config, publicationRunnerWait); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid config %d error=%v", index, err)
		}
	}
	if _, err := newPublicationRunner(nil, valid, publicationRunnerWait); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil processor error=%v", err)
	}
	if _, err := newPublicationRunner(processor, valid, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil wait error=%v", err)
	}
	if _, err := NewPublicationRunner(nil, valid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil worker error=%v", err)
	}
}

func publicationRunnerConfig42() PublicationRunnerConfig {
	config := DefaultPublicationRunnerConfig()
	config.BatchSize = 4
	config.PollInterval = 5 * time.Millisecond
	config.IdleBackoffMin = 10 * time.Millisecond
	config.IdleBackoffMax = 100 * time.Millisecond
	config.ErrorBackoff = 20 * time.Millisecond
	config.Jitter = func(time.Duration) time.Duration { return 0 }
	return config
}
