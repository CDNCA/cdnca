package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/jackc/pgx/v5/pgxpool"
)

type certificatePublicationPublisher43 struct{}

func (certificatePublicationPublisher43) Publish(
	context.Context,
	certificateasset.CertificatePublicationCommandV1,
) (certificateasset.PublicationResult, error) {
	return certificateasset.PublicationResult{Outcome: certificateasset.PublicationAck}, nil
}

type certificatePublicationLoop43 struct {
	mu              sync.Mutex
	started         chan struct{}
	startedOnce     sync.Once
	release         chan struct{}
	runErr          error
	stopErr         error
	blockStop       bool
	runCalls        int
	stopCalls       int
	stopSawCanceled bool
	runCtx          context.Context
}

func newCertificatePublicationLoop43() *certificatePublicationLoop43 {
	return &certificatePublicationLoop43{started: make(chan struct{})}
}

func (loop *certificatePublicationLoop43) Run(ctx context.Context) error {
	loop.mu.Lock()
	loop.runCalls++
	loop.runCtx = ctx
	loop.mu.Unlock()
	loop.startedOnce.Do(func() { close(loop.started) })
	if loop.runErr != nil {
		return loop.runErr
	}
	if loop.release != nil {
		<-loop.release
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (loop *certificatePublicationLoop43) Stop(ctx context.Context) error {
	loop.mu.Lock()
	loop.stopCalls++
	loop.stopSawCanceled = loop.runCtx != nil && loop.runCtx.Err() != nil
	block := loop.blockStop
	err := loop.stopErr
	loop.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func TestCertificatePublicationRuntimeBuildsStoreWorkerRunner43(t *testing.T) {
	config := defaultCertificatePublicationRuntimeConfig()
	var metrics []certificateasset.PublicationRunnerMetric
	config.Runner.Metrics = func(metric certificateasset.PublicationRunnerMetric) {
		metrics = append(metrics, metric)
	}
	runtime, err := newCertificatePublicationRuntime(
		new(pgxpool.Pool), certificatePublicationPublisher43{}, config,
	)
	if err != nil || runtime == nil || runtime.loop == nil || runtime.state != certificatePublicationRuntimeBuilt {
		t.Fatalf("runtime=(%+v,%v)", runtime, err)
	}
	if metrics != nil {
		t.Fatalf("composition emitted metrics before Start: %+v", metrics)
	}
	if err := runtime.Ready(); !errors.Is(err, errCertificatePublicationRuntimeNotStarted) {
		t.Fatalf("Ready() before Start=%v", err)
	}
}

func TestCertificatePublicationRuntimeDisabledIsExplicitlyUnconfigured43(t *testing.T) {
	config := defaultCertificatePublicationRuntimeConfig()
	config.Enabled = false
	runtime, err := newCertificatePublicationRuntime(nil, nil, config)
	if err != nil || runtime == nil || runtime.state != certificatePublicationRuntimeUnconfigured {
		t.Fatalf("disabled runtime=(%+v,%v)", runtime, err)
	}
	if err := runtime.Start(t.Context()); !errors.Is(err, errCertificatePublicationRuntimeNotConfigured) {
		t.Fatalf("disabled Start()=%v", err)
	}
	if err := runtime.Ready(); !errors.Is(err, errCertificatePublicationRuntimeNotConfigured) {
		t.Fatalf("disabled Ready()=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("disabled Close()=%v", err)
	}
}

func TestCertificatePublicationRuntimeValidatesDependenciesAndTiming43(t *testing.T) {
	valid := defaultCertificatePublicationRuntimeConfig()
	for _, test := range []struct {
		name      string
		pool      *pgxpool.Pool
		publisher certificateasset.CertificatePublisher
		mutate    func(*certificatePublicationRuntimeConfig)
	}{
		{name: "pool", publisher: certificatePublicationPublisher43{}},
		{name: "publisher", pool: new(pgxpool.Pool)},
		{name: "worker ID", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.Worker.WorkerID = ""
		}},
		{name: "lease", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.Store.LeaseDuration = 0
		}},
		{name: "unsafe operation budget", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.Store.LeaseDuration = config.Worker.PublishTimeout + config.Worker.SettlementTimeout
		}},
		{name: "batch", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.Runner.BatchSize = 0
		}},
		{name: "backoff", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.Runner.IdleBackoffMax = config.Runner.IdleBackoffMin / 2
		}},
		{name: "metrics jitter", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.Runner.Jitter = nil
		}},
		{name: "shutdown", pool: new(pgxpool.Pool), publisher: certificatePublicationPublisher43{}, mutate: func(config *certificatePublicationRuntimeConfig) {
			config.ShutdownTimeout = 0
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			if test.mutate != nil {
				test.mutate(&config)
			}
			if runtime, err := newCertificatePublicationRuntime(test.pool, test.publisher, config); err == nil || runtime != nil {
				t.Fatalf("invalid composition=(%+v,%v)", runtime, err)
			}
		})
	}
	if strings.Contains(strings.ToLower(valid.Worker.WorkerID), "secret") ||
		strings.Contains(strings.ToLower(valid.Worker.WorkerID), "token") {
		t.Fatalf("default worker ID contains sensitive semantics: %q", valid.Worker.WorkerID)
	}
}

func TestCertificatePublicationRuntimeStartsReadiesAndClosesIdempotently43(t *testing.T) {
	loop := newCertificatePublicationLoop43()
	runtime, err := newCertificatePublicationProcessRuntime(loop, time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-loop.started:
	case <-time.After(time.Second):
		t.Fatal("publication runtime did not start")
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("Ready()=%v", err)
	}
	if err := runtime.Start(t.Context()); !errors.Is(err, errCertificatePublicationRuntimeAlreadyStarted) {
		t.Fatalf("second Start()=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close()=%v", err)
	}
	loop.mu.Lock()
	stopCalls, stopSawCanceled := loop.stopCalls, loop.stopSawCanceled
	loop.mu.Unlock()
	if stopCalls != 1 || !stopSawCanceled {
		t.Fatalf("stop calls=%d sawCanceled=%v", stopCalls, stopSawCanceled)
	}
	if err := runtime.Ready(); !errors.Is(err, errCertificatePublicationRuntimeStopped) {
		t.Fatalf("Ready() after Close=%v", err)
	}
}

func TestCertificatePublicationRuntimeReportsFailureWithoutDetail43(t *testing.T) {
	loop := newCertificatePublicationLoop43()
	loop.runErr = errors.New("sensitive publisher detail")
	runtime, err := newCertificatePublicationProcessRuntime(loop, time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(t.Context()); err != nil && !errors.Is(err, errCertificatePublicationRuntimeFailed) {
		t.Fatalf("Start()=%v", err)
	}
	select {
	case <-runtime.done:
	case <-time.After(time.Second):
		t.Fatal("failed runtime did not terminate")
	}
	readyErr := runtime.Ready()
	if !errors.Is(readyErr, errCertificatePublicationRuntimeFailed) || strings.Contains(readyErr.Error(), "sensitive") {
		t.Fatalf("failed Ready()=%v", readyErr)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCertificatePublicationRuntimeStartFailureDoesNotLaunchAndCloseIsBounded43(t *testing.T) {
	loop := newCertificatePublicationLoop43()
	runtime, err := newCertificatePublicationProcessRuntime(loop, 10*time.Millisecond, true)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runtime.Start(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Start()=%v", err)
	}
	loop.mu.Lock()
	runCalls := loop.runCalls
	loop.mu.Unlock()
	if runCalls != 0 {
		t.Fatalf("cancelled Start launched %d loops", runCalls)
	}

	blocking := newCertificatePublicationLoop43()
	blocking.blockStop = true
	blocking.release = make(chan struct{})
	runtime, err = newCertificatePublicationProcessRuntime(blocking, 10*time.Millisecond, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	closeErr := runtime.Close()
	if time.Since(started) > 250*time.Millisecond || !errors.Is(closeErr, errCertificatePublicationRuntimeCloseTimeout) {
		t.Fatalf("bounded Close() duration=%s error=%v", time.Since(started), closeErr)
	}
	close(blocking.release)
}
