package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/jackc/pgx/v5/pgxpool"
)

type certificatePublicationRuntimeState string

const (
	certificatePublicationRuntimeUnconfigured certificatePublicationRuntimeState = "unconfigured"
	certificatePublicationRuntimeBuilt        certificatePublicationRuntimeState = "built"
	certificatePublicationRuntimeRunning      certificatePublicationRuntimeState = "running"
	certificatePublicationRuntimeFailed       certificatePublicationRuntimeState = "failed"
	certificatePublicationRuntimeStopping     certificatePublicationRuntimeState = "stopping"
	certificatePublicationRuntimeStopped      certificatePublicationRuntimeState = "stopped"
)

var (
	errCertificatePublicationRuntimeInvalidConfiguration = errors.New("certificate publication runtime configuration is invalid")
	errCertificatePublicationRuntimeNotConfigured        = errors.New("certificate publication runtime is not configured")
	errCertificatePublicationRuntimeNotStarted           = errors.New("certificate publication runtime is not started")
	errCertificatePublicationRuntimeAlreadyStarted       = errors.New("certificate publication runtime is already started")
	errCertificatePublicationRuntimeFailed               = errors.New("certificate publication runtime failed")
	errCertificatePublicationRuntimeStopped              = errors.New("certificate publication runtime is stopped")
	errCertificatePublicationRuntimeCloseFailed          = errors.New("certificate publication runtime close failed")
	errCertificatePublicationRuntimeCloseTimeout         = errors.New("certificate publication runtime close timeout")
)

type certificatePublicationRuntimeConfig struct {
	Enabled         bool
	Store           certificateasset.PublicationIntentStoreConfig
	Worker          certificateasset.PublicationWorkerConfig
	Runner          certificateasset.PublicationRunnerConfig
	ShutdownTimeout time.Duration
}

func defaultCertificatePublicationRuntimeConfig() certificatePublicationRuntimeConfig {
	worker := certificateasset.DefaultPublicationWorkerConfig()
	worker.WorkerID = "control-api-certificate-publication"
	return certificatePublicationRuntimeConfig{
		Enabled: true, Store: certificateasset.DefaultPublicationIntentStoreConfig(),
		Worker: worker, Runner: certificateasset.DefaultPublicationRunnerConfig(),
		ShutdownTimeout: 10 * time.Second,
	}
}

type certificatePublicationRuntimeLoop interface {
	Run(context.Context) error
	Stop(context.Context) error
}

type certificatePublicationRuntime struct {
	loop            certificatePublicationRuntimeLoop
	shutdownTimeout time.Duration

	mu        sync.Mutex
	state     certificatePublicationRuntimeState
	runErr    error
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newCertificatePublicationRuntime(
	pool *pgxpool.Pool,
	publisher certificateasset.CertificatePublisher,
	config certificatePublicationRuntimeConfig,
) (*certificatePublicationRuntime, error) {
	if !config.Enabled {
		return newCertificatePublicationProcessRuntime(nil, 0, false)
	}
	if pool == nil || publisher == nil || config.ShutdownTimeout <= 0 ||
		config.ShutdownTimeout > 5*time.Minute ||
		config.Store.LeaseDuration <= config.Worker.PublishTimeout+config.Worker.SettlementTimeout ||
		config.ShutdownTimeout < config.Worker.SettlementTimeout {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	store, err := certificateasset.NewPublicationIntentStore(pool, config.Store)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	worker, err := certificateasset.NewPublicationWorker(store, publisher, config.Worker)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	runner, err := certificateasset.NewPublicationRunner(worker, config.Runner)
	if err != nil {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	return newCertificatePublicationProcessRuntime(runner, config.ShutdownTimeout, true)
}

func newCertificatePublicationProcessRuntime(
	loop certificatePublicationRuntimeLoop,
	shutdownTimeout time.Duration,
	configured bool,
) (*certificatePublicationRuntime, error) {
	if !configured {
		return &certificatePublicationRuntime{state: certificatePublicationRuntimeUnconfigured}, nil
	}
	if loop == nil || shutdownTimeout <= 0 || shutdownTimeout > 5*time.Minute {
		return nil, errCertificatePublicationRuntimeInvalidConfiguration
	}
	return &certificatePublicationRuntime{
		loop: loop, shutdownTimeout: shutdownTimeout, state: certificatePublicationRuntimeBuilt,
	}, nil
}

func (runtime *certificatePublicationRuntime) Start(ctx context.Context) error {
	if runtime == nil {
		return errCertificatePublicationRuntimeNotConfigured
	}
	if ctx == nil {
		return errCertificatePublicationRuntimeInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.mu.Lock()
	switch runtime.state {
	case certificatePublicationRuntimeUnconfigured:
		runtime.mu.Unlock()
		return errCertificatePublicationRuntimeNotConfigured
	case certificatePublicationRuntimeBuilt:
	case certificatePublicationRuntimeFailed:
		runtime.mu.Unlock()
		return errCertificatePublicationRuntimeFailed
	case certificatePublicationRuntimeStopping, certificatePublicationRuntimeStopped:
		runtime.mu.Unlock()
		return errCertificatePublicationRuntimeStopped
	default:
		runtime.mu.Unlock()
		return errCertificatePublicationRuntimeAlreadyStarted
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.state, runtime.cancel, runtime.done = certificatePublicationRuntimeRunning, cancel, done
	runtime.mu.Unlock()

	go func() {
		err := runtime.loop.Run(runCtx)
		runtime.mu.Lock()
		runtime.runErr = err
		if runtime.state == certificatePublicationRuntimeStopping || runCtx.Err() != nil {
			runtime.state = certificatePublicationRuntimeStopped
		} else {
			runtime.state = certificatePublicationRuntimeFailed
		}
		close(done)
		runtime.mu.Unlock()
	}()
	return nil
}

func (runtime *certificatePublicationRuntime) Ready() error {
	if runtime == nil {
		return errCertificatePublicationRuntimeNotConfigured
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	switch runtime.state {
	case certificatePublicationRuntimeUnconfigured:
		return errCertificatePublicationRuntimeNotConfigured
	case certificatePublicationRuntimeBuilt:
		return errCertificatePublicationRuntimeNotStarted
	case certificatePublicationRuntimeRunning:
		return nil
	case certificatePublicationRuntimeFailed:
		return errCertificatePublicationRuntimeFailed
	default:
		return errCertificatePublicationRuntimeStopped
	}
}

func (runtime *certificatePublicationRuntime) Wait() error {
	if runtime == nil {
		return errCertificatePublicationRuntimeNotConfigured
	}
	runtime.mu.Lock()
	done := runtime.done
	state := runtime.state
	runtime.mu.Unlock()
	if state == certificatePublicationRuntimeUnconfigured {
		return errCertificatePublicationRuntimeNotConfigured
	}
	if done == nil {
		return errCertificatePublicationRuntimeNotStarted
	}
	<-done
	runtime.mu.Lock()
	err := runtime.runErr
	runtime.mu.Unlock()
	return err
}

func (runtime *certificatePublicationRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		runtime.mu.Lock()
		if runtime.state == certificatePublicationRuntimeUnconfigured {
			runtime.mu.Unlock()
			return
		}
		cancel, done := runtime.cancel, runtime.done
		if runtime.state == certificatePublicationRuntimeBuilt {
			runtime.state = certificatePublicationRuntimeStopped
			runtime.mu.Unlock()
			return
		}
		runtime.state = certificatePublicationRuntimeStopping
		runtime.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), runtime.shutdownTimeout)
		defer stopShutdown()
		if runtime.loop != nil {
			if err := runtime.loop.Stop(shutdownCtx); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					runtime.closeErr = errCertificatePublicationRuntimeCloseTimeout
				} else {
					runtime.closeErr = errCertificatePublicationRuntimeCloseFailed
				}
			}
		}
		if done != nil {
			select {
			case <-done:
			case <-shutdownCtx.Done():
				runtime.closeErr = errCertificatePublicationRuntimeCloseTimeout
			}
		}
		runtime.mu.Lock()
		runtime.state = certificatePublicationRuntimeStopped
		runtime.mu.Unlock()
	})
	return runtime.closeErr
}
