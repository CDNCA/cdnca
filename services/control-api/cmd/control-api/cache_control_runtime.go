package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/nodepresence"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type cacheControlRuntimeConfig struct {
	Enabled   bool
	CursorKey []byte
	Worker    cachecontrolruntime.Config
}

type cacheControlRuntimeDependencies struct {
	Pool        *pgxpool.Pool
	NATS        *nats.Conn
	NodeLeases  nodepresence.LeaseReader
	Entitlement *entitlementguard.Guard
	Identity    *identity.Service
	IAM         *iamlock.Authorizer
}

type cacheControlWorker interface {
	ConfiguredFor(*pgxpool.Pool, *nats.Conn) bool
	Run(context.Context, func(error)) error
	Close() error
}

type cacheControlRuntimeState uint8

type cacheControlRuntimeTerminalError struct {
	cause error
}

type cacheControlRuntimeCloseError struct {
	cause error
}

func (cacheControlRuntimeTerminalError) Error() string {
	return "cache control runtime failed"
}

func (err cacheControlRuntimeTerminalError) Unwrap() error {
	return err.cause
}

func (cacheControlRuntimeCloseError) Error() string {
	return "cache control runtime close failed"
}

func (err cacheControlRuntimeCloseError) Unwrap() error {
	return err.cause
}

const (
	cacheControlRuntimeConfigured cacheControlRuntimeState = iota
	cacheControlRuntimeStarting
	cacheControlRuntimeRunning
	cacheControlRuntimeTerminal
	cacheControlRuntimeClosed
)

type cacheControlRuntime struct {
	worker              cacheControlWorker
	pool                *pgxpool.Pool
	nats                *nats.Conn
	handlerConfig       cachecontrolhttp.ProductionConfig
	handlerDependencies cachecontrolhttp.ProductionDependencies
	lifecycleMu         sync.Mutex
	lifecycleState      cacheControlRuntimeState
	terminalError       error
	runCancel           context.CancelFunc
	runDone             chan struct{}
	closeTimeout        time.Duration
	closeOnce           sync.Once
	closeError          error
}

func buildCacheControlRuntime(
	config cacheControlRuntimeConfig,
	dependencies cacheControlRuntimeDependencies,
) (*cacheControlRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if len(config.CursorKey) < 32 || dependencies.Pool == nil || dependencies.NATS == nil ||
		dependencies.NATS.IsClosed() || dependencies.NodeLeases == nil || dependencies.Entitlement == nil ||
		dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.IAM == nil || !dependencies.IAM.Configured() {
		return nil, errors.New("cache control runtime configuration is incomplete")
	}
	worker, err := cachecontrolruntime.NewRuntime(config.Worker, cachecontrolruntime.Dependencies{
		Pool: dependencies.Pool, NATS: dependencies.NATS, NodeLeases: dependencies.NodeLeases,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "initialize cache control worker", err: err}
	}
	runtime := &cacheControlRuntime{
		worker: worker, pool: dependencies.Pool, nats: dependencies.NATS,
		closeTimeout: config.Worker.OperationTimeout,
		handlerConfig: cachecontrolhttp.ProductionConfig{
			CursorKey: bytes.Clone(config.CursorKey), Clock: config.Worker.Clock,
		},
		handlerDependencies: cachecontrolhttp.ProductionDependencies{
			Pool: dependencies.Pool, Entitlement: dependencies.Entitlement,
			Identity: dependencies.Identity, IAM: dependencies.IAM,
			SiteSettings: edgeautopublish.SiteSettingPublisher{},
		},
	}
	return runtime, nil
}

// JobCommandRouters routes the task center's cancel/retry of cache operations
// to the cache module (fix-cacheflow2 §2); nil when cache control is disabled.
func (runtime *cacheControlRuntime) JobCommandRouters() (map[string]jobhttp.ProducerCommandRouter, error) {
	if runtime == nil {
		return nil, nil
	}
	router, err := cachecontrolhttp.NewProductionJobCommandRouter(runtime.handlerConfig, runtime.handlerDependencies)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize cache operation job command router", err: err}
	}
	return map[string]jobhttp.ProducerCommandRouter{"cache.operation": router}, nil
}

func (runtime *cacheControlRuntime) HandlerFactory() httpapi.CacheControlHandlerFactory {
	if runtime == nil {
		return nil
	}
	return func(authenticate cachecontrolhttp.AuthenticateFunc) (http.Handler, error) {
		if authenticate == nil {
			return nil, errors.New("cache control authentication is unavailable")
		}
		dependencies := runtime.handlerDependencies
		dependencies.Authenticate = authenticate
		handler, err := cachecontrolhttp.NewProductionHandler(runtime.handlerConfig, dependencies)
		if err != nil {
			return nil, runtimeStageError{stage: "initialize cache control HTTP handler", err: err}
		}
		return handler, nil
	}
}

func (runtime *cacheControlRuntime) Run(ctx context.Context) (runErr error) {
	if runtime == nil || ctx == nil {
		return errors.New("cache control runtime context is required")
	}
	var runCtx context.Context
	var cancel context.CancelFunc
	runDone := make(chan struct{})
	runtime.lifecycleMu.Lock()
	switch runtime.lifecycleState {
	case cacheControlRuntimeConfigured:
		runCtx, cancel = context.WithCancel(ctx)
		runtime.lifecycleState = cacheControlRuntimeStarting
		runtime.runCancel = cancel
		runtime.runDone = runDone
	case cacheControlRuntimeStarting, cacheControlRuntimeRunning:
		runtime.lifecycleMu.Unlock()
		return errors.New("cache control runtime is already running")
	default:
		runtime.lifecycleMu.Unlock()
		return errors.New("cache control runtime is unavailable")
	}
	runtime.lifecycleMu.Unlock()
	workerStarted := false
	restoreConfigured := false
	defer func() {
		var terminalErr error
		if workerStarted {
			terminalErr = runErr
			contextErr := runCtx.Err()
			if cacheControlContextStopped(runErr, contextErr) {
				terminalErr = nil
			} else if runErr == nil ||
				(contextErr == nil && cacheControlContextStopped(runErr, context.Canceled)) {
				terminalErr = errors.New("cache control runtime stopped unexpectedly")
				runErr = terminalErr
			}
		}
		if terminalErr != nil {
			terminalErr = cacheControlRuntimeTerminalError{cause: terminalErr}
			runErr = terminalErr
		}
		cancel()
		runtime.lifecycleMu.Lock()
		if workerStarted {
			if runtime.lifecycleState == cacheControlRuntimeRunning {
				runtime.lifecycleState = cacheControlRuntimeTerminal
			}
			runtime.setTerminalErrorLocked(terminalErr)
		} else if restoreConfigured && runtime.lifecycleState == cacheControlRuntimeStarting {
			runtime.lifecycleState = cacheControlRuntimeConfigured
		}
		runtime.runCancel = nil
		runtime.runDone = nil
		close(runDone)
		runtime.lifecycleMu.Unlock()
	}()
	if err := runtime.workerConfigured(); err != nil {
		restoreConfigured = true
		return err
	}
	runtime.lifecycleMu.Lock()
	if runtime.lifecycleState != cacheControlRuntimeStarting {
		runtime.lifecycleMu.Unlock()
		return errors.New("cache control runtime is unavailable")
	}
	runtime.lifecycleState = cacheControlRuntimeRunning
	workerStarted = true
	runtime.lifecycleMu.Unlock()
	return runtime.worker.Run(runCtx, func(err error) {
		slog.Default().Error("cache control runtime operation failed",
			"error_category", cacheControlRuntimeErrorCategory(err))
	})
}

func (runtime *cacheControlRuntime) Ready() error {
	if runtime == nil {
		return errors.New("cache control runtime is not configured")
	}
	runtime.lifecycleMu.Lock()
	defer runtime.lifecycleMu.Unlock()
	terminalErr := runtime.terminalError
	if terminalErr != nil {
		return terminalErr
	}
	if runtime.lifecycleState != cacheControlRuntimeRunning {
		return errors.New("cache control runtime is unavailable")
	}
	return runtime.workerConfigured()
}

func (runtime *cacheControlRuntime) workerConfigured() error {
	if runtime.worker == nil || !runtime.worker.ConfiguredFor(runtime.pool, runtime.nats) {
		return errors.New("cache control runtime is unavailable")
	}
	return nil
}

func (runtime *cacheControlRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	timeout := runtime.closeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return runtime.CloseContext(ctx)
}

func (runtime *cacheControlRuntime) CloseContext(ctx context.Context) error {
	if runtime == nil {
		return nil
	}
	if ctx == nil {
		return cacheControlRuntimeCloseError{cause: errors.New("cache control runtime close context is required")}
	}
	runtime.closeOnce.Do(func() {
		runtime.lifecycleMu.Lock()
		runtime.lifecycleState = cacheControlRuntimeClosed
		cancel := runtime.runCancel
		if cancel != nil {
			cancel()
		}
		runtime.lifecycleMu.Unlock()
		var closeErr error
		if runtime.worker != nil {
			closeErr = runtime.worker.Close()
			if closeErr != nil {
				closeErr = cacheControlRuntimeCloseError{cause: closeErr}
			}
		}
		runtime.lifecycleMu.Lock()
		runtime.closeError = closeErr
		runtime.lifecycleMu.Unlock()
	})
	runtime.lifecycleMu.Lock()
	runDone := runtime.runDone
	closeErr := runtime.closeError
	runtime.lifecycleMu.Unlock()
	if runDone == nil {
		return closeErr
	}
	select {
	case <-runDone:
		runtime.lifecycleMu.Lock()
		closeErr = runtime.closeError
		runtime.lifecycleMu.Unlock()
		return closeErr
	case <-ctx.Done():
		timeoutErr := cacheControlRuntimeCloseError{cause: ctx.Err()}
		runtime.lifecycleMu.Lock()
		if runtime.closeError == nil {
			runtime.closeError = timeoutErr
		} else if !errors.Is(runtime.closeError, ctx.Err()) {
			runtime.closeError = errors.Join(runtime.closeError, timeoutErr)
		}
		closeErr = runtime.closeError
		runtime.lifecycleMu.Unlock()
		return closeErr
	}
}

func (runtime *cacheControlRuntime) setTerminalErrorLocked(err error) {
	if err != nil && runtime.terminalError == nil {
		runtime.terminalError = err
	}
}

func cacheControlContextStopped(err, contextErr error) bool {
	if err == nil || contextErr == nil || !errors.Is(err, contextErr) {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		unwrapped := joined.Unwrap()
		if len(unwrapped) == 0 {
			return false
		}
		for _, nested := range unwrapped {
			if !cacheControlContextStopped(nested, contextErr) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return cacheControlContextStopped(wrapped.Unwrap(), contextErr)
	}
	return err == contextErr
}

func cacheControlRuntimeErrorCategory(err error) string {
	switch {
	case cacheControlContextStopped(err, context.Canceled):
		return "canceled"
	case cacheControlContextStopped(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "internal"
	}
}
