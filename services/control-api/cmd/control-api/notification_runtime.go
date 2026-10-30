package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
)

const notificationRuntimeHealthPath = "/health/notification-runtime"
const notificationRuntimeHealthAPIPath = "/v1/notification-runtime-health"

type notificationRuntimeCore interface {
	Run(context.Context) error
	Ready(context.Context, notification.ChannelSwitches) error
	Health() notificationruntime.HealthSnapshot
	Close(context.Context) error
	RecoverySender() accountrecovery.RecoverySender
	RegisterAnonymousDispatcher(context.Context, notification.AnonymousDispatcher) (notificationruntime.Registration, error)
}

type notificationProcessRuntime struct {
	core             notificationRuntimeCore
	switches         notification.ChannelSwitches
	readinessTimeout time.Duration
	readinessCheck   func(context.Context) (notification.ChannelSwitches, error)
	shutdownTimeout  time.Duration
	runContext       context.Context
	cancel           context.CancelFunc
	done             chan struct{}

	runMu     sync.Mutex
	runErr    error
	waiting   bool
	reported  bool
	ready     atomic.Bool
	closing   atomic.Bool
	stopped   atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

type notificationRuntimeHealthSnapshot struct {
	Enabled             bool   `json:"enabled"`
	State               string `json:"state"`
	Ready               bool   `json:"ready"`
	WorkerRunning       bool   `json:"worker_running"`
	EnabledChannels     int    `json:"enabled_channels"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastErrorClass      string `json:"last_error_class,omitempty"`
}

type notificationRuntimeReadinessProbe struct {
	runtime *notificationProcessRuntime
}

func startNotificationProcessRuntime(
	ctx context.Context,
	core notificationRuntimeCore,
	switches notification.ChannelSwitches,
	startupTimeout, shutdownTimeout time.Duration,
) (*notificationProcessRuntime, error) {
	if ctx == nil || core == nil || startupTimeout <= 0 || shutdownTimeout <= 0 ||
		!switches.Email && !switches.SMS {
		return nil, errors.New("notification runtime process configuration is incomplete")
	}
	runContext, cancel := context.WithCancel(ctx)
	runtime := &notificationProcessRuntime{
		core: core, switches: switches, readinessTimeout: startupTimeout,
		shutdownTimeout: shutdownTimeout, runContext: runContext, cancel: cancel,
	}
	runtime.runMu.Lock()
	runtime.startWorkerLocked()
	runtime.runMu.Unlock()

	startupContext, stopStartup := context.WithTimeout(ctx, startupTimeout)
	defer stopStartup()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := runtime.Ready(startupContext, switches)
		if err == nil {
			return runtime, nil
		}
		if !errors.Is(err, notificationruntime.ErrWorkerNotRunning) {
			_ = runtime.Close()
			return nil, runtimeStageError{stage: "verify notification runtime readiness", err: err}
		}
		select {
		case <-runtime.currentDone():
			runErr := runtime.workerError()
			if runErr == nil {
				runErr = notificationruntime.ErrWorkerExited
			}
			_ = runtime.Close()
			return nil, runtimeStageError{stage: "start notification runtime worker", err: runErr}
		case <-startupContext.Done():
			_ = runtime.Close()
			return nil, runtimeStageError{stage: "wait for notification runtime readiness", err: startupContext.Err()}
		case <-ticker.C:
		}
	}
}

func (runtime *notificationProcessRuntime) Ready(
	ctx context.Context,
	switches notification.ChannelSwitches,
) error {
	if runtime == nil || runtime.core == nil {
		return notificationruntime.ErrDisabled
	}
	if runtime.closing.Load() || runtime.stopped.Load() {
		runtime.ready.Store(false)
		return notificationruntime.ErrWorkerNotRunning
	}
	if err := runtime.core.Ready(ctx, switches); err != nil {
		runtime.ready.Store(false)
		return err
	}
	runtime.ready.Store(true)
	select {
	case <-runtime.currentDone():
		runtime.ready.Store(false)
		return notificationruntime.ErrWorkerNotRunning
	default:
	}
	if runtime.closing.Load() || runtime.stopped.Load() {
		runtime.ready.Store(false)
		return notificationruntime.ErrWorkerNotRunning
	}
	return nil
}

func (runtime *notificationProcessRuntime) RecoverySender() accountrecovery.RecoverySender {
	if runtime == nil || runtime.core == nil || runtime.closing.Load() || runtime.stopped.Load() {
		return nil
	}
	return runtime.core.RecoverySender()
}

func (runtime *notificationProcessRuntime) RegisterAnonymousDispatcher(
	ctx context.Context,
	dispatcher notification.AnonymousDispatcher,
) (accountRecoveryDispatcherRegistration, error) {
	if runtime == nil || runtime.core == nil || runtime.closing.Load() || runtime.stopped.Load() {
		return nil, notificationruntime.ErrRegistryClosed
	}
	registration, err := runtime.core.RegisterAnonymousDispatcher(ctx, dispatcher)
	if err != nil {
		return nil, err
	}
	return registration, nil
}

func (runtime *notificationProcessRuntime) Health() notificationRuntimeHealthSnapshot {
	if runtime == nil || runtime.core == nil {
		return notificationRuntimeHealthSnapshot{State: "disabled"}
	}
	core := runtime.core.Health()
	state := string(core.State)
	if runtime.closing.Load() {
		state = "stopping"
	}
	if runtime.stopped.Load() {
		state = "stopped"
	}
	if !validNotificationHealthState(state) {
		state = "failed"
	}
	errorClass := core.LastErrorClass
	if !validNotificationHealthClass(errorClass) {
		errorClass = "unknown"
	}
	return notificationRuntimeHealthSnapshot{
		Enabled: core.Enabled, State: state,
		Ready:           runtime.ready.Load() && core.Ready && !runtime.closing.Load() && !runtime.stopped.Load(),
		WorkerRunning:   core.WorkerRunning && !runtime.stopped.Load(),
		EnabledChannels: core.EnabledChannels, ConsecutiveFailures: core.ConsecutiveFailures,
		LastErrorClass: errorClass,
	}
}

func (runtime *notificationProcessRuntime) ReadinessProbe() readinessProbe {
	return notificationRuntimeReadinessProbe{runtime: runtime}
}

func (probe notificationRuntimeReadinessProbe) Ready() error {
	if probe.runtime == nil || probe.runtime.core == nil || probe.runtime.closing.Load() || probe.runtime.stopped.Load() {
		if probe.runtime != nil {
			probe.runtime.ready.Store(false)
		}
		return notificationruntime.ErrWorkerNotRunning
	}
	ctx, cancel := context.WithTimeout(context.Background(), probe.runtime.readinessTimeout)
	defer cancel()
	switches := probe.runtime.switches
	if probe.runtime.readinessCheck != nil {
		verified, err := probe.runtime.readinessCheck(ctx)
		if err != nil {
			probe.runtime.ready.Store(false)
			return err
		}
		switches = verified
	}
	return probe.runtime.Ready(ctx, switches)
}

func (runtime *notificationProcessRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		runtime.ready.Store(false)
		runtime.closing.Store(true)
		if runtime.cancel != nil {
			runtime.cancel()
		}
		ctx, cancel := context.WithTimeout(context.Background(), runtime.shutdownTimeout)
		defer cancel()
		if runtime.core != nil {
			if err := runtime.core.Close(ctx); err != nil {
				runtime.closeErr = runtimeStageError{stage: "close notification runtime", err: err}
			}
		}
		select {
		case <-runtime.currentDone():
			runtime.stopped.Store(true)
		case <-ctx.Done():
			if runtime.closeErr == nil {
				runtime.closeErr = runtimeStageError{stage: "join notification runtime worker", err: ctx.Err()}
			}
		}
	})
	return runtime.closeErr
}

// startWorkerLocked runs one attempt of core.Run with a fresh done channel and
// no stale terminal error. Callers hold runMu.
func (runtime *notificationProcessRuntime) startWorkerLocked() {
	done := make(chan struct{})
	runtime.done, runtime.runErr, runtime.reported = done, nil, false
	go func() {
		err := runtime.core.Run(runtime.runContext)
		runtime.runMu.Lock()
		runtime.runErr = err
		runtime.runMu.Unlock()
		runtime.ready.Store(false)
		close(done)
	}()
}

func (runtime *notificationProcessRuntime) currentDone() <-chan struct{} {
	runtime.runMu.Lock()
	defer runtime.runMu.Unlock()
	return runtime.done
}

// Run waits for the current worker attempt and returns its error. The first
// attempt is started by startNotificationProcessRuntime (it gates startup
// readiness); once an attempt has been returned, the next Run starts the
// worker again, so runWithDBBackoff can retry after a database restart. Only
// one Run waits at a time, and Close ends the retries.
func (runtime *notificationProcessRuntime) Run(ctx context.Context) error {
	if runtime == nil || runtime.core == nil || ctx == nil {
		return notificationruntime.ErrWorkerExited
	}
	runtime.runMu.Lock()
	if runtime.waiting {
		runtime.runMu.Unlock()
		return notificationruntime.ErrAlreadyRunning
	}
	if runtime.reported {
		if runtime.closing.Load() || runtime.stopped.Load() {
			runtime.runMu.Unlock()
			return notificationruntime.ErrWorkerNotRunning
		}
		runtime.startWorkerLocked()
	}
	runtime.waiting = true
	done := runtime.done
	runtime.runMu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		// The attempt keeps running under the runtime's own context (Close
		// stops it); it is not consumed, so a later Run waits for it again.
		runtime.runMu.Lock()
		runtime.waiting = false
		runtime.runMu.Unlock()
		return ctx.Err()
	}
	runtime.runMu.Lock()
	defer runtime.runMu.Unlock()
	runtime.waiting, runtime.reported = false, true
	if runtime.runErr == nil {
		return notificationruntime.ErrWorkerExited
	}
	return runtime.runErr
}

func (runtime *notificationProcessRuntime) workerError() error {
	if runtime == nil {
		return notificationruntime.ErrWorkerExited
	}
	runtime.runMu.Lock()
	defer runtime.runMu.Unlock()
	return runtime.runErr
}

func runRequiredNotificationRuntime(
	ctx context.Context,
	runtime *notificationProcessRuntime,
	failures chan<- error,
) {
	if runtime == nil {
		select {
		case failures <- errors.New("notification runtime stopped: required worker is missing"):
		default:
		}
		return
	}
	// A temporarily unavailable database ends the worker attempt without
	// counting as a worker failure; retry it instead of exiting the process.
	err := runWithDBBackoff(ctx, slog.Default(), "notification runtime", 5*time.Minute, runtime.Run)
	if ctx != nil && ctx.Err() != nil {
		return
	}
	select {
	case failures <- runtimeStageError{stage: "notification runtime stopped", err: err}:
	default:
	}
}

func withNotificationRuntimeHealth(next http.Handler, runtime *notificationProcessRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && (request.URL.Path == notificationRuntimeHealthPath || request.URL.Path == notificationRuntimeHealthAPIPath) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(writer).Encode(runtime.Health())
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func validNotificationHealthState(state string) bool {
	switch state {
	case "disabled", "built", "running", "ready", "backoff", "stopping", "stopped", "failed":
		return true
	default:
		return false
	}
}

func validNotificationHealthClass(class string) bool {
	if class == "" {
		return true
	}
	if len(class) > 64 || class[0] < 'a' || class[0] > 'z' {
		return false
	}
	for _, character := range class[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

var _ accountRecoveryNotificationBridge = (*notificationProcessRuntime)(nil)
