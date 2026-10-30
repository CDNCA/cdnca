package edgeautopublish

import (
	"context"
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
	"sync"
	"time"
)

var (
	ErrRuntimeAlreadyRunning = errors.New("automatic edge publication runtime is already running")
	ErrRuntimeNotReady       = errors.New("automatic edge publication runtime is not ready")
	ErrRuntimeClosed         = errors.New("automatic edge publication runtime is closed")
)

type RuntimeWorker interface {
	RunOnce(context.Context) (bool, error)
}

// WorkerChain runs each worker once per poll; it worked when any did.
type WorkerChain []RuntimeWorker

func (chain WorkerChain) RunOnce(ctx context.Context) (bool, error) {
	worked := false
	var failures []error
	for _, worker := range chain {
		did, err := worker.RunOnce(ctx)
		worked = worked || did
		if err != nil {
			failures = append(failures, err)
		}
	}
	return worked, errors.Join(failures...)
}

type RuntimeReconciler interface {
	ReconcileOne(context.Context) (bool, error)
}

type RuntimeConfig struct {
	PollInterval     time.Duration
	ErrorBackoff     time.Duration
	OperationTimeout time.Duration
}

type Runtime struct {
	worker     RuntimeWorker
	reconciler RuntimeReconciler
	config     RuntimeConfig
	wait       func(context.Context, time.Duration) error

	mu      sync.Mutex
	running bool
	closing bool
	closed  bool
	ready   bool
	failure error
	cancel  context.CancelFunc
	done    chan struct{}
	closeMu sync.Mutex
}

func NewRuntime(worker RuntimeWorker, reconciler RuntimeReconciler, config RuntimeConfig) (*Runtime, error) {
	return newRuntime(worker, reconciler, config, waitRuntime)
}

func newRuntime(
	worker RuntimeWorker,
	reconciler RuntimeReconciler,
	config RuntimeConfig,
	wait func(context.Context, time.Duration) error,
) (*Runtime, error) {
	if nilDependency(worker) || nilDependency(reconciler) || wait == nil ||
		config.PollInterval <= 0 || config.PollInterval > time.Hour ||
		config.ErrorBackoff <= 0 || config.ErrorBackoff > time.Hour ||
		config.OperationTimeout <= 0 || config.OperationTimeout > time.Hour {
		return nil, ErrInvalidInput
	}
	return &Runtime{worker: worker, reconciler: reconciler, config: config, wait: wait}, nil
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidInput
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.mu.Lock()
	if runtime.closing || runtime.closed {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeClosed
	}
	if runtime.running {
		runtime.mu.Unlock()
		cancel()
		return ErrRuntimeAlreadyRunning
	}
	runtime.running = true
	runtime.ready = false
	runtime.failure = nil
	runtime.cancel = cancel
	runtime.done = done
	runtime.mu.Unlock()

	defer func() {
		cancel()
		runtime.mu.Lock()
		runtime.running = false
		runtime.ready = false
		runtime.closed = true
		runtime.cancel = nil
		close(done)
		runtime.mu.Unlock()
	}()

	for {
		if installationlock.Skip("edge_automatic_publication") {
			if err := runtime.wait(runCtx, runtime.config.PollInterval); err != nil {
				return nil
			}
			continue
		}
		worked, err := runtime.poll(runCtx)
		if runCtx.Err() != nil {
			return nil
		}
		delay := runtime.config.PollInterval
		if err != nil {
			runtime.recordFailure(err)
			delay = runtime.config.ErrorBackoff
		} else {
			runtime.recordSuccess()
			if worked {
				continue
			}
		}
		if err := runtime.wait(runCtx, delay); err != nil {
			if runCtx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (runtime *Runtime) Ready() error {
	if runtime == nil {
		return ErrInvalidInput
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closing || runtime.closed {
		return ErrRuntimeClosed
	}
	if runtime.failure != nil {
		return runtime.failure
	}
	if !runtime.running || !runtime.ready {
		return ErrRuntimeNotReady
	}
	return nil
}

func (runtime *Runtime) Close(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidInput
	}
	runtime.closeMu.Lock()
	defer runtime.closeMu.Unlock()

	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.closing = true
	runtime.ready = false
	cancel, done, running := runtime.cancel, runtime.done, runtime.running
	if !running {
		runtime.closed = true
	}
	runtime.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if !running {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (runtime *Runtime) poll(ctx context.Context) (bool, error) {
	workerCtx, cancelWorker := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	workerWorked, workerErr := runtime.worker.RunOnce(workerCtx)
	cancelWorker()

	reconcilerCtx, cancelReconciler := context.WithTimeout(ctx, runtime.config.OperationTimeout)
	reconcilerWorked, reconcilerErr := runtime.reconciler.ReconcileOne(reconcilerCtx)
	cancelReconciler()
	return workerWorked || reconcilerWorked, errors.Join(workerErr, reconcilerErr)
}

func (runtime *Runtime) recordFailure(err error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.ready = false
	runtime.failure = err
}

func (runtime *Runtime) recordSuccess() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.ready = true
	runtime.failure = nil
}

func waitRuntime(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
