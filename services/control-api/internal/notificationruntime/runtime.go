package notificationruntime

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

type batchProcessor interface {
	ProcessBatch(context.Context) (notification.WorkerBatchResult, error)
}

type Runtime struct {
	config         RuntimeConfig
	processor      batchProcessor
	resolver       MemberContactResolver
	providers      map[notification.Channel]ProviderTransport
	registry       *DispatcherRegistry
	recoverySender *recoverySender

	mu                  sync.Mutex
	state               RuntimeState
	ready               bool
	workerRunning       bool
	workerHealthy       bool
	runStarted          bool
	runActive           bool
	closing             bool
	closeComplete       bool
	closeErr            error
	runCancel           context.CancelFunc
	done                chan struct{}
	enabledChannels     int
	consecutiveFailures int
	lastErrorClass      string
	operationContext    context.Context
	operationCancel     context.CancelFunc
	activeReadiness     int
	readinessDrained    chan struct{}
	closeMu             sync.Mutex
}

func Build(config RuntimeConfig, dependencies Dependencies) (*Runtime, error) {
	config = normalizedConfig(config)
	if !config.Enabled {
		return buildRuntime(config, nil, dependencies.MemberContacts, dependencies.Providers)
	}
	if dependencies.Store == nil {
		return nil, ErrInvalidConfig
	}
	registry := NewDispatcherRegistry()
	sender := newMemberSender(dependencies.MemberContacts, dependencies.Providers, config.SendTimeout)
	worker, err := notification.NewWorkerWithAnonymousDispatcher(
		dependencies.Store, sender, registry, config.Worker,
	)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return buildRuntimeWithRegistry(config, worker, dependencies.MemberContacts, dependencies.Providers, registry)
}

func buildRuntime(
	config RuntimeConfig,
	processor batchProcessor,
	resolver MemberContactResolver,
	providers map[notification.Channel]ProviderTransport,
) (*Runtime, error) {
	return buildRuntimeWithRegistry(config, processor, resolver, providers, NewDispatcherRegistry())
}

func buildRuntimeWithRegistry(
	config RuntimeConfig,
	processor batchProcessor,
	resolver MemberContactResolver,
	providers map[notification.Channel]ProviderTransport,
	registry *DispatcherRegistry,
) (*Runtime, error) {
	config = normalizedConfig(config)
	if !validRuntimeConfig(config) || registry == nil || config.Enabled && processor == nil {
		return nil, ErrInvalidConfig
	}
	state := StateBuilt
	if !config.Enabled {
		state = StateDisabled
	}
	operationContext, operationCancel := context.WithCancel(context.Background())
	return &Runtime{
		config: config, processor: processor, resolver: resolver, providers: copyProviders(providers),
		registry: registry, recoverySender: newRecoverySender(providers, config.SendTimeout),
		state: state, done: make(chan struct{}), operationContext: operationContext,
		operationCancel: operationCancel,
	}, nil
}

func (r *Runtime) Run(ctx context.Context) (runErr error) {
	if r == nil || ctx == nil {
		return ErrInvalidConfig
	}
	r.mu.Lock()
	if !r.config.Enabled {
		r.mu.Unlock()
		return ErrDisabled
	}
	// Only one Run at a time. After Run returned (database restart), the caller
	// may call Run again: the retry gets a fresh done channel and starts from a
	// clean terminal state. Close ends this for good.
	if r.runActive || r.closing || r.closeComplete {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	if r.runStarted {
		r.done = make(chan struct{})
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.runStarted = true
	r.runActive = true
	r.runCancel = cancel
	r.workerRunning = true
	r.workerHealthy = false
	if r.state != StateBackoff {
		r.state = StateRunning
	}
	done := r.done
	r.mu.Unlock()

	transient := false
	defer func() {
		cancel()
		r.mu.Lock()
		r.workerRunning = false
		r.workerHealthy = false
		r.ready = false
		r.runActive = false
		if !transient && r.state != StateFailed && r.state != StateStopping && r.state != StateStopped {
			r.state = StateStopped
		}
		close(done)
		r.mu.Unlock()
	}()

	for {
		batch, err := processBatch(runCtx, r.processor)
		if runCtx.Err() != nil {
			return nil
		}
		if errors.Is(err, errWorkerPanic) {
			r.recordWorkerFailure("worker_panic", true)
			return ErrWorkerExited
		}
		if err != nil && r.config.TransientError != nil && r.config.TransientError(err) {
			// The database is temporarily unavailable: not a worker failure.
			r.recordTransientFailure(classifyWorkerError(err))
			transient = true
			return err
		}
		if err != nil {
			failureCount := r.recordWorkerFailure(classifyWorkerError(err), false)
			if failureCount >= r.config.MaxConsecutiveFailures {
				r.mu.Lock()
				r.state = StateFailed
				r.mu.Unlock()
				return ErrWorkerExited
			}
			if !waitContext(runCtx, jittered(errorBackoff(
				r.config.ErrorBackoffBase, r.config.ErrorBackoffMax, failureCount,
			))) {
				return nil
			}
			continue
		}
		r.recordWorkerSuccess(batch)
		if batch.Claimed == 0 && batch.Exhausted == 0 {
			if !waitContext(runCtx, jittered(r.config.IdleWait)) {
				return nil
			}
		}
	}
}

func (r *Runtime) Ready(ctx context.Context, switches notification.ChannelSwitches) error {
	if r == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	readyCtx, resolver, providers, templates, finish, err := r.beginReadiness(ctx)
	if err != nil {
		return err
	}
	defer finish()

	channels := enabledChannels(switches)
	if len(channels) == 0 {
		return ErrChannelUnavailable
	}
	if resolver == nil {
		return ErrSenderUnavailable
	}
	for _, channel := range channels {
		if !validTemplate(channel, templates[channel]) {
			return ErrTemplateUnavailable
		}
		provider := providers[channel]
		if provider == nil {
			return ErrProviderUnavailable
		}
		if err, panicked := callResolverReady(readyCtx, resolver, channel); err != nil || panicked {
			return readinessError(ctx, readyCtx, ErrSenderNotReady)
		}
		if err, panicked := callProviderReady(readyCtx, provider); err != nil || panicked {
			return readinessError(ctx, readyCtx, ErrProviderNotReady)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.workerRunning || !r.workerHealthy || r.state == StateStopping || r.state == StateStopped || r.state == StateFailed {
		return ErrWorkerNotRunning
	}
	r.ready = true
	r.enabledChannels = len(channels)
	r.state = StateReady
	return nil
}

func (r *Runtime) RecoverySender() accountrecovery.RecoverySender {
	if r == nil || !r.config.Enabled {
		return nil
	}
	return r.recoverySender
}

func (r *Runtime) RegisterAnonymousDispatcher(
	ctx context.Context,
	dispatcher notification.AnonymousDispatcher,
) (Registration, error) {
	if r == nil || !r.config.Enabled {
		return nil, ErrDisabled
	}
	r.mu.Lock()
	stopping := r.state == StateStopping || r.state == StateStopped || r.closeComplete
	r.mu.Unlock()
	if stopping {
		return nil, ErrRegistryClosed
	}
	return r.registry.Register(ctx, notification.EventTypeAccountRecovery, dispatcher)
}

func (r *Runtime) Health() HealthSnapshot {
	if r == nil {
		return HealthSnapshot{State: StateDisabled}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return HealthSnapshot{
		Enabled: r.config.Enabled, State: r.state, Ready: r.ready,
		WorkerRunning: r.workerRunning, EnabledChannels: r.enabledChannels,
		ConsecutiveFailures: r.consecutiveFailures, LastErrorClass: r.lastErrorClass,
	}
}

func (r *Runtime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return ErrInvalidConfig
	}
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	if r.closeComplete {
		return r.closeErr
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, r.config.ShutdownTimeout)
	defer cancel()
	r.mu.Lock()
	r.ready = false
	r.enabledChannels = 0
	if r.state != StateDisabled {
		r.state = StateStopping
	}
	r.closing = true
	runActive := r.runActive
	runCancel := r.runCancel
	done := r.done
	readinessDrained := r.readinessDrained
	if r.activeReadiness > 0 && readinessDrained == nil {
		readinessDrained = make(chan struct{})
		r.readinessDrained = readinessDrained
	}
	r.operationCancel()
	r.mu.Unlock()
	if runCancel != nil {
		runCancel()
	}
	if runActive {
		select {
		case <-done:
		case <-shutdownCtx.Done():
			r.mu.Lock()
			r.lastErrorClass = "close_timeout"
			r.mu.Unlock()
			return ErrCloseTimeout
		}
	}
	if readinessDrained != nil {
		select {
		case <-readinessDrained:
		case <-shutdownCtx.Done():
			r.mu.Lock()
			r.lastErrorClass = "close_timeout"
			r.mu.Unlock()
			return ErrCloseTimeout
		}
	}

	closeErr := r.registry.Close(shutdownCtx)
	for _, channel := range []notification.Channel{notification.ChannelEmail, notification.ChannelSMS} {
		provider := r.providers[channel]
		if provider == nil {
			continue
		}
		providerErr, panicked := callProviderClose(shutdownCtx, provider)
		if (providerErr != nil || panicked) && closeErr == nil {
			closeErr = ErrProviderClose
		}
	}
	if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
		closeErr = ErrCloseTimeout
	}
	if closeErr != nil && !errors.Is(closeErr, ErrProviderClose) && !errors.Is(closeErr, ErrCloseTimeout) {
		closeErr = ErrProviderClose
	}
	r.mu.Lock()
	r.closeComplete = true
	r.closeErr = closeErr
	r.state = StateStopped
	r.ready = false
	r.workerRunning = false
	r.workerHealthy = false
	r.mu.Unlock()
	return closeErr
}

func callResolverReady(
	ctx context.Context,
	resolver MemberContactResolver,
	channel notification.Channel,
) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err = nil
			panicked = true
		}
	}()
	err = resolver.Ready(ctx, channel)
	return err, false
}

func callProviderReady(ctx context.Context, provider ProviderTransport) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err = nil
			panicked = true
		}
	}()
	err = provider.Ready(ctx)
	return err, false
}

func callProviderClose(ctx context.Context, provider ProviderTransport) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err = nil
			panicked = true
		}
	}()
	err = provider.Close(ctx)
	return err, false
}

func (r *Runtime) beginReadiness(
	ctx context.Context,
) (
	context.Context,
	MemberContactResolver,
	map[notification.Channel]ProviderTransport,
	map[notification.Channel]notification.TemplateRef,
	func(),
	error,
) {
	r.mu.Lock()
	if !r.config.Enabled {
		r.mu.Unlock()
		return nil, nil, nil, nil, nil, ErrDisabled
	}
	if !r.workerRunning || !r.workerHealthy || r.state == StateStopping || r.state == StateStopped || r.state == StateFailed {
		r.mu.Unlock()
		return nil, nil, nil, nil, nil, ErrWorkerNotRunning
	}
	r.activeReadiness++
	operationContext := r.operationContext
	resolver := r.resolver
	providers := copyProviders(r.providers)
	templates := copyTemplates(r.config.RecoveryTemplates)
	r.mu.Unlock()

	readyCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(operationContext, cancel)
	finish := func() {
		stop()
		cancel()
		r.mu.Lock()
		r.activeReadiness--
		if r.activeReadiness == 0 && r.readinessDrained != nil {
			close(r.readinessDrained)
			r.readinessDrained = nil
		}
		r.mu.Unlock()
	}
	return readyCtx, resolver, providers, templates, finish, nil
}

func readinessError(callerContext, readinessContext context.Context, unavailable error) error {
	if err := callerContext.Err(); err != nil {
		return err
	}
	if readinessContext.Err() != nil {
		return ErrWorkerNotRunning
	}
	return unavailable
}

var errWorkerPanic = errors.New("notification_runtime_worker_panic")

func processBatch(ctx context.Context, processor batchProcessor) (result notification.WorkerBatchResult, err error) {
	defer func() {
		if recover() != nil {
			result = notification.WorkerBatchResult{}
			err = errWorkerPanic
		}
	}()
	return processor.ProcessBatch(ctx)
}

func (r *Runtime) recordWorkerFailure(class string, terminal bool) int {
	r.mu.Lock()
	r.consecutiveFailures++
	r.lastErrorClass = class
	r.ready = false
	r.workerHealthy = false
	r.enabledChannels = 0
	if terminal {
		r.state = StateFailed
	} else {
		r.state = StateBackoff
	}
	count := r.consecutiveFailures
	r.mu.Unlock()
	r.config.Logger.Warn("notification runtime worker state",
		"state", r.Health().State, "error_class", class, "failure_count", count)
	return count
}

// recordTransientFailure marks the worker unready in backoff without counting
// the error towards MaxConsecutiveFailures.
func (r *Runtime) recordTransientFailure(class string) {
	r.mu.Lock()
	r.lastErrorClass = class
	r.ready = false
	r.workerHealthy = false
	r.enabledChannels = 0
	r.state = StateBackoff
	r.mu.Unlock()
}

func (r *Runtime) recordWorkerSuccess(batch notification.WorkerBatchResult) {
	r.mu.Lock()
	r.consecutiveFailures = 0
	r.lastErrorClass = ""
	if r.state == StateBackoff {
		r.state = StateRunning
	}
	r.workerHealthy = true
	r.mu.Unlock()
	if batch.Claimed > 0 || batch.Exhausted > 0 {
		r.config.Logger.Info("notification runtime worker batch",
			"state", "processed", "claimed", batch.Claimed, "succeeded", batch.Succeeded,
			"retry_scheduled", batch.RetryScheduled, "permanent_failed", batch.PermanentFailed,
			"exhausted", batch.Exhausted)
	}
}

func classifyWorkerError(err error) string {
	switch {
	case errors.Is(err, notification.ErrClaimLost):
		return "worker_claim_lost"
	case errors.Is(err, notification.ErrLeaseUnsafe):
		return "worker_lease_unsafe"
	case errors.Is(err, context.DeadlineExceeded):
		return "worker_timeout"
	default:
		return "worker_store_unavailable"
	}
}

func normalizedConfig(config RuntimeConfig) RuntimeConfig {
	defaults := DefaultRuntimeConfig()
	if config.Worker == (notification.WorkerConfig{}) {
		config.Worker = defaults.Worker
	}
	if config.IdleWait == 0 {
		config.IdleWait = defaults.IdleWait
	}
	if config.ErrorBackoffBase == 0 {
		config.ErrorBackoffBase = defaults.ErrorBackoffBase
	}
	if config.ErrorBackoffMax == 0 {
		config.ErrorBackoffMax = defaults.ErrorBackoffMax
	}
	if config.MaxConsecutiveFailures == 0 {
		config.MaxConsecutiveFailures = defaults.MaxConsecutiveFailures
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = defaults.SendTimeout
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = defaults.ShutdownTimeout
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	config.RecoveryTemplates = copyTemplates(config.RecoveryTemplates)
	return config
}

func validRuntimeConfig(config RuntimeConfig) bool {
	return config.IdleWait > 0 && config.IdleWait <= time.Minute &&
		config.ErrorBackoffBase > 0 && config.ErrorBackoffMax >= config.ErrorBackoffBase &&
		config.ErrorBackoffMax <= 5*time.Minute && config.MaxConsecutiveFailures > 0 &&
		config.MaxConsecutiveFailures <= 100 && config.SendTimeout > 0 &&
		config.SendTimeout <= 15*time.Minute && config.ShutdownTimeout > 0 &&
		config.ShutdownTimeout <= 5*time.Minute && config.Logger != nil
}

func enabledChannels(switches notification.ChannelSwitches) []notification.Channel {
	channels := make([]notification.Channel, 0, 2)
	if switches.Email {
		channels = append(channels, notification.ChannelEmail)
	}
	if switches.SMS {
		channels = append(channels, notification.ChannelSMS)
	}
	return channels
}

func validTemplate(channel notification.Channel, ref notification.TemplateRef) bool {
	return ref.ID != "" && ref.Version > 0 && ref.Channel == channel
}

func copyTemplates(source map[notification.Channel]notification.TemplateRef) map[notification.Channel]notification.TemplateRef {
	cloned := make(map[notification.Channel]notification.TemplateRef, len(source))
	for channel, template := range source {
		cloned[channel] = template
	}
	return cloned
}

func errorBackoff(base, maximum time.Duration, failures int) time.Duration {
	delay := base
	for current := 1; current < failures && delay < maximum; current++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func jittered(delay time.Duration) time.Duration {
	maximumJitter := delay / 4
	if maximumJitter <= 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(maximumJitter)+1))
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
