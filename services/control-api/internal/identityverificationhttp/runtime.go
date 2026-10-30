package identityverificationhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultSettlementIdlePoll     = 250 * time.Millisecond
	defaultSettlementErrorBackoff = time.Second
)

var (
	ErrRuntimeAlreadyRunning = errors.New("identity verification runtime already running")
	ErrRuntimeClosed         = errors.New("identity verification runtime closed")
	ErrRuntimeNotReady       = errors.New("identity verification runtime not ready")
)

type RuntimeConfig struct {
	Enabled            bool
	Core               identityverification.Config
	Service            ServiceConfig
	Handler            HandlerConfig
	Settlement         identityverification.SettlementWorkerConfig
	Provider           ProviderWorkflowConfig
	WorkerIdlePoll     time.Duration
	WorkerErrorBackoff time.Duration
}

type RuntimeDependencies struct {
	Pool                *pgxpool.Pool
	Identity            *identity.Service
	IAM                 *iamlock.Authorizer
	Resolver            RuntimeTrustedEvidenceResolver
	SettlementPublisher RuntimeSettlementPublisher
	PrivateObjects      PrivateObjectStore
	KYCProvider         KYCProvider
	Clock               identityverification.Clock
}

type RuntimeTrustedEvidenceResolver interface {
	TrustedEvidenceResolver
	Configured() bool
}

type RuntimeSettlementPublisher interface {
	Configured() bool
	Publish(context.Context, identityverification.SettlementCommitRequest) (identityverification.SettlementCommitResult, error)
}

type settlementProcessor interface {
	RunOnce(context.Context) (bool, error)
}

type Runtime struct {
	handler      http.Handler
	worker       settlementProcessor
	provider     *ProviderWorkflow
	idlePoll     time.Duration
	errorBackoff time.Duration

	mu      sync.Mutex
	running bool
	ready   bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewRuntime assembles the package-owned HTTP and settlement-worker boundary.
func NewRuntime(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	if !config.Enabled {
		return newRuntime(http.NotFoundHandler(), nil, defaultSettlementIdlePoll,
			defaultSettlementErrorBackoff), nil
	}
	if !configuredPool(dependencies.Pool) || !dependencies.Identity.Configured() ||
		!dependencies.IAM.Configured() || !configuredResolver(dependencies.Resolver) ||
		!configuredPublisher(dependencies.SettlementPublisher) || !configuredClock(dependencies.Clock) {
		return nil, ErrInvalidService
	}
	if config.WorkerIdlePoll == 0 {
		config.WorkerIdlePoll = defaultSettlementIdlePoll
	}
	if config.WorkerErrorBackoff == 0 {
		config.WorkerErrorBackoff = defaultSettlementErrorBackoff
	}
	if config.WorkerIdlePoll <= 0 || config.WorkerErrorBackoff <= 0 {
		return nil, ErrInvalidService
	}
	config.Core.Clock = dependencies.Clock
	config.Settlement.Clock = dependencies.Clock
	core, err := identityverification.NewIAMService(dependencies.Pool, audit.New(dependencies.Pool),
		dependencies.IAM, config.Core)
	if err != nil {
		return nil, ErrInvalidService
	}
	reader, err := newPostgresReader(dependencies.Pool, core)
	if err != nil {
		return nil, ErrInvalidService
	}
	service, err := newService(core, reader, dependencies.Resolver, config.Service)
	if err != nil {
		return nil, ErrInvalidService
	}
	handler, err := newHandler(service,
		runtimeAuthenticator{identity: dependencies.Identity}.Authenticate, config.Handler)
	if err != nil {
		return nil, ErrInvalidService
	}
	worker, err := identityverification.NewSettlementWorker(dependencies.Pool, audit.New(dependencies.Pool),
		settlementPublisherCommitter{publisher: dependencies.SettlementPublisher}, config.Settlement)
	if err != nil {
		return nil, ErrInvalidService
	}
	var providerWorkflow *ProviderWorkflow
	var processor settlementProcessor = worker
	assembledHandler := http.Handler(handler)
	if len(config.Provider.TokenKey) != 0 {
		providerWorkflow, err = NewProviderWorkflow(dependencies.Pool, audit.New(dependencies.Pool), core,
			dependencies.PrivateObjects, dependencies.KYCProvider, config.Provider)
		if err != nil {
			return nil, ErrInvalidService
		}
		providerHandler, handlerErr := newProviderHandler(providerWorkflow,
			runtimeAuthenticator{identity: dependencies.Identity}.Authenticate, config.Handler)
		if handlerErr != nil {
			providerWorkflow.Close()
			return nil, ErrInvalidService
		}
		assembledHandler = providerDispatchHandler{cases: handler, provider: providerHandler}
		processor = combinedProviderProcessor{settlement: worker, provider: providerWorkflow}
	}
	runtime := newRuntime(assembledHandler, processor, config.WorkerIdlePoll, config.WorkerErrorBackoff)
	runtime.provider = providerWorkflow
	return runtime, nil
}

// NewRuntimeHandler preserves the package factory name while exposing the
// complete runtime lifecycle. Runtime also implements http.Handler.
func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	return NewRuntime(config, dependencies)
}

func newRuntime(handler http.Handler, worker settlementProcessor, idlePoll, errorBackoff time.Duration) *Runtime {
	return &Runtime{handler: handler, worker: worker, idlePoll: idlePoll, errorBackoff: errorBackoff}
}

func (runtime *Runtime) Handler() http.Handler {
	if runtime == nil {
		return nil
	}
	return runtime.handler
}

func (runtime *Runtime) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if runtime == nil || runtime.handler == nil {
		http.NotFound(writer, request)
		return
	}
	runtime.handler.ServeHTTP(writer, request)
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil {
		return ErrInvalidService
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtime.mu.Lock()
	if runtime.closed {
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
	runtime.cancel = cancel
	runtime.done = done
	runtime.mu.Unlock()
	defer func() {
		cancel()
		runtime.mu.Lock()
		runtime.running = false
		runtime.ready = false
		runtime.cancel = nil
		close(done)
		runtime.mu.Unlock()
	}()

	for runCtx.Err() == nil {
		processed, err := false, error(nil)
		if runtime.worker != nil {
			processed, err = runtime.worker.RunOnce(runCtx)
		}
		if runCtx.Err() != nil {
			break
		}
		runtime.mu.Lock()
		runtime.ready = runtime.worker != nil && err == nil
		runtime.mu.Unlock()
		delay := runtime.idlePoll
		if err != nil {
			delay = runtime.errorBackoff
		} else if processed {
			continue
		}
		if err := waitRuntime(runCtx, delay); err != nil && runCtx.Err() == nil {
			return err
		}
	}
	return nil
}

func (runtime *Runtime) Ready() error {
	if runtime == nil {
		return ErrRuntimeNotReady
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed || !runtime.running || !runtime.ready {
		return ErrRuntimeNotReady
	}
	return nil
}

func (runtime *Runtime) Close() error {
	if runtime == nil {
		return ErrInvalidService
	}
	runtime.mu.Lock()
	if runtime.closed {
		running, done := runtime.running, runtime.done
		runtime.mu.Unlock()
		if running && done != nil {
			<-done
		}
		return nil
	}
	runtime.closed = true
	if !runtime.running {
		if runtime.provider != nil {
			runtime.provider.Close()
		}
		runtime.mu.Unlock()
		return nil
	}
	cancel, done := runtime.cancel, runtime.done
	cancel()
	runtime.mu.Unlock()
	<-done
	if runtime.provider != nil {
		runtime.provider.Close()
	}
	return nil
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

type settlementPublisherCommitter struct {
	publisher RuntimeSettlementPublisher
}

type combinedProviderProcessor struct {
	settlement settlementProcessor
	provider   *ProviderWorkflow
}

func (processor combinedProviderProcessor) RunOnce(ctx context.Context) (bool, error) {
	settled, err := processor.settlement.RunOnce(ctx)
	if err != nil {
		return false, err
	}
	cleaned, err := processor.provider.RunCleanupOnce(ctx)
	return settled || cleaned, err
}

type providerDispatchHandler struct {
	cases    http.Handler
	provider http.Handler
}

func (handler providerDispatchHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, apiPrefix+"/provider-sessions") ||
		strings.HasPrefix(request.URL.Path, apiPrefix+"/provider-callbacks") {
		handler.provider.ServeHTTP(writer, request)
		return
	}
	handler.cases.ServeHTTP(writer, request)
}

func (committer settlementPublisherCommitter) Commit(ctx context.Context,
	request identityverification.SettlementCommitRequest,
) (identityverification.SettlementCommitResult, error) {
	return committer.publisher.Publish(ctx, request)
}

type runtimeAuthenticator struct {
	identity *identity.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request,
	rawSession string,
) (identity.AuthenticatedSession, error) {
	if !authenticator.identity.Configured() {
		return identity.AuthenticatedSession{}, ErrStoreUnavailable
	}
	session, err := authenticator.identity.AuthenticateSession(request.Context(), rawSession)
	if errors.Is(err, identity.ErrInvalidSession) {
		return identity.AuthenticatedSession{}, ErrUnauthenticated
	}
	if err != nil {
		return identity.AuthenticatedSession{}, ErrStoreUnavailable
	}
	return session, nil
}

func configuredPool(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil
}

func configuredResolver(resolver RuntimeTrustedEvidenceResolver) (configured bool) {
	if isNilDependency(resolver) {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return resolver.Configured()
}

func configuredPublisher(publisher RuntimeSettlementPublisher) (configured bool) {
	if isNilDependency(publisher) {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return publisher.Configured()
}

func configuredClock(clock identityverification.Clock) (configured bool) {
	if clock == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return !clock().IsZero()
}
