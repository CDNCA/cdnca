package errorpagecontrol

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultRuntimeReconcileBatchSize = 100
	defaultRuntimeReconcileTimeout   = 30 * time.Second
	defaultRuntimeWorkerIdlePoll     = 250 * time.Millisecond
	defaultRuntimeWorkerErrorBackoff = time.Second
)

var (
	ErrRuntimeAlreadyRunning = errors.New("error page control runtime already running")
	ErrRuntimeClosed         = errors.New("error page control runtime closed")
	ErrRuntimeNotReady       = errors.New("error page control runtime not ready")
)

type RuntimeConfig struct {
	Enabled            bool
	ReconcileBatchSize int
	ReconcileTimeout   time.Duration
	WorkerIdlePoll     time.Duration
	WorkerErrorBackoff time.Duration
}

type RuntimeDependencies struct {
	Pool         *pgxpool.Pool
	Identity     *identity.Service
	APIKeys      *apikey.Service
	IAM          *iamlock.Authorizer
	ContentStore ContentStore
	Scanner      Scanner
	Limits       LimitProvider
	// SlotRepublisher (optional) queues node republication for a slot change.
	SlotRepublisher SlotRepublisher
}

type runtimeReconciler interface {
	ReconcileAssets(context.Context, int) (int, error)
}

type Runtime struct {
	handler http.Handler
	service *Service
	worker  runtimeReconciler
	batch   int
	timeout time.Duration
	idle    time.Duration
	backoff time.Duration

	mu       sync.Mutex
	running  bool
	ready    bool
	closed   bool
	deadline time.Time
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewRuntimeHandler assembles the package's production HTTP, PostgreSQL
// publication, and asset-reconciliation runtime without mounting or starting it.
func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	if !config.Enabled {
		return newRuntime(http.NotFoundHandler(), nil, nil, defaultRuntimeReconcileBatchSize,
			defaultRuntimeWorkerIdlePoll, defaultRuntimeWorkerErrorBackoff), nil
	}
	if config.ReconcileBatchSize == 0 {
		config.ReconcileBatchSize = defaultRuntimeReconcileBatchSize
	}
	if config.ReconcileTimeout == 0 {
		config.ReconcileTimeout = defaultRuntimeReconcileTimeout
	}
	if config.WorkerIdlePoll == 0 {
		config.WorkerIdlePoll = defaultRuntimeWorkerIdlePoll
	}
	if config.WorkerErrorBackoff == 0 {
		config.WorkerErrorBackoff = defaultRuntimeWorkerErrorBackoff
	}
	if config.ReconcileBatchSize < 1 || config.ReconcileBatchSize > 1000 || config.ReconcileTimeout <= 0 ||
		config.WorkerIdlePoll <= 0 || config.WorkerErrorBackoff <= 0 ||
		!runtimeDependenciesConfigured(dependencies) {
		return nil, ErrInvalidStore
	}
	authorizer := runtimeTxAuthorizer{identity: dependencies.Identity, iam: dependencies.IAM}
	service, err := newRuntimeService(dependencies, authorizer)
	if err != nil {
		return nil, ErrInvalidStore
	}
	if dependencies.SlotRepublisher != nil {
		if err := service.WithSlotRepublisher(dependencies.SlotRepublisher); err != nil {
			return nil, err
		}
	}
	handler, err := NewHandler(service, runtimeAuthenticator{
		identity: dependencies.Identity, apiKeys: dependencies.APIKeys,
	})
	if err != nil {
		return nil, ErrInvalidStore
	}
	runtime := newRuntime(runtimeMetadataHandler{inner: handler}, service, service, config.ReconcileBatchSize,
		config.WorkerIdlePoll, config.WorkerErrorBackoff)
	runtime.timeout = config.ReconcileTimeout
	return runtime, nil
}

func newRuntimeService(dependencies RuntimeDependencies, authorizer runtimeTxAuthorizer) (service *Service, err error) {
	defer func() {
		if recover() != nil {
			service, err = nil, ErrInvalidStore
		}
	}()
	return NewService(dependencies.Pool, dependencies.ContentStore, dependencies.Scanner,
		dependencies.Limits, authorizer)
}

func newRuntime(
	handler http.Handler,
	service *Service,
	worker runtimeReconciler,
	batch int,
	idle time.Duration,
	backoff time.Duration,
) *Runtime {
	return &Runtime{
		handler: handler, service: service, worker: worker, batch: batch,
		timeout: defaultRuntimeReconcileTimeout, idle: idle, backoff: backoff,
	}
}

func (runtime *Runtime) Handler() http.Handler {
	if runtime == nil {
		return nil
	}
	return runtime.handler
}

func (runtime *Runtime) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if runtime == nil || runtime.handler == nil {
		http.NotFound(response, request)
		return
	}
	runtime.handler.ServeHTTP(response, request)
}

func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || ctx == nil || runtime.handler == nil || runtime.batch < 1 || runtime.timeout <= 0 ||
		runtime.idle <= 0 || runtime.backoff <= 0 {
		return ErrInvalidStore
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
		runtime.deadline = time.Time{}
		runtime.cancel = nil
		close(done)
		runtime.mu.Unlock()
	}()

	for runCtx.Err() == nil {
		processed, err := 0, error(nil)
		if runtime.worker != nil {
			reconcileCtx, cancelReconcile := context.WithTimeout(runCtx, runtime.timeout)
			runtime.mu.Lock()
			runtime.deadline = time.Now().Add(runtime.timeout)
			runtime.mu.Unlock()
			var panicked bool
			processed, err, panicked = reconcileRuntime(reconcileCtx, runtime.worker, runtime.batch)
			cancelReconcile()
			if panicked {
				runtime.mu.Lock()
				runtime.ready = false
				runtime.deadline = time.Time{}
				runtime.mu.Unlock()
				return ErrUnavailable
			}
		}
		if runCtx.Err() != nil {
			break
		}
		runtime.mu.Lock()
		runtime.ready = runtime.worker != nil && err == nil && processed >= 0
		runtime.deadline = time.Time{}
		runtime.mu.Unlock()
		delay := runtime.idle
		if err != nil || processed < 0 {
			delay = runtime.backoff
		} else if processed > 0 {
			continue
		}
		if err := waitRuntime(runCtx, delay); err != nil && runCtx.Err() == nil {
			return ErrUnavailable
		}
	}
	return nil
}

func reconcileRuntime(
	ctx context.Context,
	worker runtimeReconciler,
	batch int,
) (processed int, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			processed = 0
			err = ErrUnavailable
			panicked = true
		}
	}()
	processed, err = worker.ReconcileAssets(ctx, batch)
	return processed, err, false
}

func (runtime *Runtime) Ready() error {
	if runtime == nil {
		return ErrRuntimeNotReady
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed || !runtime.running || !runtime.ready ||
		(!runtime.deadline.IsZero() && !time.Now().Before(runtime.deadline)) {
		return ErrRuntimeNotReady
	}
	return nil
}

func (runtime *Runtime) Close() error {
	if runtime == nil {
		return ErrInvalidStore
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
	runtime.ready = false
	if !runtime.running {
		runtime.mu.Unlock()
		return nil
	}
	cancel, done := runtime.cancel, runtime.done
	cancel()
	runtime.mu.Unlock()
	<-done
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

type runtimeMetadataHandler struct {
	inner http.Handler
}

func (handler runtimeMetadataHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	normalized, err := normalizeRuntimeMetadata(request)
	if err != nil {
		setResponseHeaders(response)
		writeHTTPError(response, err)
		return
	}
	handler.inner.ServeHTTP(response, normalized)
}

func normalizeRuntimeMetadata(request *http.Request) (*http.Request, error) {
	for _, name := range []string{"Idempotency-Key", "If-Match", "Content-Type"} {
		if len(request.Header.Values(name)) > 1 {
			return nil, ErrInvalidInput
		}
	}
	requestIDs := request.Header.Values("X-Request-ID")
	if len(requestIDs) > 1 || len(requestIDs) == 1 && !writeMetadataPattern.MatchString(requestIDs[0]) {
		return nil, ErrInvalidInput
	}
	traceIDs := request.Header.Values("X-Trace-ID")
	if len(traceIDs) > 1 || len(traceIDs) == 1 && !writeMetadataPattern.MatchString(traceIDs[0]) {
		return nil, ErrInvalidInput
	}
	if len(requestIDs) == 1 && len(traceIDs) == 1 {
		return request, nil
	}
	if request.Method != http.MethodGet {
		return request, nil
	}
	normalized := request.Clone(request.Context())
	requestID := uuid.NewString()
	if len(requestIDs) == 1 {
		requestID = requestIDs[0]
	} else {
		normalized.Header.Set("X-Request-ID", requestID)
	}
	if len(traceIDs) == 0 {
		normalized.Header.Set("X-Trace-ID", requestID)
	}
	return normalized, nil
}

type runtimeAuthenticator struct {
	identity *identity.Service
	apiKeys  *apikey.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (Actor, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return Actor{}, ErrUnauthenticated
	}
	authorization := strings.TrimSpace(values[0])
	scheme, rawToken, found := strings.Cut(authorization, " ")
	rawToken = strings.TrimSpace(rawToken)
	if !found || rawToken == "" || len(rawToken) > 8192 ||
		strings.ContainsAny(rawToken, " \t\r\n") {
		return Actor{}, ErrUnauthenticated
	}
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		if authenticator.identity == nil || !authenticator.identity.Configured() {
			return Actor{}, ErrUnavailable
		}
		session, err := authenticator.identity.AuthenticateSession(request.Context(), rawToken)
		if err != nil {
			if errors.Is(err, identity.ErrInvalidSession) {
				return Actor{}, ErrUnauthenticated
			}
			return Actor{}, ErrUnavailable
		}
		return newRuntimeActor(session.Principal, CredentialKindSession, session.SessionID, rawToken)
	case strings.EqualFold(scheme, "CdncaKey"):
		if authenticator.apiKeys == nil {
			return Actor{}, ErrUnavailable
		}
		principal, keyID, _, err := authenticator.apiKeys.AuthenticateWithKeyID(request.Context(), rawToken)
		if err != nil {
			if errors.Is(err, apikey.ErrInvalidCredential) {
				return Actor{}, ErrUnauthenticated
			}
			return Actor{}, ErrUnavailable
		}
		return newRuntimeActor(principal, CredentialKindAPIKey, keyID, rawToken)
	default:
		return Actor{}, ErrUnauthenticated
	}
}

func newRuntimeActor(
	principal identity.Principal,
	credentialKind string,
	credentialID uuid.UUID,
	rawCredential string,
) (Actor, error) {
	actor := Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Credential: CredentialReference{Kind: credentialKind, ID: credentialID},
		rawSession: rawCredential,
	}
	if principal.TenantID != nil {
		tenantID := *principal.TenantID
		actor.tenantID = &tenantID
	}
	if validateRuntimeActor(actor) != nil {
		return Actor{}, ErrUnauthenticated
	}
	return actor, nil
}

type scopedTxAuthorizer interface {
	AuthorizeTarget(context.Context, pgx.Tx, Actor, uuid.UUID, string) error
}

type runtimeTxAuthorizer struct {
	identity *identity.Service
	iam      *iamlock.Authorizer
}

func (authorizer runtimeTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	permission string,
) error {
	return authorizer.AuthorizeTarget(ctx, tx, actor, actor.ScopeID, permission)
}

func (authorizer runtimeTxAuthorizer) AuthorizeTarget(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	if authorizer.identity == nil || authorizer.iam == nil || tx == nil || targetScopeID == uuid.Nil ||
		validateRuntimeActor(actor) != nil {
		return ErrPermissionDenied
	}
	var sealed iamlock.Authorization
	var err error
	switch actor.Credential.Kind {
	case CredentialKindSession:
		sealed, err = authorizer.iam.AuthorizeSession(ctx, tx, actor.rawSession, targetScopeID, permission)
	case CredentialKindAPIKey:
		sealed, err = authorizer.iam.AuthorizeAPIKey(ctx, tx, actor.rawSession, targetScopeID, permission)
	default:
		return ErrPermissionDenied
	}
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return ErrUnavailable
		case errors.Is(err, iamlock.ErrInvalidCredential):
			return ErrUnauthenticated
		case errors.Is(err, iamlock.ErrPermissionDenied):
			return ErrPermissionDenied
		default:
			return ErrUnavailable
		}
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID ||
		sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != targetScopeID ||
		sealed.CredentialKind() != actor.Credential.Kind || sealed.CredentialID() != actor.Credential.ID {
		return ErrPermissionDenied
	}
	var authenticationKind, targetKind string
	var authenticationTenantID, targetTenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR KEY SHARE`,
		actor.ScopeID).Scan(&authenticationKind, &authenticationTenantID); err != nil {
		return ErrUnavailable
	}
	if targetScopeID == actor.ScopeID {
		targetKind, targetTenantID = authenticationKind, authenticationTenantID
	} else if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR KEY SHARE`,
		targetScopeID).Scan(&targetKind, &targetTenantID); err != nil {
		return ErrUnavailable
	}
	if authenticationKind != actor.ScopeKind || !sameTenantID(authenticationTenantID, actor.tenantID) {
		return ErrPermissionDenied
	}
	sealedTenantID, sealedHasTenant := sealed.TenantID()
	if targetKind == "platform" {
		if targetTenantID != nil || sealedHasTenant {
			return ErrPermissionDenied
		}
	} else if targetKind != "tenant" || targetTenantID == nil || !sealedHasTenant ||
		*targetTenantID != sealedTenantID {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" && (targetScopeID != actor.ScopeID || targetKind != "tenant") {
		return ErrPermissionDenied
	}
	return nil
}

func validateRuntimeActor(actor Actor) error {
	if validateActor(actor) != nil || actor.rawSession == "" || len(actor.rawSession) > 8192 {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" && actor.tenantID != nil ||
		actor.ScopeKind == "tenant" && (actor.tenantID == nil || *actor.tenantID == uuid.Nil) {
		return ErrInvalidInput
	}
	return nil
}

func sameTenantID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right && *left != uuid.Nil
}

func normalizeServiceError(err error) error {
	for _, known := range []error{
		ErrInvalidInput, ErrInvalidCredential, ErrUnauthenticated, ErrPermissionDenied,
		ErrNotFound, ErrConflict, ErrRevisionConflict, ErrIdempotencyConflict,
		ErrQuotaExceeded, ErrEntitlementDenied, ErrUnsafeContent, ErrScanRejected,
		ErrUnavailable, errMethodNotAllowed,
	} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrUnavailable
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func runtimePoolConfigured(pool *pgxpool.Pool) (configured bool) {
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

func runtimeDependenciesConfigured(dependencies RuntimeDependencies) (configured bool) {
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return runtimePoolConfigured(dependencies.Pool) && dependencies.Identity.Configured() &&
		!isNilDependency(dependencies.APIKeys) &&
		dependencies.IAM.Configured() && !isNilDependency(dependencies.ContentStore) &&
		dependencies.ContentStore.Capabilities().runtimeReady() && !isNilDependency(dependencies.Scanner) &&
		writeMetadataPattern.MatchString(dependencies.Scanner.Name()) && !isNilDependency(dependencies.Limits)
}
