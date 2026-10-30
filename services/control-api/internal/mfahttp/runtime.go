package mfahttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const runtimeReadinessTimeout = time.Second

type readinessProbe func(context.Context) error

type StepUpConsumer interface {
	ConsumeStepUpTxWithScopes(context.Context, pgx.Tx, mfa.Actor, []uuid.UUID, mfa.ConsumeStepUpRequest) (mfa.Evidence, error)
}

type RuntimeConfig struct {
	Enabled bool
	Core    mfa.Config
	Handler HandlerConfig
}

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	IAM      *iamlock.Authorizer
	Cipher   mfa.EnvelopeCipher
}

type Runtime struct {
	handler http.Handler
	stepUp  StepUpConsumer
	service *mfa.Service
	enabled bool
	probe   readinessProbe

	mu      sync.Mutex
	running bool
	ready   bool
	closed  bool
	cancel  context.CancelFunc
	done    chan struct{}
}

func NewRuntime(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	if !config.Enabled {
		return newRuntime(http.NotFoundHandler(), false, nil), nil
	}
	if !configuredPool(dependencies.Pool) || !configuredIdentity(dependencies.Identity) ||
		!configuredIAM(dependencies.IAM) || !configuredCipher(dependencies.Cipher) ||
		!validCoreConfig(config.Core) {
		return nil, ErrInvalidService
	}
	service, err := mfa.NewServiceWithDependencies(dependencies.Pool, dependencies.Cipher,
		audit.New(dependencies.Pool), config.Core)
	if err != nil {
		return nil, ErrInvalidService
	}
	handler, err := newHandler(service,
		runtimeAuthenticator{identity: dependencies.Identity}.Authenticate, config.Handler)
	if err != nil {
		return nil, ErrInvalidService
	}
	runtime := newRuntime(handler, true, dependencies.Pool.Ping)
	runtime.stepUp = service
	runtime.service = service
	return runtime, nil
}

func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (*Runtime, error) {
	return NewRuntime(config, dependencies)
}

func newRuntime(handler http.Handler, enabled bool, probe readinessProbe) *Runtime {
	return &Runtime{handler: handler, enabled: enabled, probe: probe}
}

func (runtime *Runtime) Handler() http.Handler {
	if runtime == nil {
		return nil
	}
	return runtime.handler
}

// LoginVerifier is the MFA service for a sign-in that has no session yet
// (ADR 0019 BB-05 billing bridge SSO); nil when MFA is off.
func (runtime *Runtime) LoginVerifier() *mfa.Service {
	if runtime == nil || !runtime.enabled {
		return nil
	}
	return runtime.service
}

func (runtime *Runtime) StepUpConsumer() StepUpConsumer {
	if runtime == nil || !runtime.enabled {
		return nil
	}
	return runtime.stepUp
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
	runtime.ready = runtime.enabled
	runtime.cancel = cancel
	runtime.done = done
	runtime.mu.Unlock()

	<-runCtx.Done()
	cancel()
	runtime.mu.Lock()
	runtime.running = false
	runtime.ready = false
	runtime.cancel = nil
	close(done)
	runtime.mu.Unlock()
	return nil
}

func (runtime *Runtime) Ready() (result error) {
	if runtime == nil {
		return ErrRuntimeNotReady
	}
	defer func() {
		if recover() != nil {
			result = ErrRuntimeNotReady
		}
	}()
	runtime.mu.Lock()
	if runtime.closed || !runtime.running || !runtime.ready || runtime.probe == nil {
		runtime.mu.Unlock()
		return ErrRuntimeNotReady
	}
	probe := runtime.probe
	runtime.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), runtimeReadinessTimeout)
	defer cancel()
	if probe(ctx) != nil {
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

type runtimeAuthenticator struct {
	identity *identity.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request,
	rawSession string,
) (identity.AuthenticatedSession, error) {
	if authenticator.identity == nil || !authenticator.identity.Configured() {
		return identity.AuthenticatedSession{}, mfa.ErrUnavailable
	}
	session, err := authenticator.identity.AuthenticateSession(request.Context(), rawSession)
	if errors.Is(err, identity.ErrInvalidSession) {
		return identity.AuthenticatedSession{}, ErrUnauthenticated
	}
	if err != nil {
		if request.Context().Err() != nil {
			return identity.AuthenticatedSession{}, request.Context().Err()
		}
		return identity.AuthenticatedSession{}, mfa.ErrUnavailable
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

func configuredIdentity(service *identity.Service) (configured bool) {
	if service == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return service.Configured()
}

func configuredIAM(authorizer *iamlock.Authorizer) (configured bool) {
	if authorizer == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return authorizer.Configured()
}

func configuredCipher(cipher mfa.EnvelopeCipher) (configured bool) {
	if !configuredDependency(cipher) {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	if dependency, ok := cipher.(interface{ Configured() bool }); ok {
		return dependency.Configured()
	}
	return true
}

func configuredDependency(value any) bool {
	if value == nil {
		return false
	}
	kind := reflect.ValueOf(value)
	switch kind.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !kind.IsNil()
	default:
		return true
	}
}

func validCoreConfig(config mfa.Config) (valid bool) {
	if config.Clock == nil || !configuredReader(config.Random) || config.EnrollmentTTL <= 0 ||
		config.EnrollmentTTL > 15*time.Minute || config.Issuer == "" ||
		config.Issuer != strings.TrimSpace(config.Issuer) || len(config.Issuer) > 128 ||
		strings.IndexFunc(config.Issuer, func(r rune) bool {
			return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
		}) != -1 {
		return false
	}
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	return !config.Clock().IsZero()
}

func configuredReader(reader io.Reader) bool {
	return configuredDependency(reader)
}
