package urlauthpolicyhttp

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeConfig struct {
	Enabled bool
	Handler HandlerConfig
}

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	APIKeys  *apikey.Service
	IAM      *iamlock.Authorizer
	Cipher   urlauthpolicy.SecretCipher
	Now      func() time.Time
}

// NewRuntimeHandler assembles the package-owned handler without mounting it in
// the shared control-api router.
func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	if !runtimeDependenciesReady(dependencies) {
		return nil, ErrInvalidHandlerConfig
	}
	authorizer, err := urlauthpolicy.NewIAMTxAuthorizer(dependencies.IAM)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	store, err := urlauthpolicy.NewStoreWithAuthorizer(dependencies.Pool, dependencies.Now, authorizer)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	service := urlauthpolicy.NewService(store, dependencies.Cipher)
	return NewHandler(service, runtimeAuthenticator{
		pool: dependencies.Pool, identity: dependencies.Identity, apiKeys: dependencies.APIKeys,
	}, config.Handler)
}

type runtimeAuthenticator struct {
	pool     *pgxpool.Pool
	identity *identity.Service
	apiKeys  *apikey.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (authenticatedPrincipal, error) {
	if request == nil || authenticator.identity == nil || authenticator.apiKeys == nil || authenticator.pool == nil {
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	scheme, rawCredential, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	rawCredential = strings.TrimSpace(rawCredential)
	if !found || rawCredential == "" || len(rawCredential) > 8192 || strings.ContainsAny(rawCredential, " \t\r\n") {
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	var principal identity.Principal
	var sessionID uuid.UUID
	credentialKind := urlauthpolicy.CredentialSession
	var err error
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		principal, sessionID, err = authenticateSession(request.Context(), authenticator.identity, rawCredential)
	case strings.EqualFold(scheme, "CdncaKey"):
		credentialKind = urlauthpolicy.CredentialAPIKey
		principal, err = authenticateAPIKey(request.Context(), authenticator.apiKeys, rawCredential)
	default:
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	if err != nil {
		return authenticatedPrincipal{}, err
	}
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil ||
		principal.ScopeKind != "platform" && principal.ScopeKind != "tenant" {
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	if principal.ScopeKind == "platform" {
		if principal.TenantID != nil {
			return authenticatedPrincipal{}, ErrUnauthenticated
		}
		actor := urlauthpolicy.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}.
			WithCredential(credentialKind, sessionID, rawCredential, nil)
		return authenticatedPrincipal{Principal: principal, Actor: actor}, nil
	}
	if principal.TenantID == nil || *principal.TenantID == uuid.Nil {
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	var active bool
	err = authenticator.pool.QueryRow(request.Context(), `SELECT status='active' FROM tenants WHERE id=$1`, *principal.TenantID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !active {
		return authenticatedPrincipal{}, ErrUnauthenticated
	}
	if err != nil {
		return authenticatedPrincipal{}, err
	}
	actor := urlauthpolicy.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}.
		WithCredential(credentialKind, sessionID, rawCredential, principal.TenantID)
	return authenticatedPrincipal{Principal: principal, Actor: actor}, nil
}

func authenticateSession(ctx context.Context, service *identity.Service, raw string) (principal identity.Principal, sessionID uuid.UUID, err error) {
	if service == nil || !service.Configured() {
		return identity.Principal{}, uuid.Nil, ErrInvalidHandlerConfig
	}
	defer func() {
		if recover() != nil {
			principal = identity.Principal{}
			sessionID = uuid.Nil
			err = ErrInvalidHandlerConfig
		}
	}()
	session, err := service.AuthenticateSession(ctx, raw)
	if errors.Is(err, identity.ErrInvalidSession) {
		return identity.Principal{}, uuid.Nil, ErrUnauthenticated
	}
	return session.Principal, session.SessionID, err
}

func authenticateAPIKey(ctx context.Context, service *apikey.Service, raw string) (principal identity.Principal, err error) {
	if service == nil {
		return identity.Principal{}, ErrInvalidHandlerConfig
	}
	defer func() {
		if recover() != nil {
			principal = identity.Principal{}
			err = ErrInvalidHandlerConfig
		}
	}()
	principal, err = service.Authenticate(ctx, raw)
	if errors.Is(err, apikey.ErrInvalidCredential) {
		return identity.Principal{}, ErrUnauthenticated
	}
	return principal, err
}

func runtimeDependenciesReady(dependencies RuntimeDependencies) (ready bool) {
	if dependencies.Pool == nil || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() ||
		dependencies.Now == nil || nilInterface(dependencies.Cipher) {
		return false
	}
	if _, ok := dependencies.Cipher.(urlauthpolicy.BoundSecretCipher); !ok {
		return false
	}
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return dependencies.Pool.Config() != nil && dependencies.Pool.Config().MaxConns > 0
}

func nilInterface(value any) bool {
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
