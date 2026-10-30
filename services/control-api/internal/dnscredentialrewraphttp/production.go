package dnscredentialrewraphttp

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultDatabaseProbeTimeout = 3 * time.Second

type ProductionConfig struct {
	HTTP                 Config
	DatabaseProbeTimeout time.Duration
}

type ProductionDependencies struct {
	Pool      *pgxpool.Pool
	Identity  *identity.Service
	IAM       *iamlock.Authorizer
	Rewrapper Rewrapper
}

func NewProductionHandler(
	ctx context.Context,
	config ProductionConfig,
	dependencies ProductionDependencies,
) (*Handler, error) {
	if ctx == nil || !productionDependenciesReady(dependencies) {
		return nil, ErrInvalidConfig
	}
	if config.DatabaseProbeTimeout == 0 {
		config.DatabaseProbeTimeout = defaultDatabaseProbeTimeout
	}
	if config.DatabaseProbeTimeout <= 0 || config.DatabaseProbeTimeout > 30*time.Second {
		return nil, ErrInvalidConfig
	}
	probeContext, cancel := context.WithTimeout(ctx, config.DatabaseProbeTimeout)
	defer cancel()
	if err := dependencies.Pool.Ping(probeContext); err != nil {
		return nil, ErrInvalidConfig
	}
	repository := newPostgresRepository(dependencies.Pool, time.Now)
	service, err := NewService(repository, dependencies.Rewrapper)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return NewHandler(Dependencies{
		Authorizer: &productionAuthorizer{
			pool: dependencies.Pool, identity: dependencies.Identity, iam: dependencies.IAM,
		},
		Domain: service,
	}, config.HTTP)
}

type productionAuthorizer struct {
	pool     *pgxpool.Pool
	identity *identity.Service
	iam      *iamlock.Authorizer
}

func (authorizer *productionAuthorizer) Authorize(ctx context.Context, rawSession string) (Owner, error) {
	if authorizer == nil || ctx == nil || authorizer.pool == nil || authorizer.identity == nil || authorizer.iam == nil {
		return Owner{}, ErrUnavailable
	}
	session, err := authorizer.identity.AuthenticateSession(ctx, rawSession)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			return Owner{}, ErrUnauthenticated
		}
		return Owner{}, ErrUnavailable
	}
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return Owner{}, ErrUnauthenticated
	}
	if principal.ScopeKind != "platform" || principal.TenantID != nil {
		return Owner{}, ErrPermissionDenied
	}
	var authorization iamlock.Authorization
	err = pgx.BeginFunc(ctx, authorizer.pool, func(tx pgx.Tx) error {
		var authorizeErr error
		authorization, authorizeErr = authorizer.iam.AuthorizeSession(
			ctx, tx, rawSession, principal.ScopeID, PermissionManage,
		)
		return authorizeErr
	})
	if err != nil {
		switch {
		case errors.Is(err, iamlock.ErrInvalidCredential):
			return Owner{}, ErrUnauthenticated
		case errors.Is(err, iamlock.ErrPermissionDenied):
			return Owner{}, ErrPermissionDenied
		default:
			return Owner{}, ErrUnavailable
		}
	}
	if !authorization.Valid() || authorization.CredentialKind() != "session" ||
		authorization.UserID() != principal.UserID ||
		authorization.AuthenticationScopeID() != principal.ScopeID ||
		authorization.TargetScopeID() != principal.ScopeID ||
		authorization.CredentialID() != session.SessionID {
		return Owner{}, ErrPermissionDenied
	}
	return Owner{UserID: principal.UserID, ScopeID: principal.ScopeID, SessionID: session.SessionID}, nil
}

func productionDependenciesReady(dependencies ProductionDependencies) bool {
	if dependencies.Pool == nil || dependencies.Identity == nil || dependencies.IAM == nil ||
		isNilDependency(dependencies.Rewrapper) {
		return false
	}
	defer func() { _ = recover() }()
	config := dependencies.Pool.Config()
	return config != nil && config.ConnConfig != nil && config.MaxConns >= 2 &&
		dependencies.Identity.Configured() && dependencies.IAM.Configured()
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value)
	switch kind.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return kind.IsNil()
	default:
		return false
	}
}

var _ Authorizer = (*productionAuthorizer)(nil)
