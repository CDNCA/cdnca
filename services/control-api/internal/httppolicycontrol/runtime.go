package httppolicycontrol

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeConfig struct {
	Enabled bool
}

type RuntimeDependencies struct {
	Pool             *pgxpool.Pool
	Identity         *identity.Service
	IAM              *iamlock.Authorizer
	EntitlementTrust *entitlementguard.TrustStore
	Now              func() time.Time
	// Revisions publishes a policy write for an automatic scope
	// (edgeautopublish.UnrequestedRevisionPublisher); nil leaves it pending.
	Revisions SiteRevisionPublisher
}

// NewRuntimeHandler assembles the package-owned production session, locked IAM,
// PostgreSQL, and entitlement capabilities without mounting the handler.
func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	if !runtimeDependenciesReady(dependencies) {
		return nil, ErrInvalidHandlerConfig
	}
	store, err := newStoreWithAuthorizer(
		dependencies.Pool,
		dependencies.Now,
		dependencies.EntitlementTrust,
		runtimeTxAuthorizer{identity: dependencies.Identity, iam: dependencies.IAM},
	)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	if dependencies.Revisions != nil {
		store.WithSiteRevisionPublisher(dependencies.Revisions)
	}
	handler, err := NewHandler(NewService(store), runtimeAuthenticator{identity: dependencies.Identity})
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	return handler, nil
}

type runtimeAuthenticator struct {
	identity *identity.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (Actor, error) {
	if authenticator.identity == nil || request == nil {
		return Actor{}, ErrUnavailable
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return Actor{}, ErrUnauthenticated
	}
	scheme, rawSession, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	rawSession = strings.TrimSpace(rawSession)
	if !found || !strings.EqualFold(scheme, "Bearer") || rawSession == "" || len(rawSession) > 8192 ||
		strings.ContainsAny(rawSession, " \t\r\n") {
		return Actor{}, ErrUnauthenticated
	}
	session, err := authenticateRuntimeSession(request.Context(), authenticator.identity, rawSession)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) {
			return Actor{}, ErrUnauthenticated
		}
		return Actor{}, ErrUnavailable
	}
	principal := session.Principal
	actor := Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Permissions: append([]string(nil), principal.Permissions...),
		Credential:  CredentialReference{Kind: CredentialKindSession, ID: session.SessionID},
		rawSession:  rawSession,
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

type runtimeTxAuthorizer struct {
	identity *identity.Service
	iam      *iamlock.Authorizer
}

func (authorizer runtimeTxAuthorizer) AuthorizeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if authorizer.identity == nil || authorizer.iam == nil || tx == nil || targetScopeID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) || validateRuntimeActor(actor) != nil {
		return uuid.Nil, ErrPermissionDenied
	}
	sealed, err := authorizer.iam.AuthorizeSession(ctx, tx, actor.rawSession, targetScopeID, permission)
	if err != nil {
		return uuid.Nil, authorizer.mapAuthorizationError(ctx, actor, err)
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID ||
		sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != targetScopeID ||
		sealed.CredentialKind() != CredentialKindSession || sealed.CredentialID() != actor.Credential.ID {
		return uuid.Nil, ErrPermissionDenied
	}
	tenantID, hasTenant := sealed.TenantID()
	if !hasTenant || tenantID == uuid.Nil {
		return uuid.Nil, ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" {
		if actor.ScopeID != targetScopeID || actor.tenantID == nil || *actor.tenantID != tenantID {
			return uuid.Nil, ErrPermissionDenied
		}
	} else if actor.ScopeKind != "platform" || actor.tenantID != nil {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func (authorizer runtimeTxAuthorizer) mapAuthorizationError(ctx context.Context, _ Actor, err error) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	switch {
	case errors.Is(err, iamlock.ErrInvalidCredential):
		return ErrUnauthenticated
	case errors.Is(err, iamlock.ErrPermissionDenied):
		return ErrPermissionDenied
	default:
		return ErrUnavailable
	}
}

func validateRuntimeActor(actor Actor) error {
	if !validActor(actor) || actor.Credential.Kind != CredentialKindSession || actor.Credential.ID == uuid.Nil ||
		actor.rawSession == "" || len(actor.rawSession) > 8192 {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" && actor.tenantID != nil ||
		actor.ScopeKind == "tenant" && (actor.tenantID == nil || *actor.tenantID == uuid.Nil) {
		return ErrInvalidInput
	}
	return nil
}

func authenticateRuntimeSession(
	ctx context.Context,
	service *identity.Service,
	rawSession string,
) (session identity.AuthenticatedSession, err error) {
	if service == nil || !service.Configured() {
		return identity.AuthenticatedSession{}, ErrUnavailable
	}
	defer func() {
		if recover() != nil {
			session = identity.AuthenticatedSession{}
			err = ErrUnavailable
		}
	}()
	return service.AuthenticateSession(ctx, rawSession)
}

func runtimeDependenciesReady(dependencies RuntimeDependencies) bool {
	if !runtimePoolConfigured(dependencies.Pool) ||
		dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.IAM == nil || !dependencies.IAM.Configured() ||
		dependencies.EntitlementTrust == nil || dependencies.Now == nil {
		return false
	}
	return len(dependencies.EntitlementTrust.PinnedKeys()) > 0
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
