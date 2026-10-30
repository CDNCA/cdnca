package challengepolicy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RuntimeConfig struct {
	Enabled        bool
	CursorAudience string
	CursorKeyID    string
}

type RuntimeDependencies struct {
	Pool             *pgxpool.Pool
	Identity         *identity.Service
	IAM              *iamlock.Authorizer
	EntitlementTrust *entitlementguard.TrustStore
	Now              func() time.Time
	CursorKey        []byte
}

type ProductionRuntimeDependencies struct {
	RuntimeDependencies
	KeyResolver     challengepublication.KeyResolver
	SecretPublisher challengepublication.SecretPublisher
	RolloutReader   challengepublication.RolloutReader
	ConfigPublisher challengepublication.ConfigPublisher
}

// NewRuntimeHandler assembles this package's production session, transactional
// IAM, PostgreSQL, entitlement, and cursor dependencies without mounting it.
func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	service, authenticator, err := newRuntimeDomain(config, dependencies)
	if err != nil {
		return nil, err
	}
	handler, err := NewHandler(service, authenticator)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	return handler, nil
}

func NewProductionRuntimeHandler(config RuntimeConfig, dependencies ProductionRuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	if isNilDependency(dependencies.KeyResolver) || isNilDependency(dependencies.SecretPublisher) ||
		isNilDependency(dependencies.RolloutReader) || isNilDependency(dependencies.ConfigPublisher) {
		return nil, ErrInvalidHandlerConfig
	}
	service, authenticator, err := newRuntimeDomain(config, dependencies.RuntimeDependencies)
	if err != nil {
		return nil, err
	}
	crud, err := NewHandler(service, authenticator)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	publicationRuntime, err := challengepublication.NewRuntime(dependencies.KeyResolver,
		dependencies.SecretPublisher, dependencies.RolloutReader, dependencies.ConfigPublisher)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	planner, err := NewPostgresPublicationPlanner(PublicationPlannerConfig{
		Clock: dependencies.Now, ActivationTimeout: 30 * time.Second, ObservationWindow: 15 * time.Second,
		RequiredConsecutiveSuccesses: 3, Deadline: 2 * time.Minute,
	})
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	coordinator, err := NewPublicationCoordinator(service, publicationRuntime, planner,
		PostgresPublicationIdentityVerifier{})
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	publications, err := NewPublicationHandler(authenticator, coordinator)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "/publications") {
			publications.ServeHTTP(response, request)
			return
		}
		crud.ServeHTTP(response, request)
	}), nil
}

func newRuntimeDomain(config RuntimeConfig, dependencies RuntimeDependencies) (*Service, Authenticator, error) {
	if !runtimeDependenciesConfigured(dependencies) {
		return nil, nil, ErrInvalidHandlerConfig
	}
	cursor, err := NewCursorCodec(config.CursorAudience, config.CursorKeyID, dependencies.CursorKey)
	if err != nil {
		return nil, nil, ErrInvalidHandlerConfig
	}
	store, err := NewStoreWithDependencies(
		dependencies.Pool,
		dependencies.Now,
		dependencies.EntitlementTrust,
		cursor,
		runtimeTxAuthorizer{identity: dependencies.Identity, iam: dependencies.IAM},
	)
	if err != nil {
		return nil, nil, ErrInvalidHandlerConfig
	}
	return NewService(store), runtimeAuthenticator{identity: dependencies.Identity}, nil
}

func runtimeDependenciesConfigured(dependencies RuntimeDependencies) bool {
	return runtimePoolConfigured(dependencies.Pool) &&
		dependencies.Identity.Configured() && dependencies.IAM.Configured() &&
		len(dependencies.EntitlementTrust.PinnedKeys()) > 0 &&
		dependencies.Now != nil && len(dependencies.CursorKey) > 0
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

type runtimeAuthenticator struct {
	identity *identity.Service
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (Actor, error) {
	if authenticator.identity == nil {
		return Actor{}, ErrUnavailable
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return Actor{}, ErrUnauthenticated
	}
	scheme, rawCredential, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	rawCredential = strings.TrimSpace(rawCredential)
	if !found || !strings.EqualFold(scheme, "Bearer") || rawCredential == "" || len(rawCredential) > 8192 ||
		strings.ContainsAny(rawCredential, " \t\r\n") {
		return Actor{}, ErrUnauthenticated
	}
	session, err := authenticator.identity.AuthenticateSession(request.Context(), rawCredential)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) {
			return Actor{}, ErrUnauthenticated
		}
		return Actor{}, ErrUnavailable
	}
	principal := session.Principal
	actor := Actor{
		UserID:        principal.UserID,
		ScopeID:       principal.ScopeID,
		ScopeKind:     principal.ScopeKind,
		Permissions:   append([]string(nil), principal.Permissions...),
		Credential:    CredentialReference{Kind: CredentialKindSession, ID: session.SessionID},
		rawCredential: rawCredential,
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

func (authorizer runtimeTxAuthorizer) Authorize(
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
	sealed, err := authorizer.iam.AuthorizeSession(ctx, tx, actor.rawCredential, targetScopeID, permission)
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
		return ctx.Err()
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
		actor.rawCredential == "" || len(actor.rawCredential) > 8192 {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" && actor.tenantID != nil ||
		actor.ScopeKind == "tenant" && (actor.tenantID == nil || *actor.tenantID == uuid.Nil) {
		return ErrInvalidInput
	}
	return nil
}
