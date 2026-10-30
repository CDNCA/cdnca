package originauthcontrol

import (
	"context"
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
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
	IAM      *iamlock.Authorizer
	Keyring  *Keyring
	Service  Config
}

// NewRuntimeHandler assembles the package-owned production authentication,
// transactional IAM, PostgreSQL, entitlement, and encryption dependencies.
func NewRuntimeHandler(config RuntimeConfig, dependencies RuntimeDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	if !runtimePoolConfigured(dependencies.Pool) || !dependencies.Identity.Configured() ||
		!dependencies.IAM.Configured() || !dependencies.Keyring.configured() || dependencies.Service.Clock == nil ||
		isNilDependency(dependencies.Service.Verifier) ||
		dependencies.Service.Auditor != nil && isNilDependency(dependencies.Service.Auditor) ||
		dependencies.Service.Entitlement != nil && isNilDependency(dependencies.Service.Entitlement) ||
		dependencies.Service.Entitlement == nil && len(dependencies.Service.TrustStore.PinnedKeys()) == 0 {
		return nil, ErrInvalidHandlerConfig
	}
	authorizer := runtimeTxAuthorizer{identity: dependencies.Identity, iam: dependencies.IAM}
	service, err := newService(dependencies.Pool, dependencies.Keyring, dependencies.Service, authorizer)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	handler, err := NewHandler(service, runtimeAuthenticator{identity: dependencies.Identity}, config.Handler)
	if err != nil {
		return nil, ErrInvalidHandlerConfig
	}
	return runtimeMetadataHandler{inner: handler}, nil
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

type runtimeMetadataHandler struct {
	inner *Handler
}

func (handler runtimeMetadataHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	normalized, err := normalizeRuntimeMetadata(request)
	if err != nil {
		setRuntimeResponseHeaders(response, normalized)
		handler.inner.writeError(response, normalized, err)
		return
	}
	if normalized.URL == nil || normalized.URL.RawPath != "" ||
		path.Clean(normalized.URL.Path) != normalized.URL.Path {
		setRuntimeResponseHeaders(response, normalized)
		http.NotFound(response, normalized)
		return
	}
	handler.inner.ServeHTTP(response, normalized)
}

func normalizeRuntimeMetadata(request *http.Request) (*http.Request, error) {
	normalized := request.Clone(request.Context())
	requestIDs := request.Header.Values("X-Request-ID")
	traceIDs := request.Header.Values("X-Trace-ID")
	idempotencyKeys := request.Header.Values("Idempotency-Key")
	invalid := len(requestIDs) > 1 || len(traceIDs) > 1 || len(idempotencyKeys) > 1
	requestID := newRequestID()
	if len(requestIDs) == 1 && metadataPattern.MatchString(requestIDs[0]) {
		requestID = requestIDs[0]
	} else if len(requestIDs) == 1 {
		invalid = true
	}
	traceID := requestID
	if len(traceIDs) == 1 && metadataPattern.MatchString(traceIDs[0]) {
		traceID = traceIDs[0]
	} else if len(traceIDs) == 1 {
		invalid = true
	}
	normalized.Header.Set("X-Request-ID", requestID)
	normalized.Header.Set("X-Trace-ID", traceID)
	if invalid {
		return normalized, ErrInvalidInput
	}
	return normalized, nil
}

func setRuntimeResponseHeaders(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Request-ID", request.Header.Get("X-Request-ID"))
	response.Header().Set("X-Trace-ID", request.Header.Get("X-Trace-ID"))
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
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
	scheme, rawSession, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	rawSession = strings.TrimSpace(rawSession)
	if !found || !strings.EqualFold(scheme, "Bearer") || rawSession == "" || len(rawSession) > 8192 ||
		strings.ContainsAny(rawSession, " \t\r\n") {
		return Actor{}, ErrUnauthenticated
	}
	session, err := authenticator.identity.AuthenticateSession(request.Context(), rawSession)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) {
			return Actor{}, ErrUnauthenticated
		}
		return Actor{}, ErrUnavailable
	}
	principal := session.Principal
	actor := Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		Permissions: append([]string(nil), principal.Permissions...), sessionID: session.SessionID,
		rawSession: rawSession,
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
) error {
	if authorizer.identity == nil || authorizer.iam == nil || tx == nil || targetScopeID == uuid.Nil ||
		validateRuntimeActor(actor) != nil {
		return ErrPermissionDenied
	}
	sealed, err := authorizer.iam.AuthorizeSession(ctx, tx, actor.rawSession, targetScopeID, permission)
	if err != nil {
		return authorizer.mapAuthorizationError(ctx, err)
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID ||
		sealed.AuthenticationScopeID() != actor.ScopeID || sealed.TargetScopeID() != targetScopeID ||
		sealed.CredentialKind() != "session" || sealed.CredentialID() != actor.sessionID {
		return ErrPermissionDenied
	}
	var authenticationKind, targetKind string
	var authenticationTenantID, targetTenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR KEY SHARE`,
		actor.ScopeID).Scan(&authenticationKind, &authenticationTenantID); err != nil {
		return ErrUnavailable
	}
	if actor.ScopeID == targetScopeID {
		targetKind, targetTenantID = authenticationKind, authenticationTenantID
	} else if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR KEY SHARE`,
		targetScopeID).Scan(&targetKind, &targetTenantID); err != nil {
		return ErrUnavailable
	}
	if authenticationKind != actor.ScopeKind || !sameRuntimeTenant(authenticationTenantID, actor.tenantID) {
		return ErrPermissionDenied
	}
	sealedTenantID, sealedHasTenant := sealed.TenantID()
	if targetKind != "tenant" || targetTenantID == nil || !sealedHasTenant ||
		*targetTenantID != sealedTenantID {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != targetScopeID ||
		actor.tenantID == nil || *actor.tenantID != sealedTenantID) {
		return ErrPermissionDenied
	}
	return nil
}

func (authorizer runtimeTxAuthorizer) mapAuthorizationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return ErrUnauthenticated
	}
	if !errors.Is(err, iamlock.ErrPermissionDenied) {
		return ErrUnavailable
	}
	return ErrPermissionDenied
}

func validateRuntimeActor(actor Actor) error {
	if !validActor(actor) || actor.sessionID == uuid.Nil || actor.rawSession == "" || len(actor.rawSession) > 8192 {
		return ErrInvalidInput
	}
	if actor.ScopeKind == "platform" && actor.tenantID != nil ||
		actor.ScopeKind == "tenant" && (actor.tenantID == nil || *actor.tenantID == uuid.Nil) {
		return ErrInvalidInput
	}
	return nil
}

func sameRuntimeTenant(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right && *left != uuid.Nil
}
