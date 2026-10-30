package cachecontrolhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProductionConfig struct {
	CursorKey []byte
	Clock     func() time.Time
}

type ProductionDependencies struct {
	Pool         *pgxpool.Pool
	Entitlement  *entitlementguard.Guard
	Identity     *identity.Service
	IAM          *iamlock.Authorizer
	Authenticate AuthenticateFunc
	// SiteSettings enqueues the automatic publication of a saved cache
	// policy (edgeautopublish.SiteSettingPublisher).
	SiteSettings cachecontrol.SiteSettingEnqueuer
}

func NewProductionHandler(config ProductionConfig, dependencies ProductionDependencies) (*Handler, error) {
	if dependencies.Pool == nil || dependencies.Entitlement == nil || dependencies.Identity == nil ||
		dependencies.IAM == nil || !dependencies.Identity.Configured() || !dependencies.IAM.Configured() ||
		dependencies.Authenticate == nil || len(config.CursorKey) < 32 {
		return nil, ErrInvalidRequest
	}
	store, err := newProductionControlStore(config, dependencies)
	if err != nil {
		return nil, err
	}
	reader, err := newProductionPostgresReader(dependencies.Pool, dependencies.IAM)
	if err != nil {
		return nil, err
	}
	service, err := NewService(runtimeControlStore{inner: store}, reader, config.CursorKey)
	if err != nil {
		return nil, err
	}
	inner, err := NewHandler(service, runtimeContextAuthenticator)
	if err != nil {
		return nil, err
	}
	inner.authenticate = runtimeSessionHandler{
		inner: inner,
		authenticator: runtimeAuthenticator{
			identity: dependencies.Identity, authenticate: dependencies.Authenticate,
		},
	}.authenticate
	return inner, nil
}

func newProductionControlStore(config ProductionConfig, dependencies ProductionDependencies) (*cachecontrol.Store, error) {
	store, err := cachecontrol.NewStoreWithEntitlementAndIAM(
		dependencies.Pool, config.Clock, dependencies.Entitlement, dependencies.IAM,
	)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	store.WithSiteSettingEnqueuer(dependencies.SiteSettings)
	return store, nil
}

const redactedRuntimeSession = "cachecontrolhttp.runtimeSession{token:redacted}"

type runtimeSession struct {
	principal identity.Principal
	sessionID uuid.UUID
	rawToken  string
	// apiKeyID/rawAPIKey: a task-center command authenticated with an API key
	// (fix-cacheflow3 §1). Only the job command router sets them; rawToken is
	// then empty and the HTTP handler and reader refuse the context.
	apiKeyID  uuid.UUID
	rawAPIKey string
}

func (runtimeSession) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedRuntimeSession))
}

func (runtimeSession) String() string   { return redactedRuntimeSession }
func (runtimeSession) GoString() string { return redactedRuntimeSession }

func (runtimeSession) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedRuntimeSession)
}

type runtimeSessionResult struct {
	session runtimeSession
	err     error
}

type runtimeSessionKey struct{}

type runtimeSessionHandler struct {
	inner         http.Handler
	authenticator runtimeAuthenticator
}

func (handler runtimeSessionHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	session, err := handler.authenticator.Authenticate(request)
	ctx := context.WithValue(request.Context(), runtimeSessionKey{}, runtimeSessionResult{session: session, err: err})
	handler.inner.ServeHTTP(writer, request.WithContext(ctx))
}

func (handler runtimeSessionHandler) authenticate(request *http.Request) (identity.Principal, error) {
	if request == nil {
		return identity.Principal{}, ErrUnauthenticated
	}
	session, err := handler.authenticator.Authenticate(request)
	if err != nil {
		return identity.Principal{}, err
	}
	ctx := context.WithValue(request.Context(), runtimeSessionKey{}, runtimeSessionResult{session: session})
	*request = *request.WithContext(ctx)
	return session.principal, nil
}

type runtimeAuthenticator struct {
	identity     *identity.Service
	authenticate AuthenticateFunc
}

func (authenticator runtimeAuthenticator) Authenticate(request *http.Request) (runtimeSession, error) {
	if authenticator.identity == nil || !authenticator.identity.Configured() ||
		authenticator.authenticate == nil || request == nil {
		return runtimeSession{}, ErrStoreUnavailable
	}
	rawToken, err := strictBearerToken(request)
	if err != nil {
		return runtimeSession{}, err
	}
	principal, err := authenticator.authenticate(request)
	if err != nil {
		return runtimeSession{}, ErrUnauthenticated
	}
	session, err := authenticator.identity.AuthenticateSession(request.Context(), rawToken)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrAccountDisabled) ||
			errors.Is(err, identity.ErrMembershipDisabled) {
			return runtimeSession{}, ErrUnauthenticated
		}
		if request.Context().Err() != nil {
			return runtimeSession{}, request.Context().Err()
		}
		return runtimeSession{}, ErrStoreUnavailable
	}
	if session.SessionID == uuid.Nil || !sameRuntimePrincipal(session.Principal, principal) {
		return runtimeSession{}, ErrUnauthenticated
	}
	return runtimeSession{principal: session.Principal, sessionID: session.SessionID, rawToken: rawToken}, nil
}

func strictBearerToken(request *http.Request) (string, error) {
	if request == nil {
		return "", ErrUnauthenticated
	}
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", ErrUnauthenticated
	}
	rawToken := strings.TrimPrefix(values[0], "Bearer ")
	if rawToken == "" || len(rawToken) >= 8192 || strings.ContainsFunc(rawToken, unicode.IsSpace) {
		return "", ErrUnauthenticated
	}
	return rawToken, nil
}

type runtimeControlStore struct {
	inner ControlStore
}

func (store runtimeControlStore) authorize(
	ctx context.Context,
	actor cachecontrol.Actor,
) (context.Context, cachecontrol.Actor, error) {
	session, err := runtimeSessionFromContext(ctx)
	if err != nil || store.inner == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		session.principal.UserID != actor.UserID || session.principal.ScopeID == uuid.Nil ||
		actor.ActorScopeID == uuid.Nil || actor.ActorScopeID != session.principal.ScopeID {
		return nil, cachecontrol.Actor{}, cachecontrol.ErrPermissionDenied
	}
	var authorizedCtx context.Context
	if session.rawToken != "" {
		authorizedCtx, err = cachecontrol.WithSessionAuthorization(ctx, session.rawToken)
	} else {
		authorizedCtx, err = cachecontrol.WithAPIKeyAuthorization(ctx, session.apiKeyID, session.rawAPIKey)
	}
	if err != nil {
		return nil, cachecontrol.Actor{}, cachecontrol.ErrPermissionDenied
	}
	return authorizedCtx, actor, nil
}

func (store runtimeControlStore) PublishPolicy(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.PublishPolicyRequest,
) (cachecontrol.PolicyWriteResult, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.PolicyWriteResult{}, err
	}
	return store.inner.PublishPolicy(ctx, actor, request)
}

func (store runtimeControlStore) GetPolicy(
	ctx context.Context,
	actor cachecontrol.Actor,
	siteID uuid.UUID,
	revision int64,
) (cachecontrol.PolicyRevision, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.PolicyRevision{}, err
	}
	return store.inner.GetPolicy(ctx, actor, siteID, revision)
}

func (store runtimeControlStore) CreateOperation(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.CreateOperationRequest,
) (cachecontrol.OperationWriteResult, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.OperationWriteResult{}, err
	}
	return store.inner.CreateOperation(ctx, actor, request)
}

func (store runtimeControlStore) GetOperation(
	ctx context.Context,
	actor cachecontrol.Actor,
	operationID uuid.UUID,
) (cachecontrol.Operation, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.Operation{}, err
	}
	return store.inner.GetOperation(ctx, actor, operationID)
}

func (store runtimeControlStore) ResolveTargetSites(
	ctx context.Context,
	actor cachecontrol.Actor,
	allScopes bool,
	request cachecontrol.ResolveTargetSitesRequest,
) (cachecontrol.TargetSiteGrouping, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.TargetSiteGrouping{}, err
	}
	return store.inner.ResolveTargetSites(ctx, actor, allScopes, request)
}

func (store runtimeControlStore) CarryingNodes(
	ctx context.Context,
	actor cachecontrol.Actor,
) ([]cachecontrol.CarryingNode, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return nil, err
	}
	return store.inner.CarryingNodes(ctx, actor)
}

func (store runtimeControlStore) WriteReceipt(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.WriteReceiptRequest,
) (cachecontrol.WriteReceipt, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.WriteReceipt{}, err
	}
	return store.inner.WriteReceipt(ctx, actor, request)
}

func (store runtimeControlStore) DailyUsage(
	ctx context.Context,
	actor cachecontrol.Actor,
) (cachecontrol.DailyUsage, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.DailyUsage{}, err
	}
	return store.inner.DailyUsage(ctx, actor)
}

func (store runtimeControlStore) SetAccountLimits(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.SetAccountLimitsRequest,
) (cachecontrol.DailyUsage, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.DailyUsage{}, err
	}
	return store.inner.SetAccountLimits(ctx, actor, request)
}

func (store runtimeControlStore) Retry(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.RetryRequest,
) (cachecontrol.OperationWriteResult, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.OperationWriteResult{}, err
	}
	return store.inner.Retry(ctx, actor, request)
}

func (store runtimeControlStore) Resubmit(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.ResubmitRequest,
) (cachecontrol.OperationWriteResult, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.OperationWriteResult{}, err
	}
	return store.inner.Resubmit(ctx, actor, request)
}

func (store runtimeControlStore) Cancel(
	ctx context.Context,
	actor cachecontrol.Actor,
	request cachecontrol.CancelRequest,
) (cachecontrol.OperationWriteResult, error) {
	ctx, actor, err := store.authorize(ctx, actor)
	if err != nil {
		return cachecontrol.OperationWriteResult{}, err
	}
	return store.inner.Cancel(ctx, actor, request)
}

func runtimeContextAuthenticator(request *http.Request) (identity.Principal, error) {
	if request == nil {
		return identity.Principal{}, ErrUnauthenticated
	}
	result, ok := request.Context().Value(runtimeSessionKey{}).(runtimeSessionResult)
	if !ok || result.err != nil || result.session.rawToken == "" {
		if ok && result.err != nil {
			return identity.Principal{}, result.err
		}
		return identity.Principal{}, ErrUnauthenticated
	}
	return result.session.principal, nil
}

func runtimeSessionFromContext(ctx context.Context) (runtimeSession, error) {
	if ctx == nil {
		return runtimeSession{}, ErrUnauthenticated
	}
	result, ok := ctx.Value(runtimeSessionKey{}).(runtimeSessionResult)
	if !ok || result.err != nil || (result.session.rawToken == "") == (result.session.rawAPIKey == "") {
		// Exactly one credential: a session token or an API key.
		return runtimeSession{}, ErrUnauthenticated
	}
	return result.session, nil
}

func sameRuntimePrincipal(left, right identity.Principal) bool {
	if left.UserID != right.UserID || left.ScopeID != right.ScopeID || left.ScopeKind != right.ScopeKind {
		return false
	}
	if left.TenantID == nil || right.TenantID == nil {
		return left.TenantID == nil && right.TenantID == nil
	}
	return *left.TenantID != uuid.Nil && *left.TenantID == *right.TenantID
}

var _ fmt.Formatter = runtimeSession{}
var _ fmt.Stringer = runtimeSession{}
var _ json.Marshaler = runtimeSession{}
