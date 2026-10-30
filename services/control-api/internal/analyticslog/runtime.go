package analyticslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	credentialSession     = "session"
	credentialAPIKey      = "api_key"
	defaultConnectTimeout = 3 * time.Second
)

var errAuthenticationRequired = errors.New("analytics log authentication required")

// Principal contains authenticated identity facts used by the package's test
// adapter. Production credential material remains package-private.
type Principal struct {
	ID             string
	ScopeID        string
	SessionID      string
	ScopeKind      string
	TenantID       string
	Permissions    []string
	credentialKind string
	rawCredential  string
}

const redactedPrincipal = "analyticslog.Principal{credential:redacted}"

func (Principal) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redactedPrincipal)) }
func (Principal) String() string                 { return redactedPrincipal }
func (Principal) GoString() string               { return redactedPrincipal }
func (Principal) MarshalJSON() ([]byte, error) {
	return []byte(`"analyticslog.Principal{credential:redacted}"`), nil
}

type AuthenticatePrincipalFunc func(*http.Request) (Principal, error)

type AuthorizationRequest struct {
	Permission string
	Audience   Audience
	TenantID   string
	SiteID     string
	NodeID     string
}

type Authorizer interface {
	AuthorizeAnalyticsLogRead(context.Context, Principal, AuthorizationRequest) error
}

type HTTPConfig struct {
	ConnectTimeout time.Duration
	Client         ClientConfig
	Handler        HandlerConfig
	RootCAs        *x509.CertPool
}

type RuntimeConfig struct {
	Enabled bool
	HTTP    HTTPConfig
}

type HTTPDependencies struct {
	Identity        *identity.Service
	APIKeys         *apikey.Service
	Pool            *pgxpool.Pool
	IAM             *iamlock.Authorizer
	BlockActivation BlockActivationStarter
}

type handlerDependencies struct {
	Authenticate AuthenticatePrincipalFunc
	Authorizer   Authorizer
}

type authorizedActorKey struct{}

type authorizedHandler struct {
	inner        *Handler
	blocks       *BlockStateHandler
	authenticate AuthenticatePrincipalFunc
	authorizer   Authorizer
	timeout      time.Duration
}

// NewRuntimeHandler returns a closed 404 surface while disabled. Enabling with
// incomplete production dependencies fails without returning a handler.
func NewRuntimeHandler(config RuntimeConfig, dependencies HTTPDependencies) (http.Handler, error) {
	if !config.Enabled {
		return http.NotFoundHandler(), nil
	}
	return NewHTTPHandler(config.HTTP, dependencies)
}

// NewHTTPHandler assembles production session/API-key authentication, locked
// IAM authorization, the ClickHouse client, query service, and guarded handler.
func NewHTTPHandler(config HTTPConfig, dependencies HTTPDependencies) (http.Handler, error) {
	if !dependencies.Identity.Configured() || dependencies.APIKeys == nil ||
		!configuredPGXPool(dependencies.Pool) || !dependencies.IAM.Configured() {
		return nil, ErrInvalidConfiguration
	}
	authenticate := credentialAuthenticator(dependencies.Identity, dependencies.APIKeys)
	authorizer := &iamAuthorizer{
		pool: dependencies.Pool, authorizer: dependencies.IAM,
		identity: dependencies.Identity, apiKeys: dependencies.APIKeys,
	}
	guarded, err := newHTTPHandler(config, handlerDependencies{
		Authenticate: authenticate,
		Authorizer:   authorizer,
	})
	if err != nil {
		return nil, err
	}
	authorized, ok := guarded.(*authorizedHandler)
	if !ok {
		return nil, ErrInvalidConfiguration
	}
	store, err := NewPostgresBlockStateStore(dependencies.Pool, time.Now)
	if err != nil {
		return nil, err
	}
	exports, err := NewExportManager(dependencies.Pool, authorized.inner.service.store, time.Now)
	if err != nil {
		return nil, err
	}
	authorized.inner.service.exports = exports
	// Access / block rows carry the client address' carrier, region, ASN and
	// IDC from the control plane's verified IP intelligence library.
	authorized.inner.SetIPIntelLookup(NewPostgresIPIntelLookup(dependencies.Pool, nil))
	// Block rows name their site (domain) and rule (policy version rule name).
	authorized.inner.SetEventNameLookup(NewPostgresEventNameLookup(dependencies.Pool, nil))
	// Platform access rows name their node.
	authorized.inner.SetNodeNameLookup(NewPostgresNodeNameLookup(dependencies.Pool, nil))
	activation := dependencies.BlockActivation
	if nilInterface(activation) {
		activation = unavailableBlockActivation{}
	}
	blockService, err := NewBlockStateService(
		store, securitypolicy.NewService(securitypolicy.NewStoreWithClock(dependencies.Pool, time.Now)),
		activation, time.Now,
	)
	if err != nil {
		return nil, err
	}
	authorized.blocks, err = NewBlockStateHandler(
		blockService, dependencies.Pool, authenticate, authorizer, authorized.inner, authorized.timeout,
	)
	if err != nil {
		return nil, err
	}
	return authorized, nil
}

func newHTTPHandler(config HTTPConfig, dependencies handlerDependencies) (http.Handler, error) {
	if dependencies.Authenticate == nil || nilInterface(dependencies.Authorizer) {
		return nil, ErrInvalidConfiguration
	}
	clientTimeout := config.Client.QueryTimeout
	if clientTimeout == 0 {
		clientTimeout = defaultQueryTimeout
	}
	connectTimeout := config.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = defaultConnectTimeout
	}
	handlerTimeout := config.Handler.QueryTimeout
	if handlerTimeout == 0 {
		handlerTimeout = defaultHandlerTimeout
	}
	clientResponseLimit := config.Client.MaxResponseBytes
	if clientResponseLimit == 0 {
		clientResponseLimit = defaultMaxResponse
	}
	handlerResponseLimit := config.Handler.MaxResponseBytes
	if handlerResponseLimit == 0 {
		handlerResponseLimit = defaultHandlerMaxResponse
	}
	if connectTimeout < 0 || handlerTimeout <= clientTimeout || handlerResponseLimit > int(clientResponseLimit) {
		return nil, ErrInvalidConfiguration
	}

	httpClient := newRuntimeHTTPClient(connectTimeout, clientTimeout, config.RootCAs)
	client, err := NewClient(config.Client, httpClient)
	if err != nil {
		return nil, err
	}
	service, err := NewService(client)
	if err != nil {
		return nil, err
	}
	inner, err := NewHandler(service, func(request *http.Request) (Actor, error) {
		actor, ok := request.Context().Value(authorizedActorKey{}).(Actor)
		if !ok {
			return Actor{}, ErrPermissionDenied
		}
		return actor, nil
	}, config.Handler)
	if err != nil {
		return nil, err
	}
	return &authorizedHandler{
		inner: inner, authenticate: dependencies.Authenticate,
		authorizer: dependencies.Authorizer, timeout: handlerTimeout,
	}, nil
}

type iamAuthorizer struct {
	pool       *pgxpool.Pool
	authorizer *iamlock.Authorizer
	identity   *identity.Service
	apiKeys    *apikey.Service
}

func credentialAuthenticator(
	identityService *identity.Service,
	apiKeyService *apikey.Service,
) AuthenticatePrincipalFunc {
	return func(request *http.Request) (Principal, error) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			return Principal{}, errAuthenticationRequired
		}
		authorization := strings.TrimSpace(values[0])
		scheme, rawToken, found := strings.Cut(authorization, " ")
		rawToken = strings.TrimSpace(rawToken)
		if !found || rawToken == "" || strings.ContainsAny(rawToken, " \t\r\n") {
			return Principal{}, errAuthenticationRequired
		}
		switch {
		case strings.EqualFold(scheme, "Bearer"):
			session, err := identityService.AuthenticateSession(request.Context(), rawToken)
			if err != nil {
				if errors.Is(err, identity.ErrInvalidSession) {
					return Principal{}, errAuthenticationRequired
				}
				return Principal{}, authenticationDependencyError(request.Context(), err)
			}
			return authenticatedPrincipal(session.Principal, credentialSession, rawToken, session.SessionID), nil
		case strings.EqualFold(scheme, "CdncaKey"):
			principal, err := apiKeyService.Authenticate(request.Context(), rawToken)
			if err != nil {
				if errors.Is(err, apikey.ErrInvalidCredential) {
					return Principal{}, errAuthenticationRequired
				}
				return Principal{}, authenticationDependencyError(request.Context(), err)
			}
			return authenticatedPrincipal(principal, credentialAPIKey, rawToken, uuid.Nil), nil
		default:
			return Principal{}, errAuthenticationRequired
		}
	}
}

func authenticatedPrincipal(
	principal identity.Principal,
	credentialKind string,
	rawCredential string,
	sessionID uuid.UUID,
) Principal {
	tenantID := ""
	if principal.TenantID != nil {
		tenantID = principal.TenantID.String()
	}
	result := Principal{
		ID: principal.UserID.String(), ScopeID: principal.ScopeID.String(),
		ScopeKind: principal.ScopeKind, TenantID: tenantID,
		Permissions:    append([]string(nil), principal.Permissions...),
		credentialKind: credentialKind, rawCredential: rawCredential,
	}
	if sessionID != uuid.Nil {
		result.SessionID = sessionID.String()
	}
	return result
}

func (authorizer *iamAuthorizer) AuthorizeAnalyticsLogRead(
	ctx context.Context,
	principal Principal,
	request AuthorizationRequest,
) error {
	if authorizer == nil || authorizer.pool == nil || authorizer.authorizer == nil ||
		authorizer.identity == nil || authorizer.apiKeys == nil ||
		(request.Permission != ReadPermission && request.Permission != blockManagePermission) {
		return ErrStorageUnavailable
	}
	userID, err := uuid.Parse(principal.ID)
	if err != nil || userID == uuid.Nil {
		return ErrScopeForbidden
	}
	scopeID, err := uuid.Parse(principal.ScopeID)
	if err != nil || scopeID == uuid.Nil {
		return ErrScopeForbidden
	}
	targetScopeID, targetTenantID, err := authorizer.targetScopeHint(ctx, principal, scopeID, request)
	if err != nil {
		return err
	}
	if principal.rawCredential == "" {
		return ErrScopeForbidden
	}

	tx, err := authorizer.pool.Begin(ctx)
	if err != nil {
		return authenticationDependencyError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var authorization iamlock.Authorization
	switch principal.credentialKind {
	case credentialSession:
		authorization, err = authorizer.authorizer.AuthorizeSession(
			ctx, tx, principal.rawCredential, targetScopeID, request.Permission)
	case credentialAPIKey:
		if request.Audience != AudienceTenant {
			return errAuthenticationRequired
		}
		authorization, err = authorizer.authorizer.AuthorizeAPIKey(
			ctx, tx, principal.rawCredential, targetScopeID, request.Permission)
	default:
		return ErrScopeForbidden
	}
	if err != nil {
		return authorizer.authorizationError(ctx, err)
	}
	if !authorization.Valid() || authorization.UserID() != userID ||
		authorization.AuthenticationScopeID() != scopeID ||
		authorization.TargetScopeID() != targetScopeID ||
		authorization.CredentialKind() != principal.credentialKind {
		return ErrScopeForbidden
	}
	sealedTenantID, hasTenantID := authorization.TenantID()
	if targetTenantID == uuid.Nil {
		if hasTenantID {
			return ErrScopeForbidden
		}
	} else if !hasTenantID || sealedTenantID != targetTenantID {
		return ErrScopeForbidden
	}
	if principal.credentialKind == credentialSession {
		sessionID, parseErr := uuid.Parse(principal.SessionID)
		if parseErr != nil || sessionID == uuid.Nil || authorization.CredentialID() != sessionID {
			return ErrScopeForbidden
		}
	}
	// PostgreSQL locks define a point-in-time authorization snapshot only. They
	// are released before the external ClickHouse read; no cross-store atomicity
	// is claimed, and the next request re-authenticates and re-authorizes.
	if err := tx.Commit(ctx); err != nil {
		return authenticationDependencyError(ctx, err)
	}
	return nil
}

func (authorizer *iamAuthorizer) targetScopeHint(
	ctx context.Context,
	principal Principal,
	authenticationScopeID uuid.UUID,
	request AuthorizationRequest,
) (uuid.UUID, uuid.UUID, error) {
	switch request.Audience {
	case AudienceTenant:
		tenantID, err := uuid.Parse(request.TenantID)
		if err != nil || tenantID == uuid.Nil {
			return uuid.Nil, uuid.Nil, ErrScopeForbidden
		}
		if principal.ScopeKind != "tenant" || principal.TenantID != tenantID.String() {
			return uuid.Nil, uuid.Nil, ErrScopeForbidden
		}
		return authenticationScopeID, tenantID, nil
	case AudiencePlatform:
		if principal.ScopeKind != "platform" || principal.TenantID != "" ||
			principal.credentialKind != credentialSession {
			return uuid.Nil, uuid.Nil, errAuthenticationRequired
		}
		if request.TenantID == "" {
			return authenticationScopeID, uuid.Nil, nil
		}
		tenantID, err := uuid.Parse(request.TenantID)
		if err != nil || tenantID == uuid.Nil {
			return uuid.Nil, uuid.Nil, ErrScopeForbidden
		}
		var targetScopeID uuid.UUID
		err = authorizer.pool.QueryRow(ctx, `SELECT id FROM access_scopes
			WHERE kind='tenant' AND tenant_id=$1`, tenantID).Scan(&targetScopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, ErrScopeForbidden
		}
		if err != nil || targetScopeID == uuid.Nil {
			return uuid.Nil, uuid.Nil, authenticationDependencyError(ctx, err)
		}
		return targetScopeID, tenantID, nil
	default:
		return uuid.Nil, uuid.Nil, ErrScopeForbidden
	}
}

func (authorizer *iamAuthorizer) authorizationError(
	ctx context.Context,
	err error,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, iamlock.ErrInvalidCredential) {
		return errAuthenticationRequired
	}
	if !errors.Is(err, iamlock.ErrPermissionDenied) {
		return ErrStorageUnavailable
	}
	return ErrPermissionDenied
}

func authenticationDependencyError(ctx context.Context, _ error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrStorageUnavailable
}

func (handler *authorizedHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler.blocks != nil && handler.blocks.Owns(request.URL.Path) {
		handler.blocks.ServeHTTP(writer, request)
		return
	}
	request = requestWithID(request)
	requestID := RequestIDFromContext(request.Context())
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")

	route, ok := resolveRoute(request.URL.Path)
	if !ok || !routeAllowsMethod(route.kind, request.Method) {
		handler.inner.ServeHTTP(writer, request)
		return
	}
	if request.Method == http.MethodGet && getRequestHasBody(request) {
		handler.inner.writeServiceError(writer, request, ErrInvalidInput)
		return
	}
	if err := validateRawQueryEnvelope(request); err != nil {
		handler.inner.writeServiceError(writer, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)

	if route.audience == AudiencePlatform {
		values := request.Header.Values("Authorization")
		if len(values) == 1 {
			scheme, _, _ := strings.Cut(strings.TrimSpace(values[0]), " ")
			if strings.EqualFold(scheme, "CdncaKey") {
				handler.writeAuthenticationError(writer, request, errAuthenticationRequired)
				return
			}
		}
	}
	principal, err := handler.authenticate(request)
	if err != nil {
		handler.writeAuthenticationError(writer, request, err)
		return
	}
	if route.audience == AudiencePlatform && principal.credentialKind == credentialAPIKey {
		handler.writeAuthenticationError(writer, request, errAuthenticationRequired)
		return
	}
	authorization, err := authorizationFor(request, route)
	if err != nil {
		handler.inner.writeServiceError(writer, request, err)
		return
	}
	principal, actor, err := scopedPrincipal(principal, authorization.Audience, authorization.TenantID)
	if err != nil {
		handler.inner.writeServiceError(writer, request, err)
		return
	}
	if authorization.Audience == AudienceTenant {
		authorization.TenantID = actor.TenantID
	} else {
		authorization.TenantID = strings.ToLower(authorization.TenantID)
	}
	if err := handler.authorizer.AuthorizeAnalyticsLogRead(ctx, principal, authorization); err != nil {
		if errors.Is(err, errAuthenticationRequired) {
			handler.writeAuthenticationError(writer, request, err)
			return
		}
		handler.inner.writeServiceError(writer, request, err)
		return
	}
	request = request.WithContext(context.WithValue(request.Context(), authorizedActorKey{}, actor))
	handler.inner.ServeHTTP(writer, request)
}

func validateRawQueryEnvelope(request *http.Request) error {
	query, err := parseRawQuery(request)
	if err != nil {
		return err
	}
	for _, values := range query {
		if len(values) != 1 {
			return ErrInvalidInput
		}
	}
	return nil
}

func (handler *authorizedHandler) writeAuthenticationError(
	writer http.ResponseWriter,
	request *http.Request,
	err error,
) {
	if request.Context().Err() != nil {
		handler.inner.writeServiceError(writer, request, request.Context().Err())
		return
	}
	if errors.Is(err, ErrStorageUnavailable) {
		handler.inner.writeServiceError(writer, request, err)
		return
	}
	handler.inner.writeError(writer, request, http.StatusUnauthorized,
		"analytics_logs_authentication_required", "authentication is required")
}

func authorizationFor(request *http.Request, route handlerRoute) (AuthorizationRequest, error) {
	authorization := AuthorizationRequest{Permission: ReadPermission, Audience: route.audience}
	if route.kind >= routeAccessExportCollection {
		tenantID, err := parseExportScope(request, route.audience)
		if err != nil {
			return AuthorizationRequest{}, err
		}
		authorization.TenantID = tenantID
		return authorization, nil
	}
	if route.kind == routeBlockStateUnsupported {
		tenantID, err := parseUnsupportedScope(request, route.audience)
		if err != nil {
			return AuthorizationRequest{}, err
		}
		authorization.TenantID = tenantID
		return authorization, nil
	}
	query, err := parseQuery(request, route)
	if err != nil {
		return AuthorizationRequest{}, err
	}
	if err := validateFilter(query.Filter); err != nil ||
		route.kind == routeAccess && query.Filter.HasStatus && query.Filter.StatusCode == 0 {
		return AuthorizationRequest{}, ErrInvalidInput
	}
	query.Filter = normalizeFilter(query.Filter)
	authorization.TenantID = query.TenantID
	authorization.SiteID = query.Filter.SiteID
	authorization.NodeID = query.Filter.NodeID
	return authorization, nil
}

func scopedPrincipal(principal Principal, audience Audience, tenantID string) (Principal, Actor, error) {
	principal.ID = strings.ToLower(principal.ID)
	principal.TenantID = strings.ToLower(principal.TenantID)
	if !validUUID(principal.ID) {
		return Principal{}, Actor{}, ErrScopeForbidden
	}
	switch audience {
	case AudiencePlatform:
		tenantID = strings.ToLower(tenantID)
		if principal.ScopeKind != "platform" || principal.TenantID != "" {
			return Principal{}, Actor{}, ErrScopeForbidden
		}
		if tenantID != "" && !validUUID(tenantID) {
			return Principal{}, Actor{}, ErrInvalidInput
		}
		return principal, Actor{
			ScopeKind: "platform", ActorID: principal.ID, ScopeID: principal.ScopeID,
			SessionID: principal.SessionID, Permissions: []string{ReadPermission},
		}, nil
	case AudienceTenant:
		if principal.ScopeKind != "tenant" || tenantID != "" || !validUUID(principal.TenantID) {
			return Principal{}, Actor{}, ErrScopeForbidden
		}
		return principal, Actor{
			ScopeKind: "tenant", TenantID: principal.TenantID, ActorID: principal.ID, ScopeID: principal.ScopeID,
			SessionID: principal.SessionID, Permissions: []string{ReadPermission},
		}, nil
	default:
		return Principal{}, Actor{}, ErrInvalidInput
	}
}

func requestWithID(request *http.Request) *http.Request {
	requestID := RequestIDFromContext(request.Context())
	if requestID == "" && requestIDPattern.MatchString(request.Header.Get("X-Request-ID")) {
		requestID = request.Header.Get("X-Request-ID")
	}
	if requestID == "" {
		requestID = newRequestID()
	}
	return request.WithContext(WithRequestID(request.Context(), requestID))
}

func newRuntimeHTTPClient(connectTimeout, queryTimeout time.Duration, rootCAs *x509.CertPool) *http.Client {
	if rootCAs != nil {
		rootCAs = rootCAs.Clone()
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    10,
		MaxConnsPerHost:        10,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    connectTimeout,
		ResponseHeaderTimeout:  queryTimeout,
		ExpectContinueTimeout:  minDuration(time.Second, queryTimeout),
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

func configuredPGXPool(pool *pgxpool.Pool) (configured bool) {
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
