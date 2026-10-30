package cccoordhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/cccoord"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	readPermission   = "sites.read"
	managePermission = "security_policies.manage"
)

var (
	errUnauthenticated = errors.New("CC coordination authentication required")
	errForbidden       = errors.New("CC coordination permission denied")
)

type stateStore interface {
	ListStates(context.Context, uuid.UUID, uuid.UUID, int) ([]cccoord.State, error)
	GetState(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (cccoord.State, error)
	Release(context.Context, securitypolicy.Actor, cccoord.ReleaseInput) (cccoord.ReleaseResult, error)
}

type principal struct {
	userID, scopeID, tenantID uuid.UUID
	scopeKind, credentialKind string
	rawCredential             string
	sessionID                 uuid.UUID
}

type authenticateFunc func(*http.Request) (principal, error)
type authorizeFunc func(context.Context, principal, uuid.UUID, string) (securitypolicy.Actor, error)

type Handler struct {
	store        stateStore
	pool         *pgxpool.Pool
	authenticate authenticateFunc
	authorize    authorizeFunc
	timeout      time.Duration
}

type RuntimeDependencies struct {
	Pool     *pgxpool.Pool
	Identity *identity.Service
	APIKeys  *apikey.Service
	IAM      *iamlock.Authorizer
	Store    *cccoord.Store
}

func NewRuntimeHandler(dependencies RuntimeDependencies) (*Handler, error) {
	if !configuredPool(dependencies.Pool) || dependencies.Identity == nil || !dependencies.Identity.Configured() ||
		dependencies.APIKeys == nil || dependencies.IAM == nil || !dependencies.IAM.Configured() || dependencies.Store == nil {
		return nil, cccoord.ErrInvalidInput
	}
	authenticate := runtimeAuthenticator(dependencies.Identity, dependencies.APIKeys)
	authorize := runtimeAuthorizer(dependencies.Pool, dependencies.IAM)
	return newHandler(dependencies.Store, dependencies.Pool, authenticate, authorize, 5*time.Second)
}

func newHandler(store stateStore, pool *pgxpool.Pool, authenticate authenticateFunc, authorize authorizeFunc, timeout time.Duration) (*Handler, error) {
	if store == nil || !configuredPool(pool) || authenticate == nil || authorize == nil || timeout <= 0 || timeout > 30*time.Second {
		return nil, cccoord.ErrInvalidInput
	}
	return &Handler{store: store, pool: pool, authenticate: authenticate, authorize: authorize, timeout: timeout}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	platform, stateID, release, ok := route(request.URL.Path)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	wantMethod := http.MethodGet
	if release {
		wantMethod = http.MethodPost
	}
	if request.Method != wantMethod {
		writer.Header().Set("Allow", wantMethod)
		writeError(writer, http.StatusMethodNotAllowed, "cc_coordination_method_not_allowed")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	identity, err := handler.authenticate(request)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	tenantScopeID, siteID, limit, err := handler.target(request, identity, platform, release)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	permission := readPermission
	if release {
		permission = managePermission
	}
	authorizeScopeID := tenantScopeID
	if authorizeScopeID == uuid.Nil {
		authorizeScopeID = identity.scopeID
	}
	actor, err := handler.authorize(ctx, identity, authorizeScopeID, permission)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	if !release {
		states, err := handler.store.ListStates(ctx, tenantScopeID, siteID, limit)
		if err != nil {
			writeMappedError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, struct {
			Items []cccoord.State `json:"items"`
		}{Items: states})
		return
	}
	key, err := exactHeader(request, "Idempotency-Key")
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	requestID, err := exactHeader(request, "X-Request-ID")
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	var body struct {
		ReasonCode         string `json:"reason_code"`
		ExpectedGeneration int64  `json:"expected_generation"`
	}
	if err := decodeBody(request, &body); err != nil || body.ReasonCode != cccoord.ReasonFalsePositiveConfirmed || body.ExpectedGeneration < 1 {
		writeMappedError(writer, cccoord.ErrInvalidInput)
		return
	}
	state, err := handler.store.GetState(ctx, tenantScopeID, siteID, stateID)
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	result, err := handler.store.Release(ctx, actor, cccoord.ReleaseInput{
		TenantScopeID: tenantScopeID, SiteID: siteID, RuleID: state.RuleID, ClientCIDR: state.ClientCIDR,
		Host: state.Host, Path: state.Path, Method: state.Method, ListenerPort: state.ListenerPort,
		Protocol: state.Protocol, ExpectedGeneration: body.ExpectedGeneration,
		IdempotencyKey: key, RequestID: requestID,
	})
	if err != nil {
		writeMappedError(writer, err)
		return
	}
	if result.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	writeJSON(writer, http.StatusAccepted, result)
}

func route(path string) (platform bool, stateID uuid.UUID, release bool, ok bool) {
	for _, candidate := range []struct {
		prefix   string
		platform bool
	}{{"/v1/admin/analytics/logs/cc-coordination", true}, {"/v1/analytics/logs/cc-coordination", false}} {
		if path == candidate.prefix {
			return candidate.platform, uuid.Nil, false, true
		}
		prefix := candidate.prefix + "/"
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
		if len(parts) != 2 || parts[1] != "release" {
			return false, uuid.Nil, false, false
		}
		id, err := uuid.Parse(parts[0])
		if err != nil || id == uuid.Nil || id.String() != parts[0] {
			return false, uuid.Nil, false, false
		}
		return candidate.platform, id, true, true
	}
	return false, uuid.Nil, false, false
}

func (handler *Handler) target(request *http.Request, identity principal, platform, release bool) (uuid.UUID, uuid.UUID, int, error) {
	query := request.URL.Query()
	allowed := map[string]bool{"site_id": true}
	if platform {
		allowed["tenant_id"] = true
	}
	if !release {
		allowed["limit"] = true
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return uuid.Nil, uuid.Nil, 0, cccoord.ErrInvalidInput
		}
	}
	// Listing is open-ended: no site lists every site, and on the platform
	// route no tenant lists every tenant. A release names both.
	siteID := uuid.Nil
	if raw := query.Get("site_id"); raw != "" || release {
		parsed, err := parseUUID(raw)
		if err != nil {
			return uuid.Nil, uuid.Nil, 0, err
		}
		siteID = parsed
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return uuid.Nil, uuid.Nil, 0, cccoord.ErrInvalidInput
		}
		limit = parsed
	}
	if !platform {
		if identity.scopeKind != "tenant" || identity.scopeID == uuid.Nil || identity.tenantID == uuid.Nil {
			return uuid.Nil, uuid.Nil, 0, errForbidden
		}
		return identity.scopeID, siteID, limit, nil
	}
	if identity.scopeKind != "platform" || identity.credentialKind != "session" {
		return uuid.Nil, uuid.Nil, 0, errForbidden
	}
	if query.Get("tenant_id") == "" && !release {
		// Platform-wide list, authorized against the operator's own scope.
		return uuid.Nil, siteID, limit, nil
	}
	tenantID, err := parseUUID(query.Get("tenant_id"))
	if err != nil {
		return uuid.Nil, uuid.Nil, 0, err
	}
	var scopeID uuid.UUID
	if err := handler.pool.QueryRow(request.Context(), `SELECT id FROM access_scopes WHERE kind='tenant' AND tenant_id=$1`, tenantID).Scan(&scopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, uuid.Nil, 0, errForbidden
		}
		return uuid.Nil, uuid.Nil, 0, cccoord.ErrUnavailable
	}
	return scopeID, siteID, limit, nil
}

func runtimeAuthenticator(identityService *identity.Service, apiKeys *apikey.Service) authenticateFunc {
	return func(request *http.Request) (principal, error) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 {
			return principal{}, errUnauthenticated
		}
		scheme, credential, found := strings.Cut(strings.TrimSpace(values[0]), " ")
		credential = strings.TrimSpace(credential)
		if !found || credential == "" || strings.ContainsAny(credential, " \t\r\n") {
			return principal{}, errUnauthenticated
		}
		if strings.EqualFold(scheme, "Bearer") {
			session, err := identityService.AuthenticateSession(request.Context(), credential)
			if err != nil {
				if errors.Is(err, identity.ErrInvalidSession) {
					return principal{}, errUnauthenticated
				}
				return principal{}, cccoord.ErrUnavailable
			}
			return runtimePrincipal(session.Principal, "session", credential, session.SessionID), nil
		}
		if strings.EqualFold(scheme, "CdncaKey") {
			value, err := apiKeys.Authenticate(request.Context(), credential)
			if err != nil {
				if errors.Is(err, apikey.ErrInvalidCredential) {
					return principal{}, errUnauthenticated
				}
				return principal{}, cccoord.ErrUnavailable
			}
			return runtimePrincipal(value, "api_key", credential, uuid.Nil), nil
		}
		return principal{}, errUnauthenticated
	}
}

func runtimePrincipal(value identity.Principal, kind, raw string, sessionID uuid.UUID) principal {
	tenantID := uuid.Nil
	if value.TenantID != nil {
		tenantID = *value.TenantID
	}
	return principal{userID: value.UserID, scopeID: value.ScopeID, tenantID: tenantID,
		scopeKind: value.ScopeKind, credentialKind: kind, rawCredential: raw, sessionID: sessionID}
}

func runtimeAuthorizer(pool *pgxpool.Pool, authorizer *iamlock.Authorizer) authorizeFunc {
	return func(ctx context.Context, identity principal, targetScopeID uuid.UUID, permission string) (securitypolicy.Actor, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return securitypolicy.Actor{}, cccoord.ErrUnavailable
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		var sealed iamlock.Authorization
		switch identity.credentialKind {
		case "session":
			sealed, err = authorizer.AuthorizeSession(ctx, tx, identity.rawCredential, targetScopeID, permission)
		case "api_key":
			sealed, err = authorizer.AuthorizeAPIKey(ctx, tx, identity.rawCredential, targetScopeID, permission)
		default:
			return securitypolicy.Actor{}, errForbidden
		}
		if err != nil {
			if errors.Is(err, iamlock.ErrInvalidCredential) {
				return securitypolicy.Actor{}, errUnauthenticated
			}
			if errors.Is(err, iamlock.ErrPermissionDenied) {
				return securitypolicy.Actor{}, errForbidden
			}
			return securitypolicy.Actor{}, cccoord.ErrUnavailable
		}
		if !sealed.Valid() || sealed.UserID() != identity.userID || sealed.AuthenticationScopeID() != identity.scopeID ||
			sealed.TargetScopeID() != targetScopeID || sealed.CredentialKind() != identity.credentialKind {
			return securitypolicy.Actor{}, errForbidden
		}
		if identity.credentialKind == "session" && sealed.CredentialID() != identity.sessionID {
			return securitypolicy.Actor{}, errForbidden
		}
		if err := tx.Commit(ctx); err != nil {
			return securitypolicy.Actor{}, cccoord.ErrUnavailable
		}
		return securitypolicy.Actor{UserID: identity.userID, ScopeID: identity.scopeID, ScopeKind: identity.scopeKind}, nil
	}
}

func parseUUID(value string) (uuid.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return uuid.Nil, cccoord.ErrInvalidInput
	}
	return id, nil
}

func exactHeader(request *http.Request, name string) (string, error) {
	values := request.Header.Values(name)
	if len(values) != 1 || len(values[0]) < 1 || len(values[0]) > 128 {
		return "", cccoord.ErrInvalidInput
	}
	for _, value := range values[0] {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' ||
			value == '.' || value == '_' || value == ':' || value == '-' {
			continue
		}
		return "", cccoord.ErrInvalidInput
	}
	return values[0], nil
}

func decodeBody(request *http.Request, target any) error {
	payload, err := io.ReadAll(io.LimitReader(request.Body, 4097))
	if err != nil || len(payload) == 0 || len(payload) > 4096 {
		return cccoord.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return cccoord.ErrInvalidInput
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "cc_coordination_unavailable")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}

func writeMappedError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnauthenticated):
		writeError(writer, http.StatusUnauthorized, "cc_coordination_authentication_required")
	case errors.Is(err, errForbidden), errors.Is(err, cccoord.ErrScopeMismatch):
		writeError(writer, http.StatusForbidden, "cc_coordination_permission_denied")
	case errors.Is(err, cccoord.ErrInvalidInput):
		writeError(writer, http.StatusBadRequest, "cc_coordination_invalid_request")
	case errors.Is(err, cccoord.ErrGenerationConflict), errors.Is(err, cccoord.ErrIdempotencyConflict):
		writeError(writer, http.StatusConflict, "cc_coordination_conflict")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeError(writer, http.StatusGatewayTimeout, "cc_coordination_timeout")
	default:
		writeError(writer, http.StatusServiceUnavailable, "cc_coordination_unavailable")
	}
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code}})
}

func configuredPool(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() { configured = recover() == nil && configured }()
	configured = pool.Config() != nil && pool.Config().MaxConns > 0
	return configured
}
