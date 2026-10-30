package impersonationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
	"github.com/google/uuid"
)

const (
	CookieName                   = "cdnca_impersonation"
	defaultTimeout               = 15 * time.Second
	defaultMaxRequestBytes int64 = 64 << 10
)

var (
	ErrInvalidService  = errors.New("invalid impersonation HTTP service")
	ErrInvalidRequest  = errors.New("invalid impersonation HTTP request")
	ErrUnauthenticated = errors.New("impersonation authentication required")
	metadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	traceparentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$`)
)

type HandlerConfig struct {
	CommandTimeout  time.Duration
	MaxRequestBytes int64
}

type AuthenticateFunc func(*http.Request, string) (identity.AuthenticatedSession, error)

type SessionIssuer interface {
	Issue(context.Context, impersonation.Session) (string, error)
}

type SessionDecoder interface {
	Decode(context.Context, string) (impersonation.Session, error)
}

type impersonationService interface {
	Create(context.Context, impersonation.Actor, impersonation.CreateRequest) (impersonation.CreateResult, error)
	Exchange(context.Context, impersonation.ExchangeRequest) (impersonation.Session, error)
	Authorize(context.Context, impersonation.UseRequest) (impersonation.EffectiveIdentity, error)
	Revoke(context.Context, impersonation.Actor, impersonation.RevokeRequest) (impersonation.Revocation, error)
}

type Handler struct {
	service         impersonationService
	authenticate    AuthenticateFunc
	issuer          SessionIssuer
	timeout         time.Duration
	maxRequestBytes int64
}

func New(service *impersonation.Service, authenticate AuthenticateFunc, issuer SessionIssuer, config HandlerConfig) (*Handler, error) {
	return newHandler(service, authenticate, issuer, config)
}

func newHandler(service impersonationService, authenticate AuthenticateFunc, issuer SessionIssuer, config HandlerConfig) (*Handler, error) {
	timeout, maximum, err := normalizeConfig(config)
	if err != nil || service == nil || authenticate == nil || issuer == nil {
		return nil, ErrInvalidService
	}
	return &Handler{service: service, authenticate: authenticate, issuer: issuer, timeout: timeout, maxRequestBytes: maximum}, nil
}

func normalizeConfig(config HandlerConfig) (time.Duration, int64, error) {
	if config.CommandTimeout == 0 {
		config.CommandTimeout = defaultTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.CommandTimeout <= 0 || config.CommandTimeout > 30*time.Second ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 {
		return 0, 0, ErrInvalidService
	}
	return config.CommandTimeout, config.MaxRequestBytes, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer.Header())
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	requestID, traceID, metadataOK := requestMetadata(request)
	if requestID != "" {
		writer.Header().Set("X-Request-ID", requestID)
	}
	if !metadataOK || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		handler.writeError(writer, requestID, ErrInvalidRequest)
		return
	}
	route, grantID, method := resolveRoute(request.URL.Path)
	if route == "" {
		handler.writePublicError(writer, requestID, http.StatusNotFound, "impersonation_route_not_found")
		return
	}
	if request.Method != method {
		writer.Header().Set("Allow", method)
		handler.writePublicError(writer, requestID, http.StatusMethodNotAllowed, "impersonation_method_not_allowed")
		return
	}
	key, ok := singleHeader(request, "Idempotency-Key")
	if !ok || !idempotencyPattern.MatchString(key) {
		handler.writeError(writer, requestID, ErrInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	metadata := impersonation.RequestContext{RequestID: requestID, TraceID: traceID}

	switch route {
	case "create":
		if hasCookie(request, CookieName) {
			handler.writeError(writer, requestID, impersonation.ErrNested)
			return
		}
		actor, ok := handler.primaryActor(writer, request, requestID)
		if !ok {
			return
		}
		var body struct {
			TenantID      string `json:"tenant_id"`
			TenantScopeID string `json:"tenant_scope_id"`
			SubjectUserID string `json:"subject_user_id"`
		}
		if !handler.decode(writer, request, requestID, &body) {
			return
		}
		tenantID, tenantScopeID, subjectID, ok := threeUUIDs(body.TenantID, body.TenantScopeID, body.SubjectUserID)
		if !ok {
			handler.writeError(writer, requestID, ErrInvalidRequest)
			return
		}
		result, err := handler.service.Create(ctx, actor, impersonation.CreateRequest{
			TenantID: tenantID, TenantScopeID: tenantScopeID, SubjectUserID: subjectID,
			IdempotencyKey: key, Context: metadata,
		})
		if err != nil {
			handler.writeError(writer, requestID, err)
			return
		}
		status := http.StatusCreated
		if result.Replayed {
			status = http.StatusOK
		}
		handler.writeJSON(writer, status, struct {
			Grant             impersonation.Grant `json:"grant"`
			AuthorizationCode string              `json:"authorization_code"`
			Replayed          bool                `json:"replayed"`
		}{result.Grant, result.AuthorizationCode, result.Replayed})
	case "exchange":
		if hasCookie(request, CookieName) || len(request.Header.Values("Authorization")) != 0 {
			handler.writeError(writer, requestID, impersonation.ErrNested)
			return
		}
		var body struct {
			TenantID          string `json:"tenant_id"`
			TenantScopeID     string `json:"tenant_scope_id"`
			AuthorizationCode string `json:"authorization_code"`
		}
		if !handler.decode(writer, request, requestID, &body) {
			return
		}
		tenantID, err1 := canonicalUUID(body.TenantID)
		tenantScopeID, err2 := canonicalUUID(body.TenantScopeID)
		if err1 != nil || err2 != nil {
			handler.writeError(writer, requestID, ErrInvalidRequest)
			return
		}
		session, err := handler.service.Exchange(ctx, impersonation.ExchangeRequest{
			TenantID: tenantID, TenantScopeID: tenantScopeID, AuthorizationCode: body.AuthorizationCode,
			IdempotencyKey: key, Context: metadata,
		})
		if err != nil {
			handler.writeError(writer, requestID, err)
			return
		}
		credential, err := handler.issuer.Issue(ctx, session)
		if err != nil || credential == "" {
			handler.writeError(writer, requestID, ErrInvalidService)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: CookieName, Value: credential, Path: "/", Expires: session.ExpiresAt,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		status := http.StatusCreated
		if session.Replayed {
			status = http.StatusOK
		}
		handler.writeJSON(writer, status, exchangeView{Principal: session.Principal, Banner: session.Banner,
			ExpiresAt: session.ExpiresAt, Refreshable: session.Refreshable, Replayed: session.Replayed})
	case "revoke":
		actor, ok := handler.primaryActor(writer, request, requestID)
		if !ok {
			return
		}
		var body struct {
			TenantID      string `json:"tenant_id"`
			TenantScopeID string `json:"tenant_scope_id"`
			Reason        string `json:"reason"`
		}
		if !handler.decode(writer, request, requestID, &body) {
			return
		}
		tenantID, err1 := canonicalUUID(body.TenantID)
		tenantScopeID, err2 := canonicalUUID(body.TenantScopeID)
		if err1 != nil || err2 != nil {
			handler.writeError(writer, requestID, ErrInvalidRequest)
			return
		}
		result, err := handler.service.Revoke(ctx, actor, impersonation.RevokeRequest{GrantID: grantID,
			TenantID: tenantID, TenantScopeID: tenantScopeID, Reason: body.Reason,
			IdempotencyKey: key, Context: metadata})
		if err != nil {
			handler.writeError(writer, requestID, err)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1,
			Expires: time.Unix(1, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		handler.writeJSON(writer, http.StatusOK, struct {
			impersonation.Revocation
			Replayed bool `json:"replayed"`
		}{result, result.Replayed})
	}
}

type exchangeView struct {
	Principal   impersonation.SubjectPrincipal `json:"principal"`
	Banner      impersonation.BannerClaims     `json:"banner"`
	ExpiresAt   time.Time                      `json:"expires_at"`
	Refreshable bool                           `json:"refreshable"`
	Replayed    bool                           `json:"replayed"`
}

func (handler *Handler) primaryActor(writer http.ResponseWriter, request *http.Request, requestID string) (impersonation.Actor, bool) {
	raw, err := bearer(request)
	if err != nil {
		handler.writeError(writer, requestID, ErrUnauthenticated)
		return impersonation.Actor{}, false
	}
	session, err := handler.authenticate(request, raw)
	// A platform administrator, or (ADR 0018 RS-07) a reseller's member
	// holding reseller.customers.manage; the service confirms the reseller is
	// active and the target is one of its customers.
	platform := session.Principal.ScopeKind == "platform" && session.Principal.TenantID == nil &&
		contains(session.Principal.Permissions, impersonation.ManagePermission)
	reseller := session.Principal.ScopeKind == "tenant" && session.Principal.TenantID != nil &&
		contains(session.Principal.Permissions, impersonation.ResellerPermission)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil ||
		session.Principal.ScopeID == uuid.Nil || !platform && !reseller {
		handler.writeError(writer, requestID, ErrUnauthenticated)
		return impersonation.Actor{}, false
	}
	return impersonation.Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
		PrimaryAuthSessionID: session.SessionID, ScopeKind: session.Principal.ScopeKind,
		SessionKind: impersonation.SessionKindPrimary}, true
}

func (handler *Handler) decode(writer http.ResponseWriter, request *http.Request, requestID string, destination any) bool {
	contentType, ok := singleHeader(request, "Content-Type")
	if !ok || contentType != "application/json" {
		handler.writePublicError(writer, requestID, http.StatusUnsupportedMediaType, "impersonation_unsupported_media_type")
		return false
	}
	payload, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes))
	if err != nil || !utf8.Valid(payload) || !uniqueJSONObject(payload) {
		handler.writeError(writer, requestID, ErrInvalidRequest)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		handler.writeError(writer, requestID, ErrInvalidRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		handler.writeError(writer, requestID, ErrInvalidRequest)
		return false
	}
	return true
}

func (handler *Handler) writeError(writer http.ResponseWriter, requestID string, err error) {
	status, code := publicError(err)
	handler.writePublicError(writer, requestID, status, code)
}

func (handler *Handler) writePublicError(writer http.ResponseWriter, requestID string, status int, code string) {
	handler.writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func publicError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, impersonation.ErrInvalidInput):
		return http.StatusBadRequest, "impersonation_invalid_request"
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized, "impersonation_unauthenticated"
	case errors.Is(err, impersonation.ErrPermissionDenied):
		return http.StatusForbidden, "impersonation_permission_denied"
	case errors.Is(err, impersonation.ErrNested):
		return http.StatusForbidden, "impersonation_nested_denied"
	case errors.Is(err, impersonation.ErrIdempotencyConflict):
		return http.StatusConflict, "impersonation_idempotency_conflict"
	case errors.Is(err, impersonation.ErrInvalidCode):
		return http.StatusUnprocessableEntity, "impersonation_invalid_code"
	case errors.Is(err, impersonation.ErrCodeReplay):
		return http.StatusConflict, "impersonation_code_replay"
	case errors.Is(err, impersonation.ErrGrantExpired):
		return http.StatusGone, "impersonation_grant_expired"
	case errors.Is(err, impersonation.ErrGrantRevoked):
		return http.StatusGone, "impersonation_grant_revoked"
	case errors.Is(err, impersonation.ErrSessionExpired):
		return http.StatusGone, "impersonation_session_expired"
	case errors.Is(err, impersonation.ErrSessionRevoked):
		return http.StatusGone, "impersonation_session_revoked"
	case errors.Is(err, impersonation.ErrPrincipalChanged):
		return http.StatusForbidden, "impersonation_principal_changed"
	case errors.Is(err, impersonation.ErrSensitiveAction):
		return http.StatusForbidden, "impersonation_sensitive_action_denied"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "impersonation_request_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "impersonation_request_timeout"
	default:
		return http.StatusServiceUnavailable, "impersonation_unavailable"
	}
}

type AuthorizedSession struct {
	identity.AuthenticatedSession
	Banner impersonation.BannerClaims
}

type SessionAuthorizer struct {
	service impersonationService
	decoder SessionDecoder
	timeout time.Duration
}

func NewSessionAuthorizer(service impersonationService, decoder SessionDecoder, config HandlerConfig) (*SessionAuthorizer, error) {
	timeout, _, err := normalizeConfig(config)
	if err != nil || service == nil || decoder == nil {
		return nil, ErrInvalidService
	}
	return &SessionAuthorizer{service: service, decoder: decoder, timeout: timeout}, nil
}

func (authorizer *SessionAuthorizer) Authorize(request *http.Request, action string) (AuthorizedSession, error) {
	if authorizer == nil || request == nil {
		return AuthorizedSession{}, ErrUnauthenticated
	}
	requestID, traceID, ok := requestMetadata(request)
	credentials := cookieValues(request, CookieName)
	if !ok || len(credentials) != 1 || credentials[0] == "" {
		return AuthorizedSession{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(request.Context(), authorizer.timeout)
	defer cancel()
	session, err := authorizer.decoder.Decode(ctx, credentials[0])
	if err != nil {
		return AuthorizedSession{}, ErrUnauthenticated
	}
	effective, err := authorizer.service.Authorize(ctx, impersonation.UseRequest{Session: session, Action: action,
		Context: impersonation.RequestContext{RequestID: requestID, TraceID: traceID}})
	if err != nil {
		return AuthorizedSession{}, err
	}
	principal := effective.Session.Principal
	tenantID := principal.TenantID
	return AuthorizedSession{AuthenticatedSession: identity.AuthenticatedSession{SessionID: effective.Session.ID,
		Principal: identity.Principal{UserID: principal.UserID, DisplayID: principal.DisplayID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
			TenantID: &tenantID, Username: principal.Username, DisplayName: principal.DisplayName,
			Roles: append([]string(nil), principal.Roles...), Permissions: append([]string(nil), effective.Permissions...)}},
		Banner: effective.Session.Banner}, nil
}

type sessionEnder interface {
	EndSession(context.Context, impersonation.EndSessionRequest) error
}

// End revokes the impersonation carried by the request's cookie (sign-out
// while impersonating, fix-pre1035). No cookie, or a cookie that no longer
// decodes, is nothing to end and returns nil.
func (authorizer *SessionAuthorizer) End(request *http.Request, reason string) error {
	if authorizer == nil || request == nil {
		return nil
	}
	ender, ok := authorizer.service.(sessionEnder)
	credentials := cookieValues(request, CookieName)
	if !ok || len(credentials) == 0 {
		return nil
	}
	requestID, traceID, metadataOK := requestMetadata(request)
	if !metadataOK {
		return ErrInvalidRequest
	}
	ctx, cancel := context.WithTimeout(request.Context(), authorizer.timeout)
	defer cancel()
	for _, credential := range credentials {
		session, err := authorizer.decoder.Decode(ctx, credential)
		if err != nil {
			continue
		}
		err = ender.EndSession(ctx, impersonation.EndSessionRequest{Session: session, Reason: reason,
			Context: impersonation.RequestContext{RequestID: requestID, TraceID: traceID}})
		if err != nil && !errors.Is(err, impersonation.ErrPrincipalChanged) {
			return err
		}
	}
	return nil
}

func resolveRoute(path string) (string, uuid.UUID, string) {
	if path == "/v1/admin/impersonation/grants" {
		return "create", uuid.Nil, http.MethodPost
	}
	if path == "/v1/admin/impersonation/exchanges" {
		return "exchange", uuid.Nil, http.MethodPost
	}
	const prefix, suffix = "/v1/admin/impersonation/grants/", "/revocations"
	if strings.HasPrefix(path, prefix) && strings.HasSuffix(path, suffix) {
		raw := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
		if id, err := canonicalUUID(raw); err == nil {
			return "revoke", id, http.MethodPost
		}
	}
	return "", uuid.Nil, ""
}

func requestMetadata(request *http.Request) (string, string, bool) {
	requestID, requestOK := singleHeader(request, "X-Request-ID")
	traceparent, traceOK := singleHeader(request, "Traceparent")
	match := traceparentPattern.FindStringSubmatch(traceparent)
	return requestID, func() string {
			if match == nil {
				return ""
			}
			return match[1]
		}(),
		requestOK && metadataPattern.MatchString(requestID) && traceOK && match != nil &&
			match[1] != strings.Repeat("0", 32) && match[2] != strings.Repeat("0", 16)
}

func bearer(request *http.Request) (string, error) {
	raw, ok := singleHeader(request, "Authorization")
	if !ok || !strings.HasPrefix(raw, "Bearer ") || len(raw) <= 7 || strings.TrimSpace(raw[7:]) != raw[7:] {
		return "", ErrUnauthenticated
	}
	return raw[7:], nil
}

func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func canonicalUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func threeUUIDs(first, second, third string) (uuid.UUID, uuid.UUID, uuid.UUID, bool) {
	a, errA := canonicalUUID(first)
	b, errB := canonicalUUID(second)
	c, errC := canonicalUUID(third)
	return a, b, c, errA == nil && errB == nil && errC == nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasCookie(request *http.Request, name string) bool { return len(cookieValues(request, name)) > 0 }

func cookieValues(request *http.Request, name string) []string {
	var values []string
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			values = append(values, cookie.Value)
		}
	}
	return values
}

func uniqueJSONObject(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	return uniqueValue(decoder, true) == nil && func() bool { _, err := decoder.Token(); return errors.Is(err, io.EOF) }()
}

func uniqueValue(decoder *json.Decoder, root bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		if root {
			return ErrInvalidRequest
		}
		return nil
	}
	if root && delim != '{' {
		return ErrInvalidRequest
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidRequest
			}
			seen[key] = struct{}{}
			if err := uniqueValue(decoder, false); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := uniqueValue(decoder, false); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidRequest
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func securityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'")
	header.Set("X-Frame-Options", "DENY")
}
