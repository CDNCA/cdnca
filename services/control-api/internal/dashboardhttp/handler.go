package dashboardhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/dashboard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const (
	defaultQueryTimeout     = 6 * time.Second
	maximumQueryTimeout     = 30 * time.Second
	defaultMaxResponseBytes = 1 << 20
	minimumMaxResponseBytes = 512
	maximumMaxResponseBytes = 4 << 20
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type SessionAuthenticator interface {
	AuthenticateSession(context.Context, string) (identity.AuthenticatedSession, error)
}

type Reader interface {
	Admin(context.Context, dashboard.Actor, dashboard.Query) (dashboard.AdminResponse, error)
	Tenant(context.Context, dashboard.Actor, dashboard.Query) (dashboard.TenantResponse, error)
}

type Config struct {
	Now              func() time.Time
	QueryTimeout     time.Duration
	MaxResponseBytes int
}

type Handler struct {
	authenticator    SessionAuthenticator
	reader           Reader
	now              func() time.Time
	queryTimeout     time.Duration
	maxResponseBytes int
}

func NewHandler(authenticator SessionAuthenticator, reader Reader, config Config) (*Handler, error) {
	if authenticator == nil || reader == nil {
		return nil, dashboard.ErrInvalidConfig
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maximumQueryTimeout ||
		config.MaxResponseBytes < minimumMaxResponseBytes || config.MaxResponseBytes > maximumMaxResponseBytes {
		return nil, dashboard.ErrInvalidConfig
	}
	return &Handler{
		authenticator: authenticator, reader: reader, now: config.Now,
		queryTimeout: config.QueryTimeout, maxResponseBytes: config.MaxResponseBytes,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := request.Header.Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = newRequestID()
	}
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")

	audience, ok := routeAudience(request.URL.Path)
	if !ok {
		handler.writeError(writer, http.StatusNotFound, "dashboard_route_not_found", "dashboard route was not found", requestID)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		handler.writeError(writer, http.StatusMethodNotAllowed, "dashboard_method_not_allowed", "dashboard route requires GET", requestID)
		return
	}
	if hasSelfAssertedIdentity(request.Header) {
		handler.writeError(writer, http.StatusBadRequest, "dashboard_invalid_request", "self-asserted identity headers are forbidden", requestID)
		return
	}
	rawSession, ok := bearerSession(request.Header)
	if !ok {
		handler.writeError(writer, http.StatusUnauthorized, "dashboard_authentication_required", "authentication is required", requestID)
		return
	}
	authenticated, err := handler.authenticator.AuthenticateSession(request.Context(), rawSession)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidSession):
			handler.writeError(writer, http.StatusUnauthorized, "dashboard_authentication_required", "authentication is required", requestID)
		case errors.Is(err, context.Canceled), errors.Is(request.Context().Err(), context.Canceled):
			handler.writeServiceError(writer, context.Canceled, requestID)
		case errors.Is(err, context.DeadlineExceeded), errors.Is(request.Context().Err(), context.DeadlineExceeded):
			handler.writeServiceError(writer, context.DeadlineExceeded, requestID)
		default:
			handler.writeServiceError(writer, dashboard.ErrUnavailable, requestID)
		}
		return
	}
	actor, err := actorFor(authenticated, rawSession, audience)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	query, err := parseQuery(request, audience, handler.now())
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	if audience == dashboard.AudienceAdmin {
		response, err := handler.reader.Admin(ctx, actor, query)
		if err != nil {
			handler.writeServiceError(writer, err, requestID)
			return
		}
		handler.writeResult(writer, response, requestID)
		return
	}
	response, err := handler.reader.Tenant(ctx, actor, query)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	handler.writeResult(writer, response, requestID)
}

func routeAudience(path string) (dashboard.Audience, bool) {
	switch path {
	case "/v1/admin/dashboard":
		return dashboard.AudienceAdmin, true
	case "/v1/dashboard":
		return dashboard.AudienceTenant, true
	default:
		return dashboard.AudienceInvalid, false
	}
}

func actorFor(session identity.AuthenticatedSession, rawSession string, audience dashboard.Audience) (dashboard.Actor, error) {
	actor := dashboard.Actor{
		RawSession: rawSession, SessionID: session.SessionID, UserID: session.Principal.UserID,
		ScopeID: session.Principal.ScopeID, ScopeKind: session.Principal.ScopeKind,
	}
	if session.Principal.TenantID != nil {
		actor.TenantID = *session.Principal.TenantID
	}
	if !actor.Valid() {
		return dashboard.Actor{}, dashboard.ErrPermissionDenied
	}
	if audience == dashboard.AudienceAdmin && actor.ScopeKind != "platform" ||
		audience == dashboard.AudienceTenant && actor.ScopeKind != "tenant" {
		return dashboard.Actor{}, dashboard.ErrScopeForbidden
	}
	return actor, nil
}

func parseQuery(request *http.Request, audience dashboard.Audience, now time.Time) (dashboard.Query, error) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return dashboard.Query{}, dashboard.ErrInvalidQuery
	}
	if _, exists := query["tenant_id"]; exists {
		return dashboard.Query{}, dashboard.ErrScopeForbidden
	}
	for key, values := range query {
		if key != "range" && key != "timezone" && key != "site_id" && key != "node_id" ||
			len(values) != 1 || values[0] == "" {
			return dashboard.Query{}, dashboard.ErrInvalidQuery
		}
	}
	if len(query) < 2 || len(query) > 4 || len(query["range"]) != 1 || len(query["timezone"]) != 1 {
		return dashboard.Query{}, dashboard.ErrInvalidQuery
	}
	return dashboard.NewFilteredQuery(
		audience, query.Get("range"), query.Get("timezone"), query.Get("site_id"), query.Get("node_id"), now,
	)
}

func bearerSession(header http.Header) (string, bool) {
	values := header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	raw := strings.TrimPrefix(values[0], "Bearer ")
	if len(raw) == 0 || len(raw) > 8192 || strings.ContainsRune(raw, ',') || strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return "", false
	}
	return raw, true
}

func hasSelfAssertedIdentity(header http.Header) bool {
	for _, name := range []string{
		"X-User-ID", "X-Scope-ID", "X-Tenant-ID", "X-Session-ID", "X-Role", "X-Permissions",
	} {
		if _, exists := header[http.CanonicalHeaderKey(name)]; exists {
			return true
		}
	}
	return false
}

func (handler *Handler) writeResult(writer http.ResponseWriter, value any, requestID string) {
	body, err := json.Marshal(value)
	if err != nil {
		handler.writeError(writer, http.StatusInternalServerError, "dashboard_internal_error", "dashboard response failed", requestID)
		return
	}
	if len(body) > handler.maxResponseBytes {
		handler.writeError(writer, http.StatusBadGateway, "dashboard_response_too_large", "dashboard response exceeded its limit", requestID)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(append(body, '\n'))
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, dashboard.ErrInvalidQuery):
		handler.writeError(writer, http.StatusBadRequest, "dashboard_invalid_request", "dashboard query is invalid", requestID)
	case errors.Is(err, dashboard.ErrScopeForbidden):
		handler.writeError(writer, http.StatusForbidden, "dashboard_scope_forbidden", "dashboard scope is forbidden", requestID)
	case errors.Is(err, dashboard.ErrPermissionDenied):
		handler.writeError(writer, http.StatusForbidden, "dashboard_permission_denied", "dashboard permission is denied", requestID)
	case errors.Is(err, context.Canceled):
		handler.writeError(writer, http.StatusRequestTimeout, "dashboard_request_cancelled", "dashboard request was cancelled", requestID)
	case errors.Is(err, context.DeadlineExceeded):
		handler.writeError(writer, http.StatusGatewayTimeout, "dashboard_query_timeout", "dashboard query timed out", requestID)
	case errors.Is(err, dashboard.ErrUnavailable):
		handler.writeError(writer, http.StatusServiceUnavailable, "dashboard_storage_unavailable", "dashboard storage is unavailable", requestID)
	default:
		handler.writeError(writer, http.StatusInternalServerError, "dashboard_internal_error", "dashboard request failed", requestID)
	}
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, code, message, requestID string) {
	body, _ := json.Marshal(struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}{Error: struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}{Code: code, Message: message, RequestID: requestID}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(body, '\n'))
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "dashboard-request"
	}
	return hex.EncodeToString(raw)
}

var _ http.Handler = (*Handler)(nil)
var _ dashboard.Reader = Reader(nil)
