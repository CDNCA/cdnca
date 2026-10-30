package l4analyticshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4analytics"
	"github.com/google/uuid"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type Authenticator func(*http.Request) (identity.Principal, error)

type Config struct {
	QueryTimeout     time.Duration
	MaxResponseBytes int
}

type Handler struct {
	reader       l4analytics.Reader
	authenticate Authenticator
	timeout      time.Duration
	maxResponse  int
}

func NewHandler(reader l4analytics.Reader, authenticate Authenticator, config Config) (*Handler, error) {
	if reader == nil || authenticate == nil {
		return nil, l4analytics.ErrInvalidConfig
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = 5 * time.Second
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 1 << 20
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > 30*time.Second || config.MaxResponseBytes < 512 || config.MaxResponseBytes > 4<<20 {
		return nil, l4analytics.ErrInvalidConfig
	}
	return &Handler{reader: reader, authenticate: authenticate, timeout: config.QueryTimeout, maxResponse: config.MaxResponseBytes}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := writer.Header().Get("X-Request-ID")
	if !requestIDPattern.MatchString(requestID) {
		requestID = ""
		if request != nil && len(request.Header.Values("X-Request-ID")) == 1 {
			requestID = strings.TrimSpace(request.Header.Get("X-Request-ID"))
		}
		if !requestIDPattern.MatchString(requestID) {
			requestID = uuid.NewString()
		}
	}
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		writeError(writer, http.StatusBadRequest, "l4_analytics_invalid_request")
		return
	}
	audience, logs, ok := routeAudience(request.URL.Path)
	if !ok {
		writeError(writer, http.StatusNotFound, "l4_analytics_route_not_found")
		return
	}
	principal, err := handler.authenticate(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "l4_analytics_unauthenticated")
		return
	}
	actor, err := actorFor(principal, audience)
	if err != nil {
		writeError(writer, http.StatusForbidden, errorCode(err))
		return
	}
	query, err := parseQuery(request, audience, actor.TenantID, logs)
	if err != nil {
		statusCode := http.StatusBadRequest
		if errors.Is(err, l4analytics.ErrPermissionDenied) {
			statusCode = http.StatusForbidden
		}
		writeError(writer, statusCode, errorCode(err))
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	var response any
	if logs {
		reader, supported := handler.reader.(l4analytics.SessionLogReader)
		if !supported {
			err = l4analytics.ErrSessionLogUnavailable
		} else {
			values := request.URL.Query()
			response, err = reader.ReadSessionLogs(ctx, actor, l4analytics.SessionLogQuery{Query: query,
				ClientIP: values.Get("client_ip"), EndReason: values.Get("end_reason")})
		}
	} else {
		response, err = handler.reader.Read(ctx, actor, query)
	}
	if err != nil {
		statusCode := http.StatusServiceUnavailable
		if errors.Is(err, l4analytics.ErrPermissionDenied) {
			statusCode = http.StatusForbidden
		} else if errors.Is(err, l4analytics.ErrInvalidRequest) || errors.Is(err, l4analytics.ErrInvalidCursor) {
			statusCode = http.StatusBadRequest
		}
		writeError(writer, statusCode, errorCode(err))
		return
	}
	payload, err := json.Marshal(response)
	if err != nil || len(payload) > handler.maxResponse {
		writeError(writer, http.StatusInternalServerError, "l4_analytics_response_too_large")
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(payload)
}

// routeAudience returns the audience of path and whether it is the session
// log route.
func routeAudience(path string) (l4analytics.Audience, bool, bool) {
	switch path {
	case "/v1/analytics/l4-realtime":
		return l4analytics.AudienceTenant, false, true
	case "/v1/admin/analytics/l4-realtime":
		return l4analytics.AudiencePlatform, false, true
	case "/v1/analytics/l4-session-logs":
		return l4analytics.AudienceTenant, true, true
	case "/v1/admin/analytics/l4-session-logs":
		return l4analytics.AudiencePlatform, true, true
	default:
		return "", false, false
	}
}

func actorFor(principal identity.Principal, audience l4analytics.Audience) (l4analytics.Actor, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return l4analytics.Actor{}, l4analytics.ErrPermissionDenied
	}
	switch audience {
	case l4analytics.AudienceTenant:
		if principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil ||
			!hasPermission(principal.Permissions, l4analytics.ReadPermission) {
			return l4analytics.Actor{}, l4analytics.ErrPermissionDenied
		}
		return l4analytics.Actor{ScopeKind: "tenant", TenantID: principal.TenantID.String(), Permissions: append([]string(nil), principal.Permissions...)}, nil
	case l4analytics.AudiencePlatform:
		if principal.ScopeKind != "platform" || principal.TenantID != nil || !hasPermission(principal.Permissions, "platform.admin") {
			return l4analytics.Actor{}, l4analytics.ErrPermissionDenied
		}
		return l4analytics.Actor{ScopeKind: "platform", Permissions: append([]string(nil), principal.Permissions...)}, nil
	default:
		return l4analytics.Actor{}, l4analytics.ErrPermissionDenied
	}
}

func parseQuery(request *http.Request, audience l4analytics.Audience, sessionTenantID string, logs bool) (l4analytics.Query, error) {
	values := request.URL.Query()
	allowed := map[string]bool{"tenant_id": true, "range": true, "from": true, "to": true, "timezone": true, "site_id": true, "stream_id": true, "node_id": true, "protocol": true, "listen_port": true, "limit": true, "cursor": true,
		"client_ip": logs, "end_reason": logs}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" {
			return l4analytics.Query{}, l4analytics.ErrInvalidRequest
		}
	}
	if audience == l4analytics.AudienceTenant {
		if values.Get("tenant_id") != "" {
			return l4analytics.Query{}, l4analytics.ErrPermissionDenied
		}
	} else if audience != l4analytics.AudiencePlatform {
		return l4analytics.Query{}, l4analytics.ErrPermissionDenied
	}
	tenantID := values.Get("tenant_id")
	if audience == l4analytics.AudienceTenant {
		tenantID = sessionTenantID
	}
	query := l4analytics.Query{Audience: audience, TenantID: tenantID, Range: values.Get("range"), Timezone: values.Get("timezone"), SiteID: values.Get("site_id"), StreamID: values.Get("stream_id"), NodeID: values.Get("node_id"), Protocol: values.Get("protocol"), Cursor: values.Get("cursor"), Limit: 10}
	if raw := values.Get("listen_port"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || value == 0 || value > 65535 || strconv.FormatUint(value, 10) != raw {
			return l4analytics.Query{}, l4analytics.ErrInvalidRequest
		}
		query.ListenPort = uint16(value)
	}
	if raw := values.Get("limit"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || value == 0 || value > 100 || strconv.FormatUint(value, 10) != raw {
			return l4analytics.Query{}, l4analytics.ErrInvalidRequest
		}
		query.Limit = uint16(value)
	}
	if query.Range == "custom" {
		var err error
		query.From, err = parseUTC(values.Get("from"))
		if err != nil {
			return l4analytics.Query{}, l4analytics.ErrInvalidRequest
		}
		query.To, err = parseUTC(values.Get("to"))
		if err != nil {
			return l4analytics.Query{}, l4analytics.ErrInvalidRequest
		}
	}
	return query, nil
}

func parseUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, l4analytics.ErrInvalidRequest
	}
	return parsed, nil
}

func hasPermission(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, l4analytics.ErrSessionLogUnavailable):
		return "l4_session_log_unavailable"
	case errors.Is(err, l4analytics.ErrInvalidCursor):
		return "l4_analytics_invalid_cursor"
	case errors.Is(err, l4analytics.ErrPermissionDenied):
		return "l4_analytics_forbidden"
	case errors.Is(err, l4analytics.ErrDependencyUnavailable):
		return "l4_analytics_dependency_unavailable"
	case errors.Is(err, l4analytics.ErrInvalidRequest):
		return "l4_analytics_invalid_request"
	default:
		return "l4_analytics_unavailable"
	}
}

func writeError(writer http.ResponseWriter, statusCode int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": code, "message": "请求无法完成", "request_id": writer.Header().Get("X-Request-ID")}})
}

var _ http.Handler = (*Handler)(nil)
