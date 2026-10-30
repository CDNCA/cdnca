package qualitydiagnosticshttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/google/uuid"
)

const (
	defaultQueryTimeout  = 3 * time.Second
	maximumQueryTimeout  = 10 * time.Second
	maximumRawQueryBytes = 8192
	maximumCursorBytes   = 4096
	maximumResponseBytes = 512 << 10
)

var (
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	cursorPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

type Authenticator func(*http.Request) (identity.Principal, error)

type Config struct {
	QueryTimeout time.Duration
}

type Handler struct {
	reader       qualitydiagnostics.Reader
	authenticate Authenticator
	queryTimeout time.Duration
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewHandler(reader qualitydiagnostics.Reader, authenticate Authenticator, config Config) (*Handler, error) {
	if reader == nil || authenticate == nil {
		return nil, qualitydiagnostics.ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > maximumQueryTimeout {
		return nil, qualitydiagnostics.ErrInvalidConfiguration
	}
	return &Handler{reader: reader, authenticate: authenticate, queryTimeout: config.QueryTimeout}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := responseRequestID(request)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Request-ID", requestID)

	audience, ok := routeAudience(request)
	if !ok {
		handler.writeError(writer, http.StatusNotFound, "quality_diagnostics_route_not_found", "route not found", requestID)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		handler.writeError(writer, http.StatusMethodNotAllowed, "quality_diagnostics_method_not_allowed", "method not allowed", requestID)
		return
	}
	if request.URL == nil || len(request.URL.RawQuery) > maximumRawQueryBytes || request.ContentLength != 0 ||
		len(request.TransferEncoding) != 0 || request.Body != nil && request.Body != http.NoBody || hasSelfAssertedIdentity(request.Header) {
		handler.writeError(writer, http.StatusBadRequest, "quality_diagnostics_invalid_request", "invalid request", requestID)
		return
	}

	principal, err := handler.authenticate(request)
	if err != nil {
		handler.writeAuthenticationError(writer, request, err, requestID)
		return
	}
	actor, err := actorFor(principal, audience)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	query, err := parseQuery(request.URL.RawQuery, audience)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	response, err := handler.reader.Read(ctx, actor, query)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	if response.Items == nil {
		response.Items = []qualitydiagnostics.Item{}
	}
	handler.writeResponse(writer, response, requestID)
}

func routeAudience(request *http.Request) (qualitydiagnostics.Audience, bool) {
	if request == nil || request.URL == nil {
		return "", false
	}
	switch request.URL.Path {
	case "/v1/analytics/quality-diagnostics":
		return qualitydiagnostics.AudienceTenant, true
	case "/v1/admin/analytics/quality-diagnostics":
		return qualitydiagnostics.AudiencePlatform, true
	default:
		return "", false
	}
}

func actorFor(principal identity.Principal, audience qualitydiagnostics.Audience) (qualitydiagnostics.Actor, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return qualitydiagnostics.Actor{}, qualitydiagnostics.ErrPermissionDenied
	}
	switch audience {
	case qualitydiagnostics.AudienceTenant:
		if principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil {
			return qualitydiagnostics.Actor{}, qualitydiagnostics.ErrScopeForbidden
		}
		if !hasPermission(principal.Permissions, "sites.read") {
			return qualitydiagnostics.Actor{}, qualitydiagnostics.ErrPermissionDenied
		}
		return qualitydiagnostics.Actor{
			ScopeKind: "tenant", TenantID: *principal.TenantID,
			Permissions: append([]string(nil), principal.Permissions...),
		}, nil
	case qualitydiagnostics.AudiencePlatform:
		if principal.ScopeKind != "platform" || principal.TenantID != nil {
			return qualitydiagnostics.Actor{}, qualitydiagnostics.ErrScopeForbidden
		}
		if !hasPermission(principal.Permissions, "platform.admin") {
			return qualitydiagnostics.Actor{}, qualitydiagnostics.ErrPermissionDenied
		}
		return qualitydiagnostics.Actor{
			ScopeKind: "platform", Permissions: append([]string(nil), principal.Permissions...),
		}, nil
	default:
		return qualitydiagnostics.Actor{}, qualitydiagnostics.ErrScopeForbidden
	}
}

func parseQuery(raw string, audience qualitydiagnostics.Audience) (qualitydiagnostics.Query, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
	}
	allowed := map[string]bool{
		"from": true, "to": true, "tenant_id": true, "site_id": true, "node_id": true,
		"category": true, "limit": true, "cursor": true,
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
		}
	}
	if len(values["from"]) != 1 || len(values["to"]) != 1 {
		return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
	}
	if audience == qualitydiagnostics.AudienceTenant {
		if _, exists := values["tenant_id"]; exists {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrScopeForbidden
		}
	} else if audience == qualitydiagnostics.AudiencePlatform {
		if len(values["tenant_id"]) != 1 {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
		}
	} else {
		return qualitydiagnostics.Query{}, qualitydiagnostics.ErrScopeForbidden
	}

	from, fromErr := canonicalUTC(values.Get("from"))
	to, toErr := canonicalUTC(values.Get("to"))
	if fromErr != nil || toErr != nil || !from.Before(to) || to.Sub(from) > 31*24*time.Hour {
		return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
	}
	query := qualitydiagnostics.Query{Audience: audience, From: from, To: to, Limit: qualitydiagnostics.DefaultLimit}
	if audience == qualitydiagnostics.AudiencePlatform {
		query.TenantID, err = canonicalUUID(values.Get("tenant_id"))
		if err != nil {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
		}
	}
	if rawSite := values.Get("site_id"); rawSite != "" {
		query.SiteID, err = canonicalUUID(rawSite)
		if err != nil {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
		}
	}
	if rawNode := values.Get("node_id"); rawNode != "" {
		query.NodeID, err = canonicalUUID(rawNode)
		if err != nil {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
		}
	}
	query.Category = qualitydiagnostics.Category(values.Get("category"))
	if !validCategory(query.Category) {
		return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
	}
	if rawLimit := values.Get("limit"); rawLimit != "" {
		parsed, parseErr := strconv.ParseUint(rawLimit, 10, 16)
		if parseErr != nil || parsed < 1 || parsed > uint64(qualitydiagnostics.MaxLimit) || strconv.FormatUint(parsed, 10) != rawLimit {
			return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
		}
		query.Limit = uint16(parsed)
	}
	query.Cursor = values.Get("cursor")
	if query.Cursor != "" && (len(query.Cursor) > maximumCursorBytes || !cursorPattern.MatchString(query.Cursor)) {
		return qualitydiagnostics.Query{}, qualitydiagnostics.ErrInvalidRequest
	}
	return query, nil
}

func canonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value ||
		!parsed.Equal(parsed.Truncate(time.Millisecond)) {
		return time.Time{}, qualitydiagnostics.ErrInvalidRequest
	}
	return parsed, nil
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, qualitydiagnostics.ErrInvalidRequest
	}
	return parsed, nil
}

func validCategory(value qualitydiagnostics.Category) bool {
	switch value {
	case "", qualitydiagnostics.CategoryUpstream5xx, qualitydiagnostics.CategoryEdge530,
		qualitydiagnostics.CategoryNoHost, qualitydiagnostics.CategoryConfigMismatch:
		return true
	default:
		return false
	}
}

func hasPermission(permissions []string, wanted string) bool {
	for _, permission := range permissions {
		if permission == wanted {
			return true
		}
	}
	return false
}

func hasSelfAssertedIdentity(header http.Header) bool {
	for _, name := range []string{"X-User-ID", "X-Scope-ID", "X-Tenant-ID", "X-Session-ID", "X-Role", "X-Permissions"} {
		if _, exists := header[http.CanonicalHeaderKey(name)]; exists {
			return true
		}
	}
	return false
}

func responseRequestID(request *http.Request) string {
	if request != nil && requestIDPattern.MatchString(request.Header.Get("X-Request-ID")) {
		return request.Header.Get("X-Request-ID")
	}
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "quality-diagnostics-request"
	}
	return hex.EncodeToString(buffer)
}

func (handler *Handler) writeAuthenticationError(writer http.ResponseWriter, request *http.Request, err error, requestID string) {
	switch {
	case errors.Is(err, identity.ErrInvalidSession):
		handler.writeError(writer, http.StatusUnauthorized, "quality_diagnostics_authentication_required", "authentication required", requestID)
	case errors.Is(err, context.Canceled), request != nil && errors.Is(request.Context().Err(), context.Canceled):
		handler.writeServiceError(writer, context.Canceled, requestID)
	case errors.Is(err, context.DeadlineExceeded), request != nil && errors.Is(request.Context().Err(), context.DeadlineExceeded):
		handler.writeServiceError(writer, context.DeadlineExceeded, requestID)
	default:
		handler.writeServiceError(writer, qualitydiagnostics.ErrUnavailable, requestID)
	}
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, qualitydiagnostics.ErrInvalidRequest):
		handler.writeError(writer, http.StatusBadRequest, "quality_diagnostics_invalid_request", "invalid request", requestID)
	case errors.Is(err, qualitydiagnostics.ErrInvalidCursor):
		handler.writeError(writer, http.StatusBadRequest, "quality_diagnostics_invalid_cursor", "invalid cursor", requestID)
	case errors.Is(err, qualitydiagnostics.ErrPermissionDenied):
		handler.writeError(writer, http.StatusForbidden, "quality_diagnostics_permission_denied", "permission denied", requestID)
	case errors.Is(err, qualitydiagnostics.ErrScopeForbidden):
		handler.writeError(writer, http.StatusForbidden, "quality_diagnostics_scope_forbidden", "scope forbidden", requestID)
	case errors.Is(err, qualitydiagnostics.ErrInvalidSnapshot):
		handler.writeError(writer, http.StatusConflict, "quality_diagnostics_snapshot_conflict", "snapshot unavailable", requestID)
	case errors.Is(err, qualitydiagnostics.ErrInvalidResponse):
		handler.writeError(writer, http.StatusBadGateway, "quality_diagnostics_invalid_source_response", "source response invalid", requestID)
	case errors.Is(err, context.Canceled):
		handler.writeError(writer, http.StatusRequestTimeout, "quality_diagnostics_request_cancelled", "request cancelled", requestID)
	case errors.Is(err, context.DeadlineExceeded):
		handler.writeError(writer, http.StatusGatewayTimeout, "quality_diagnostics_timeout", "query timed out", requestID)
	case errors.Is(err, qualitydiagnostics.ErrUnavailable):
		handler.writeError(writer, http.StatusServiceUnavailable, "quality_diagnostics_unavailable", "source unavailable", requestID)
	default:
		handler.writeError(writer, http.StatusInternalServerError, "quality_diagnostics_internal_error", "request failed", requestID)
	}
}

func (handler *Handler) writeResponse(writer http.ResponseWriter, response qualitydiagnostics.Response, requestID string) {
	body, err := json.Marshal(response)
	if err != nil || len(body) > maximumResponseBytes {
		handler.writeError(writer, http.StatusBadGateway, "quality_diagnostics_invalid_source_response", "source response invalid", requestID)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(append(body, '\n'))
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, code, message, requestID string) {
	envelope := errorEnvelope{}
	envelope.Error.Code = code
	envelope.Error.Message = message
	envelope.Error.RequestID = requestID
	body, _ := json.Marshal(envelope)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(body, '\n'))
}
