package analyticsrealtimehttp

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
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	defaultQueryTimeout     = 5 * time.Second
	maximumQueryTimeout     = 30 * time.Second
	defaultMaxResponseBytes = 1 << 20
	minimumMaxResponseBytes = 512
	maximumMaxResponseBytes = 4 << 20
	maximumRawQueryBytes    = 8192
	maximumCursorBytes      = 4096
)

var (
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	cursorPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

type Authenticator func(*http.Request) (identity.Principal, error)

type Config struct {
	QueryTimeout     time.Duration
	MaxResponseBytes int
}

type Handler struct {
	reader           analyticsrealtime.Reader
	authenticate     Authenticator
	queryTimeout     time.Duration
	maxResponseBytes int
}

type responseEnvelope struct {
	Version string                                               `json:"version"`
	Meta    responseMeta                                         `json:"meta"`
	Basic   analyticsrealtime.Section[analyticsrealtime.Basic]   `json:"basic"`
	Quality analyticsrealtime.Section[analyticsrealtime.Quality] `json:"quality"`
	Origin  analyticsrealtime.Section[analyticsrealtime.Origin]  `json:"origin"`
	Rank    analyticsrealtime.Section[analyticsrealtime.Rank]    `json:"rank"`
}

type responseMeta struct {
	Range             string    `json:"range"`
	Timezone          string    `json:"timezone"`
	From              time.Time `json:"from"`
	To                time.Time `json:"to"`
	Bucket            string    `json:"bucket"`
	Downsample        bool      `json:"downsample"`
	SnapshotAt        time.Time `json:"snapshot_at"`
	SourceWatermark   uint64    `json:"source_watermark"`
	FinalizedThrough  time.Time `json:"finalized_through"`
	SnapshotExpiresAt time.Time `json:"snapshot_expires_at"`
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewHandler(reader analyticsrealtime.Reader, authenticate Authenticator, config Config) (*Handler, error) {
	if reader == nil || authenticate == nil {
		return nil, analyticsrealtime.ErrInvalidConfig
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > maximumQueryTimeout ||
		config.MaxResponseBytes < minimumMaxResponseBytes || config.MaxResponseBytes > maximumMaxResponseBytes {
		return nil, analyticsrealtime.ErrInvalidConfig
	}
	return &Handler{
		reader: reader, authenticate: authenticate, queryTimeout: config.QueryTimeout,
		maxResponseBytes: config.MaxResponseBytes,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := responseRequestID(request)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Request-ID", requestID)

	audience, ok := routeAudience(request)
	if !ok {
		handler.writeError(writer, http.StatusNotFound, "analytics_monitoring_route_not_found", "route not found", requestID)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		handler.writeError(writer, http.StatusMethodNotAllowed, "analytics_monitoring_method_not_allowed", "method not allowed", requestID)
		return
	}
	if request.URL == nil || len(request.URL.RawQuery) > maximumRawQueryBytes || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		handler.writeError(writer, http.StatusBadRequest, "analytics_monitoring_invalid_request", "invalid request", requestID)
		return
	}
	if hasSelfAssertedIdentity(request.Header) {
		handler.writeError(writer, http.StatusBadRequest, "analytics_monitoring_invalid_request", "invalid request", requestID)
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
	query, err := parseQuery(request.URL.RawQuery, audience, actor.TenantID)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	result, err := handler.reader.Read(ctx, actor, query)
	if err != nil {
		handler.writeServiceError(writer, err, requestID)
		return
	}
	handler.writeResponse(writer, result, requestID)
}

func routeAudience(request *http.Request) (analyticsrealtime.Audience, bool) {
	if request == nil || request.URL == nil {
		return "", false
	}
	switch request.URL.Path {
	case "/v1/analytics/site-monitoring":
		return analyticsrealtime.AudienceTenant, true
	case "/v1/admin/analytics/site-monitoring":
		return analyticsrealtime.AudiencePlatform, true
	default:
		return "", false
	}
}

func actorFor(principal identity.Principal, audience analyticsrealtime.Audience) (analyticsrealtime.Actor, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return analyticsrealtime.Actor{}, analyticsrealtime.ErrPermissionDenied
	}
	switch audience {
	case analyticsrealtime.AudienceTenant:
		if principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil ||
			!containsPermission(principal.Permissions, analyticsrealtime.ReadPermission) {
			return analyticsrealtime.Actor{}, analyticsrealtime.ErrScopeForbidden
		}
		return analyticsrealtime.Actor{
			ScopeKind: "tenant", TenantID: principal.TenantID.String(), Permissions: append([]string(nil), principal.Permissions...),
		}, nil
	case analyticsrealtime.AudiencePlatform:
		if principal.ScopeKind != "platform" || principal.TenantID != nil {
			return analyticsrealtime.Actor{}, analyticsrealtime.ErrScopeForbidden
		}
		if !containsPermission(principal.Permissions, "platform.admin") {
			return analyticsrealtime.Actor{}, analyticsrealtime.ErrPermissionDenied
		}
		return analyticsrealtime.Actor{
			ScopeKind: "platform", Permissions: append([]string(nil), principal.Permissions...),
		}, nil
	default:
		return analyticsrealtime.Actor{}, analyticsrealtime.ErrScopeForbidden
	}
}

func parseQuery(raw string, audience analyticsrealtime.Audience, sessionTenantID string) (analyticsrealtime.Query, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return analyticsrealtime.Query{}, analyticsrealtime.ErrInvalidRequest
	}
	allowed := map[string]bool{
		"tenant_id": true, "range": true, "from": true, "to": true, "timezone": true,
		"site_id": true, "node_id": true, "domain": true, "listen_port": true,
		"rank_by": true, "limit": true, "cursor": true,
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" {
			return analyticsrealtime.Query{}, analyticsrealtime.ErrInvalidRequest
		}
	}
	if audience == analyticsrealtime.AudienceTenant {
		if _, exists := values["tenant_id"]; exists {
			return analyticsrealtime.Query{}, analyticsrealtime.ErrScopeForbidden
		}
	} else if audience != analyticsrealtime.AudiencePlatform {
		return analyticsrealtime.Query{}, analyticsrealtime.ErrScopeForbidden
	}

	tenantID := sessionTenantID
	if audience == analyticsrealtime.AudiencePlatform {
		tenantID = values.Get("tenant_id")
	}
	if !canonicalUUID(tenantID) || !validTimezone(values.Get("timezone")) {
		return analyticsrealtime.Query{}, analyticsrealtime.ErrInvalidRequest
	}

	query := analyticsrealtime.Query{
		Audience: audience, TenantID: tenantID, Range: values.Get("range"), Timezone: values.Get("timezone"),
		SiteID: values.Get("site_id"), NodeID: values.Get("node_id"), Domain: values.Get("domain"), Cursor: values.Get("cursor"),
	}
	if !canonicalOptionalUUID(query.SiteID) || !canonicalOptionalUUID(query.NodeID) ||
		!validOptionalDomain(query.Domain) || !validCursor(query.Cursor) {
		return analyticsrealtime.Query{}, analyticsrealtime.ErrInvalidRequest
	}
	if err := parseRange(values, &query); err != nil {
		return analyticsrealtime.Query{}, err
	}
	if err := parseOptions(values, &query); err != nil {
		return analyticsrealtime.Query{}, err
	}
	return query, nil
}

func parseRange(values url.Values, query *analyticsrealtime.Query) error {
	switch query.Range {
	case "1h", "6h", "12h":
		if _, exists := values["from"]; exists {
			return analyticsrealtime.ErrInvalidRequest
		}
		if _, exists := values["to"]; exists {
			return analyticsrealtime.ErrInvalidRequest
		}
		return nil
	case "custom":
		from, fromErr := canonicalUTC(values.Get("from"))
		to, toErr := canonicalUTC(values.Get("to"))
		if fromErr != nil || toErr != nil || !from.Before(to) {
			return analyticsrealtime.ErrInvalidRequest
		}
		query.From, query.To = from, to
		return nil
	default:
		return analyticsrealtime.ErrInvalidRequest
	}
}

func parseOptions(values url.Values, query *analyticsrealtime.Query) error {
	query.RankBy = analyticsrealtime.RankByHost
	if raw := values.Get("rank_by"); raw != "" {
		query.RankBy = analyticsrealtime.RankDimension(raw)
	}
	switch query.RankBy {
	case analyticsrealtime.RankByHost, analyticsrealtime.RankBySite,
		analyticsrealtime.RankByNode, analyticsrealtime.RankByStatusCode:
	default:
		return analyticsrealtime.ErrInvalidRequest
	}
	query.Limit = 10
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || parsed < 1 || parsed > 100 || strconv.FormatUint(parsed, 10) != raw {
			return analyticsrealtime.ErrInvalidRequest
		}
		query.Limit = uint16(parsed)
	}
	if raw := values.Get("listen_port"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || parsed < 1 || strconv.FormatUint(parsed, 10) != raw {
			return analyticsrealtime.ErrInvalidRequest
		}
		query.ListenPort = uint16(parsed)
	}
	return nil
}

func canonicalUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, analyticsrealtime.ErrInvalidRequest
	}
	return parsed, nil
}

func validTimezone(value string) bool {
	if value == "" || value == "Local" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	location, err := time.LoadLocation(value)
	return err == nil && location != time.Local
}

func canonicalOptionalUUID(value string) bool {
	return value == "" || canonicalUUID(value)
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validOptionalDomain(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 253 || strings.ToLower(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}

func validCursor(value string) bool {
	return value == "" || len(value) <= maximumCursorBytes && cursorPattern.MatchString(value)
}

func containsPermission(permissions []string, want string) bool {
	for _, permission := range permissions {
		if permission == want {
			return true
		}
	}
	return false
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

func (handler *Handler) writeAuthenticationError(writer http.ResponseWriter, request *http.Request, err error, requestID string) {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(request.Context().Err(), context.Canceled):
		handler.writeError(writer, http.StatusRequestTimeout, "analytics_monitoring_request_cancelled", "request cancelled", requestID)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(request.Context().Err(), context.DeadlineExceeded):
		handler.writeError(writer, http.StatusGatewayTimeout, "analytics_monitoring_timeout", "request timed out", requestID)
	case errors.Is(err, identity.ErrInvalidSession):
		handler.writeError(writer, http.StatusUnauthorized, "analytics_monitoring_unauthenticated", "authentication required", requestID)
	default:
		handler.writeError(writer, http.StatusServiceUnavailable, "analytics_monitoring_unavailable", "service unavailable", requestID)
	}
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, context.Canceled):
		handler.writeError(writer, http.StatusRequestTimeout, "analytics_monitoring_request_cancelled", "request cancelled", requestID)
	case errors.Is(err, context.DeadlineExceeded):
		handler.writeError(writer, http.StatusGatewayTimeout, "analytics_monitoring_timeout", "query timed out", requestID)
	case errors.Is(err, analyticsrealtime.ErrInvalidRequest), errors.Is(err, analyticsrealtime.ErrInvalidCursor):
		handler.writeError(writer, http.StatusBadRequest, "analytics_monitoring_invalid_request", "invalid request", requestID)
	case errors.Is(err, analyticsrealtime.ErrScopeForbidden):
		handler.writeError(writer, http.StatusForbidden, "analytics_monitoring_scope_forbidden", "scope forbidden", requestID)
	case errors.Is(err, analyticsrealtime.ErrPermissionDenied):
		handler.writeError(writer, http.StatusForbidden, "analytics_monitoring_permission_denied", "permission denied", requestID)
	case errors.Is(err, analyticsrealtime.ErrInvalidSnapshot), errors.Is(err, analyticsrealtime.ErrInvalidResponse):
		handler.writeError(writer, http.StatusBadGateway, "analytics_monitoring_invalid_response", "invalid monitoring evidence", requestID)
	default:
		handler.writeError(writer, http.StatusServiceUnavailable, "analytics_monitoring_unavailable", "service unavailable", requestID)
	}
}

func (handler *Handler) writeResponse(writer http.ResponseWriter, result analyticsrealtime.Response, requestID string) {
	response := responseEnvelope{
		Version: result.Version,
		Meta: responseMeta{
			Range: result.Meta.Range, Timezone: result.Meta.Timezone, From: result.Meta.From, To: result.Meta.To,
			Bucket: result.Meta.Bucket.String(), Downsample: result.Meta.Downsample,
			SnapshotAt: result.Meta.Snapshot.At, SourceWatermark: result.Meta.Snapshot.SourceWatermark,
			FinalizedThrough: result.Meta.Snapshot.FinalizedThrough, SnapshotExpiresAt: result.Meta.Snapshot.ExpiresAt,
		},
		Basic: result.Basic, Quality: result.Quality, Origin: result.Origin, Rank: result.Rank,
	}
	body, err := json.Marshal(response)
	if err != nil {
		handler.writeError(writer, http.StatusBadGateway, "analytics_monitoring_invalid_response", "invalid monitoring evidence", requestID)
		return
	}
	if len(body) > handler.maxResponseBytes {
		handler.writeError(writer, http.StatusBadGateway, "analytics_monitoring_response_too_large", "monitoring response exceeded its limit", requestID)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(append(body, '\n'))
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, code, message, requestID string) {
	response := errorEnvelope{}
	response.Error.Code, response.Error.Message, response.Error.RequestID = code, message, requestID
	body, _ := json.Marshal(response)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(body, '\n'))
}

func responseRequestID(request *http.Request) string {
	if request != nil && requestIDPattern.MatchString(request.Header.Get("X-Request-ID")) {
		return request.Header.Get("X-Request-ID")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "analytics-monitoring-request"
	}
	return hex.EncodeToString(raw)
}

var _ http.Handler = (*Handler)(nil)
