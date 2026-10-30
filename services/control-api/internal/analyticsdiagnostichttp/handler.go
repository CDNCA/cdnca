package analyticsdiagnostichttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostic"
)

const (
	defaultQueryTimeout = 3 * time.Second
	maximumQueryTimeout = 10 * time.Second
	maximumRawQuery     = 4096
)

type Authenticator func(*http.Request) (analyticsdiagnostic.Actor, error)

type Config struct {
	QueryTimeout time.Duration
}

type Handler struct {
	service      *analyticsdiagnostic.Service
	authenticate Authenticator
	queryTimeout time.Duration
}

type responseEnvelope struct {
	Data struct {
		Items      []analyticsdiagnostic.Item `json:"items"`
		NextCursor *string                    `json:"next_cursor"`
		SnapshotAt *time.Time                 `json:"snapshot_at"`
	} `json:"data"`
	Meta responseMeta `json:"meta"`
}

type responseMeta struct {
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Timezone string    `json:"timezone"`
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func NewHandler(service *analyticsdiagnostic.Service, authenticate Authenticator, config Config) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, analyticsdiagnostic.ErrInvalidConfiguration
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.QueryTimeout < time.Millisecond || config.QueryTimeout > maximumQueryTimeout {
		return nil, analyticsdiagnostic.ErrInvalidConfiguration
	}
	return &Handler{service: service, authenticate: authenticate, queryTimeout: config.QueryTimeout}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	audience, route := resolveRoute(request)
	if !route {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeError(writer, http.StatusMethodNotAllowed, "analytics_diagnostic_method_not_allowed", "method not allowed")
		return
	}
	if request.URL == nil || len(request.URL.RawQuery) > maximumRawQuery || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writeError(writer, http.StatusBadRequest, "analytics_diagnostic_invalid_request", "invalid request")
		return
	}
	actor, err := handler.authenticate(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, "analytics_diagnostic_unauthenticated", "authentication required")
		return
	}
	query, err := parseQuery(request, audience)
	if err != nil {
		status := http.StatusBadRequest
		code := "analytics_diagnostic_invalid_request"
		if errors.Is(err, analyticsdiagnostic.ErrScopeForbidden) {
			status, code = http.StatusForbidden, "analytics_diagnostic_scope_forbidden"
		}
		writeError(writer, status, code, "request rejected")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	page, err := handler.service.List(ctx, actor, query)
	if err != nil {
		writeServiceError(writer, err)
		return
	}
	response := responseEnvelope{Meta: responseMeta{From: query.From.UTC(), To: query.To.UTC(), Timezone: "UTC"}}
	response.Data.Items = page.Items
	response.Data.SnapshotAt = page.SnapshotAt
	if page.NextCursor != "" {
		cursor := page.NextCursor
		response.Data.NextCursor = &cursor
	}
	writeJSON(writer, http.StatusOK, response)
}

func resolveRoute(request *http.Request) (analyticsdiagnostic.Audience, bool) {
	if request == nil || request.URL == nil {
		return 0, false
	}
	switch request.URL.Path {
	case "/v1/admin/analytics/site-quality-diagnostics":
		return analyticsdiagnostic.AudiencePlatform, true
	case "/v1/analytics/site-quality-diagnostics":
		return analyticsdiagnostic.AudienceTenant, true
	default:
		return 0, false
	}
}

func parseQuery(request *http.Request, audience analyticsdiagnostic.Audience) (analyticsdiagnostic.QueryRequest, error) {
	values := request.URL.Query()
	allowed := map[string]bool{"from": true, "to": true, "tenant_id": true, "site_id": true, "node_id": true, "limit": true, "cursor": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return analyticsdiagnostic.QueryRequest{}, analyticsdiagnostic.ErrInvalidInput
		}
	}
	if audience == analyticsdiagnostic.AudienceTenant {
		if _, present := values["tenant_id"]; present {
			return analyticsdiagnostic.QueryRequest{}, analyticsdiagnostic.ErrScopeForbidden
		}
	}
	from, fromErr := time.Parse(time.RFC3339Nano, values.Get("from"))
	to, toErr := time.Parse(time.RFC3339Nano, values.Get("to"))
	if fromErr != nil || toErr != nil {
		return analyticsdiagnostic.QueryRequest{}, analyticsdiagnostic.ErrInvalidInput
	}
	limit := analyticsdiagnostic.DefaultLimit
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err != nil {
			return analyticsdiagnostic.QueryRequest{}, analyticsdiagnostic.ErrInvalidInput
		}
		limit = uint16(parsed)
	}
	return analyticsdiagnostic.QueryRequest{
		Audience: audience, TenantID: values.Get("tenant_id"), From: from.UTC(), To: to.UTC(),
		SiteID: values.Get("site_id"), NodeID: values.Get("node_id"), Limit: limit, Cursor: values.Get("cursor"),
	}, nil
}

func writeServiceError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.Canceled):
		writeError(writer, http.StatusRequestTimeout, "analytics_diagnostic_request_cancelled", "request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(writer, http.StatusGatewayTimeout, "analytics_diagnostic_timeout", "query timed out")
	case errors.Is(err, analyticsdiagnostic.ErrInvalidInput):
		writeError(writer, http.StatusBadRequest, "analytics_diagnostic_invalid_request", "invalid request")
	case errors.Is(err, analyticsdiagnostic.ErrPermissionDenied):
		writeError(writer, http.StatusForbidden, "analytics_diagnostic_permission_denied", "permission denied")
	case errors.Is(err, analyticsdiagnostic.ErrScopeForbidden):
		writeError(writer, http.StatusForbidden, "analytics_diagnostic_scope_forbidden", "scope forbidden")
	case errors.Is(err, analyticsdiagnostic.ErrInvalidResponse):
		writeError(writer, http.StatusBadGateway, "analytics_diagnostic_invalid_response", "diagnostic evidence invalid")
	default:
		writeError(writer, http.StatusServiceUnavailable, "analytics_diagnostic_evidence_unavailable", "diagnostic evidence unavailable")
	}
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	response := errorEnvelope{}
	response.Error.Code, response.Error.Message = code, message
	writeJSON(writer, status, response)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
