package cnameallocationhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultQueryTimeout = 6 * time.Second
	maximumQueryTimeout = 30 * time.Second
	defaultPageLimit    = 50
	maximumPageLimit    = 100
	maximumQueryBytes   = 2048
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

type HandlerConfig struct{ QueryTimeout time.Duration }

type Handler struct {
	reader       Reader
	authenticate AuthenticateFunc
	queryTimeout time.Duration
	mux          *http.ServeMux
}

type audience uint8

const (
	audienceTenant audience = iota + 1
	audienceAdmin
)

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewHandler(reader Reader, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if reader == nil || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultQueryTimeout
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maximumQueryTimeout {
		return nil, ErrInvalidRequest
	}
	handler := &Handler{reader: reader, authenticate: authenticate, queryTimeout: config.QueryTimeout, mux: http.NewServeMux()}
	for _, route := range []struct {
		prefix   string
		audience audience
	}{{"/v1", audienceTenant}, {"/v1/admin", audienceAdmin}} {
		prefix, target := route.prefix, route.audience
		handler.mux.HandleFunc(prefix+"/cname-allocations", func(w http.ResponseWriter, r *http.Request) {
			handler.list(w, r, target)
		})
		handler.mux.HandleFunc(prefix+"/cname-allocations/diagnose", func(w http.ResponseWriter, r *http.Request) {
			handler.diagnose(w, r, target)
		})
		handler.mux.HandleFunc(prefix+"/cname-allocations/{allocation_id}", func(w http.ResponseWriter, r *http.Request) {
			handler.get(w, r, target)
		})
	}
	handler.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handler.writeError(w, r, ErrNotFound) })
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	response.Header().Set("X-Request-ID", requestID)
	request = request.Clone(context.WithValue(request.Context(), requestIDKey{}, requestID))
	defer func() {
		if recover() != nil {
			response.Header().Del("Content-Type")
			response.WriteHeader(http.StatusInternalServerError)
		}
	}()
	if len(request.URL.RawQuery) > maximumQueryBytes || request.Body != nil && request.Body != http.NoBody {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) list(response http.ResponseWriter, request *http.Request, target audience) {
	if !requireGet(response, request, handler) {
		return
	}
	scopeID, ok := handler.scope(response, request, target, map[string]bool{"limit": true, "cursor": true})
	if !ok {
		return
	}
	limit := defaultPageLimit
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > maximumPageLimit || strconv.Itoa(value) != raw {
			handler.writeError(response, request, ErrInvalidRequest)
			return
		}
		limit = value
	}
	var afterID *uuid.UUID
	if raw := request.URL.Query().Get("cursor"); raw != "" {
		value, err := canonicalUUID(raw)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		afterID = &value
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	items, err := handler.reader.List(ctx, scopeID, ListQuery{AfterID: afterID, Limit: limit + 1})
	if err != nil {
		handler.writeError(response, request, normalizeError(ctx, err))
		return
	}
	page := AllocationPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID.String()
	}
	handler.writeJSON(response, http.StatusOK, page)
}

func (handler *Handler) get(response http.ResponseWriter, request *http.Request, target audience) {
	if !requireGet(response, request, handler) {
		return
	}
	scopeID, ok := handler.scope(response, request, target, nil)
	if !ok {
		return
	}
	allocationID, err := canonicalUUID(request.PathValue("allocation_id"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	item, err := handler.reader.Get(ctx, scopeID, allocationID)
	if err != nil {
		handler.writeError(response, request, normalizeError(ctx, err))
		return
	}
	handler.writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) diagnose(response http.ResponseWriter, request *http.Request, target audience) {
	if !requireGet(response, request, handler) {
		return
	}
	scopeID, ok := handler.scope(response, request, target, map[string]bool{"site_id": true, "domain": true, "hostname": true})
	if !ok {
		return
	}
	siteID, err := canonicalUUID(request.URL.Query().Get("site_id"))
	if err != nil || !validOptionalName(request.URL.Query().Get("domain")) || !validOptionalName(request.URL.Query().Get("hostname")) {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	result, err := handler.reader.Diagnose(ctx, scopeID, DiagnoseQuery{
		SiteID: siteID, Domain: request.URL.Query().Get("domain"), Hostname: request.URL.Query().Get("hostname"),
	})
	if err != nil {
		handler.writeError(response, request, normalizeError(ctx, err))
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) scope(response http.ResponseWriter, request *http.Request, target audience, allowed map[string]bool) (uuid.UUID, bool) {
	principal, err := handler.authenticate(request)
	if err != nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		handler.writeError(response, request, ErrUnauthenticated)
		return uuid.Nil, false
	}
	queryAllowed := make(map[string]bool, len(allowed)+1)
	for key, value := range allowed {
		queryAllowed[key] = value
	}
	if target == audienceAdmin {
		queryAllowed["scope_id"] = true
	}
	if validateQuery(request.URL.RawQuery, queryAllowed) != nil {
		handler.writeError(response, request, ErrInvalidRequest)
		return uuid.Nil, false
	}
	switch target {
	case audienceTenant:
		if principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil || !hasPermission(principal.Permissions, "dns.read") {
			handler.writeError(response, request, ErrPermissionDenied)
			return uuid.Nil, false
		}
		return principal.ScopeID, true
	case audienceAdmin:
		if principal.ScopeKind != "platform" || principal.TenantID != nil || !hasPermission(principal.Permissions, "platform.admin") {
			handler.writeError(response, request, ErrPermissionDenied)
			return uuid.Nil, false
		}
		scopeID, err := canonicalUUID(request.URL.Query().Get("scope_id"))
		if err != nil {
			handler.writeError(response, request, err)
			return uuid.Nil, false
		}
		return scopeID, true
	default:
		handler.writeError(response, request, ErrInvalidRequest)
		return uuid.Nil, false
	}
}

func requireGet(response http.ResponseWriter, request *http.Request, handler *Handler) bool {
	if request.Method == http.MethodGet {
		return true
	}
	response.Header().Set("Allow", http.MethodGet)
	handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "request method is not allowed")
	return false
}

func validateQuery(raw string, allowed map[string]bool) error {
	if raw == "" {
		return nil
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return ErrInvalidRequest
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return ErrInvalidRequest
		}
	}
	return nil
}

func canonicalUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func hasPermission(values []string, required string) bool {
	for _, value := range values {
		if value == required {
			return true
		}
	}
	return false
}

func normalizeError(ctx context.Context, err error) error {
	if errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrUnauthenticated) {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrUnavailable
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		handler.writeAPIError(response, request, http.StatusBadRequest, "validation_error", "query parameters are invalid")
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "invalid_session", "authentication is required")
	case errors.Is(err, ErrPermissionDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "permission_denied", "permission is required")
	case errors.Is(err, ErrNotFound):
		handler.writeAPIError(response, request, http.StatusNotFound, "cname_allocation_not_found", "CNAME allocation authority was not found")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusRequestTimeout, "request_timeout", "CNAME allocation query timed out")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "cname_allocation_unavailable", "CNAME allocation authority is unavailable")
	}
}

func (handler *Handler) writeAPIError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	var envelope errorEnvelope
	envelope.Error.Code, envelope.Error.Message = code, message
	envelope.Error.RequestID = requestID(request.Context())
	handler.writeJSON(response, status, envelope)
}

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}

type requestIDKey struct{}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}
