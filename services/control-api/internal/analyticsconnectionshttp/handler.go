package analyticsconnectionshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type audience uint8

const (
	audienceTenant audience = iota + 1
	audienceAdmin
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Handler struct {
	service          *Service
	authenticate     AuthenticateFunc
	queryTimeout     time.Duration
	maxResponseBytes int
	mux              *http.ServeMux
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewHandler(store RetentionStore, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if nilDependency(store) || authenticate == nil {
		return nil, ErrInvalidRequest
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultRetentionQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultRetentionResponseBytes
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maximumRetentionQueryTimeout ||
		config.MaxResponseBytes < 256 || config.MaxResponseBytes > maximumRetentionResponseBytes {
		return nil, ErrInvalidRequest
	}
	service, err := NewService(store)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		service: service, authenticate: authenticate, queryTimeout: config.QueryTimeout,
		maxResponseBytes: config.MaxResponseBytes, mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("/v1/analytics/connections/retention", func(w http.ResponseWriter, r *http.Request) {
		handler.retention(w, r, audienceTenant)
	})
	handler.mux.HandleFunc("/v1/admin/analytics/connections/retention", func(w http.ResponseWriter, r *http.Request) {
		handler.retention(w, r, audienceAdmin)
	})
	handler.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler.writeAPIError(w, r, http.StatusNotFound, "retention_not_found", "retention route was not found")
	})
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if !requestIDPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	request.Header.Set("X-Request-ID", requestID)
	response.Header().Set("X-Request-ID", requestID)
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) retention(response http.ResponseWriter, request *http.Request, target audience) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "retention_method_not_allowed", "request method is not allowed")
		return
	}
	session, err := handler.authenticate(request)
	if err != nil || !validSession(session) {
		handler.writeError(response, request, ErrUnauthenticated)
		return
	}
	tenantID, err := authorize(session.Principal, target)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	input, err := parseRetentionRequest(request, target, tenantID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	page, err := handler.service.Query(ctx, input)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if !handler.writeJSON(response, http.StatusOK, page) {
		handler.writeError(response, request, ErrResponseTooLarge)
	}
}

func authorize(principal identity.Principal, target audience) (string, error) {
	if !hasPermission(principal, "sites.read") {
		return "", ErrPermissionDenied
	}
	switch target {
	case audienceTenant:
		if principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil {
			return "", ErrPermissionDenied
		}
		return principal.TenantID.String(), nil
	case audienceAdmin:
		if principal.ScopeKind != "platform" || principal.TenantID != nil || !hasPermission(principal, "platform.admin") {
			return "", ErrPermissionDenied
		}
		return "", nil
	default:
		return "", ErrPermissionDenied
	}
}

func parseRetentionRequest(request *http.Request, target audience, tenantID string) (RetentionRequest, error) {
	if len(request.URL.RawQuery) == 0 || len(request.URL.RawQuery) > maximumRetentionQueryBytes ||
		request.Body != nil && request.Body != http.NoBody {
		return RetentionRequest{}, ErrInvalidRequest
	}
	allowed := map[string]bool{"subscription_id": true, "from": true, "to": true, "limit": true}
	if target == audienceAdmin {
		allowed["tenant_id"] = true
	}
	query, err := strictQuery(request.URL.RawQuery, allowed)
	if err != nil {
		return RetentionRequest{}, err
	}
	if target == audienceAdmin {
		tenantID = query.Get("tenant_id")
	}
	if !canonicalUUIDText(tenantID) || !canonicalUUIDText(query.Get("subscription_id")) {
		return RetentionRequest{}, ErrInvalidRequest
	}
	from, err := parseUTC(query.Get("from"))
	if err != nil {
		return RetentionRequest{}, err
	}
	to, err := parseUTC(query.Get("to"))
	if err != nil || !from.Before(to) || to.Sub(from) > maximumRetentionWindow {
		return RetentionRequest{}, ErrInvalidRequest
	}
	limit := defaultRetentionLimit
	if raw := query.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > maximumRetentionLimit || strconv.Itoa(value) != raw {
			return RetentionRequest{}, ErrInvalidRequest
		}
		limit = value
	}
	return RetentionRequest{
		TenantID: tenantID, SubscriptionID: query.Get("subscription_id"), From: from, To: to, Limit: limit,
	}, nil
}

func strictQuery(raw string, allowed map[string]bool) (url.Values, error) {
	for _, pair := range strings.Split(raw, "&") {
		rawKey, rawValue, found := strings.Cut(pair, "=")
		key, keyErr := url.QueryUnescape(rawKey)
		_, valueErr := url.QueryUnescape(rawValue)
		if !found || rawKey == "" || rawValue == "" || keyErr != nil || valueErr != nil || key != rawKey {
			return nil, ErrInvalidRequest
		}
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return nil, ErrInvalidRequest
		}
	}
	for _, required := range []string{"subscription_id", "from", "to"} {
		if query.Get(required) == "" {
			return nil, ErrInvalidRequest
		}
	}
	return query, nil
}

func parseUTC(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, ErrInvalidRequest
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, ErrInvalidRequest
	}
	return parsed, nil
}

func validSession(session identity.AuthenticatedSession) bool {
	return session.SessionID != uuid.Nil && session.Principal.UserID != uuid.Nil && session.Principal.ScopeID != uuid.Nil
}

func hasPermission(principal identity.Principal, permission string) bool {
	for _, candidate := range principal.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest):
		handler.writeAPIError(response, request, http.StatusBadRequest, "retention_invalid_request", "retention request is invalid")
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "retention_authentication_required", "authentication is required")
	case errors.Is(err, ErrPermissionDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "retention_permission_denied", "permission is denied")
	case errors.Is(err, ErrResponseTooLarge):
		handler.writeAPIError(response, request, http.StatusBadGateway, "retention_response_too_large", "retention response exceeds its limit")
	case errors.Is(err, ErrInvalidResponse):
		handler.writeAPIError(response, request, http.StatusBadGateway, "retention_invalid_response", "retention response is invalid")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusRequestTimeout, "retention_request_timeout", "retention request timed out")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "retention_unavailable", "retention service is unavailable")
	}
}

func (handler *Handler) writeAPIError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	var body errorEnvelope
	body.Error.Code, body.Error.Message = code, message
	body.Error.RequestID = request.Header.Get("X-Request-ID")
	_ = handler.writeJSON(response, status, body)
}

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, body any) bool {
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded)+1 > handler.maxResponseBytes {
		return false
	}
	encoded = append(encoded, '\n')
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
	return true
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
