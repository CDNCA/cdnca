package analyticsconnectionshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type DLQHandler struct {
	service          *DLQService
	authenticate     AuthenticateFunc
	queryTimeout     time.Duration
	maxResponseBytes int
	mux              *http.ServeMux
}

type dlqErrorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewDLQHandler(store DeadLetterStore, authenticate AuthenticateFunc, config DLQHandlerConfig) (*DLQHandler, error) {
	if nilDependency(store) || authenticate == nil {
		return nil, ErrDeadLetterInvalidRequest
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = defaultDeadLetterQueryTimeout
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultDeadLetterResponseBytes
	}
	if config.QueryTimeout <= 0 || config.QueryTimeout > maximumDeadLetterQueryTimeout ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > maximumDeadLetterResponseBytes {
		return nil, ErrDeadLetterInvalidRequest
	}
	service, err := NewDLQService(store)
	if err != nil {
		return nil, err
	}
	handler := &DLQHandler{
		service: service, authenticate: authenticate, queryTimeout: config.QueryTimeout,
		maxResponseBytes: config.MaxResponseBytes, mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("/v1/analytics/connections/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		handler.list(w, r, false)
	})
	handler.mux.HandleFunc("/v1/analytics/connections/dead-letters/{dead_letter_id}", func(w http.ResponseWriter, r *http.Request) {
		handler.detail(w, r, false)
	})
	handler.mux.HandleFunc("/v1/admin/analytics/connections/dead-letters", func(w http.ResponseWriter, r *http.Request) {
		handler.list(w, r, true)
	})
	handler.mux.HandleFunc("/v1/admin/analytics/connections/dead-letters/{dead_letter_id}", func(w http.ResponseWriter, r *http.Request) {
		handler.detail(w, r, true)
	})
	handler.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler.writeAPIError(w, r, http.StatusNotFound, "connections_dead_letter_not_found", "dead-letter route was not found")
	})
	return handler, nil
}

func (handler *DLQHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
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

func (handler *DLQHandler) list(response http.ResponseWriter, request *http.Request, platform bool) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "connections_dead_letter_method_not_allowed", "dead-letter route uses a different method")
		return
	}
	session, ok := handler.authenticateRequest(response, request)
	if !ok {
		return
	}
	tenantID, err := authorizeDeadLetter(session.Principal, platform)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	input, err := parseDeadLetterListRequest(request, platform, tenantID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	page, err := handler.service.List(ctx, input)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if !handler.writeJSON(response, http.StatusOK, page) {
		handler.writeError(response, request, ErrDeadLetterTooLarge)
	}
}

func (handler *DLQHandler) detail(response http.ResponseWriter, request *http.Request, platform bool) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "connections_dead_letter_method_not_allowed", "dead-letter route uses a different method")
		return
	}
	session, ok := handler.authenticateRequest(response, request)
	if !ok {
		return
	}
	tenantID, err := authorizeDeadLetter(session.Principal, platform)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody {
		handler.writeError(response, request, ErrDeadLetterInvalidRequest)
		return
	}
	deadLetterID := request.PathValue("dead_letter_id")
	ctx, cancel := context.WithTimeout(request.Context(), handler.queryTimeout)
	defer cancel()
	item, err := handler.service.Get(ctx, tenantID, deadLetterID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	if !handler.writeJSON(response, http.StatusOK, struct {
		Item DeadLetterItem `json:"item"`
	}{Item: item}) {
		handler.writeError(response, request, ErrDeadLetterTooLarge)
	}
}

func (handler *DLQHandler) authenticateRequest(response http.ResponseWriter, request *http.Request) (identity.AuthenticatedSession, bool) {
	if _, err := strictDeadLetterBearer(request); err != nil || hasUntrustedDeadLetterHeaders(request) {
		handler.writeError(response, request, ErrDeadLetterUnauthenticated)
		return identity.AuthenticatedSession{}, false
	}
	session, err := handler.authenticate(request)
	if err != nil || !validDeadLetterSession(session) {
		handler.writeError(response, request, ErrDeadLetterUnauthenticated)
		return identity.AuthenticatedSession{}, false
	}
	return session, true
}

func authorizeDeadLetter(principal identity.Principal, platform bool) (string, error) {
	if !hasPermission(principal, "sites.read") {
		return "", ErrDeadLetterPermission
	}
	if platform {
		if principal.ScopeKind != "platform" || principal.TenantID != nil || !hasPermission(principal, "platform.admin") {
			return "", ErrDeadLetterPermission
		}
		return "", nil
	}
	if principal.ScopeKind != "tenant" || principal.TenantID == nil || *principal.TenantID == uuid.Nil {
		return "", ErrDeadLetterPermission
	}
	return principal.TenantID.String(), nil
}

func parseDeadLetterListRequest(request *http.Request, platform bool, tenantID string) (DeadLetterListRequest, error) {
	if len(request.URL.RawQuery) > maximumDeadLetterQueryBytes || request.Body != nil && request.Body != http.NoBody {
		return DeadLetterListRequest{}, ErrDeadLetterInvalidRequest
	}
	allowed := map[string]bool{"limit": true, "after_sequence": true}
	if platform {
		allowed["tenant_id"] = true
	}
	query, err := strictDeadLetterQuery(request.URL.RawQuery, allowed)
	if err != nil {
		return DeadLetterListRequest{}, err
	}
	if platform {
		tenantID = query.Get("tenant_id")
	}
	if !platform && !canonicalDeadLetterUUID(tenantID) || platform && tenantID != "" && !canonicalDeadLetterUUID(tenantID) {
		return DeadLetterListRequest{}, ErrDeadLetterInvalidRequest
	}
	limit := defaultDeadLetterLimit
	if raw := query.Get("limit"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed < 1 || parsed > maximumDeadLetterLimit || strconv.Itoa(parsed) != raw {
			return DeadLetterListRequest{}, ErrDeadLetterInvalidRequest
		}
		limit = parsed
	}
	var after uint64
	if raw := query.Get("after_sequence"); raw != "" {
		parsed, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != raw {
			return DeadLetterListRequest{}, ErrDeadLetterInvalidRequest
		}
		after = parsed
	}
	return DeadLetterListRequest{TenantID: tenantID, AfterSequence: after, Limit: limit}, nil
}

func strictDeadLetterQuery(raw string, allowed map[string]bool) (url.Values, error) {
	if raw == "" {
		return url.Values{}, nil
	}
	for _, pair := range strings.Split(raw, "&") {
		rawKey, rawValue, found := strings.Cut(pair, "=")
		key, keyErr := url.QueryUnescape(rawKey)
		_, valueErr := url.QueryUnescape(rawValue)
		if !found || rawKey == "" || rawValue == "" || keyErr != nil || valueErr != nil || key != rawKey {
			return nil, ErrDeadLetterInvalidRequest
		}
	}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return nil, ErrDeadLetterInvalidRequest
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return nil, ErrDeadLetterInvalidRequest
		}
	}
	return query, nil
}

func strictDeadLetterBearer(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", ErrDeadLetterUnauthenticated
	}
	raw := strings.TrimPrefix(values[0], "Bearer ")
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n,") || values[0] != "Bearer "+raw {
		return "", ErrDeadLetterUnauthenticated
	}
	return raw, nil
}

func hasUntrustedDeadLetterHeaders(request *http.Request) bool {
	for _, name := range []string{"CdncaKey", "X-Actor-ID", "X-User-ID", "X-Scope-ID", "X-Scope-Kind", "X-Tenant-ID", "X-Principal-ID", "X-Session-ID", "X-Role", "X-Permissions"} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func validDeadLetterSession(session identity.AuthenticatedSession) bool {
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return false
	}
	switch principal.ScopeKind {
	case "tenant":
		return principal.TenantID != nil && *principal.TenantID != uuid.Nil
	case "platform":
		return principal.TenantID == nil
	default:
		return false
	}
}

func (handler *DLQHandler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrDeadLetterInvalidRequest):
		handler.writeAPIError(response, request, http.StatusBadRequest, "connections_dead_letter_invalid_request", "dead-letter request is invalid")
	case errors.Is(err, ErrDeadLetterUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "connections_dead_letter_authentication_required", "authentication is required")
	case errors.Is(err, ErrDeadLetterPermission):
		handler.writeAPIError(response, request, http.StatusForbidden, "connections_dead_letter_permission_denied", "permission is denied")
	case errors.Is(err, ErrDeadLetterNotFound):
		handler.writeAPIError(response, request, http.StatusNotFound, "connections_dead_letter_not_found", "dead-letter record was not found")
	case errors.Is(err, ErrDeadLetterInvalidResponse):
		handler.writeAPIError(response, request, http.StatusBadGateway, "connections_dead_letter_invalid_response", "dead-letter response is invalid")
	case errors.Is(err, ErrDeadLetterTooLarge):
		handler.writeAPIError(response, request, http.StatusBadGateway, "connections_dead_letter_response_too_large", "dead-letter response exceeds its limit")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusRequestTimeout, "connections_dead_letter_request_timeout", "dead-letter request timed out")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "connections_dead_letter_unavailable", "dead-letter service is unavailable")
	}
}

func (handler *DLQHandler) writeAPIError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	var body dlqErrorEnvelope
	body.Error.Code, body.Error.Message = code, message
	body.Error.RequestID = request.Header.Get("X-Request-ID")
	handler.writeJSON(response, status, body)
}

func (handler *DLQHandler) writeJSON(response http.ResponseWriter, status int, body any) bool {
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
