package urlauthpolicyhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
)

const (
	defaultOperationTimeout = 8 * time.Second
	defaultMaxRequestBytes  = int64(32 << 10)
	defaultMaxResponseBytes = 1 << 20
	defaultMaxHeaderBytes   = 16 << 10
	maximumRequestBytes     = int64(128 << 10)
	maximumResponseBytes    = 8 << 20
	maximumHeaderBytes      = 64 << 10
)

var (
	ErrInvalidHandlerConfig = errors.New("invalid URL auth policy HTTP handler configuration")
	ErrUnauthenticated      = errors.New("URL auth policy authentication required")
	ErrInvalidRequest       = errors.New("invalid URL auth policy HTTP request")
)

type PolicyService interface {
	Create(context.Context, urlauthpolicy.Actor, urlauthpolicy.CreateRequest) (urlauthpolicy.SecretWriteResult, error)
	Update(context.Context, urlauthpolicy.Actor, urlauthpolicy.UpdateRequest) (urlauthpolicy.WriteResult, error)
	Rotate(context.Context, urlauthpolicy.Actor, urlauthpolicy.RotateRequest) (urlauthpolicy.SecretWriteResult, error)
	Revoke(context.Context, urlauthpolicy.Actor, urlauthpolicy.RevokeRequest) (urlauthpolicy.WriteResult, error)
	SetEnabled(context.Context, urlauthpolicy.Actor, urlauthpolicy.StateRequest) (urlauthpolicy.WriteResult, error)
	Get(context.Context, urlauthpolicy.Actor, uuid.UUID) (urlauthpolicy.Policy, error)
	List(context.Context, urlauthpolicy.Actor, urlauthpolicy.ListFilter) (urlauthpolicy.ListResult, error)
	Snapshot(context.Context, urlauthpolicy.Actor, uuid.UUID) (urlauthpolicy.SnapshotResult, error)
}

type Authenticator interface {
	Authenticate(*http.Request) (authenticatedPrincipal, error)
}

type authenticatedPrincipal struct {
	Principal identity.Principal
	Actor     urlauthpolicy.Actor
}

type AuthenticateFunc func(*http.Request) (authenticatedPrincipal, error)

func (function AuthenticateFunc) Authenticate(request *http.Request) (authenticatedPrincipal, error) {
	return function(request)
}

type HandlerConfig struct {
	OperationTimeout time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
	MaxHeaderBytes   int
}

type Handler struct {
	service          PolicyService
	authenticator    Authenticator
	mux              *http.ServeMux
	operationTimeout time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
	maxHeaderBytes   int
}

type createBody struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	urlauthpolicy.PolicyFields
}

type revokeBody struct {
	KeyID string `json:"key_id"`
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewHandler(service PolicyService, authenticator Authenticator, config HandlerConfig) (*Handler, error) {
	if service == nil || authenticator == nil {
		return nil, ErrInvalidHandlerConfig
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = defaultOperationTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxHeaderBytes == 0 {
		config.MaxHeaderBytes = defaultMaxHeaderBytes
	}
	if config.OperationTimeout <= 0 || config.OperationTimeout > 30*time.Second ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > maximumRequestBytes ||
		config.MaxResponseBytes < 128 || config.MaxResponseBytes > maximumResponseBytes ||
		config.MaxHeaderBytes < 1024 || config.MaxHeaderBytes > maximumHeaderBytes {
		return nil, ErrInvalidHandlerConfig
	}
	handler := &Handler{
		service: service, authenticator: authenticator, operationTimeout: config.OperationTimeout,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes,
		maxHeaderBytes: config.MaxHeaderBytes, mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("/v1/url-auth-policies", handler.collection)
	handler.mux.HandleFunc("/v1/url-auth-policies/{id}", handler.item)
	handler.mux.HandleFunc("/v1/url-auth-policies/{id}/enable", handler.enable)
	handler.mux.HandleFunc("/v1/url-auth-policies/{id}/disable", handler.disable)
	handler.mux.HandleFunc("/v1/url-auth-policies/{id}/rotate", handler.rotate)
	handler.mux.HandleFunc("/v1/url-auth-policies/{id}/revoke", handler.revoke)
	handler.mux.HandleFunc("/v1/url-auth-policies/{id}/edge-snapshot", handler.snapshot)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	invalidSingletons := invalidSingletonHeaders(request.Header)
	requestID := newRequestID()
	if values := request.Header.Values("X-Request-ID"); len(values) == 1 && validMetadata(values[0]) {
		requestID = values[0]
	}
	request.Header.Set("X-Request-ID", requestID)
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if headerBytes(request.Header) > handler.maxHeaderBytes {
		handler.writeAPIError(response, request, http.StatusRequestHeaderFieldsTooLarge, "request_headers_too_large", "request headers are too large")
		return
	}
	if invalidSingletons {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.operationTimeout)
	defer cancel()
	handler.mux.ServeHTTP(response, request.WithContext(ctx))
}

func (handler *Handler) collection(response http.ResponseWriter, request *http.Request) {
	permission := "url_auth_policies.read"
	if request.Method == http.MethodPost {
		permission = "url_auth_policies.manage"
	}
	principal, ok := handler.authorize(response, request, permission)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		filter, err := parseListFilter(request)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.List(request.Context(), actor(principal), filter)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, request, http.StatusOK, result)
	case http.MethodPost:
		metadata, ok := handler.writeMetadata(response, request, false)
		if !ok {
			return
		}
		var body createBody
		if err := handler.decodeBody(response, request, &body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		targetScopeID, err := optionalUUID(body.TargetScopeID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		ownerID, err := optionalUUID(body.OwnerID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.Create(request.Context(), actor(principal), urlauthpolicy.CreateRequest{
			TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.PolicyFields,
			IdempotencyKey: metadata.idempotencyKey, RequestID: metadata.requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
		response.Header().Set("Location", "/v1/url-auth-policies/"+result.Policy.ID.String())
		setReplayHeader(response, result.Replayed)
		handler.writeJSON(response, request, http.StatusCreated, result)
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) item(response http.ResponseWriter, request *http.Request) {
	permission := "url_auth_policies.read"
	if request.Method == http.MethodPatch {
		permission = "url_auth_policies.manage"
	}
	principal, resourceID, ok := handler.authorizeResource(response, request, permission)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		item, err := handler.service.Get(request.Context(), actor(principal), resourceID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(item.Revision))
		handler.writeJSON(response, request, http.StatusOK, item)
	case http.MethodPatch:
		metadata, ok := handler.writeMetadata(response, request, true)
		if !ok {
			return
		}
		var fields urlauthpolicy.PolicyFields
		if err := handler.decodeBody(response, request, &fields); err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.Update(request.Context(), actor(principal), urlauthpolicy.UpdateRequest{
			ID: resourceID, ExpectedRevision: metadata.revision, Fields: fields,
			IdempotencyKey: metadata.idempotencyKey, RequestID: metadata.requestID,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
		setReplayHeader(response, result.Replayed)
		handler.writeJSON(response, request, http.StatusOK, result)
	default:
		handler.methodNotAllowed(response, request, "GET, PATCH")
	}
}

func (handler *Handler) rotate(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	principal, resourceID, ok := handler.authorizeResource(response, request, "url_auth_policies.manage")
	if !ok {
		return
	}
	metadata, ok := handler.writeMetadata(response, request, true)
	if !ok || !handler.emptyJSONBody(response, request) {
		if ok {
			handler.writeError(response, request, ErrInvalidRequest)
		}
		return
	}
	result, err := handler.service.Rotate(request.Context(), actor(principal), urlauthpolicy.RotateRequest{
		ID: resourceID, ExpectedRevision: metadata.revision,
		IdempotencyKey: metadata.idempotencyKey, RequestID: metadata.requestID,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
	setReplayHeader(response, result.Replayed)
	handler.writeJSON(response, request, http.StatusOK, result)
}

func (handler *Handler) enable(response http.ResponseWriter, request *http.Request) {
	handler.setEnabled(response, request, true)
}

func (handler *Handler) disable(response http.ResponseWriter, request *http.Request) {
	handler.setEnabled(response, request, false)
}

func (handler *Handler) setEnabled(response http.ResponseWriter, request *http.Request, enabled bool) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	principal, resourceID, ok := handler.authorizeResource(response, request, urlauthpolicy.PermissionManage)
	if !ok {
		return
	}
	metadata, ok := handler.writeMetadata(response, request, true)
	if !ok || !handler.emptyJSONBody(response, request) {
		if ok {
			handler.writeError(response, request, ErrInvalidRequest)
		}
		return
	}
	result, err := handler.service.SetEnabled(request.Context(), actor(principal), urlauthpolicy.StateRequest{
		ID: resourceID, ExpectedRevision: metadata.revision, Enabled: enabled,
		IdempotencyKey: metadata.idempotencyKey, RequestID: metadata.requestID,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
	setReplayHeader(response, result.Replayed)
	handler.writeJSON(response, request, http.StatusOK, result)
}

func (handler *Handler) revoke(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	principal, resourceID, ok := handler.authorizeResource(response, request, "url_auth_policies.manage")
	if !ok {
		return
	}
	metadata, ok := handler.writeMetadata(response, request, true)
	if !ok {
		return
	}
	var body revokeBody
	if err := handler.decodeBody(response, request, &body); err != nil {
		handler.writeError(response, request, err)
		return
	}
	result, err := handler.service.Revoke(request.Context(), actor(principal), urlauthpolicy.RevokeRequest{
		ID: resourceID, KeyID: body.KeyID, ExpectedRevision: metadata.revision,
		IdempotencyKey: metadata.idempotencyKey, RequestID: metadata.requestID,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
	setReplayHeader(response, result.Replayed)
	handler.writeJSON(response, request, http.StatusOK, result)
}

func (handler *Handler) snapshot(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		handler.methodNotAllowed(response, request, "GET")
		return
	}
	principal, resourceID, ok := handler.authorizeResource(response, request, "url_auth_policies.read")
	if !ok {
		return
	}
	if request.URL.RawQuery != "" {
		handler.writeError(response, request, ErrInvalidRequest)
		return
	}
	result, err := handler.service.Snapshot(request.Context(), actor(principal), resourceID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", `"sha256:`+result.SHA256+`"`)
	handler.writeJSON(response, request, http.StatusOK, result)
}

func (handler *Handler) authorize(response http.ResponseWriter, request *http.Request, permission string) (authenticatedPrincipal, bool) {
	principal, err := handler.authenticator.Authenticate(request)
	if err == nil {
		err = identity.Authorize(principal.Principal, permission)
	}
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) || errors.Is(err, identity.ErrInvalidSession) {
			handler.writeError(response, request, ErrUnauthenticated)
		} else if errors.Is(err, identity.ErrPermissionDenied) || errors.Is(err, urlauthpolicy.ErrPermissionDenied) {
			handler.writeError(response, request, urlauthpolicy.ErrPermissionDenied)
		} else {
			handler.writeError(response, request, err)
		}
		return authenticatedPrincipal{}, false
	}
	return principal, true
}

func (handler *Handler) authorizeResource(response http.ResponseWriter, request *http.Request, permission string) (authenticatedPrincipal, uuid.UUID, bool) {
	principal, ok := handler.authorize(response, request, permission)
	if !ok {
		return authenticatedPrincipal{}, uuid.Nil, false
	}
	resourceID, err := strictUUID(request.PathValue("id"))
	if err != nil {
		handler.writeError(response, request, err)
		return authenticatedPrincipal{}, uuid.Nil, false
	}
	return principal, resourceID, true
}

type writeMetadata struct {
	requestID      string
	idempotencyKey string
	revision       int64
}

func (handler *Handler) writeMetadata(response http.ResponseWriter, request *http.Request, revisionRequired bool) (writeMetadata, bool) {
	metadata := writeMetadata{
		requestID:      strings.TrimSpace(request.Header.Get("X-Request-ID")),
		idempotencyKey: strings.TrimSpace(request.Header.Get("Idempotency-Key")),
	}
	if !validMetadata(metadata.requestID) || !validMetadata(metadata.idempotencyKey) {
		handler.writeError(response, request, ErrInvalidRequest)
		return writeMetadata{}, false
	}
	if revisionRequired {
		var err error
		metadata.revision, err = expectedRevision(request.Header.Get("If-Match"))
		if err != nil {
			handler.writeError(response, request, err)
			return writeMetadata{}, false
		}
	}
	return metadata, true
}

func (handler *Handler) decodeBody(response http.ResponseWriter, request *http.Request, destination any) error {
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return ErrInvalidRequest
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || int64(len(raw)) > handler.maxRequestBytes || rejectDuplicateKeys(raw) != nil {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func (handler *Handler) emptyJSONBody(response http.ResponseWriter, request *http.Request) bool {
	var body struct{}
	return handler.decodeBody(response, request, &body) == nil
}

func parseListFilter(request *http.Request) (urlauthpolicy.ListFilter, error) {
	for key, values := range request.URL.Query() {
		switch key {
		case "page", "limit", "name", "status", "site_id":
		default:
			return urlauthpolicy.ListFilter{}, ErrInvalidRequest
		}
		if len(values) != 1 || values[0] == "" {
			return urlauthpolicy.ListFilter{}, ErrInvalidRequest
		}
	}
	page, err := queryInt(request, "page", 1)
	if err != nil {
		return urlauthpolicy.ListFilter{}, err
	}
	limit, err := queryInt(request, "limit", 20)
	if err != nil || limit > 100 {
		return urlauthpolicy.ListFilter{}, ErrInvalidRequest
	}
	var siteID uuid.UUID
	if raw := request.URL.Query().Get("site_id"); raw != "" {
		siteID, err = strictUUID(raw)
		if err != nil {
			return urlauthpolicy.ListFilter{}, err
		}
	}
	status := request.URL.Query().Get("status")
	if status != "" && status != "enabled" && status != "disabled" {
		return urlauthpolicy.ListFilter{}, ErrInvalidRequest
	}
	return urlauthpolicy.ListFilter{
		Page: page, Limit: limit, Name: request.URL.Query().Get("name"), Status: status, SiteID: siteID,
	}, nil
}

func queryInt(request *http.Request, name string, fallback int) (int, error) {
	raw := request.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 1_000_000 {
		return 0, ErrInvalidRequest
	}
	return value, nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
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
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return ErrInvalidRequest
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required")
	case errors.Is(err, ErrInvalidRequest):
		handler.writeAPIError(response, request, http.StatusBadRequest, "invalid_request", "request is invalid")
	case errors.Is(err, urlauthpolicy.ErrInvalidInput):
		handler.writeAPIError(response, request, http.StatusUnprocessableEntity, "validation_error", "request fields are invalid")
	case errors.Is(err, urlauthpolicy.ErrPermissionDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "permission_denied", "permission is denied")
	case errors.Is(err, urlauthpolicy.ErrNotFound):
		handler.writeAPIError(response, request, http.StatusNotFound, "url_auth_policy_not_found", "URL auth policy was not found")
	case errors.Is(err, urlauthpolicy.ErrRevisionConflict):
		handler.writeAPIError(response, request, http.StatusPreconditionFailed, "version_conflict", "resource revision has changed")
	case errors.Is(err, urlauthpolicy.ErrIdempotencyConflict):
		handler.writeAPIError(response, request, http.StatusConflict, "idempotency_conflict", "idempotency key conflicts with the original request")
	case errors.Is(err, urlauthpolicy.ErrConflict):
		handler.writeAPIError(response, request, http.StatusConflict, "url_auth_policy_conflict", "URL auth policy conflicts with current state")
	case errors.Is(err, urlauthpolicy.ErrKeyNotRevocable):
		handler.writeAPIError(response, request, http.StatusConflict, "url_auth_key_not_revocable", "only the current previous key can be revoked")
	case errors.Is(err, urlauthpolicy.ErrEncryptionUnavailable):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "credential_encryption_unavailable", "credential encryption is unavailable")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "request_canceled", "request was canceled")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "service_unavailable", "a required dependency is unavailable")
	}
}

func (handler *Handler) methodNotAllowed(response http.ResponseWriter, request *http.Request, allow string) {
	response.Header().Set("Allow", allow)
	handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "request method is not allowed")
}

func (handler *Handler) writeAPIError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	var envelope errorEnvelope
	envelope.Error.Code, envelope.Error.Message = code, message
	envelope.Error.RequestID = request.Header.Get("X-Request-ID")
	handler.writeJSON(response, request, status, envelope)
}

func (handler *Handler) writeJSON(response http.ResponseWriter, request *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > handler.maxResponseBytes {
		if status == http.StatusServiceUnavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "response_too_large", "response exceeds the configured limit")
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func actor(principal authenticatedPrincipal) urlauthpolicy.Actor {
	if principal.Actor.UserID != uuid.Nil {
		return principal.Actor
	}
	return urlauthpolicy.Actor{UserID: principal.Principal.UserID, ScopeID: principal.Principal.ScopeID, ScopeKind: principal.Principal.ScopeKind}
}

func optionalUUID(raw string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.Nil, nil
	}
	return strictUUID(raw)
}

func strictUUID(raw string) (uuid.UUID, error) {
	if raw != strings.ToLower(raw) || len(raw) != 36 {
		return uuid.Nil, ErrInvalidRequest
	}
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func expectedRevision(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrInvalidRequest
	}
	value, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || value < 1 {
		return 0, ErrInvalidRequest
	}
	return value, nil
}

func quoteRevision(revision int64) string { return `"` + strconv.FormatInt(revision, 10) + `"` }

func setReplayHeader(response http.ResponseWriter, replayed bool) {
	if replayed {
		response.Header().Set("X-Idempotent-Replay", "true")
	}
}

func validMetadata(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._-", character) {
			continue
		}
		return false
	}
	return true
}

func invalidSingletonHeaders(header http.Header) bool {
	for _, name := range []string{"Authorization", "X-Request-ID", "Idempotency-Key", "If-Match", "Content-Type"} {
		if len(header.Values(name)) > 1 {
			return true
		}
	}
	return false
}

func headerBytes(header http.Header) int {
	total := 0
	for name, values := range header {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
	}
	return total
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "request-unavailable"
	}
	return hex.EncodeToString(raw)
}
