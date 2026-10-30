package httppolicycontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type Authenticator interface {
	Authenticate(*http.Request) (Actor, error)
}

type AuthenticatorFunc func(*http.Request) (Actor, error)

func (function AuthenticatorFunc) Authenticate(request *http.Request) (Actor, error) {
	return function(request)
}

type Handler struct {
	service       *Service
	authenticator Authenticator
	mux           *http.ServeMux
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
	} `json:"error"`
}

type createBody struct {
	SiteID  string `json:"site_id"`
	Enabled bool   `json:"enabled"`
	Config  Config `json:"config"`
}

type updateBody struct {
	Config Config `json:"config"`
}

func NewHandler(service *Service, authenticator Authenticator) (*Handler, error) {
	if service == nil || service.store == nil || !service.store.ready() || isNilDependency(authenticator) {
		return nil, ErrInvalidHandlerConfig
	}
	handler := &Handler{service: service, authenticator: authenticator, mux: http.NewServeMux()}
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/http-policies", handler.collection)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/http-policies/publication-preview", handler.publicationPreview)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}", handler.item)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/enable", handler.enable)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/disable", handler.disable)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if handler == nil || handler.mux == nil || handler.service == nil || handler.service.store == nil ||
		isNilDependency(handler.authenticator) {
		handler.writeError(response, request, ErrUnavailable)
		return
	}
	metadata, err := requestMetadata(request, false)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("X-Request-ID", metadata.RequestID)
	response.Header().Set("X-Trace-ID", metadata.TraceID)
	response.Header().Set("Cache-Control", "no-store")
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) collection(response http.ResponseWriter, request *http.Request) {
	actor, targetScopeID, ok := handler.authorizeRoute(response, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPost:
		metadata, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		var body createBody
		if err := decodeBody(response, request, &body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		siteID, err := strictUUID(body.SiteID)
		if err != nil {
			handler.writeError(response, request, ErrValidation)
			return
		}
		result, err := handler.service.Create(request.Context(), actor, CreateRequest{
			TargetScopeID: targetScopeID, SiteID: siteID, Enabled: body.Enabled,
			Config: body.Config, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
		response.Header().Set("Location", fmt.Sprintf(
			"/v1/tenant-scopes/%s/http-policies/%s", targetScopeID, result.Policy.ID))
		if result.Replayed {
			response.Header().Set("X-Idempotent-Replay", "true")
		}
		handler.writeJSON(response, request, http.StatusCreated, result.Policy)
	case http.MethodGet:
		filter, err := parseListFilter(request, targetScopeID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.List(request.Context(), actor, filter)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, request, http.StatusOK, result)
	default:
		handler.writeMethodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) item(response http.ResponseWriter, request *http.Request) {
	actor, targetScopeID, policyID, ok := handler.authorizeResource(response, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		item, err := handler.service.Get(request.Context(), actor, targetScopeID, policyID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(item.Revision))
		handler.writeJSON(response, request, http.StatusOK, item)
	case http.MethodPatch:
		metadata, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		revision, err := expectedRevision(request)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		var body updateBody
		if err := decodeBody(response, request, &body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.Update(request.Context(), actor, UpdateRequest{
			TargetScopeID: targetScopeID, ID: policyID, ExpectedRevision: revision,
			Config: body.Config, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeResult(response, request, result)
	case http.MethodDelete:
		metadata, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		revision, err := expectedRevision(request)
		if err != nil || !emptyBody(request) {
			if err == nil {
				err = ErrInvalidInput
			}
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.Delete(request.Context(), actor, DeleteRequest{
			TargetScopeID: targetScopeID, ID: policyID, ExpectedRevision: revision,
			WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeResult(response, request, result)
	default:
		handler.writeMethodNotAllowed(response, request, "DELETE, GET, PATCH")
	}
}

func (handler *Handler) enable(response http.ResponseWriter, request *http.Request) {
	handler.state(response, request, true)
}

func (handler *Handler) disable(response http.ResponseWriter, request *http.Request) {
	handler.state(response, request, false)
}

func (handler *Handler) state(response http.ResponseWriter, request *http.Request, enabled bool) {
	if request.Method != http.MethodPost {
		handler.writeMethodNotAllowed(response, request, "POST")
		return
	}
	actor, targetScopeID, policyID, ok := handler.authorizeResource(response, request)
	if !ok {
		return
	}
	metadata, ok := handler.writeMetadata(response, request)
	if !ok {
		return
	}
	revision, err := expectedRevision(request)
	if err != nil || !emptyJSONObject(response, request) {
		if err == nil {
			err = ErrInvalidInput
		}
		handler.writeError(response, request, err)
		return
	}
	result, err := handler.service.SetEnabled(request.Context(), actor, StateRequest{
		TargetScopeID: targetScopeID, ID: policyID, ExpectedRevision: revision,
		Enabled: enabled, WriteMetadata: metadata,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeResult(response, request, result)
}

func (handler *Handler) publicationPreview(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		handler.writeMethodNotAllowed(response, request, "GET")
		return
	}
	if request.URL.RawQuery != "" {
		handler.writeError(response, request, ErrInvalidInput)
		return
	}
	actor, targetScopeID, ok := handler.authorizeRoute(response, request)
	if !ok {
		return
	}
	preview, err := handler.service.PublicationPreview(request.Context(), actor, targetScopeID)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", `"sha256:`+preview.SHA256+`"`)
	handler.writeJSON(response, request, http.StatusOK, preview)
}

func (handler *Handler) authorizeRoute(response http.ResponseWriter, request *http.Request) (Actor, uuid.UUID, bool) {
	actor, err := handler.authenticator.Authenticate(request)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			handler.writeError(response, request, ErrUnauthenticated)
		} else {
			handler.writeError(response, request, ErrUnavailable)
		}
		return Actor{}, uuid.Nil, false
	}
	targetScopeID, err := strictUUID(request.PathValue("tenant_scope_id"))
	if err != nil {
		handler.writeError(response, request, ErrInvalidInput)
		return Actor{}, uuid.Nil, false
	}
	return actor, targetScopeID, true
}

func (handler *Handler) authorizeResource(response http.ResponseWriter, request *http.Request) (Actor, uuid.UUID, uuid.UUID, bool) {
	actor, targetScopeID, ok := handler.authorizeRoute(response, request)
	if !ok {
		return Actor{}, uuid.Nil, uuid.Nil, false
	}
	policyID, err := strictUUID(request.PathValue("policy_id"))
	if err != nil {
		handler.writeError(response, request, ErrInvalidInput)
		return Actor{}, uuid.Nil, uuid.Nil, false
	}
	return actor, targetScopeID, policyID, true
}

func (handler *Handler) writeMetadata(response http.ResponseWriter, request *http.Request) (WriteMetadata, bool) {
	metadata, err := requestMetadata(request, true)
	if err != nil {
		handler.writeError(response, request, err)
		return WriteMetadata{}, false
	}
	return metadata, true
}

func requestMetadata(request *http.Request, write bool) (WriteMetadata, error) {
	for _, name := range []string{"X-Request-ID", "X-Trace-ID", "Idempotency-Key", "If-Match", "Content-Type"} {
		if len(request.Header.Values(name)) > 1 {
			return WriteMetadata{}, ErrInvalidInput
		}
	}
	metadata := WriteMetadata{
		RequestID: strings.TrimSpace(request.Header.Get("X-Request-ID")),
		TraceID:   strings.TrimSpace(request.Header.Get("X-Trace-ID")),
	}
	if write {
		metadata.IdempotencyKey = strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	} else {
		metadata.IdempotencyKey = "request"
	}
	if !validWriteMetadata(metadata) {
		return WriteMetadata{}, ErrInvalidInput
	}
	if !write {
		metadata.IdempotencyKey = ""
	}
	return metadata, nil
}

func parseListFilter(request *http.Request, targetScopeID uuid.UUID) (ListFilter, error) {
	for key, values := range request.URL.Query() {
		switch key {
		case "limit", "cursor", "site_id", "enabled":
		default:
			return ListFilter{}, ErrInvalidInput
		}
		if len(values) != 1 {
			return ListFilter{}, ErrInvalidInput
		}
	}
	filter := ListFilter{TargetScopeID: targetScopeID, Limit: 50, Cursor: request.URL.Query().Get("cursor")}
	if raw := request.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return ListFilter{}, ErrInvalidInput
		}
		filter.Limit = value
	}
	if raw := request.URL.Query().Get("site_id"); raw != "" {
		value, err := strictUUID(raw)
		if err != nil {
			return ListFilter{}, ErrInvalidInput
		}
		filter.SiteID = value
	}
	if raw := request.URL.Query().Get("enabled"); raw != "" {
		if raw != "true" && raw != "false" {
			return ListFilter{}, ErrInvalidInput
		}
		value := raw == "true"
		filter.Enabled = &value
	}
	return filter, nil
}

func decodeBody(response http.ResponseWriter, request *http.Request, destination any) error {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return ErrInvalidInput
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return ErrInvalidInput
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes || rejectDuplicateKeys(raw) != nil {
		return ErrInvalidInput
	}
	switch destination.(type) {
	case *createBody:
		if requirePolicyBody(raw, true) != nil {
			return ErrInvalidInput
		}
	case *updateBody:
		if requirePolicyBody(raw, false) != nil {
			return ErrInvalidInput
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	return nil
}

func requirePolicyBody(raw []byte, create bool) error {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil || body == nil {
		return ErrInvalidInput
	}
	required := []string{"config"}
	if create {
		required = append(required, "site_id", "enabled")
	}
	if requireFields(body, required...) != nil {
		return ErrInvalidInput
	}
	var config map[string]json.RawMessage
	if err := json.Unmarshal(body["config"], &config); err != nil || config == nil || requireFields(config,
		"max_upload_bytes", "request_headers", "response_headers", "rewrites",
		"redirect_allowed_hosts", "redirects", "cors", "referer_check",
	) != nil {
		return ErrInvalidInput
	}
	for _, field := range []string{"request_headers", "response_headers"} {
		if requireObjectArray(config[field], "kind", "name", "values") != nil {
			return ErrInvalidInput
		}
	}
	if requireObjectArray(config["rewrites"],
		"rule_id", "priority", "match_kind", "match_path", "target_path", "preserve_query", "preserve_cookie",
	) != nil || requireObjectArray(config["redirects"],
		"rule_id", "priority", "match_kind", "match_path", "status", "target_url", "preserve_query", "preserve_path",
	) != nil {
		return ErrInvalidInput
	}
	if !bytes.Equal(bytes.TrimSpace(config["referer_check"]), []byte("null")) {
		var check map[string]json.RawMessage
		if err := json.Unmarshal(config["referer_check"], &check); err != nil || check == nil ||
			requireFields(check, "allow_empty", "allow_same_domain", "allowed_domains", "denied_domains", "check_origin", "extensions") != nil {
			return ErrInvalidInput
		}
	}
	if bytes.Equal(bytes.TrimSpace(config["cors"]), []byte("null")) {
		return nil
	}
	var cors map[string]json.RawMessage
	if err := json.Unmarshal(config["cors"], &cors); err != nil || cors == nil {
		return ErrInvalidInput
	}
	return requireFields(cors, "allowed_origins", "allowed_methods", "allowed_headers", "exposed_headers", "allow_credentials", "max_age_seconds")
}

func requireObjectArray(raw json.RawMessage, fields ...string) error {
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objects); err != nil || objects == nil {
		return ErrInvalidInput
	}
	for _, object := range objects {
		if requireFields(object, fields...) != nil {
			return ErrInvalidInput
		}
	}
	return nil
}

func requireFields(object map[string]json.RawMessage, fields ...string) error {
	if object == nil {
		return ErrInvalidInput
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return ErrInvalidInput
		}
	}
	return nil
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
					return ErrInvalidInput
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidInput
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
			return ErrInvalidInput
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidInput
	}
	return nil
}

func emptyJSONObject(response http.ResponseWriter, request *http.Request) bool {
	var body struct{}
	return decodeBody(response, request, &body) == nil
}

func emptyBody(request *http.Request) bool {
	if request.Body == nil {
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, 1))
	return err == nil && len(raw) == 0
}

func expectedRevision(request *http.Request) (int64, error) {
	values := request.Header.Values("If-Match")
	if len(values) == 0 {
		return 0, ErrPreconditionRequired
	}
	if len(values) != 1 {
		return 0, ErrInvalidInput
	}
	raw := strings.TrimSpace(values[0])
	if raw == "" {
		return 0, ErrPreconditionRequired
	}
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrInvalidInput
	}
	value, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || value < 1 {
		return 0, ErrInvalidInput
	}
	return value, nil
}

func quoteRevision(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}

func (handler *Handler) writeResult(response http.ResponseWriter, request *http.Request, result WriteResult) {
	response.Header().Set("ETag", quoteRevision(result.Policy.Revision))
	if result.Replayed {
		response.Header().Set("X-Idempotent-Replay", "true")
	}
	handler.writeJSON(response, request, http.StatusOK, result.Policy)
}

func (handler *Handler) writeMethodNotAllowed(response http.ResponseWriter, request *http.Request, allow string) {
	response.Header().Set("Allow", allow)
	handler.writeAPIError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "request method is not allowed")
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required")
	case errors.Is(err, ErrInvalidInput):
		handler.writeAPIError(response, request, http.StatusBadRequest, "invalid_request", "request is invalid")
	case errors.Is(err, ErrValidation):
		handler.writeAPIError(response, request, http.StatusUnprocessableEntity, "validation_error", "request fields are invalid")
	case errors.Is(err, ErrPermissionDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "permission_denied", "permission is denied")
	case errors.Is(err, ErrEntitlementDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "entitlement_denied", "the current entitlement does not allow this operation")
	case errors.Is(err, ErrNotFound):
		handler.writeAPIError(response, request, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, ErrSiteLocked):
		handler.writeAPIError(response, request, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, ErrConflict):
		handler.writeAPIError(response, request, http.StatusConflict, "resource_conflict", "resource conflicts with current state")
	case errors.Is(err, ErrIdempotencyConflict):
		handler.writeAPIError(response, request, http.StatusConflict, "idempotency_conflict", "idempotency key was used with another request")
	case errors.Is(err, ErrPreconditionRequired):
		handler.writeAPIError(response, request, http.StatusPreconditionFailed, "precondition_required", "If-Match is required")
	case errors.Is(err, ErrRevisionConflict):
		handler.writeAPIError(response, request, http.StatusPreconditionFailed, "revision_conflict", "resource revision has changed")
	case errors.Is(err, ErrEntitlementUnavailable):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "entitlement_unavailable", "entitlement state is unavailable")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "request_canceled", "request was canceled")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "service_unavailable", "a required dependency is unavailable")
	}
}

func (handler *Handler) writeAPIError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	var envelope errorEnvelope
	envelope.Error.Code = code
	envelope.Error.Message = message
	envelope.Error.RequestID = safeCorrelationID(request.Header.Get("X-Request-ID"))
	envelope.Error.TraceID = safeCorrelationID(request.Header.Get("X-Trace-ID"))
	handler.writeJSON(response, request, status, envelope)
}

func safeCorrelationID(raw string) string {
	value := strings.TrimSpace(raw)
	if !metadataPattern.MatchString(value) {
		return "invalid"
	}
	return value
}

func (handler *Handler) writeJSON(response http.ResponseWriter, request *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > maxResponseBytes {
		if status == http.StatusServiceUnavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "service_unavailable", "a required dependency is unavailable")
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(append(encoded, '\n'))
}
