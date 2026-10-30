package originauthcontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultOperationTimeout = 8 * time.Second
	maximumOperationTimeout = 30 * time.Second
	defaultMaxRequestBytes  = 32 << 10
	maximumMaxRequestBytes  = 128 << 10
	defaultMaxResponseBytes = maximumJSONBytes
	maximumMaxResponseBytes = maximumJSONBytes
)

var ErrInvalidHandlerConfig = errors.New("invalid origin authentication handler configuration")

type Authenticator interface {
	Authenticate(*http.Request) (Actor, error)
}

type AuthenticatorFunc func(*http.Request) (Actor, error)

func (function AuthenticatorFunc) Authenticate(request *http.Request) (Actor, error) {
	return function(request)
}

type HandlerConfig struct {
	OperationTimeout time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
}

type Handler struct {
	service          *Service
	authenticator    Authenticator
	mux              *http.ServeMux
	operationTimeout time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
	} `json:"error"`
}

type createCredentialBody struct {
	Provider string           `json:"provider"`
	Name     string           `json:"name"`
	Secret   CredentialSecret `json:"secret"`
}

type replaceCredentialBody struct {
	Secret CredentialSecret `json:"secret"`
}

type createRuleBody struct {
	SiteID         string     `json:"site_id"`
	SourcePosition int        `json:"source_position"`
	Config         RuleConfig `json:"config"`
	Enabled        bool       `json:"enabled"`
}

type updateRuleBody struct {
	Config RuleConfig `json:"config"`
}

type rotateRuleBody struct {
	CurrentCredential CredentialReference `json:"current_credential"`
	ActivateCurrentAt time.Time           `json:"activate_current_at"`
}

func NewHandler(service *Service, authenticator Authenticator, config HandlerConfig) (*Handler, error) {
	if service == nil || service.pool == nil || authenticator == nil {
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
	if config.OperationTimeout <= 0 || config.OperationTimeout > maximumOperationTimeout ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > maximumMaxRequestBytes ||
		config.MaxResponseBytes < 1024 || config.MaxResponseBytes > maximumMaxResponseBytes {
		return nil, ErrInvalidHandlerConfig
	}
	handler := &Handler{
		service: service, authenticator: authenticator, operationTimeout: config.OperationTimeout,
		maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes,
		mux: http.NewServeMux(),
	}
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials", handler.credentials)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}", handler.credential)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}/replace", handler.replaceCredential)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}/verify", handler.verifyCredential)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/credentials/{credential_id}/disable", handler.disableCredential)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules", handler.rules)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}", handler.rule)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}/enable", handler.enableRule)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}/disable", handler.disableRule)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/rules/{rule_id}/rotate", handler.rotateRule)
	handler.mux.HandleFunc("/v1/tenant-scopes/{tenant_scope_id}/origin-auth/publications", handler.publications)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	traceID := strings.TrimSpace(request.Header.Get("X-Trace-ID"))
	if requestID == "" {
		requestID = newRequestID()
		request.Header.Set("X-Request-ID", requestID)
	}
	if traceID == "" {
		traceID = requestID
		request.Header.Set("X-Trace-ID", traceID)
	}
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("X-Trace-ID", traceID)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if !metadataPattern.MatchString(requestID) || !metadataPattern.MatchString(traceID) {
		handler.writeError(response, request, ErrInvalidInput)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.operationTimeout)
	defer cancel()
	handler.mux.ServeHTTP(response, request.WithContext(ctx))
}

func (handler *Handler) credentials(response http.ResponseWriter, request *http.Request) {
	actor, target, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPost:
		metadata, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		var body createCredentialBody
		if err := handler.decodeBody(response, request, &body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.CreateCredential(request.Context(), actor, CreateCredentialRequest{
			TargetScopeID: target, Provider: body.Provider, Name: body.Name, Secret: body.Secret,
			WriteMetadata: metadata,
		})
		clearSecret(&body.Secret)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Credential.Revision))
		response.Header().Set("Location", request.URL.Path+"/"+result.Credential.ID.String())
		handler.writeReplay(response, result.Replayed)
		handler.writeJSON(response, request, http.StatusCreated, result.Credential)
	case http.MethodGet:
		filter, err := credentialFilter(request, target)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.ListCredentials(request.Context(), actor, filter)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, request, http.StatusOK, result)
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) credential(response http.ResponseWriter, request *http.Request) {
	actor, target, resourceID, ok := handler.authorizeResource(response, request, "credential_id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		item, err := handler.service.GetCredential(request.Context(), actor, target, resourceID)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(item.Revision))
		handler.writeJSON(response, request, http.StatusOK, item)
	case http.MethodDelete:
		metadata, revision, ok := handler.emptyMutation(response, request)
		if !ok {
			return
		}
		result, err := handler.service.DeleteCredential(request.Context(), actor, CredentialMutationRequest{
			TargetScopeID: target, CredentialID: resourceID, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeCredentialResult(response, request, result)
	default:
		handler.methodNotAllowed(response, request, "DELETE, GET")
	}
}

func (handler *Handler) replaceCredential(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	actor, target, resourceID, ok := handler.authorizeResource(response, request, "credential_id")
	if !ok {
		return
	}
	metadata, ok := handler.writeMetadata(response, request)
	if !ok {
		return
	}
	revision, err := expectedRevision(request, false)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	var body replaceCredentialBody
	if err := handler.decodeBody(response, request, &body); err != nil {
		handler.writeError(response, request, err)
		return
	}
	result, err := handler.service.ReplaceCredential(request.Context(), actor, ReplaceCredentialRequest{
		TargetScopeID: target, CredentialID: resourceID, ExpectedRevision: revision,
		Secret: body.Secret, WriteMetadata: metadata,
	})
	clearSecret(&body.Secret)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeCredentialResult(response, request, result)
}

func (handler *Handler) verifyCredential(response http.ResponseWriter, request *http.Request) {
	handler.credentialState(response, request, "verify")
}

func (handler *Handler) disableCredential(response http.ResponseWriter, request *http.Request) {
	handler.credentialState(response, request, "disable")
}

func (handler *Handler) credentialState(response http.ResponseWriter, request *http.Request, operation string) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	actor, target, resourceID, ok := handler.authorizeResource(response, request, "credential_id")
	if !ok {
		return
	}
	metadata, revision, ok := handler.emptyMutation(response, request)
	if !ok {
		return
	}
	input := CredentialMutationRequest{
		TargetScopeID: target, CredentialID: resourceID, ExpectedRevision: revision, WriteMetadata: metadata,
	}
	var result CredentialWriteResult
	var err error
	if operation == "verify" {
		result, err = handler.service.VerifyCredential(request.Context(), actor, input)
	} else {
		result, err = handler.service.DisableCredential(request.Context(), actor, input)
	}
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeCredentialResult(response, request, result)
}

func (handler *Handler) rules(response http.ResponseWriter, request *http.Request) {
	actor, target, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPost:
		metadata, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		var body createRuleBody
		if err := handler.decodeBody(response, request, &body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		siteID, err := strictUUID(body.SiteID)
		if err != nil {
			handler.writeError(response, request, ErrValidation)
			return
		}
		result, err := handler.service.CreateRule(request.Context(), actor, CreateRuleRequest{
			TargetScopeID: target, SiteID: siteID, SourcePosition: body.SourcePosition,
			Config: body.Config, Enabled: body.Enabled, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Rule.Revision))
		response.Header().Set("Location", request.URL.Path+"/"+result.Rule.ID.String())
		handler.writeReplay(response, result.Replayed)
		handler.writeJSON(response, request, http.StatusCreated, result.Rule)
	case http.MethodGet:
		filter, err := ruleFilter(request, target)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.ListRules(request.Context(), actor, filter)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeJSON(response, request, http.StatusOK, result)
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) rule(response http.ResponseWriter, request *http.Request) {
	actor, target, ruleID, ok := handler.authorizeResource(response, request, "rule_id")
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		item, err := handler.service.GetRule(request.Context(), actor, target, ruleID)
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
		revision, err := expectedRevision(request, false)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		var body updateRuleBody
		if err := handler.decodeBody(response, request, &body); err != nil {
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.UpdateRule(request.Context(), actor, UpdateRuleRequest{
			TargetScopeID: target, RuleID: ruleID, ExpectedRevision: revision,
			Config: body.Config, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeRuleResult(response, request, result)
	case http.MethodDelete:
		metadata, revision, ok := handler.emptyMutation(response, request)
		if !ok {
			return
		}
		result, err := handler.service.DeleteRule(request.Context(), actor, RuleMutationRequest{
			TargetScopeID: target, RuleID: ruleID, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		handler.writeRuleResult(response, request, result)
	default:
		handler.methodNotAllowed(response, request, "DELETE, GET, PATCH")
	}
}

func (handler *Handler) enableRule(response http.ResponseWriter, request *http.Request) {
	handler.ruleState(response, request, true)
}

func (handler *Handler) disableRule(response http.ResponseWriter, request *http.Request) {
	handler.ruleState(response, request, false)
}

func (handler *Handler) ruleState(response http.ResponseWriter, request *http.Request, enabled bool) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	actor, target, ruleID, ok := handler.authorizeResource(response, request, "rule_id")
	if !ok {
		return
	}
	metadata, revision, ok := handler.emptyMutation(response, request)
	if !ok {
		return
	}
	input := RuleMutationRequest{
		TargetScopeID: target, RuleID: ruleID, ExpectedRevision: revision, WriteMetadata: metadata,
	}
	var result RuleWriteResult
	var err error
	if enabled {
		result, err = handler.service.EnableRule(request.Context(), actor, input)
	} else {
		result, err = handler.service.DisableRule(request.Context(), actor, input)
	}
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeRuleResult(response, request, result)
}

func (handler *Handler) rotateRule(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		handler.methodNotAllowed(response, request, "POST")
		return
	}
	actor, target, ruleID, ok := handler.authorizeResource(response, request, "rule_id")
	if !ok {
		return
	}
	metadata, ok := handler.writeMetadata(response, request)
	if !ok {
		return
	}
	revision, err := expectedRevision(request, false)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	var body rotateRuleBody
	if err := handler.decodeBody(response, request, &body); err != nil {
		handler.writeError(response, request, err)
		return
	}
	result, err := handler.service.RotateRule(request.Context(), actor, RotateRuleRequest{
		TargetScopeID: target, RuleID: ruleID, ExpectedRevision: revision,
		CurrentCredential: body.CurrentCredential, ActivateCurrentAt: body.ActivateCurrentAt,
		WriteMetadata: metadata,
	})
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	handler.writeRuleResult(response, request, result)
}

func (handler *Handler) publications(response http.ResponseWriter, request *http.Request) {
	actor, target, ok := handler.authorize(response, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodPost:
		metadata, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		revision, err := expectedRevision(request, true)
		if err != nil || !handler.emptyJSONBody(response, request) {
			if err == nil {
				err = ErrInvalidInput
			}
			handler.writeError(response, request, err)
			return
		}
		result, err := handler.service.CreatePublication(request.Context(), actor, CreatePublicationRequest{
			TargetScopeID: target, ExpectedRevision: revision, WriteMetadata: metadata,
		})
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Publication.Revision))
		handler.writeReplay(response, result.Replayed)
		handler.writeJSON(response, request, http.StatusCreated, result.Publication)
	case http.MethodGet:
		if len(request.URL.Query()) != 0 {
			handler.writeError(response, request, ErrInvalidInput)
			return
		}
		result, err := handler.service.GetLatestPublication(request.Context(), actor, target)
		if err != nil {
			handler.writeError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteRevision(result.Revision))
		handler.writeJSON(response, request, http.StatusOK, result)
	default:
		handler.methodNotAllowed(response, request, "GET, POST")
	}
}

func (handler *Handler) authorize(response http.ResponseWriter, request *http.Request) (Actor, uuid.UUID, bool) {
	actor, err := handler.authenticator.Authenticate(request)
	if err != nil {
		handler.writeError(response, request, err)
		return Actor{}, uuid.Nil, false
	}
	target, err := strictUUID(request.PathValue("tenant_scope_id"))
	if err != nil {
		handler.writeError(response, request, ErrInvalidInput)
		return Actor{}, uuid.Nil, false
	}
	return actor, target, true
}

func (handler *Handler) authorizeResource(
	response http.ResponseWriter,
	request *http.Request,
	parameter string,
) (Actor, uuid.UUID, uuid.UUID, bool) {
	actor, target, ok := handler.authorize(response, request)
	if !ok {
		return Actor{}, uuid.Nil, uuid.Nil, false
	}
	resourceID, err := strictUUID(request.PathValue(parameter))
	if err != nil {
		handler.writeError(response, request, ErrInvalidInput)
		return Actor{}, uuid.Nil, uuid.Nil, false
	}
	return actor, target, resourceID, true
}

func (handler *Handler) writeMetadata(response http.ResponseWriter, request *http.Request) (WriteMetadata, bool) {
	metadata := WriteMetadata{
		IdempotencyKey: strings.TrimSpace(request.Header.Get("Idempotency-Key")),
		RequestID:      strings.TrimSpace(request.Header.Get("X-Request-ID")),
		TraceID:        strings.TrimSpace(request.Header.Get("X-Trace-ID")),
	}
	if !validWriteMetadata(metadata) {
		handler.writeError(response, request, ErrInvalidInput)
		return WriteMetadata{}, false
	}
	return metadata, true
}

func (handler *Handler) emptyMutation(
	response http.ResponseWriter,
	request *http.Request,
) (WriteMetadata, int64, bool) {
	metadata, ok := handler.writeMetadata(response, request)
	if !ok {
		return WriteMetadata{}, 0, false
	}
	revision, err := expectedRevision(request, false)
	if err != nil || !handler.emptyJSONBody(response, request) {
		if err == nil {
			err = ErrInvalidInput
		}
		handler.writeError(response, request, err)
		return WriteMetadata{}, 0, false
	}
	return metadata, revision, true
}

func (handler *Handler) decodeBody(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, handler.maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || int64(len(raw)) > handler.maxRequestBytes || rejectDuplicateKeys(raw) != nil {
		return ErrInvalidInput
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

func (handler *Handler) emptyJSONBody(response http.ResponseWriter, request *http.Request) bool {
	var body struct{}
	return handler.decodeBody(response, request, &body) == nil
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

func credentialFilter(request *http.Request, target uuid.UUID) (CredentialListFilter, error) {
	allowed := map[string]bool{"provider": true, "status": true, "limit": true, "cursor": true}
	if err := validateQuery(request, allowed); err != nil {
		return CredentialListFilter{}, err
	}
	limit, err := parseLimit(request.URL.Query().Get("limit"))
	if err != nil {
		return CredentialListFilter{}, err
	}
	return CredentialListFilter{
		TargetScopeID: target, Provider: request.URL.Query().Get("provider"),
		Status: request.URL.Query().Get("status"), Limit: limit, Cursor: request.URL.Query().Get("cursor"),
	}, nil
}

func ruleFilter(request *http.Request, target uuid.UUID) (RuleListFilter, error) {
	allowed := map[string]bool{"site_id": true, "enabled": true, "limit": true, "cursor": true}
	if err := validateQuery(request, allowed); err != nil {
		return RuleListFilter{}, err
	}
	limit, err := parseLimit(request.URL.Query().Get("limit"))
	if err != nil {
		return RuleListFilter{}, err
	}
	var siteID uuid.UUID
	if raw := request.URL.Query().Get("site_id"); raw != "" {
		siteID, err = strictUUID(raw)
		if err != nil {
			return RuleListFilter{}, ErrInvalidInput
		}
	}
	var enabled *bool
	if raw := request.URL.Query().Get("enabled"); raw != "" {
		if raw != "true" && raw != "false" {
			return RuleListFilter{}, ErrInvalidInput
		}
		value := raw == "true"
		enabled = &value
	}
	return RuleListFilter{
		TargetScopeID: target, SiteID: siteID, Enabled: enabled,
		Limit: limit, Cursor: request.URL.Query().Get("cursor"),
	}, nil
}

func validateQuery(request *http.Request, allowed map[string]bool) error {
	for key, values := range request.URL.Query() {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			return ErrInvalidInput
		}
	}
	return nil
}

func parseLimit(raw string) (int, error) {
	if raw == "" {
		return 50, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 100 {
		return 0, ErrInvalidInput
	}
	return value, nil
}

func strictUUID(raw string) (uuid.UUID, error) {
	if raw != strings.ToLower(raw) || len(raw) != 36 {
		return uuid.Nil, ErrInvalidInput
	}
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidInput
	}
	return value, nil
}

func expectedRevision(request *http.Request, allowZero bool) (int64, error) {
	raw := strings.TrimSpace(request.Header.Get("If-Match"))
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, ErrInvalidInput
	}
	value, err := strconv.ParseInt(raw[1:len(raw)-1], 10, 64)
	if err != nil || value < 0 || value > maxSafeRevision || !allowZero && value == 0 {
		return 0, ErrInvalidInput
	}
	return value, nil
}

func quoteRevision(revision int64) string {
	return `"` + strconv.FormatInt(revision, 10) + `"`
}

func (handler *Handler) writeCredentialResult(
	response http.ResponseWriter,
	request *http.Request,
	result CredentialWriteResult,
) {
	response.Header().Set("ETag", quoteRevision(result.Credential.Revision))
	handler.writeReplay(response, result.Replayed)
	handler.writeJSON(response, request, http.StatusOK, result.Credential)
}

func (handler *Handler) writeRuleResult(response http.ResponseWriter, request *http.Request, result RuleWriteResult) {
	response.Header().Set("ETag", quoteRevision(result.Rule.Revision))
	handler.writeReplay(response, result.Replayed)
	handler.writeJSON(response, request, http.StatusOK, result.Rule)
}

func (handler *Handler) writeReplay(response http.ResponseWriter, replayed bool) {
	if replayed {
		response.Header().Set("X-Idempotent-Replay", "true")
	}
}

func (handler *Handler) methodNotAllowed(response http.ResponseWriter, request *http.Request, allow string) {
	response.Header().Set("Allow", allow)
	handler.writeAPIError(response, request, http.StatusMethodNotAllowed,
		"method_not_allowed", "request method is not allowed")
}

func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required")
	case errors.Is(err, ErrInvalidInput):
		handler.writeAPIError(response, request, http.StatusBadRequest, "invalid_request", "request is invalid")
	case errors.Is(err, ErrPermissionDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "permission_denied", "permission is denied")
	case errors.Is(err, ErrEntitlementDenied):
		handler.writeAPIError(response, request, http.StatusForbidden, "entitlement_denied", "entitlement does not allow this operation")
	case errors.Is(err, ErrNotFound):
		handler.writeAPIError(response, request, http.StatusNotFound, "not_found", "resource was not found")
	case errors.Is(err, ErrSiteLocked):
		handler.writeAPIError(response, request, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, ErrConflict), errors.Is(err, ErrIdempotencyConflict):
		code := "resource_conflict"
		if errors.Is(err, ErrIdempotencyConflict) {
			code = "idempotency_conflict"
		}
		handler.writeAPIError(response, request, http.StatusConflict, code, "resource conflicts with current state")
	case errors.Is(err, ErrRevisionConflict):
		handler.writeAPIError(response, request, http.StatusPreconditionFailed, "revision_conflict", "resource revision has changed")
	case errors.Is(err, ErrValidation), errors.Is(err, ErrCredentialUnverified), errors.Is(err, ErrVerificationRejected):
		code := "validation_error"
		if errors.Is(err, ErrCredentialUnverified) {
			code = "credential_unverified"
		} else if errors.Is(err, ErrVerificationRejected) {
			code = "credential_verification_rejected"
		}
		handler.writeAPIError(response, request, http.StatusUnprocessableEntity, code, "request fields are invalid")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable, "request_canceled", "request was canceled")
	case errors.Is(err, ErrVerifierUnavailable):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable,
			"credential_verifier_unavailable", "credential verifier is unavailable")
	case errors.Is(err, ErrEncryptionUnavailable):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable,
			"credential_encryption_unavailable", "credential encryption is unavailable")
	case errors.Is(err, ErrEntitlementUnavailable):
		handler.writeAPIError(response, request, http.StatusServiceUnavailable,
			"entitlement_unavailable", "entitlement state is unavailable")
	default:
		handler.writeAPIError(response, request, http.StatusServiceUnavailable,
			"service_unavailable", "a required dependency is unavailable")
	}
}

func (handler *Handler) writeAPIError(
	response http.ResponseWriter,
	request *http.Request,
	status int,
	code, message string,
) {
	var envelope errorEnvelope
	envelope.Error.Code, envelope.Error.Message = code, message
	envelope.Error.RequestID = strings.TrimSpace(request.Header.Get("X-Request-ID"))
	envelope.Error.TraceID = strings.TrimSpace(request.Header.Get("X-Trace-ID"))
	handler.writeJSON(response, request, status, envelope)
}

func (handler *Handler) writeJSON(response http.ResponseWriter, request *http.Request, status int, value any) {
	encoded, err := encodeJSON(value)
	if err != nil || len(encoded) > handler.maxResponseBytes {
		if status == http.StatusServiceUnavailable {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.writeAPIError(response, request, http.StatusServiceUnavailable,
			"service_unavailable", "a required dependency is unavailable")
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func newRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "request-unavailable"
	}
	return hex.EncodeToString(raw)
}
