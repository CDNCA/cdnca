package openrestysecurityhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/google/uuid"
)

type API interface {
	GetGlobal(context.Context, openrestysecurity.ReadGlobalRequest) (openrestysecurity.Document, error)
	PatchGlobal(context.Context, openrestysecurity.PatchGlobalRequest) (openrestysecurity.WriteResult, error)
	ListOverrides(context.Context, openrestysecurity.ListOverridesRequest) (openrestysecurity.OverridePage, error)
	CreateOverride(context.Context, openrestysecurity.CreateOverrideRequest) (openrestysecurity.WriteResult, error)
	PatchOverride(context.Context, openrestysecurity.PatchOverrideRequest) (openrestysecurity.WriteResult, error)
	DeleteOverride(context.Context, openrestysecurity.DeleteOverrideRequest) (bool, error)
	SearchTargets(context.Context, openrestysecurity.SearchTargetsRequest) (openrestysecurity.TargetPage, error)
	Effective(context.Context, openrestysecurity.EffectiveRequest) (openrestysecurity.Document, error)
	RuleGroups(context.Context, openrestysecurity.RuleGroupsRequest) ([]openrestysecurity.RuleGroup, error)
	SetRuleGroupEnabled(context.Context, openrestysecurity.RuleGroupStateRequest) error
	DownloadCCImage(context.Context, openrestysecurity.DownloadCCImageRequest) (bool, error)
}

type Authenticator func(*http.Request) (openrestysecurity.Actor, error)

type Handler struct {
	api               API
	authenticate      Authenticator
	catalog           SystemRuleCatalog
	catalogAuthorizer ruleGroupTxAuthorizer
}

func NewHandler(api API, authenticate Authenticator) (*Handler, error) {
	if api == nil || authenticate == nil {
		return nil, errors.New("invalid OpenResty security HTTP dependencies")
	}
	return &Handler{api: api, authenticate: authenticate}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = uuid.NewString()
	}
	request.Header.Set("X-Request-ID", requestID)
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Request-ID", requestID)
	actor, err := handler.authenticate(request)
	if err != nil {
		writeError(response, err)
		return
	}
	path := request.URL.Path
	if IsSystemRulePath(path) {
		handler.serveSystemRules(response, request, actor)
		return
	}
	ruleGroupsRead := (path == "/v1/cc-rule-groups" || path == ruleGroupSummaryPath) && request.Method == http.MethodGet
	if actor.ScopeKind != openrestysecurity.ScopePlatform && !ruleGroupsRead {
		writeError(response, openrestysecurity.ErrPermissionDenied)
		return
	}
	if _, exists := request.URL.Query()["target_scope_id"]; exists {
		writeError(response, openrestysecurity.ErrInvalidInput)
		return
	}
	targetScopeID := actor.ScopeID
	switch {
	case path == "/v1/openresty-security/configs/global" && request.Method == http.MethodGet:
		document, err := handler.api.GetGlobal(request.Context(), openrestysecurity.ReadGlobalRequest{Actor: actor, TargetScopeID: targetScopeID})
		if err != nil {
			writeError(response, err)
			return
		}
		writeDocument(response, http.StatusOK, document, false)
	case path == "/v1/openresty-security/configs/global" && request.Method == http.MethodPatch:
		var input struct {
			Patch json.RawMessage `json:"patch"`
		}
		if decodeBody(response, request, &input) != nil {
			writeError(response, openrestysecurity.ErrInvalidInput)
			return
		}
		patch, err := openrestysecurity.DecodeConfig(input.Patch, false)
		if err != nil {
			writeError(response, err)
			return
		}
		result, err := handler.api.PatchGlobal(request.Context(), openrestysecurity.PatchGlobalRequest{
			Actor: actor, TargetScopeID: targetScopeID, ExpectedRevision: mustETag(request),
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"), Patch: patch,
		})
		if err != nil {
			writeError(response, err)
			return
		}
		writeDocument(response, http.StatusOK, result.Document, result.Replayed)
	case path == "/v1/openresty-security/overrides" && request.Method == http.MethodGet:
		page, pageSize, err := parsePage(request)
		if err != nil {
			writeError(response, err)
			return
		}
		result, err := handler.api.ListOverrides(request.Context(), openrestysecurity.ListOverridesRequest{
			Actor: actor, TargetScopeID: targetScopeID, ScopeType: request.URL.Query().Get("scope_type"),
			Query: request.URL.Query().Get("query"), Page: page, PageSize: pageSize,
		})
		if err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case path == "/v1/openresty-security/overrides" && request.Method == http.MethodPost:
		var input struct {
			ScopeType string          `json:"scope_type"`
			ScopeID   string          `json:"scope_id"`
			Config    json.RawMessage `json:"config"`
		}
		if decodeBody(response, request, &input) != nil || mustETag(request) != 0 {
			writeError(response, openrestysecurity.ErrInvalidInput)
			return
		}
		config, err := openrestysecurity.DecodeConfig(input.Config, true)
		if err != nil {
			writeError(response, err)
			return
		}
		result, err := handler.api.CreateOverride(request.Context(), openrestysecurity.CreateOverrideRequest{
			Actor: actor, TargetScopeID: targetScopeID, ScopeType: input.ScopeType, ScopeID: input.ScopeID, Config: config,
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeError(response, err)
			return
		}
		writeDocument(response, http.StatusCreated, result.Document, result.Replayed)
	case strings.HasPrefix(path, "/v1/openresty-security/overrides/") && request.Method == http.MethodPatch:
		id, err := parsePathID(path)
		if err != nil {
			writeError(response, err)
			return
		}
		var input struct {
			Patch         json.RawMessage `json:"patch"`
			RemovedFields []string        `json:"removed_fields"`
		}
		if decodeBody(response, request, &input) != nil {
			writeError(response, openrestysecurity.ErrInvalidInput)
			return
		}
		patch, err := openrestysecurity.DecodeConfig(input.Patch, true)
		if err != nil {
			writeError(response, err)
			return
		}
		if err := openrestysecurity.ValidateOverridePatch(patch, input.RemovedFields); err != nil {
			writeError(response, err)
			return
		}
		result, err := handler.api.PatchOverride(request.Context(), openrestysecurity.PatchOverrideRequest{
			Actor: actor, TargetScopeID: targetScopeID, ID: id, ExpectedRevision: mustETag(request), Patch: patch,
			RemovedFields:  input.RemovedFields,
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeError(response, err)
			return
		}
		writeDocument(response, http.StatusOK, result.Document, result.Replayed)
	case strings.HasPrefix(path, "/v1/openresty-security/overrides/") && request.Method == http.MethodDelete:
		id, err := parsePathID(path)
		if err != nil {
			writeError(response, err)
			return
		}
		replayed, err := handler.api.DeleteOverride(request.Context(), openrestysecurity.DeleteOverrideRequest{
			Actor: actor, TargetScopeID: targetScopeID, ID: id, ExpectedRevision: mustETag(request),
			IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeError(response, err)
			return
		}
		if replayed {
			response.Header().Set("Idempotent-Replay", "true")
		}
		response.WriteHeader(http.StatusNoContent)
	case path == "/v1/openresty-security/targets" && request.Method == http.MethodGet:
		page, pageSize, err := parsePage(request)
		if err != nil {
			writeError(response, err)
			return
		}
		result, err := handler.api.SearchTargets(request.Context(), openrestysecurity.SearchTargetsRequest{
			Actor: actor, TargetScopeID: targetScopeID, ScopeType: request.URL.Query().Get("scope_type"),
			Query: request.URL.Query().Get("query"), Page: page, PageSize: pageSize,
		})
		if err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, result)
	case path == "/v1/openresty-security/effective" && request.Method == http.MethodGet:
		nodeID, err := strictUUID(request.URL.Query().Get("node_id"))
		if err != nil {
			writeError(response, err)
			return
		}
		document, err := handler.api.Effective(request.Context(), openrestysecurity.EffectiveRequest{Actor: actor,
			TargetScopeID: targetScopeID, NodeID: nodeID})
		if err != nil {
			writeError(response, err)
			return
		}
		writeDocument(response, http.StatusOK, document, false)
	case path == "/v1/cc-rule-groups" && request.Method == http.MethodGet:
		groups, err := handler.api.RuleGroups(request.Context(), openrestysecurity.RuleGroupsRequest{Actor: actor, TargetScopeID: targetScopeID})
		if err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, groups)
	case path == ruleGroupSummaryPath && request.Method == http.MethodGet:
		summary, err := handler.ruleGroupSummary(request.Context(), actor, targetScopeID)
		if err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, summary)
	case strings.HasPrefix(path, "/v1/cc-rule-groups/") && (strings.HasSuffix(path, "/enable") || strings.HasSuffix(path, "/disable")) && request.Method == http.MethodPost:
		raw := strings.TrimPrefix(path, "/v1/cc-rule-groups/")
		enabled := false
		switch {
		case strings.HasSuffix(raw, "/enable"):
			enabled = true
			raw = strings.TrimSuffix(raw, "/enable")
		case strings.HasSuffix(raw, "/disable"):
			raw = strings.TrimSuffix(raw, "/disable")
		}
		if raw == "" || strings.Contains(raw, "/") {
			writeError(response, openrestysecurity.ErrInvalidInput)
			return
		}
		if err := handler.api.SetRuleGroupEnabled(request.Context(), openrestysecurity.RuleGroupStateRequest{Actor: actor, TargetScopeID: targetScopeID, SystemRuleID: raw, Enabled: enabled}); err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{"id": raw, "enabled": enabled})
	case path == "/v1/openresty-security/actions/download-cc-image" && request.Method == http.MethodPost:
		replayed, err := handler.api.DownloadCCImage(request.Context(), openrestysecurity.DownloadCCImageRequest{
			Actor: actor, TargetScopeID: targetScopeID, IdempotencyKey: request.Header.Get("Idempotency-Key"),
			RequestID: request.Header.Get("X-Request-ID"),
		})
		if err != nil {
			writeError(response, err)
			return
		}
		if replayed {
			response.Header().Set("Idempotent-Replay", "true")
		}
		writeJSON(response, http.StatusAccepted, map[string]string{"status": "queued"})
	default:
		if allow, ok := allowedMethods(path); ok {
			response.Header().Set("Allow", allow)
			writeAPIError(response, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeAPIError(response, http.StatusNotFound, "not_found")
	}
}

func allowedMethods(path string) (string, bool) {
	switch path {
	case "/v1/openresty-security/configs/global":
		return "GET, PATCH", true
	case "/v1/openresty-security/overrides":
		return "GET, POST", true
	case "/v1/openresty-security/targets", "/v1/openresty-security/effective", "/v1/cc-rule-groups", ruleGroupSummaryPath:
		return "GET", true
	case "/v1/openresty-security/actions/download-cc-image":
		return "POST", true
	default:
		if strings.HasPrefix(path, "/v1/cc-rule-groups/") {
			return "POST", true
		}
		if _, err := parsePathID(path); err == nil {
			return "PATCH, DELETE", true
		}
		return "", false
	}
}

func strictUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, openrestysecurity.ErrInvalidInput
	}
	return parsed, nil
}

func parsePathID(path string) (uuid.UUID, error) {
	value := strings.TrimPrefix(path, "/v1/openresty-security/overrides/")
	if value == "" || strings.Contains(value, "/") {
		return uuid.Nil, openrestysecurity.ErrInvalidInput
	}
	return strictUUID(value)
}

func parsePage(request *http.Request) (int, int, error) {
	page, pageSize := 1, 20
	var err error
	if value := request.URL.Query().Get("page"); value != "" {
		page, err = strconv.Atoi(value)
		if err != nil {
			return 0, 0, openrestysecurity.ErrInvalidInput
		}
	}
	if value := request.URL.Query().Get("page_size"); value != "" {
		pageSize, err = strconv.Atoi(value)
		if err != nil {
			return 0, 0, openrestysecurity.ErrInvalidInput
		}
	}
	if page < 1 || pageSize < 1 || pageSize > 100 {
		return 0, 0, openrestysecurity.ErrInvalidInput
	}
	return page, pageSize, nil
}

func mustETag(request *http.Request) int64 {
	value := request.Header.Get("If-Match")
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' || strings.TrimSpace(value) != value {
		return -1
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 0 || revision > 1<<53-1 {
		return -1
	}
	return revision
}

func decodeBody(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, 3<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON document")
	}
	return nil
}

func writeDocument(response http.ResponseWriter, status int, document openrestysecurity.Document, replayed bool) {
	response.Header().Set("ETag", fmt.Sprintf(`"%d"`, document.Revision))
	if replayed {
		response.Header().Set("Idempotent-Replay", "true")
	}
	writeJSON(response, status, document)
}

func writeError(response http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "openresty_security_unavailable"
	switch {
	case errors.Is(err, openrestysecurity.ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, openrestysecurity.ErrPermissionDenied):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, openrestysecurity.ErrNotFound):
		status, code = http.StatusNotFound, "openresty_security_not_found"
	case errors.Is(err, openrestysecurity.ErrInvalidInput):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, openrestysecurity.ErrRevisionConflict):
		status, code = http.StatusPreconditionFailed, "revision_conflict"
	case errors.Is(err, openrestysecurity.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, openrestysecurity.ErrDuplicateTarget):
		status, code = http.StatusConflict, "duplicate_target"
	}
	writeAPIError(response, status, code)
}

func writeAPIError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{
		"code": code, "request_id": response.Header().Get("X-Request-ID"),
	}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
