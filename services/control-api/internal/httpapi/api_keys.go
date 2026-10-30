package httpapi

import (
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type apiKeyFieldsRequest struct {
	Name        string   `json:"name"`
	Scopes      []string `json:"scopes"`
	IPAllowlist []string `json:"ip_allowlist"`
	ExpiresAt   *string  `json:"expires_at"`
}

type adminCreateAPIKeyRequest struct {
	Name              string   `json:"name"`
	Scopes            []string `json:"scopes"`
	IPAllowlist       []string `json:"ip_allowlist"`
	ExpiresAt         *string  `json:"expires_at"`
	PendingTTLSeconds int64    `json:"pending_ttl_seconds"`
}

type apiKeyMutationRequest struct {
	IPAllowlist []string `json:"ip_allowlist"`
	// GrantAllScopes 只被轮换接受（简单版"重置密钥"：权限同时刷新为当前账号可授予的全部）。
	GrantAllScopes bool `json:"grant_all_scopes,omitempty"`
}

type apiKeyFieldError struct {
	Code   string
	Params map[string]any
}

type apiKeyFieldErrorEnvelope struct {
	Error struct {
		Code      string         `json:"code"`
		Message   string         `json:"message"`
		RequestID string         `json:"request_id"`
		Params    map[string]any `json:"params"`
	} `json:"error"`
}

type apiKeyListResponse struct {
	Items      []apikey.Key `json:"items"`
	NextCursor string       `json:"next_cursor"`
	HasMore    bool         `json:"has_more"`
	// Total: first page and offset pages only (tp-b7b 共 N 条).
	Total *int `json:"total,omitempty"`
}

func (s *Server) handleListSelfAPIKeys(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "tenant", "api_keys.self.manage")
	if !ok {
		return
	}
	input, err := parseAPIKeyListRawQuery(r.URL.RawQuery)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	page, err := s.apiKeys.ListSelfPage(r.Context(), principal, input)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newAPIKeyListResponse(page))
}

func (s *Server) handleCreateSelfAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "tenant", "api_keys.self.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok || !s.requireCollectionIfMatch(w, r) {
		return
	}
	var body apiKeyFieldsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	allowlist, failure := normalizeAPIKeyIPAllowlist(body.IPAllowlist)
	if failure != nil {
		writeAPIKeyFieldError(w, r, failure)
		return
	}
	expiresAt, err := parseOptionalTime(body.ExpiresAt)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expires_at must be an RFC3339 timestamp")
		return
	}
	result, err := s.apiKeys.CreateSelf(r.Context(), principal, apikey.CreateInput{
		Name: body.Name, Scopes: body.Scopes, IPAllowlist: allowlist, ExpiresAt: expiresAt,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", quoteVersion(result.Key.Revision))
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleGetSelfAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "tenant", "api_keys.self.manage")
	if !ok {
		return
	}
	id, ok := s.apiKeyPathID(w, r)
	if !ok {
		return
	}
	result, err := s.apiKeys.GetSelf(r.Context(), principal, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateSelfAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "tenant", "api_keys.self.manage")
	if !ok {
		return
	}
	id, ok := s.apiKeyPathID(w, r)
	if !ok {
		return
	}
	revision, ok := s.apiKeyWriteHeaders(w, r)
	if !ok {
		return
	}
	var body apiKeyFieldsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	allowlist, failure := normalizeAPIKeyIPAllowlist(body.IPAllowlist)
	if failure != nil {
		writeAPIKeyFieldError(w, r, failure)
		return
	}
	expiresAt, err := parseOptionalTime(body.ExpiresAt)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expires_at must be an RFC3339 timestamp")
		return
	}
	result, err := s.apiKeys.UpdateSelf(r.Context(), principal, apikey.UpdateInput{
		ID: id, ExpectedRevision: revision, Name: body.Name, Scopes: body.Scopes,
		IPAllowlist: allowlist, ExpiresAt: expiresAt,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")), RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleActivateSelfAPIKey(w http.ResponseWriter, r *http.Request) {
	s.handleIssueSelfAPIKey(w, r, true)
}

func (s *Server) handleRotateSelfAPIKey(w http.ResponseWriter, r *http.Request) {
	s.handleIssueSelfAPIKey(w, r, false)
}

func (s *Server) handleIssueSelfAPIKey(w http.ResponseWriter, r *http.Request, activate bool) {
	principal, ok := s.requireSessionPermission(w, r, "tenant", "api_keys.self.manage")
	if !ok {
		return
	}
	id, ok := s.apiKeyPathID(w, r)
	if !ok {
		return
	}
	revision, ok := s.apiKeyWriteHeaders(w, r)
	if !ok {
		return
	}
	allowlist, grantAll, ok := decodeAPIKeyMutationBodyWith(w, r, !activate)
	if !ok {
		return
	}
	input := apikey.MutationInput{
		ID: id, ExpectedRevision: revision, IPAllowlist: allowlist, GrantAllScopes: grantAll,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")), RequestID: requestID(r.Context()),
	}
	var result apikey.IssuedKey
	var err error
	if activate {
		result, err = s.apiKeys.ActivateSelf(r.Context(), principal, input)
	} else {
		result, err = s.apiKeys.RotateSelf(r.Context(), principal, input)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", quoteVersion(result.Key.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRevokeSelfAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "tenant", "api_keys.self.manage")
	if !ok {
		return
	}
	id, ok := s.apiKeyPathID(w, r)
	if !ok {
		return
	}
	revision, ok := s.apiKeyWriteHeaders(w, r)
	if !ok {
		return
	}
	allowlist, ok := decodeAPIKeyMutationBody(w, r)
	if !ok {
		return
	}
	result, err := s.apiKeys.RevokeSelf(r.Context(), principal, apikey.MutationInput{
		ID: id, ExpectedRevision: revision, IPAllowlist: allowlist,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")), RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminListUserAPIKeys(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "platform", "api_keys.admin.manage")
	if !ok {
		return
	}
	targetUserID, ok := s.targetUserPathID(w, r)
	if !ok {
		return
	}
	targetScopeID, listQuery, ok := s.adminAPIKeyTargetScope(w, r, true)
	if !ok {
		return
	}
	input, err := parseAPIKeyListRawQuery(listQuery)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	page, err := s.apiKeys.AdminListPage(r.Context(), principal, targetScopeID, targetUserID, input)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, newAPIKeyListResponse(page))
}

func (s *Server) handleAdminCreateUserAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "platform", "api_keys.admin.manage")
	if !ok {
		return
	}
	targetUserID, ok := s.targetUserPathID(w, r)
	if !ok {
		return
	}
	targetScopeID, _, ok := s.adminAPIKeyTargetScope(w, r, false)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok || !s.requireCollectionIfMatch(w, r) {
		return
	}
	var body adminCreateAPIKeyRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	allowlist, failure := normalizeAPIKeyIPAllowlist(body.IPAllowlist)
	if failure != nil {
		writeAPIKeyFieldError(w, r, failure)
		return
	}
	expiresAt, err := parseOptionalTime(body.ExpiresAt)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expires_at must be an RFC3339 timestamp")
		return
	}
	pendingTTL, err := parsePendingTTLSeconds(body.PendingTTLSeconds)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "pending_ttl_seconds is invalid")
		return
	}
	result, err := s.apiKeys.AdminCreatePending(r.Context(), principal, apikey.AdminCreateInput{
		TargetScopeID: targetScopeID, TargetUserID: targetUserID, Name: body.Name, Scopes: body.Scopes,
		IPAllowlist: allowlist, ExpiresAt: expiresAt,
		PendingTTL:     pendingTTL,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleAdminRevokeUserAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSessionPermission(w, r, "platform", "api_keys.admin.manage")
	if !ok {
		return
	}
	targetUserID, ok := s.targetUserPathID(w, r)
	if !ok {
		return
	}
	targetScopeID, _, ok := s.adminAPIKeyTargetScope(w, r, false)
	if !ok {
		return
	}
	id, ok := s.apiKeyPathID(w, r)
	if !ok {
		return
	}
	revision, ok := s.apiKeyWriteHeaders(w, r)
	if !ok {
		return
	}
	allowlist, ok := decodeAPIKeyMutationBody(w, r)
	if !ok {
		return
	}
	result, err := s.apiKeys.AdminRevoke(r.Context(), principal, apikey.AdminRevokeInput{
		TargetScopeID: targetScopeID, TargetUserID: targetUserID,
		ID: id, ExpectedRevision: revision, IPAllowlist: allowlist,
		IdempotencyKey: strings.TrimSpace(r.Header.Get("Idempotency-Key")), RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) adminAPIKeyTargetScope(
	w http.ResponseWriter,
	r *http.Request,
	allowListParameters bool,
) (uuid.UUID, string, bool) {
	query := r.URL.Query()
	values := query["tenant_scope_id"]
	if len(values) != 1 || values[0] == "" {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "tenant_scope_id is required")
		return uuid.Nil, "", false
	}
	targetScopeID, err := uuid.Parse(values[0])
	if err != nil || targetScopeID == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "tenant_scope_id must be a UUID")
		return uuid.Nil, "", false
	}
	query.Del("tenant_scope_id")
	if !allowListParameters && len(query) != 0 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return uuid.Nil, "", false
	}
	return targetScopeID, query.Encode(), true
}

func (s *Server) requireSessionPermission(
	w http.ResponseWriter,
	r *http.Request,
	scopeKind string,
	permission string,
) (identity.Principal, bool) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err == nil && principal.ScopeKind != scopeKind {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func parseAPIKeyListRawQuery(raw string) (apikey.APIKeyListInput, error) {
	input := apikey.APIKeyListInput{Limit: 50}
	query, err := url.ParseQuery(raw)
	if err != nil {
		return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
	}
	for key, values := range query {
		if len(values) != 1 || values[0] == "" {
			return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
		}
		value := values[0]
		switch key {
		case "limit":
			if value[0] == '0' || len(value) > 3 {
				return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
			}
			for _, character := range value {
				if character < '0' || character > '9' {
					return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
				}
			}
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 100 {
				return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
			}
			input.Limit = limit
		case "status":
			input.Status = value
		case "name":
			input.Name = value
		case "key_id":
			input.KeyID = value
		case "cursor":
			if len(value) > 4096 {
				return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
			}
			input.Cursor = value
		case "offset":
			if len(value) > 5 || len(value) > 1 && value[0] == '0' {
				return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
			}
			for _, character := range value {
				if character < '0' || character > '9' {
					return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
				}
			}
			offset, err := strconv.Atoi(value)
			if err != nil || offset > apikey.MaxListOffset {
				return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
			}
			input.Offset = offset
		default:
			return apikey.APIKeyListInput{}, apikey.ErrInvalidInput
		}
	}
	return input, nil
}

func newAPIKeyListResponse(page apikey.APIKeyListPage) apiKeyListResponse {
	items := page.Items
	if items == nil {
		items = []apikey.Key{}
	}
	return apiKeyListResponse{
		Items: items, NextCursor: page.NextCursor, HasMore: page.NextCursor != "", Total: page.Total,
	}
}

func (s *Server) apiKeyWriteHeaders(w http.ResponseWriter, r *http.Request) (int64, bool) {
	if _, ok := s.idempotencyKey(w, r); !ok {
		return 0, false
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive revision")
		return 0, false
	}
	return revision, true
}

func (s *Server) requireCollectionIfMatch(w http.ResponseWriter, r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("If-Match")) != `"0"` {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must be \"0\" when creating an API key")
		return false
	}
	return true
}

func (s *Server) apiKeyPathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("key_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "API key ID must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

func (s *Server) targetUserPathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "user ID must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

func parseOptionalTime(raw *string) (*time.Time, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return nil, err
	}
	value = value.UTC()
	return &value, nil
}

func normalizeAPIKeyIPAllowlist(values []string) ([]string, *apiKeyFieldError) {
	if len(values) > 32 {
		return nil, &apiKeyFieldError{Code: "api_key_ip_allowlist_too_many", Params: map[string]any{
			"field": "ip_allowlist", "maximum": 32, "actual": len(values),
		}}
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]int, len(values))
	normalized := make([]string, 0, len(values))
	for index, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Addr().Is4In6() {
			return nil, &apiKeyFieldError{Code: "api_key_ip_allowlist_unsupported_prefix", Params: map[string]any{
				"field": "ip_allowlist", "index": index,
			}}
		}
		if err != nil || prefix != prefix.Masked() || prefix.String() != raw {
			return nil, &apiKeyFieldError{Code: "api_key_ip_allowlist_invalid_cidr", Params: map[string]any{
				"field": "ip_allowlist", "index": index,
			}}
		}
		if duplicate, exists := seen[prefix]; exists {
			return nil, &apiKeyFieldError{Code: "api_key_ip_allowlist_duplicate", Params: map[string]any{
				"field": "ip_allowlist", "index": index, "duplicate_of": duplicate,
			}}
		}
		for previous, existing := range prefixes {
			if existing.Contains(prefix.Addr()) || prefix.Contains(existing.Addr()) {
				return nil, &apiKeyFieldError{Code: "api_key_ip_allowlist_overlap", Params: map[string]any{
					"field": "ip_allowlist", "index": index, "overlaps": previous,
				}}
			}
		}
		seen[prefix] = index
		prefixes = append(prefixes, prefix)
		normalized = append(normalized, raw)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func writeAPIKeyFieldError(w http.ResponseWriter, r *http.Request, failure *apiKeyFieldError) {
	var response apiKeyFieldErrorEnvelope
	response.Error.Code = failure.Code
	response.Error.Message = "API key IP allowlist is invalid"
	response.Error.RequestID = requestID(r.Context())
	response.Error.Params = failure.Params
	writeJSONStatus(w, http.StatusBadRequest, response)
}

func decodeAPIKeyMutationBody(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	allowlist, _, ok := decodeAPIKeyMutationBodyWith(w, r, false)
	return allowlist, ok
}

func decodeAPIKeyMutationBodyWith(w http.ResponseWriter, r *http.Request, allowGrantAll bool) ([]string, bool, bool) {
	var body apiKeyMutationRequest
	if err := decodeJSON(w, r, &body); err != nil || body.GrantAllScopes && !allowGrantAll {
		writeJSONStatus(w, http.StatusBadRequest, errorEnvelope{Error: apiError{
			Code: "invalid_request", Message: "request body is invalid",
			RequestID: requestID(r.Context()),
		}})
		return nil, false, false
	}
	allowlist, failure := normalizeAPIKeyIPAllowlist(body.IPAllowlist)
	if failure != nil {
		writeAPIKeyFieldError(w, r, failure)
		return nil, false, false
	}
	return allowlist, body.GrantAllScopes, true
}

func parsePendingTTLSeconds(raw int64) (time.Duration, error) {
	if raw == 0 {
		return 0, nil
	}
	if raw < 1 || raw > int64((30*24*time.Hour)/time.Second) {
		return 0, apikey.ErrInvalidInput
	}
	return time.Duration(raw) * time.Second, nil
}
