package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

// 「分组管理 / 默认设置」是转发列表页的页签，接口按同一目标作用域下的
// stream-groups 与 user-configs(type=stream) 两组资源暴露。

type createStreamGroupRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	l4forward.GroupFields
}

type updateStreamGroupRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	l4forward.GroupFields
}

type createStreamDefaultRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	l4forward.UserDefaultFields
}

type l4StreamGroupService interface {
	l4StreamService
	CreateGroup(context.Context, l4forward.Actor, l4forward.GroupCreateRequest) (l4forward.GroupWriteResult, error)
	UpdateGroup(context.Context, l4forward.Actor, l4forward.GroupUpdateRequest) (l4forward.GroupWriteResult, error)
	DeleteGroup(context.Context, l4forward.Actor, l4forward.GroupDeleteRequest) error
	ListGroups(context.Context, l4forward.Actor, l4forward.GroupListFilter) (l4forward.GroupListResult, error)
	ListUserDefaults(context.Context, l4forward.Actor, l4forward.UserDefaultListFilter) (l4forward.UserDefaultListResult, error)
	EffectiveDefaults(context.Context, l4forward.Actor, uuid.UUID, uuid.UUID, []uuid.UUID) (l4forward.FieldDefaults, error)
	CreateUserDefault(context.Context, l4forward.Actor, l4forward.UserDefaultCreateRequest) (l4forward.UserDefaultWriteResult, error)
	DeleteUserDefault(context.Context, l4forward.Actor, l4forward.UserDefaultDeleteRequest) error
}

var errBadListWindow = errors.New("pagination window is invalid")

func (s *Server) handleListStreamGroups(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	filter, err := parseGroupListFilter(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.streamGroups.ListGroups(r.Context(), streamActor(principal), filter)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateStreamGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createStreamGroupRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	targetScopeID, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "target_scope_id must be a UUID")
		return
	}
	ownerID, err := optionalUUID(body.OwnerID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "owner_id must be a UUID")
		return
	}
	result, err := s.streamGroups.CreateGroup(r.Context(), streamActor(principal), l4forward.GroupCreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.GroupFields,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Group.Revision))
	writeJSONStatus(w, http.StatusCreated, result.Group)
}

func (s *Server) handleUpdateStreamGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "stream group ID must be a UUID")
		return
	}
	version, ok := s.streamWriteVersion(w, r)
	if !ok {
		return
	}
	var body updateStreamGroupRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if body.ExpectedRevision != version {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	result, err := s.streamGroups.UpdateGroup(r.Context(), streamActor(principal), l4forward.GroupUpdateRequest{
		ID: id, ExpectedRevision: version, Fields: body.GroupFields,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Group.Revision))
	writeJSON(w, http.StatusOK, result.Group)
}

func (s *Server) handleDeleteStreamGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "stream group ID must be a UUID")
		return
	}
	version, ok := s.streamWriteVersion(w, r)
	if !ok {
		return
	}
	if err := s.streamGroups.DeleteGroup(r.Context(), streamActor(principal), l4forward.GroupDeleteRequest{
		ID: id, ExpectedRevision: version, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListUserConfigs(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	query := r.URL.Query()
	if len(query["type"]) != 1 || strings.TrimSpace(query["type"][0]) != "stream" {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "type must be stream")
		return
	}
	filter, err := parseUserDefaultListFilter(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.streamGroups.ListUserDefaults(r.Context(), streamActor(principal), filter)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// handleEffectiveUserConfigs 返回新建转发草稿要预填的默认值（L4-DEFAULT-01）：与建转发同一解析，
// null 表示该项没有默认。group_id 可重复（所选分组）。
func (s *Server) handleEffectiveUserConfigs(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	query, err := parseEffectiveDefaultsQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	defaults, err := s.streamGroups.EffectiveDefaults(r.Context(), streamActor(principal), query.targetScopeID, query.ownerID, query.groupIDs)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, defaults)
}

type effectiveDefaultsQuery struct {
	targetScopeID, ownerID uuid.UUID
	groupIDs               []uuid.UUID
}

func parseEffectiveDefaultsQuery(r *http.Request) (effectiveDefaultsQuery, error) {
	query := r.URL.Query()
	groupValues := query["group_id"]
	query.Del("group_id")
	if !singleValueQuery(query, "type", "target_scope_id", "owner_id") {
		return effectiveDefaultsQuery{}, errors.New("query parameters are invalid")
	}
	if query.Get("type") != "stream" {
		return effectiveDefaultsQuery{}, errors.New("type must be stream")
	}
	var parsed effectiveDefaultsQuery
	var err error
	if parsed.targetScopeID, err = optionalUUID(query.Get("target_scope_id")); err != nil {
		return effectiveDefaultsQuery{}, errors.New("target_scope_id must be a UUID")
	}
	if parsed.ownerID, err = optionalUUID(query.Get("owner_id")); err != nil {
		return effectiveDefaultsQuery{}, errors.New("owner_id must be a UUID")
	}
	for _, raw := range groupValues {
		id, err := uuid.Parse(raw)
		if err != nil {
			return effectiveDefaultsQuery{}, errors.New("group_id must be a UUID")
		}
		parsed.groupIDs = append(parsed.groupIDs, id)
	}
	return parsed, nil
}

func (s *Server) handleCreateUserConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createStreamDefaultRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	targetScopeID, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "target_scope_id must be a UUID")
		return
	}
	ownerID, err := optionalUUID(body.OwnerID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "owner_id must be a UUID")
		return
	}
	result, err := s.streamGroups.CreateUserDefault(r.Context(), streamActor(principal), l4forward.UserDefaultCreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.UserDefaultFields,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result.Default)
}

func (s *Server) handleDeleteUserConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "stream setting ID must be a UUID")
		return
	}
	if err := s.streamGroups.DeleteUserDefault(r.Context(), streamActor(principal), l4forward.UserDefaultDeleteRequest{
		ID: id, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// streamWriteVersion 解析 If-Match；分组与默认设置的写入都走乐观并发。
func (s *Server) streamWriteVersion(w http.ResponseWriter, r *http.Request) (int64, bool) {
	values := r.Header.Values("If-Match")
	if len(values) != 1 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain one quoted positive version")
		return 0, false
	}
	version, err := parseIfMatch(values[0])
	if err != nil || quoteVersion(version) != values[0] {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain one quoted positive version")
		return 0, false
	}
	return version, true
}

func parseGroupListFilter(r *http.Request) (l4forward.GroupListFilter, error) {
	query := r.URL.Query()
	if !singleValueQuery(query, "page", "limit", "search") {
		return l4forward.GroupListFilter{}, l4forward.ErrInvalidInput
	}
	page, err := positiveIntOr(query.Get("page"), 1)
	if err != nil {
		return l4forward.GroupListFilter{}, errBadListWindow
	}
	limit, err := positiveIntOr(query.Get("limit"), 20)
	if err != nil {
		return l4forward.GroupListFilter{}, errBadListWindow
	}
	return l4forward.GroupListFilter{Page: page, Limit: limit, Search: query.Get("search")}, nil
}

func parseUserDefaultListFilter(r *http.Request) (l4forward.UserDefaultListFilter, error) {
	query := r.URL.Query()
	if !singleValueQuery(query, "type", "page", "limit", "search") {
		return l4forward.UserDefaultListFilter{}, l4forward.ErrInvalidInput
	}
	page, err := positiveIntOr(query.Get("page"), 1)
	if err != nil {
		return l4forward.UserDefaultListFilter{}, errBadListWindow
	}
	limit, err := positiveIntOr(query.Get("limit"), 20)
	if err != nil {
		return l4forward.UserDefaultListFilter{}, errBadListWindow
	}
	return l4forward.UserDefaultListFilter{Page: page, Limit: limit, Search: query.Get("search")}, nil
}

func singleValueQuery(query map[string][]string, allowed ...string) bool {
	permitted := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		permitted[key] = struct{}{}
	}
	for key, values := range query {
		if _, ok := permitted[key]; !ok || len(values) != 1 {
			return false
		}
	}
	return true
}
