package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
)

type createStreamRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	// GroupIDs 对应转发列表的「所属分组」列，可不选。
	GroupIDs []string `json:"group_ids"`
	l4forward.Fields
}

type updateStreamRequest struct {
	ExpectedRevision int64     `json:"expected_revision"`
	GroupIDs         *[]string `json:"group_ids"`
	l4forward.Fields
}

type l4StreamWriteService interface {
	Create(context.Context, l4forward.Actor, l4forward.CreateRequest) (l4forward.WriteResult, error)
	Update(context.Context, l4forward.Actor, l4forward.UpdateRequest) (l4forward.WriteResult, error)
}

type l4StreamService interface {
	l4StreamWriteService
	Delete(context.Context, l4forward.Actor, l4forward.DeleteRequest) (l4forward.DeleteResult, error)
	Get(context.Context, l4forward.Actor, uuid.UUID) (l4forward.Forward, error)
	List(context.Context, l4forward.Actor, l4forward.ListFilter) (l4forward.ListResult, error)
	BatchCreate(context.Context, l4forward.Actor, l4forward.BatchCreateRequest) (l4forward.BatchCreateResult, error)
	BatchAction(context.Context, l4forward.Actor, l4forward.BatchActionRequest) (l4forward.BatchActionResult, error)
}

// batchCreateStreamRequest is 批量添加: the fields every line shares
// (template: package, site, remark, timeouts, …; listen/origin fields come
// from each line), the lines and 忽略错误.
type batchCreateStreamRequest struct {
	TargetScopeID string           `json:"target_scope_id"`
	OwnerID       string           `json:"owner_id"`
	GroupIDs      []string         `json:"group_ids"`
	Template      l4forward.Fields `json:"template"`
	Lines         []string         `json:"lines"`
	IgnoreErrors  bool             `json:"ignore_errors"`
}

func (s *Server) handleBatchCreateStreams(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body batchCreateStreamRequest
	if err := decodeL4StreamJSON(w, r, &body); err != nil {
		if errors.Is(err, errL4UnsupportedMediaType) {
			s.writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
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
	groupIDs, err := streamGroupIDs(body.GroupIDs)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group_ids must be an array of UUIDs")
		return
	}
	result, err := s.streams.BatchCreate(r.Context(), streamActor(principal), l4forward.BatchCreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Template: body.Template, GroupIDs: groupIDs,
		Lines: body.Lines, IgnoreErrors: body.IgnoreErrors, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if errors.Is(err, l4forward.ErrBatchFailed) {
		// 未开忽略错误: nothing was written; the lines say which failed.
		writeJSONStatus(w, http.StatusUnprocessableEntity, result)
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleBatchStreamAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body l4forward.BatchActionRequest
	if err := decodeL4StreamJSON(w, r, &body); err != nil {
		if errors.Is(err, errL4UnsupportedMediaType) {
			s.writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	body.IdempotencyKey, body.RequestID = key, requestID(r.Context())
	result, err := s.streams.BatchAction(r.Context(), streamActor(principal), body)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type l4StreamWriteHandler struct {
	server    *Server
	service   l4StreamWriteService
	authorize func(http.ResponseWriter, *http.Request, string) (identity.Principal, bool)
}

var errL4UnsupportedMediaType = errors.New("unsupported L4 stream media type")

func (s *Server) handleCreateStream(w http.ResponseWriter, r *http.Request) {
	l4StreamWriteHandler{server: s, service: s.streams, authorize: s.requireStreamPermission}.handleCreate(w, r)
}

func (h l4StreamWriteHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := h.server.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createStreamRequest
	if err := decodeL4StreamJSON(w, r, &body); err != nil {
		if errors.Is(err, errL4UnsupportedMediaType) {
			h.server.writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
		h.server.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	targetScopeID, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "target_scope_id must be a UUID")
		return
	}
	ownerID, err := optionalUUID(body.OwnerID)
	if err != nil {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "owner_id must be a UUID")
		return
	}
	groupIDs, err := streamGroupIDs(body.GroupIDs)
	if err != nil {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group_ids must be an array of UUIDs")
		return
	}
	result, err := h.service.Create(r.Context(), streamActor(principal), l4forward.CreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.Fields, GroupIDs: groupIDs,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		h.server.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Forward.Revision))
	w.Header().Set("X-Publish-Intent-Version", strconv.FormatInt(result.Forward.PublishIntent.Version, 10))
	writeJSONStatus(w, http.StatusCreated, result.Forward)
}

func decodeL4StreamJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return errL4UnsupportedMediaType
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" {
		return errL4UnsupportedMediaType
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		return err
	}
	if !utf8.Valid(raw) {
		return errors.New("request body must be valid UTF-8")
	}
	if err := validateL4JSONSurrogates(raw); err != nil {
		return err
	}
	if err := validateL4JSONKeys(raw); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if listeners, supplied := fields["additional_listeners"]; supplied &&
		(len(listeners) == 0 || listeners[0] != '[') {
		return errors.New("additional_listeners must be an array")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	return decodeJSON(w, r, destination)
}

func validateL4JSONSurrogates(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); {
		if !inString {
			if raw[index] == '"' {
				inString = true
			}
			index++
			continue
		}
		switch raw[index] {
		case '"':
			inString = false
			index++
		case '\\':
			if index+1 >= len(raw) {
				return errors.New("incomplete JSON escape")
			}
			if raw[index+1] != 'u' {
				index += 2
				continue
			}
			code, ok := parseL4JSONHex(raw, index+2)
			if !ok {
				return errors.New("invalid JSON Unicode escape")
			}
			switch {
			case code >= 0xd800 && code <= 0xdbff:
				if index+12 > len(raw) || raw[index+6] != '\\' || raw[index+7] != 'u' {
					return errors.New("unpaired JSON high surrogate")
				}
				low, ok := parseL4JSONHex(raw, index+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("unpaired JSON high surrogate")
				}
				index += 12
			case code >= 0xdc00 && code <= 0xdfff:
				return errors.New("unpaired JSON low surrogate")
			default:
				index += 6
			}
		default:
			index++
		}
	}
	return nil
}

func parseL4JSONHex(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, digit := range raw[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func validateL4JSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := readL4JSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func readL4JSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			keys[key] = struct{}{}
			if err := readL4JSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := readL4JSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func (s *Server) handleListStreams(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	filter, err := parseStreamListFilter(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	result, err := s.streams.List(r.Context(), streamActor(principal), filter)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetStream(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "forwarding rule ID must be a UUID")
		return
	}
	item, err := s.streams.Get(r.Context(), streamActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleUpdateStream(w http.ResponseWriter, r *http.Request) {
	l4StreamWriteHandler{server: s, service: s.streams, authorize: s.requireStreamPermission}.handleUpdate(w, r)
}

func (h l4StreamWriteHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, "streams.manage")
	if !ok {
		return
	}
	key, ok := h.server.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "forwarding rule ID must be a UUID")
		return
	}
	ifMatchValues := r.Header.Values("If-Match")
	if len(ifMatchValues) != 1 {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain one quoted positive version")
		return
	}
	version, err := parseIfMatch(ifMatchValues[0])
	if err != nil || quoteVersion(version) != ifMatchValues[0] {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain one quoted positive version")
		return
	}
	var body updateStreamRequest
	if err := decodeL4StreamJSON(w, r, &body); err != nil {
		if errors.Is(err, errL4UnsupportedMediaType) {
			h.server.writeAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
			return
		}
		h.server.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if body.ExpectedRevision != version {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	groupIDs, err := optionalStreamGroupIDs(body.GroupIDs)
	if err != nil {
		h.server.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "group_ids must be an array of UUIDs")
		return
	}
	result, err := h.service.Update(r.Context(), streamActor(principal), l4forward.UpdateRequest{
		ID: id, ExpectedRevision: version, Fields: body.Fields, GroupIDs: groupIDs,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		h.server.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Forward.Revision))
	w.Header().Set("X-Publish-Intent-Version", strconv.FormatInt(result.Forward.PublishIntent.Version, 10))
	writeJSON(w, http.StatusOK, result.Forward)
}

func (s *Server) handleDeleteStream(w http.ResponseWriter, r *http.Request) {
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
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "forwarding rule ID must be a UUID")
		return
	}
	ifMatchValues := r.Header.Values("If-Match")
	if len(ifMatchValues) != 1 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain one quoted positive version")
		return
	}
	version, err := parseIfMatch(ifMatchValues[0])
	if err != nil || quoteVersion(version) != ifMatchValues[0] {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain one quoted positive version")
		return
	}
	result, err := s.streams.Delete(r.Context(), streamActor(principal), l4forward.DeleteRequest{
		ID: id, ExpectedRevision: version, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("X-Publish-Intent-Version", strconv.FormatInt(result.PublishIntent.Version, 10))
	w.WriteHeader(http.StatusNoContent)
}

func streamGroupIDs(raw []string) ([]uuid.UUID, error) {
	groupIDs := make([]uuid.UUID, 0, len(raw))
	for _, item := range raw {
		id, err := uuid.Parse(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		groupIDs = append(groupIDs, id)
	}
	return groupIDs, nil
}

// optionalStreamGroupIDs 区分「未提交 group_ids」与「提交了空数组」：前者保持原有分组，后者清空。
func optionalStreamGroupIDs(raw *[]string) (*[]uuid.UUID, error) {
	if raw == nil {
		return nil, nil
	}
	groupIDs, err := streamGroupIDs(*raw)
	if err != nil {
		return nil, err
	}
	return &groupIDs, nil
}

func (s *Server) requireStreamPermission(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func streamActor(principal identity.Principal) l4forward.Actor {
	return l4forward.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}

func parseStreamListFilter(r *http.Request) (l4forward.ListFilter, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return l4forward.ListFilter{}, l4forward.ErrInvalidInput
	}
	allowed := map[string]bool{
		"page": true, "limit": true, "search": true, "protocol": true, "enabled": true,
		"listen_port": true, "upstream": true, "display_id": true, "group_id": true, "package_product_id": true,
		"owner_display_id": true, "publication_state": true, "cname_domain": true, "cname_hostname": true,
		"region_id": true, "node_group_id": true, "sync_state": true, "admin_status": true,
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 {
			return l4forward.ListFilter{}, l4forward.ErrInvalidInput
		}
	}
	page, err := positiveIntOr(query.Get("page"), 1)
	if err != nil {
		return l4forward.ListFilter{}, err
	}
	limit, err := positiveIntOr(query.Get("limit"), 20)
	if err != nil {
		return l4forward.ListFilter{}, err
	}
	var enabled *bool
	if query.Has("enabled") {
		raw := query.Get("enabled")
		if raw != "true" && raw != "false" {
			return l4forward.ListFilter{}, l4forward.ErrInvalidInput
		}
		value := raw == "true"
		enabled = &value
	}
	if query.Has("protocol") && query.Get("protocol") != l4forward.ProtocolTCP && query.Get("protocol") != l4forward.ProtocolUDP ||
		query.Has("publication_state") && !l4forward.ValidPublicationState(query.Get("publication_state")) {
		return l4forward.ListFilter{}, l4forward.ErrInvalidInput
	}
	filter := l4forward.ListFilter{
		Page: page, Limit: limit, Search: query.Get("search"),
		Protocol: query.Get("protocol"), Enabled: enabled,
		Upstream: query.Get("upstream"), PublicationState: query.Get("publication_state"),
		CNAMEDomain: query.Get("cname_domain"), CNAMEHostname: query.Get("cname_hostname"),
		SyncState: query.Get("sync_state"), AdminStatus: query.Get("admin_status"),
	}
	if query.Has("upstream") && strings.TrimSpace(filter.Upstream) == "" {
		return l4forward.ListFilter{}, l4forward.ErrInvalidInput
	}
	if (query.Has("cname_domain") && strings.TrimSpace(filter.CNAMEDomain) == "") ||
		(query.Has("cname_hostname") && strings.TrimSpace(filter.CNAMEHostname) == "") {
		return l4forward.ListFilter{}, l4forward.ErrInvalidInput
	}
	for key, target := range map[string]**int64{"listen_port": &filter.ListenPort, "display_id": &filter.DisplayID, "owner_display_id": &filter.OwnerDisplayID} {
		if !query.Has(key) {
			continue
		}
		raw := query.Get(key)
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 || strconv.FormatInt(value, 10) != raw || (key == "listen_port" && value > 65535) {
			return l4forward.ListFilter{}, l4forward.ErrInvalidInput
		}
		*target = &value
	}
	if query.Has("sync_state") && filter.SyncState != l4forward.SyncStateDone && filter.SyncState != l4forward.SyncStatePending &&
		filter.SyncState != l4forward.SyncStateFailed || query.Has("admin_status") && !l4forward.ValidAdminStatus(filter.AdminStatus) {
		return l4forward.ListFilter{}, l4forward.ErrInvalidInput
	}
	for key, target := range map[string]**uuid.UUID{"group_id": &filter.GroupID, "package_product_id": &filter.PackageProductID,
		"region_id": &filter.RegionID, "node_group_id": &filter.NodeGroupID} {
		if !query.Has(key) {
			continue
		}
		value, err := uuid.Parse(query.Get(key))
		if err != nil || value == uuid.Nil {
			return l4forward.ListFilter{}, l4forward.ErrInvalidInput
		}
		*target = &value
	}
	return filter, nil
}
