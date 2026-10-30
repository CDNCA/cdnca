package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sitegroup"
	"github.com/google/uuid"
)

type siteGroupCreateRequest struct {
	TargetScopeID string          `json:"target_scope_id"`
	Name          string          `json:"name"`
	Remark        json.RawMessage `json:"remark,omitempty"`
}

type siteGroupWriteRequest struct {
	ExpectedRevision int64           `json:"expected_revision"`
	Name             string          `json:"name,omitempty"`
	Remark           json.RawMessage `json:"remark,omitempty"`
}

func (s *Server) handleListSiteGroups(w http.ResponseWriter, r *http.Request) {
	if s.siteGroups == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "site_group_unavailable", "site group service is unavailable")
		return
	}
	actor, scopeID, ok := s.siteGroupActorAndScope(w, r, r.URL.Query().Get("scope_id"))
	if !ok {
		return
	}
	page, err := positiveIntOr(r.URL.Query().Get("page"), 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page is invalid")
		return
	}
	limit, err := positiveIntOr(r.URL.Query().Get("limit"), 20)
	if err != nil || limit > 100 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit is invalid")
		return
	}
	result, err := s.siteGroups.List(r.Context(), actor, sitegroup.ListRequest{TargetScopeID: scopeID, Page: page, Limit: limit})
	if err != nil {
		s.writeSiteGroupError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateSiteGroup(w http.ResponseWriter, r *http.Request) {
	if s.siteGroups == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "site_group_unavailable", "site group service is unavailable")
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body siteGroupCreateRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	actor, scopeID, ok := s.siteGroupActorAndScope(w, r, body.TargetScopeID)
	if !ok {
		return
	}
	remark, err := siteGroupRemark(body.Remark)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "remark must be a string")
		return
	}
	result, err := s.siteGroups.Create(r.Context(), actor, sitegroup.CreateRequest{
		TargetScopeID: scopeID,
		Name:          body.Name,
		Remark:        remark,
		WriteMetadata: sitegroup.WriteMetadata{IdempotencyKey: key, RequestID: requestID(r.Context())},
	})
	if err != nil {
		s.writeSiteGroupError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Group.Revision))
	if result.Replayed {
		writeJSONStatus(w, http.StatusCreated, result.Response)
		return
	}
	writeJSONStatus(w, http.StatusCreated, result.Group)
}

func (s *Server) handleRenameSiteGroup(w http.ResponseWriter, r *http.Request) {
	siteID, ok := s.parseSiteGroupID(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, ok := s.siteGroupWriteVersion(w, r)
	if !ok {
		return
	}
	var body siteGroupWriteRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if body.ExpectedRevision != revision {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must match If-Match")
		return
	}
	actor, scopeID, ok := s.siteGroupActorAndScope(w, r, r.URL.Query().Get("scope_id"))
	if !ok {
		return
	}
	remark, err := siteGroupRemark(body.Remark)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "remark must be a string")
		return
	}
	result, err := s.siteGroups.Rename(r.Context(), actor, sitegroup.RenameRequest{
		TargetScopeID: scopeID, ID: siteID, ExpectedRevision: revision, Name: body.Name, Remark: remark,
		WriteMetadata: sitegroup.WriteMetadata{IdempotencyKey: key, RequestID: requestID(r.Context())},
	})
	if err != nil {
		s.writeSiteGroupError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Group.Revision))
	if result.Replayed {
		writeJSONStatus(w, http.StatusOK, result.Response)
		return
	}
	writeJSON(w, http.StatusOK, result.Group)
}

func (s *Server) handleDeleteSiteGroup(w http.ResponseWriter, r *http.Request) {
	siteID, ok := s.parseSiteGroupID(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, ok := s.siteGroupWriteVersion(w, r)
	if !ok {
		return
	}
	actor, scopeID, ok := s.siteGroupActorAndScope(w, r, r.URL.Query().Get("scope_id"))
	if !ok {
		return
	}
	_, err := s.siteGroups.Delete(r.Context(), actor, sitegroup.DeleteRequest{
		TargetScopeID: scopeID, ID: siteID, ExpectedRevision: revision,
		WriteMetadata: sitegroup.WriteMetadata{IdempotencyKey: key, RequestID: requestID(r.Context())},
	})
	if err != nil {
		s.writeSiteGroupError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteGroupActorAndScope(w http.ResponseWriter, r *http.Request, rawScope string) (sitegroup.Actor, uuid.UUID, bool) {
	scopeID, err := uuid.Parse(strings.TrimSpace(rawScope))
	if err != nil || scopeID == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "scope_id must be a UUID")
		return sitegroup.Actor{}, uuid.Nil, false
	}
	actor, ok := s.siteGroupActor(w, r)
	return actor, scopeID, ok
}

func (s *Server) siteGroupActor(w http.ResponseWriter, r *http.Request) (sitegroup.Actor, bool) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, raw, found := strings.Cut(authorization, " ")
	if !found || raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " \t\r\n") {
		s.writeError(w, r, identity.ErrInvalidSession)
		return sitegroup.Actor{}, false
	}
	kind := sitegroup.CredentialSession
	if strings.EqualFold(scheme, "CdncaKey") {
		kind = sitegroup.CredentialAPIKey
	} else if !strings.EqualFold(scheme, "Bearer") {
		s.writeError(w, r, identity.ErrInvalidSession)
		return sitegroup.Actor{}, false
	}
	return sitegroup.Actor{Credential: sitegroup.Credential{Kind: kind, Raw: raw}}, true
}

func siteGroupRemark(raw json.RawMessage) (*string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var remark *string
	if err := json.Unmarshal(raw, &remark); err != nil || remark == nil {
		return nil, errors.New("remark must be a string")
	}
	return remark, nil
}

func (s *Server) parseSiteGroupID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site group ID must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

func (s *Server) siteGroupWriteVersion(w http.ResponseWriter, r *http.Request) (int64, bool) {
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

func (s *Server) writeSiteGroupError(w http.ResponseWriter, r *http.Request, err error) {
	if located, ok := fielderr.As(err); ok && errors.Is(err, sitegroup.ErrInvalidInput) {
		s.writeFieldError(w, r, located.Field, located.Reason)
		return
	}
	status := http.StatusInternalServerError
	code := "site_group_unavailable"
	message := "site group service is unavailable"
	switch {
	case errors.Is(err, sitegroup.ErrAuthenticationRequired):
		status, code, message = http.StatusUnauthorized, "authentication_required", "authentication is required"
	case errors.Is(err, sitegroup.ErrPermissionDenied):
		status, code, message = http.StatusForbidden, "permission_denied", "permission denied"
	case errors.Is(err, sitegroup.ErrInvalidInput), errors.Is(err, sitegroup.ErrInvalidReference):
		status, code, message = http.StatusBadRequest, "validation_error", "site group request is invalid"
	case errors.Is(err, sitegroup.ErrNotFound):
		status, code, message = http.StatusNotFound, "not_found", "site group was not found"
	case errors.Is(err, sitegroup.ErrNameConflict):
		status, code, message = http.StatusConflict, "site_group_name_conflict", "site group name is already in use"
	case errors.Is(err, sitegroup.ErrRevisionConflict):
		status, code, message = http.StatusConflict, "revision_conflict", "site group changed; reload and retry"
	case errors.Is(err, sitegroup.ErrIdempotencyConflict):
		status, code, message = http.StatusConflict, "idempotency_conflict", "idempotency key was reused with different input"
	case errors.Is(err, sitegroup.ErrInUse):
		status, code, message = http.StatusConflict, "site_group_in_use", "site group is still used by a site"
	case errors.Is(err, sitegroup.ErrResultUnknown):
		status, code, message = http.StatusServiceUnavailable, "result_unknown", "site group write result is unknown"
	}
	s.writeAPIError(w, r, status, code, message)
}
