package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/ccreference"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type ccReferenceWriteBody struct {
	TargetScopeID string          `json:"target_scope_id"`
	OwnerID       string          `json:"owner_id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Enabled       bool            `json:"enabled"`
	Field         string          `json:"field"`
	Operator      string          `json:"operator"`
	Key           string          `json:"key"`
	Values        []string        `json:"values"`
	Type          string          `json:"type"`
	Parameters    json.RawMessage `json:"parameters"`
}

func (s *Server) handleCreateCCReference(w http.ResponseWriter, r *http.Request, kind ccreference.Kind) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body ccReferenceWriteBody
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	scopeID, err := optionalUUID(body.TargetScopeID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "target_scope_id must be a UUID")
		return
	}
	ownerID, err := optionalUUID(body.OwnerID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "owner_id must be a UUID")
		return
	}
	request := ccreference.CreateRequest{Kind: kind, TargetScopeID: scopeID, OwnerUserID: ownerID, IdempotencyKey: key, RequestID: ccReferenceRequestID(r)}
	if kind == ccreference.KindMatcher {
		request.Matcher = ccreference.MatcherFields{Name: body.Name, Description: body.Description, Enabled: body.Enabled, Field: body.Field, Operator: body.Operator, Key: body.Key, Values: body.Values}
	} else {
		request.Filter = ccreference.FilterFields{Name: body.Name, Description: body.Description, Enabled: body.Enabled, Type: body.Type, Parameters: body.Parameters}
	}
	result, err := s.ccReferences.Create(r.Context(), securityPolicyCCReferenceActor(principal), request)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Item.Revision))
	writeJSONStatus(w, http.StatusCreated, mapCCReferenceForScope(result.Item, principal.ScopeKind))
}

func (s *Server) handleGetCCReference(w http.ResponseWriter, r *http.Request, kind ccreference.Kind) {
	principal, id, ok := s.ccReferenceResource(w, r, kind, "security_policies.read")
	if !ok {
		return
	}
	item, err := s.ccReferences.Get(r.Context(), securityPolicyCCReferenceActor(principal), kind, id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSON(w, http.StatusOK, mapCCReferenceForScope(item, principal.ScopeKind))
}

func (s *Server) handleUpdateCCReference(w http.ResponseWriter, r *http.Request, kind ccreference.Kind) {
	principal, id, ok := s.ccReferenceResource(w, r, kind, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var body ccReferenceWriteBody
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	request := ccreference.UpdateRequest{Kind: kind, ID: id, ExpectedRevision: revision, IdempotencyKey: key, RequestID: ccReferenceRequestID(r)}
	if kind == ccreference.KindMatcher {
		request.Matcher = ccreference.MatcherFields{Name: body.Name, Description: body.Description, Enabled: body.Enabled, Field: body.Field, Operator: body.Operator, Key: body.Key, Values: body.Values}
	} else {
		request.Filter = ccreference.FilterFields{Name: body.Name, Description: body.Description, Enabled: body.Enabled, Type: body.Type, Parameters: body.Parameters}
	}
	result, err := s.ccReferences.Update(r.Context(), securityPolicyCCReferenceActor(principal), request)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Item.Revision))
	writeJSON(w, http.StatusOK, mapCCReferenceForScope(result.Item, principal.ScopeKind))
}

func (s *Server) handleDeleteCCReference(w http.ResponseWriter, r *http.Request, kind ccreference.Kind) {
	principal, id, ok := s.ccReferenceResource(w, r, kind, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	result, err := s.ccReferences.Delete(r.Context(), securityPolicyCCReferenceActor(principal), ccreference.DeleteRequest{Kind: kind, ID: id, ExpectedRevision: revision, IdempotencyKey: key, RequestID: ccReferenceRequestID(r)})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetCCReferenceEnabled(w http.ResponseWriter, r *http.Request, kind ccreference.Kind, enabled bool) {
	principal, id, ok := s.ccReferenceResource(w, r, kind, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	result, err := s.ccReferences.SetEnabled(r.Context(), securityPolicyCCReferenceActor(principal), kind, id, revision, enabled, key, ccReferenceRequestID(r))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Item.Revision))
	writeJSON(w, http.StatusOK, mapCCReferenceForScope(result.Item, principal.ScopeKind))
}

func (s *Server) ccReferenceResource(w http.ResponseWriter, r *http.Request, kind ccreference.Kind, permission string) (identity.Principal, uuid.UUID, bool) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, permission)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil || id == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "CC reference ID must be a UUID")
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, id, true
}

func ccReferenceRequestID(r *http.Request) string {
	if value := requestID(r.Context()); value != "" {
		return value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" {
		return value
	}
	return uuid.NewString()
}
