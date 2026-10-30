package httpapi

import (
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
)

type createURLAuthPolicyRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	urlauthpolicy.PolicyFields
}

type revokeURLAuthKeyRequest struct {
	KeyID string `json:"key_id"`
}

func (s *Server) handleCreateURLAuthPolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireURLAuthPolicyPermission(w, r, "url_auth_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createURLAuthPolicyRequest
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
	result, err := s.urlAuthPolicies.Create(r.Context(), urlAuthPolicyActor(principal), urlauthpolicy.CreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.PolicyFields, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSONStatus(w, http.StatusCreated, result)
}

func (s *Server) handleListURLAuthPolicies(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireURLAuthPolicyPermission(w, r, "url_auth_policies.read")
	if !ok {
		return
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 20)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	var siteID uuid.UUID
	if raw := strings.TrimSpace(r.URL.Query().Get("site_id")); raw != "" {
		siteID, err = uuid.Parse(raw)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site_id must be a UUID")
			return
		}
	}
	result, err := s.urlAuthPolicies.List(r.Context(), urlAuthPolicyActor(principal), urlauthpolicy.ListFilter{Page: page, Limit: limit, Status: r.URL.Query().Get("status"), Name: r.URL.Query().Get("name"), SiteID: siteID})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetURLAuthPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.urlAuthPolicyResource(w, r, "url_auth_policies.read")
	if !ok {
		return
	}
	item, err := s.urlAuthPolicies.Get(r.Context(), urlAuthPolicyActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleUpdateURLAuthPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.urlAuthPolicyResource(w, r, "url_auth_policies.manage")
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
	var fields urlauthpolicy.PolicyFields
	if err := decodeJSON(w, r, &fields); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.urlAuthPolicies.Update(r.Context(), urlAuthPolicyActor(principal), urlauthpolicy.UpdateRequest{ID: id, ExpectedRevision: revision, Fields: fields, IdempotencyKey: key, RequestID: requestID(r.Context())})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRotateURLAuthPolicy(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.urlAuthPolicyResource(w, r, "url_auth_policies.manage")
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
	result, err := s.urlAuthPolicies.Rotate(r.Context(), urlAuthPolicyActor(principal), urlauthpolicy.RotateRequest{ID: id, ExpectedRevision: revision, IdempotencyKey: key, RequestID: requestID(r.Context())})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRevokeURLAuthPolicyKey(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.urlAuthPolicyResource(w, r, "url_auth_policies.manage")
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
	var body revokeURLAuthKeyRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.urlAuthPolicies.Revoke(r.Context(), urlAuthPolicyActor(principal), urlauthpolicy.RevokeRequest{ID: id, KeyID: body.KeyID, ExpectedRevision: revision, IdempotencyKey: key, RequestID: requestID(r.Context())})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Policy.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetURLAuthPolicySnapshot(w http.ResponseWriter, r *http.Request) {
	principal, id, ok := s.urlAuthPolicyResource(w, r, "url_auth_policies.read")
	if !ok {
		return
	}
	result, err := s.urlAuthPolicies.Snapshot(r.Context(), urlAuthPolicyActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) urlAuthPolicyResource(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, uuid.UUID, bool) {
	principal, ok := s.requireURLAuthPolicyPermission(w, r, permission)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "URL auth policy ID must be a UUID")
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, id, true
}

func (s *Server) requireURLAuthPolicyPermission(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
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

func urlAuthPolicyActor(principal identity.Principal) urlauthpolicy.Actor {
	return urlauthpolicy.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
