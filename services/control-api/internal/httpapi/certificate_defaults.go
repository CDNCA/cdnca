package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/certdefaults"
	"github.com/google/uuid"
)

type certificateDefaultsRequest struct {
	TargetScopeID    string  `json:"target_scope_id"`
	TargetUserID     string  `json:"target_user_id"`
	CertificateType  string  `json:"certificate_type"`
	DNSProviderID    *string `json:"dns_provider_id"`
	Issuer           *string `json:"issuer"`
	ExpectedRevision int64   `json:"expected_revision"`
}

func (s *Server) handleGetCertificateDefaults(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "certificates.read")
	if !ok {
		return
	}
	scopeID, userID, err := certificateDefaultsTarget(r.URL.Query().Get("target_scope_id"), r.URL.Query().Get("target_user_id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.certificateDefaults.Get(r.Context(), certdefaults.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, certdefaults.Request{TargetScopeID: scopeID, TargetUserID: userID})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateCertificateDefaults(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePermission(w, r, "certificates.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body certificateDefaultsRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	scopeID, userID, err := certificateDefaultsTarget(body.TargetScopeID, body.TargetUserID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var providerID *uuid.UUID
	if body.DNSProviderID != nil && *body.DNSProviderID != "" {
		parsed, parseErr := uuid.Parse(*body.DNSProviderID)
		if parseErr != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "dns_provider_id must be a UUID")
			return
		}
		providerID = &parsed
	}
	result, err := s.certificateDefaults.Update(r.Context(), certdefaults.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, certdefaults.UpdateRequest{
		TargetScopeID: scopeID, TargetUserID: userID, CertificateType: body.CertificateType, DNSProviderID: providerID,
		Issuer: emptyAsNil(body.Issuer), ExpectedRevision: body.ExpectedRevision, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}

func certificateDefaultsTarget(rawScopeID, rawUserID string) (uuid.UUID, uuid.UUID, error) {
	var scopeID, userID uuid.UUID
	var err error
	if rawScopeID != "" {
		scopeID, err = uuid.Parse(rawScopeID)
		if err != nil {
			return uuid.Nil, uuid.Nil, certdefaults.ErrInvalidInput
		}
	}
	if rawUserID != "" {
		userID, err = uuid.Parse(rawUserID)
		if err != nil {
			return uuid.Nil, uuid.Nil, certdefaults.ErrInvalidInput
		}
	}
	return scopeID, userID, nil
}

// emptyAsNil treats "" like an omitted optional field (the platform default).
func emptyAsNil(value *string) *string {
	if value == nil || *value == "" {
		return nil
	}
	return value
}
