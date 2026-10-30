package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

type updateManagedUserSecondaryVerificationRequest struct {
	ExpectedRevision *int64  `json:"expected_revision"`
	Enabled          *bool   `json:"enabled"`
	Deadline         *string `json:"deadline"`
	ExpiryAction     *string `json:"expiry_action"`
}

func (body *updateManagedUserSecondaryVerificationRequest) UnmarshalJSON(raw []byte) error {
	if err := validateL4JSONKeys(raw); err != nil {
		return err
	}
	type fields updateManagedUserSecondaryVerificationRequest
	var value fields
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*body = updateManagedUserSecondaryVerificationRequest(value)
	return nil
}

func (s *Server) handleGetManagedUserSecondaryVerification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, ok := s.requireLoginSecuritySession(w, r)
	if !ok {
		return
	}
	userID, scopeID, ok := loginSecurityIDs(r)
	if !ok {
		s.writeAPIError(w, r, 400, "validation_error", "secondary verification target is invalid")
		return
	}
	result, err := s.identity.GetManagedUserSecondaryVerification(r.Context(), identity.Actor{UserID: session.Principal.UserID,
		ScopeID: session.Principal.ScopeID, ScopeKind: session.Principal.ScopeKind, SessionID: session.SessionID}, userID, scopeID)
	if err != nil {
		s.writeSecondaryVerificationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateManagedUserSecondaryVerification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, ok := s.requireLoginSecuritySession(w, r)
	if !ok {
		return
	}
	userID, scopeID, ok := loginSecurityIDs(r)
	if !ok {
		s.writeAPIError(w, r, 400, "validation_error", "secondary verification target is invalid")
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body updateManagedUserSecondaryVerificationRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, 400, "invalid_request", "request body is invalid")
		return
	}
	if body.ExpectedRevision == nil || body.Enabled == nil || body.ExpiryAction == nil {
		s.writeAPIError(w, r, 400, "validation_error", "secondary verification fields are required")
		return
	}
	var deadline *time.Time
	if body.Deadline != nil {
		parsed, err := time.Parse(time.RFC3339, *body.Deadline)
		if err != nil {
			s.writeAPIError(w, r, 400, "validation_error", "deadline must be an RFC 3339 timestamp")
			return
		}
		deadline = &parsed
	}
	result, err := s.identity.UpdateManagedUserSecondaryVerification(r.Context(), identity.Actor{UserID: session.Principal.UserID,
		ScopeID: session.Principal.ScopeID, ScopeKind: session.Principal.ScopeKind, SessionID: session.SessionID},
		identity.UpdateManagedUserSecondaryVerificationInput{
			UserID: userID, TenantScopeID: scopeID, ExpectedRevision: *body.ExpectedRevision, Enabled: *body.Enabled,
			Deadline: deadline, ExpiryAction: *body.ExpiryAction, IdempotencyKey: key, RequestID: requestID(r.Context()),
		})
	if err != nil {
		s.writeSecondaryVerificationError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeSecondaryVerificationError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, identity.ErrSecondaryVerificationUnavailable) {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "secondary_verification_unavailable", "secondary verification is temporarily unavailable")
		return
	}
	s.writeError(w, r, err)
}
