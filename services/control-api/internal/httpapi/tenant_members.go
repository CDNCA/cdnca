package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// Tenant members / sub-accounts (identity.TenantMember): the tenant
// administrator of the caller's own scope; never a platform session.

type createTenantMemberRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

func (s *Server) tenantMemberPrincipal(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	if principal.ScopeKind != "tenant" {
		s.writeError(w, r, identity.ErrPermissionDenied)
		return identity.Principal{}, false
	}
	return principal, true
}

func (s *Server) writeTenantMemberError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrTenantMemberOutranks):
		s.writeAPIError(w, r, http.StatusForbidden, "tenant_member_outranks", "this member holds permissions you do not have")
	case errors.Is(err, identity.ErrTenantMemberProtected):
		s.writeAPIError(w, r, http.StatusConflict, "tenant_member_protected", "the tenant owner and yourself cannot be changed here")
	case errors.Is(err, identity.ErrTenantMemberShared):
		s.writeAPIError(w, r, http.StatusConflict, "tenant_member_shared", "the member also belongs to another account")
	case errors.Is(err, identity.ErrTenantMemberOwnsResources):
		var owned *identity.TenantMemberOwnsResourcesError
		if errors.As(err, &owned) {
			writeJSONStatus(w, http.StatusConflict, map[string]any{"error": map[string]any{
				"code": "tenant_member_owns_resources", "message": "the member still owns resources",
				"request_id": requestID(r.Context()), "resources": owned.Resources}})
			return
		}
		s.writeAPIError(w, r, http.StatusConflict, "tenant_member_owns_resources", "the member still owns resources")
	case errors.Is(err, identity.ErrTenantMemberTransferTarget):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "tenant_member_transfer_target_invalid", "transfer_to must be another active member")
	case errors.Is(err, identity.ErrMembershipNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "tenant_member_not_found", "member was not found")
	case errors.Is(err, identity.ErrTenantMemberPasswordResetGone):
		s.writeAPIError(w, r, http.StatusGone, "tenant_member_password_reset_result_gone",
			"the reset result was already retrieved or expired; the password was not reset again")
	case errors.Is(err, identity.ErrTenantMemberPasswordResetUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "tenant_member_password_reset_unavailable", "password reset is unavailable")
	case errors.Is(err, identity.ErrMembershipStatusConflict):
		s.writeAPIError(w, r, http.StatusConflict, "tenant_member_status_conflict", "member status changed")
	default:
		s.writeError(w, r, err)
	}
}

func (s *Server) handleListTenantMembers(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return
	}
	members, err := s.identity.ListTenantMembers(r.Context(), principal)
	if err != nil {
		s.writeTenantMemberError(w, r, err)
		return
	}
	if members == nil {
		members = []identity.TenantMember{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": members})
}

func (s *Server) handleCreateTenantMember(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return
	}
	var body createTenantMemberRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request body is invalid")
		return
	}
	member, err := s.identity.CreateTenantMember(r.Context(), principal, identity.CreateTenantMemberInput{
		Username: body.Username, DisplayName: body.DisplayName, Email: body.Email, Password: body.Password, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeTenantMemberError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, member)
}

func (s *Server) tenantMemberTarget(w http.ResponseWriter, r *http.Request) (identity.Principal, uuid.UUID, bool) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	userID, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "user_id is invalid")
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, userID, true
}

// tenantMemberTransferTo reads the optional transfer_to query parameter.
func (s *Server) tenantMemberTransferTo(w http.ResponseWriter, r *http.Request) (*uuid.UUID, bool) {
	raw := r.URL.Query().Get("transfer_to")
	if raw == "" {
		return nil, true
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "transfer_to is invalid")
		return nil, false
	}
	return &id, true
}

func (s *Server) handleDeleteTenantMember(w http.ResponseWriter, r *http.Request) {
	principal, userID, ok := s.tenantMemberTarget(w, r)
	if !ok {
		return
	}
	transferTo, ok := s.tenantMemberTransferTo(w, r)
	if !ok {
		return
	}
	if err := s.identity.DeleteTenantMember(r.Context(), principal, userID, transferTo, requestID(r.Context())); err != nil {
		s.writeTenantMemberError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleResetTenantMemberPassword resets with an Idempotency-Key. If the
// response was lost, the same request (same key) returns the retained result
// once within 10 minutes instead of resetting again (TENANT-PWRESET-UNKNOWN).
func (s *Server) handleResetTenantMemberPassword(w http.ResponseWriter, r *http.Request) {
	principal, userID, ok := s.tenantMemberTarget(w, r)
	if !ok {
		return
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "Idempotency-Key is required")
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	reset, err := s.identity.ResetTenantMemberPassword(r.Context(), principal, userID, key, requestID(r.Context()))
	if err != nil {
		s.writeTenantMemberError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, reset)
}

func (s *Server) handleSetTenantMemberStatus(active bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.tenantMemberPrincipal(w, r)
		if !ok {
			return
		}
		userID, err := uuid.Parse(r.PathValue("user_id"))
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "user_id is invalid")
			return
		}
		var transferTo *uuid.UUID
		if !active {
			if transferTo, ok = s.tenantMemberTransferTo(w, r); !ok {
				return
			}
		}
		member, err := s.identity.SetTenantMemberStatus(r.Context(), principal, userID, active, transferTo, requestID(r.Context()))
		if err != nil {
			s.writeTenantMemberError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, member)
	}
}

type tenantMemberPasswordChangeRequest struct {
	Required *bool `json:"required"`
}

// handleSetTenantMemberPasswordChange sets or clears "change the password at
// the next sign-in" (identity.SetTenantMemberPasswordChangeRequired).
func (s *Server) handleSetTenantMemberPasswordChange(w http.ResponseWriter, r *http.Request) {
	principal, userID, ok := s.tenantMemberTarget(w, r)
	if !ok {
		return
	}
	var body tenantMemberPasswordChangeRequest
	if err := decodeJSON(w, r, &body); err != nil || body.Required == nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "required must be a boolean")
		return
	}
	member, err := s.identity.SetTenantMemberPasswordChangeRequired(r.Context(), principal, userID, *body.Required, requestID(r.Context()))
	if err != nil {
		s.writeTenantMemberError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

// Tenant member email invitations (identity.TenantMemberInvitation).

func (s *Server) writeTenantMemberInvitationError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrTenantMemberInvitationUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "tenant_member_invitation_unavailable", "email invitations are not available: the email channel is off or not configured")
	case errors.Is(err, identity.ErrTenantMemberInvitationInvalid):
		s.writeAPIError(w, r, http.StatusGone, "tenant_member_invitation_invalid", "the invitation link is invalid, used or expired")
	case errors.Is(err, identity.ErrTenantMemberEmailTaken):
		s.writeAPIError(w, r, http.StatusConflict, "tenant_member_email_taken", "the email address already belongs to an account")
	case errors.Is(err, identity.ErrMembershipNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "tenant_member_invitation_not_found", "pending invitation was not found")
	default:
		s.writeError(w, r, err)
	}
}

func (s *Server) handleListTenantMemberInvitations(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return
	}
	items, err := s.identity.ListTenantMemberInvitations(r.Context(), principal)
	if err != nil {
		s.writeTenantMemberInvitationError(w, r, err)
		return
	}
	if items == nil {
		items = []identity.TenantMemberInvitation{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleInviteTenantMember(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request body is invalid")
		return
	}
	invitation, err := s.identity.InviteTenantMember(r.Context(), principal, body.Email, requestID(r.Context()))
	if err != nil {
		s.writeTenantMemberInvitationError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusCreated, invitation)
}

func (s *Server) handleRevokeTenantMemberInvitation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("invitation_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invitation_id is invalid")
		return
	}
	if err := s.identity.RevokeTenantMemberInvitation(r.Context(), principal, id, requestID(r.Context())); err != nil {
		s.writeTenantMemberInvitationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAcceptTenantMemberInvitation is anonymous: the invitation token is
// the credential. The new member signs in normally afterwards.
func (s *Server) handleAcceptTenantMemberInvitation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "request body is invalid")
		return
	}
	member, err := s.identity.AcceptTenantMemberInvitation(r.Context(), identity.AcceptTenantMemberInvitationInput{
		Token: body.Token, Username: body.Username, DisplayName: body.DisplayName, Password: body.Password, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeTenantMemberInvitationError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusCreated, member)
}
