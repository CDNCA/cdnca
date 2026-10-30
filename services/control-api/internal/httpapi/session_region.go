package httpapi

import (
	"net/http"
	"strings"
)

type sessionRegionVerificationRequest struct {
	Password string `json:"password"`
}

// handleVerifySessionRegion re-binds the caller's session to its current
// region after session_region_changed (identity.VerifySessionRegion).
func (s *Server) handleVerifySessionRegion(w http.ResponseWriter, r *http.Request) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	scheme, rawToken, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rawToken) == "" || s.identity == nil {
		s.writeAPIError(w, r, http.StatusUnauthorized, "invalid_session", "authentication is required")
		return
	}
	var body sessionRegionVerificationRequest
	if err := decodeJSON(w, r, &body); err != nil || body.Password == "" || len(body.Password) > 1024 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "password is required")
		return
	}
	if err := s.identity.VerifySessionRegion(r.Context(), strings.TrimSpace(rawToken), body.Password, s.requestInfo(r)); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
