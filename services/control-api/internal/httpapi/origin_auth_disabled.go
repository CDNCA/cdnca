package httpapi

import "net/http"

// handleOriginAuthDisabled answers every origin authentication route while
// ORIGIN_AUTH_RUNTIME_ENABLED is off.
func (s *Server) handleOriginAuthDisabled(w http.ResponseWriter, r *http.Request) {
	s.writeAPIError(w, r, http.StatusServiceUnavailable, "feature_disabled",
		"origin authentication is not enabled on this control plane (ORIGIN_AUTH_RUNTIME_ENABLED)")
}
