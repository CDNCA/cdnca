package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

type accountLocaleRequest struct {
	Locale string `json:"locale"`
}

// handleSetAccountLocale stores the console language of the
// signed-in user (platform or tenant session); notifications to that user use
// the matching template language.
func (s *Server) handleSetAccountLocale(w http.ResponseWriter, r *http.Request) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var body accountLocaleRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if !notification.ValidLocale(body.Locale) {
		s.writeFieldError(w, r, "locale", fielderr.Invalid)
		return
	}
	if s.pool == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_locale_unavailable", "account locale is unavailable")
		return
	}
	if _, err := s.pool.Exec(r.Context(), `UPDATE users SET locale=$2 WHERE id=$1 AND locale IS DISTINCT FROM $2`,
		principal.UserID, body.Locale); err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_locale_unavailable", "account locale is unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
