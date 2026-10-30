package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/siteschedule302"
	"github.com/google/uuid"
)

// handleGetSiteSchedule302 is a site's HTTP 302 scheduling (GET
// /v1/sites/{id}/schedule302, sites.read). ETag is the site
// version.
func (s *Server) handleGetSiteSchedule302(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	state, err := s.siteSchedule302.Get(r.Context(), siteSchedule302Actor(principal), id)
	if err != nil {
		s.writeSiteSchedule302Error(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePutSiteSchedule302 replaces the site's settings (PUT,
// Idempotency-Key, If-Match site version, sites.manage).
func (s *Server) handlePutSiteSchedule302(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var settings siteschedule302.Settings
	if err := decodeJSON(w, r, &settings); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	state, err := s.siteSchedule302.Update(r.Context(), siteSchedule302Actor(principal), siteschedule302.UpdateRequest{
		SiteID: id, ExpectedRevision: version, Settings: settings, IdempotencyKey: key,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSiteSchedule302Error(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) writeSiteSchedule302Error(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, siteschedule302.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site 302 scheduling request is invalid")
	case errors.Is(err, siteschedule302.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, siteschedule302.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, siteschedule302.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	case errors.Is(err, siteschedule302.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, siteschedule302.ErrNoPlainListener):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "schedule302_no_plain_http",
			"302 scheduling lands on plain HTTP; the site needs an HTTP port")
	default:
		s.writeError(w, r, err)
	}
}

func siteSchedule302Actor(principal identity.Principal) siteschedule302.Actor {
	return siteschedule302.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
