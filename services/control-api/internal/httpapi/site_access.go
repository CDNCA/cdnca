package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/siteaccess"
	"github.com/google/uuid"
)

// handleGetSiteAccess is a site's request handling (GET
// /v1/sites/{site_id}/access, sites.read): host redirects,
// HSTS, compression, per-client limits, basic auth users (names only),
// maintenance page and the forced HTTPS status/exclusions. ETag is the site
// version.
func (s *Server) handleGetSiteAccess(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("site_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	state, err := s.siteAccess.Get(r.Context(), siteAccessActor(principal), id)
	if err != nil {
		s.writeSiteAccessError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePutSiteAccess replaces them (PUT, Idempotency-Key, If-Match site
// version, sites.manage). A basic auth user without a password keeps its
// stored secret; passwords are never returned.
func (s *Server) handlePutSiteAccess(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("site_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	version, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive version")
		return
	}
	var settings siteaccess.Settings
	if err := decodeJSON(w, r, &settings); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	state, err := s.siteAccess.Update(r.Context(), siteAccessActor(principal), siteaccess.UpdateRequest{
		SiteID: id, ExpectedRevision: version, Settings: settings, IdempotencyKey: key,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSiteAccessError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) writeSiteAccessError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, siteaccess.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "validation_error", "site access settings are invalid")
	case errors.Is(err, siteaccess.ErrNeedsHTTPS):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "site_access_https_required",
			"HSTS and forced HTTPS settings need the site's HTTPS")
	case errors.Is(err, siteaccess.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, siteaccess.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, siteaccess.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	case errors.Is(err, siteaccess.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	default:
		s.writeError(w, r, err)
	}
}

func siteAccessActor(principal identity.Principal) siteaccess.Actor {
	return siteaccess.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
