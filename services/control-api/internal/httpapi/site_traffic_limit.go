package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sitetrafficlimit"
	"github.com/google/uuid"
)

// handleGetSiteTrafficLimit is a website's own traffic caps and their
// enforcement (GET /v1/sites/{site_id}/traffic-limit, sites.read;
// ge-analytics). ETag is the site version.
func (s *Server) handleGetSiteTrafficLimit(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("site_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	state, err := s.siteTrafficLimits.Get(r.Context(), siteTrafficLimitActor(principal), id)
	if err != nil {
		s.writeSiteTrafficLimitError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePutSiteTrafficLimit replaces the site's caps (PUT, Idempotency-Key,
// If-Match site version, sites.manage). The site's next release carries the
// enforcement; an automatic scope publishes it.
func (s *Server) handlePutSiteTrafficLimit(w http.ResponseWriter, r *http.Request) {
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
	var setting sitetrafficlimit.Setting
	if err := decodeJSON(w, r, &setting); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	state, err := s.siteTrafficLimits.Update(r.Context(), siteTrafficLimitActor(principal), sitetrafficlimit.UpdateRequest{
		SiteID: id, ExpectedRevision: version, Setting: setting, IdempotencyKey: key,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSiteTrafficLimitError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) writeSiteTrafficLimitError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sitetrafficlimit.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site traffic limit request is invalid")
	case errors.Is(err, sitetrafficlimit.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, sitetrafficlimit.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, sitetrafficlimit.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	case errors.Is(err, sitetrafficlimit.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	default:
		s.writeError(w, r, err)
	}
}

func siteTrafficLimitActor(principal identity.Principal) sitetrafficlimit.Actor {
	return sitetrafficlimit.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
