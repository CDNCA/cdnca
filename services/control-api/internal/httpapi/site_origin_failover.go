package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/originfailover"
	"github.com/google/uuid"
)

// handleGetSiteOriginStatus is the pool's probe state and active origin
// level (GET /v1/sites/{site_id}/origin-status, sites.read).
func (s *Server) handleGetSiteOriginStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("site_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	status, err := s.originFailover.Status(r.Context(), originFailoverActor(principal), id)
	if err != nil {
		s.writeOriginFailoverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// handlePostSiteOriginFailback switches a pool back to its best healthy
// higher level (POST .../origin-failback, Idempotency-Key, sites.manage).
func (s *Server) handlePostSiteOriginFailback(w http.ResponseWriter, r *http.Request) {
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
	status, err := s.originFailover.Failback(r.Context(), originFailoverActor(principal), id, key)
	if err != nil {
		s.writeOriginFailoverError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) writeOriginFailoverError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, originfailover.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "origin failback request is invalid")
	case errors.Is(err, originfailover.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, originfailover.ErrFailbackUnavailable):
		s.writeAPIError(w, r, http.StatusConflict, "origin_failback_unavailable", "no higher origin level is healthy")
	default:
		s.writeError(w, r, err)
	}
}

func originFailoverActor(principal identity.Principal) originfailover.Actor {
	return originfailover.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
