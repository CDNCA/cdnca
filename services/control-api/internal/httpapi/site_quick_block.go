package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitequickblock"
	"github.com/google/uuid"
)

// handleGetSiteQuickBlock is a site's own quick block (GET
// /v1/sites/{site_id}/quick-block, security_policies.read):
// the site's override, its WAF rule library's quick block
// and the effective result. ETag is the site version.
func (s *Server) handleGetSiteQuickBlock(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("site_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	state, err := s.siteQuickBlocks.Get(r.Context(), siteQuickBlockActor(principal), id)
	if err != nil {
		s.writeSiteQuickBlockError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePutSiteQuickBlock replaces the site's override (PUT, Idempotency-Key,
// If-Match site version, security_policies.manage): each item null
// (inherit the library) or the site's value. The site's next release (an
// automatic scope publishes it) runs it; other sites keep their library's.
func (s *Server) handlePutSiteQuickBlock(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.manage")
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
	var override securitypolicy.QuickBlockOverride
	if err := decodeJSON(w, r, &override); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	state, err := s.siteQuickBlocks.Update(r.Context(), siteQuickBlockActor(principal), sitequickblock.UpdateRequest{
		SiteID: id, ExpectedRevision: version, Override: override, IdempotencyKey: key,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSiteQuickBlockError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) writeSiteQuickBlockError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sitequickblock.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site quick block request is invalid")
	case errors.Is(err, sitequickblock.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, sitequickblock.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, sitequickblock.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	case errors.Is(err, sitequickblock.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, sitequickblock.ErrNoLibrary):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "quick_block_no_library",
			"the site has no WAF rule library to override")
	default:
		if !writeQuickBlockError(s, w, r, err) {
			s.writeError(w, r, err)
		}
	}
}

func siteQuickBlockActor(principal identity.Principal) sitequickblock.Actor {
	return sitequickblock.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
