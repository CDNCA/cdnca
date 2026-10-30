package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/google/uuid"
)

// handleGetSiteCRS is a site's own OWASP CRS settings (GET
// /v1/sites/{site_id}/crs, security_policies.read; PA-12): the site's
// override, its WAF rule library's profile and exclusions, the effective
// result and the selectable CRS profile packs. ETag is the site version.
func (s *Server) handleGetSiteCRS(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, "security_policies.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("site_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	state, err := s.siteCRS.Get(r.Context(), siteCRSActor(principal), id)
	if err != nil {
		s.writeSiteCRSError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePutSiteCRS replaces the site's override (PUT, Idempotency-Key,
// If-Match site version, security_policies.manage): profile / exclusions
// null (inherit the library) or the site's value.
func (s *Server) handlePutSiteCRS(w http.ResponseWriter, r *http.Request) {
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
	var override securitypolicy.CRSOverride
	if err := decodeJSON(w, r, &override); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	state, err := s.siteCRS.Update(r.Context(), siteCRSActor(principal), sitecrs.UpdateRequest{
		SiteID: id, ExpectedRevision: version, Override: override, IdempotencyKey: key,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSiteCRSError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) writeSiteCRSError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sitecrs.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site CRS request is invalid")
	case errors.Is(err, sitecrs.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, sitecrs.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, sitecrs.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	case errors.Is(err, sitecrs.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, sitecrs.ErrNoManagedWAF):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "crs_no_managed_waf",
			"the site's WAF rule library runs no OWASP CRS managed WAF")
	case errors.Is(err, sitecrs.ErrProfileUnavailable):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "crs_profile_unavailable",
			"the CRS profile pack is not downloaded on this control plane")
	case errors.Is(err, sitecrs.ErrExclusionNotExported):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "crs_exclusion_not_exported",
			"an excluded rule is not one the CRS profile lets a site exclude")
	case errors.Is(err, sitecrs.ErrAppUnavailable):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "crs_app_unavailable",
			"an application type's exclusion pack is not downloaded on this control plane")
	default:
		s.writeError(w, r, err)
	}
}

func siteCRSActor(principal identity.Principal) sitecrs.Actor {
	return sitecrs.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
