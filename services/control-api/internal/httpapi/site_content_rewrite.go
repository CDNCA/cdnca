package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/libs/edgeconfig/contentrewrite"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecontentrewrite"
	"github.com/google/uuid"
)

// handleGetSiteContentRewrite is a site's 内容改写 rules (GET
// /v1/sites/{id}/content-rewrite, sites.read; ). ETag is the site
// version.
func (s *Server) handleGetSiteContentRewrite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	state, err := s.siteContentRewrite.Get(r.Context(), siteContentRewriteActor(principal), id)
	if err != nil {
		s.writeSiteContentRewriteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePutSiteContentRewrite replaces the rules (PUT, If-Match site
// version, sites.manage).
func (s *Server) handlePutSiteContentRewrite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
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
	var settings contentrewrite.Settings
	if err := decodeJSON(w, r, &settings); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	state, err := s.siteContentRewrite.Update(r.Context(), siteContentRewriteActor(principal), sitecontentrewrite.UpdateRequest{
		SiteID: id, ExpectedRevision: version, Settings: settings,
		RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSiteContentRewriteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(state.Version))
	writeJSON(w, http.StatusOK, state)
}

// handlePostSiteContentRewriteTest runs draft rules on a pasted body with
// the node's algorithm (POST .../content-rewrite/test, sites.read; nothing
// is written).
func (s *Server) handlePostSiteContentRewriteTest(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	var request sitecontentrewrite.TestRequest
	if err := decodeJSON(w, r, &request); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.siteContentRewrite.Test(r.Context(), siteContentRewriteActor(principal), id, request)
	if err != nil {
		s.writeSiteContentRewriteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeSiteContentRewriteError(w http.ResponseWriter, r *http.Request, err error) {
	var field *contentrewrite.FieldError
	switch {
	case errors.As(err, &field):
		s.writeFieldError(w, r, field.Field, field.Reason)
	case errors.Is(err, sitecontentrewrite.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "content rewrite request is invalid")
	case errors.Is(err, sitecontentrewrite.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, sitecontentrewrite.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "site_locked", "site is locked by a platform administrator")
	case errors.Is(err, sitecontentrewrite.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "site version is stale")
	default:
		s.writeError(w, r, err)
	}
}

func siteContentRewriteActor(principal identity.Principal) sitecontentrewrite.Actor {
	return sitecontentrewrite.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}
}
