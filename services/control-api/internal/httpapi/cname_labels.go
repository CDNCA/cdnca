package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// Administrator-defined CNAME names. Platform session only (a tenant session
// answers 403, the user interface shows no editor):
//
//	GET  /v1/admin/cname-labels/{kind}/{id}             {"label"}
//	PUT  /v1/admin/cname-labels/{kind}/{id}             {"label"} ("" clears); a site name re-allocates its CNAME
//	GET  /v1/admin/cname-labels/{kind}/{id}/affected    {"sites"}: line group prefixes only
//	POST /v1/admin/cname-labels/{kind}/{id}/regenerate  regenerate under the new prefix; {"sites"}
//
// kind: site | line-group.
var cnameLabelKinds = map[string]struct{ kind, permission string }{
	"site":       {site.CNAMELabelSite, "sites.manage"},
	"line-group": {site.CNAMELabelLineGroup, "node_scheduling.manage"},
}

func (s *Server) cnameLabelCall(w http.ResponseWriter, r *http.Request) (site.Actor, string, uuid.UUID, bool) {
	spec, known := cnameLabelKinds[r.PathValue("kind")]
	id, err := uuid.Parse(r.PathValue("id"))
	if !known || err != nil || id == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "kind or id is invalid")
		return site.Actor{}, "", uuid.Nil, false
	}
	principal, err := s.authenticatedPrincipal(r)
	if err == nil && principal.ScopeKind != "platform" {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, spec.permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return site.Actor{}, "", uuid.Nil, false
	}
	actor, err := s.siteWriteActor(r, principal)
	if err != nil {
		s.writeError(w, r, err)
		return site.Actor{}, "", uuid.Nil, false
	}
	if s.sites == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "sites_unavailable", "sites are not configured")
		return site.Actor{}, "", uuid.Nil, false
	}
	return actor, spec.kind, id, true
}

func (s *Server) writeCNAMELabelError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, cnameallocation.ErrLabelInvalid):
		s.writeAPIError(w, r, http.StatusBadRequest, cnameallocation.CodeLabelInvalid,
			"use lowercase letters, digits and hyphens, not starting or ending with a hyphen")
	case errors.Is(err, cnameallocation.ErrLabelReserved):
		s.writeAPIError(w, r, http.StatusBadRequest, cnameallocation.CodeLabelReserved, "this name is reserved")
	case errors.Is(err, cnameallocation.ErrLabelTaken):
		s.writeAPIError(w, r, http.StatusConflict, cnameallocation.CodeLabelTaken, "this name is already used")
	case errors.Is(err, site.ErrCNAMELabelFollowsPackage):
		s.writeAPIError(w, r, http.StatusConflict, "cname_label_follows_package", "the site shares the CNAME of its package")
	case errors.Is(err, site.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "not_found", "object not found")
	case errors.Is(err, site.ErrPermissionDenied):
		s.writeError(w, r, identity.ErrPermissionDenied)
	default:
		s.writeSiteError(w, r, err)
	}
}

func (s *Server) handleGetCNAMELabel(w http.ResponseWriter, r *http.Request) {
	actor, kind, id, ok := s.cnameLabelCall(w, r)
	if !ok {
		return
	}
	label, err := s.sites.GetCNAMELabel(r.Context(), actor, kind, id)
	if err != nil {
		s.writeCNAMELabelError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"label": label})
}

func (s *Server) handlePutCNAMELabel(w http.ResponseWriter, r *http.Request) {
	actor, kind, id, ok := s.cnameLabelCall(w, r)
	if !ok {
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	result, err := s.sites.SetCNAMELabel(r.Context(), actor, site.CNAMELabelRequest{Kind: kind, SubjectID: id, Label: body.Label, RequestID: key})
	if err != nil {
		s.writeCNAMELabelError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCNAMELabelAffected(w http.ResponseWriter, r *http.Request) {
	actor, kind, id, ok := s.cnameLabelCall(w, r)
	if !ok {
		return
	}
	count, err := s.sites.CountPrefixAffected(r.Context(), actor, kind, id)
	if err != nil {
		s.writeCNAMELabelError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"sites": count})
}

func (s *Server) handleCNAMELabelRegenerate(w http.ResponseWriter, r *http.Request) {
	actor, kind, id, ok := s.cnameLabelCall(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	count, err := s.sites.RegeneratePrefix(r.Context(), actor, kind, id, key)
	if err != nil {
		s.writeCNAMELabelError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"sites": count})
}
