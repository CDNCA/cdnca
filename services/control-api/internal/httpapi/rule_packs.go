package httpapi

import (
	"errors"
	"io"
	"net/http"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
)

// Rule packs (ADR 0007 §5.4, PA-10/PA-11). pack_id contains "/", so pack
// routes take it as a query parameter. Reads need security_policies.read,
// writes security_policies.manage; which level an actor may write is decided
// by rulepackcontrol (platform: every level; tenant: itself and its sites,
// only where the levels above allow adjustment).

type rulePackConflictEnvelope struct {
	Error rulePackConflictError `json:"error"`
}

type rulePackConflictError struct {
	Code       string              `json:"code"`
	Message    string              `json:"message"`
	RequestID  string              `json:"request_id"`
	Resolution rulepack.Resolution `json:"resolution"`
}

func (s *Server) handleRulePackView(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.rulePackActor(w, r, "security_policies.read")
	if !ok {
		return
	}
	level, ok := s.rulePackLevel(w, r)
	if !ok {
		return
	}
	view, err := s.rulePacks.View(r.Context(), actor, level)
	if err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleImportRulePack(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.rulePackActor(w, r, "security_policies.manage")
	if !ok {
		return
	}
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, rulepack.MaxPackBytes))
	if err != nil {
		s.writeAPIError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large", "rule pack exceeds 1 MiB")
		return
	}
	pack, err := s.rulePacks.Import(r.Context(), actor, content)
	if err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, pack)
}

func (s *Server) handleUpdateRulePack(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.rulePackActor(w, r, "security_policies.manage")
	if !ok {
		return
	}
	var update rulepackcontrol.PackUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	pack, err := s.rulePacks.UpdatePack(r.Context(), actor, r.URL.Query().Get("pack_id"), update)
	if err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pack)
}

func (s *Server) handleDeleteRulePackVersion(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.rulePackActor(w, r, "security_policies.manage")
	if !ok {
		return
	}
	query := r.URL.Query()
	if err := s.rulePacks.DeleteVersion(r.Context(), actor, query.Get("pack_id"), query.Get("version")); err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePutRulePackEnablement sets one row; 204 when the row was removed
// (state inherit without anything else).
func (s *Server) handlePutRulePackEnablement(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.rulePackActor(w, r, "security_policies.manage")
	if !ok {
		return
	}
	var input rulepackcontrol.OverrideInput
	if err := decodeJSON(w, r, &input); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	row, kept, err := s.rulePacks.PutOverride(r.Context(), actor, input)
	if err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	if !kept {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, row)
}

func (s *Server) handleGetSiteSecurityMounts(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.rulePackSite(w, r, "security_policies.read")
	if !ok {
		return
	}
	result, err := s.rulePacks.Site(r.Context(), actor, siteID)
	if err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePublishSiteSecurityMounts(w http.ResponseWriter, r *http.Request) {
	actor, siteID, ok := s.rulePackSite(w, r, "security_policies.manage")
	if !ok {
		return
	}
	result, err := s.rulePacks.PublishSite(r.Context(), actor, siteID)
	if err != nil {
		s.writeRulePackError(w, r, err)
		return
	}
	if s.ruleMountsPublished != nil {
		s.ruleMountsPublished()
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) rulePackActor(w http.ResponseWriter, r *http.Request, permission string) (rulepackcontrol.Actor, bool) {
	principal, ok := s.requireSecurityPolicyPermission(w, r, permission)
	if !ok {
		return rulepackcontrol.Actor{}, false
	}
	if s.rulePacks == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "unavailable", "rule packs are unavailable")
		return rulepackcontrol.Actor{}, false
	}
	return rulepackcontrol.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind,
		SourceIP: s.requestInfo(r).SourceIP, RequestID: requestID(r.Context())}, true
}

func (s *Server) rulePackLevel(w http.ResponseWriter, r *http.Request) (rulepackcontrol.LevelInput, bool) {
	query := r.URL.Query()
	level := rulepackcontrol.LevelInput{Level: rulepack.Level(query.Get("level"))}
	if raw := query.Get("object_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil || id.String() != raw {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "object_id must be a canonical UUID")
			return rulepackcontrol.LevelInput{}, false
		}
		level.ObjectID = &id
	}
	return level, true
}

func (s *Server) rulePackSite(w http.ResponseWriter, r *http.Request, permission string) (rulepackcontrol.Actor, uuid.UUID, bool) {
	actor, ok := s.rulePackActor(w, r, permission)
	if !ok {
		return rulepackcontrol.Actor{}, uuid.Nil, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id.String() != r.PathValue("id") {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a canonical UUID")
		return rulepackcontrol.Actor{}, uuid.Nil, false
	}
	return actor, id, true
}

func (s *Server) writeRulePackError(w http.ResponseWriter, r *http.Request, err error) {
	var conflict *rulepackcontrol.ConflictError
	switch {
	case errors.As(err, &conflict):
		writeJSONStatus(w, http.StatusUnprocessableEntity, rulePackConflictEnvelope{Error: rulePackConflictError{
			Code: "rule_pack_conflict", Message: "the site's enabled rule packs conflict; disable one side at a level",
			RequestID: requestID(r.Context()), Resolution: conflict.Resolution,
		}})
	case errors.Is(err, rulepackcontrol.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", err.Error())
	case errors.Is(err, rulepackcontrol.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "not_found", "rule pack, level or site was not found")
	case errors.Is(err, rulepackcontrol.ErrPermissionDenied):
		s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "this level or pack is managed by another scope")
	case errors.Is(err, rulepackcontrol.ErrLocked):
		s.writeAPIError(w, r, http.StatusConflict, "rule_pack_locked", "an upper level does not allow adjusting this pack here")
	case errors.Is(err, rulepackcontrol.ErrInUse):
		s.writeAPIError(w, r, http.StatusConflict, "rule_pack_in_use", "the pack is enabled at some level or mounted by a published site")
	case errors.Is(err, rulepackcontrol.ErrExists):
		s.writeAPIError(w, r, http.StatusConflict, "rule_pack_version_exists", "this pack version is already downloaded")
	default:
		s.writeError(w, r, err)
	}
}
