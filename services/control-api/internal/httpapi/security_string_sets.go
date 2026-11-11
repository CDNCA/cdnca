package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitystringset"
	"github.com/google/uuid"
)

// Named string sets: tenant routes
// /v1/security-string-sets manage the caller's tenant sets and read the
// platform's; platform routes /v1/admin/security-string-sets manage platform
// sets every tenant may reference. Reads need security_policies.read,
// writes security_policies.manage and an Idempotency-Key.
//
//	GET    {base}                         list (no entries)
//	POST   {base}                         {"name","description","match_mode","case_sensitive","entries"}
//	GET    {base}/{set_id}                one set with entries
//	GET    {base}/{set_id}/references     policies referencing it
//	PUT    {base}/{set_id}                {"expected_revision","name","description","entries"}
//	DELETE {base}/{set_id}?expected_revision=
func (s *Server) securityStringSetActor(w http.ResponseWriter, r *http.Request, permission string) (securitystringset.Actor, bool) {
	principal, err := s.authenticatedPrincipal(r)
	admin := strings.HasPrefix(r.URL.Path, "/v1/admin/")
	if err == nil && admin != (principal.ScopeKind == "platform") {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return securitystringset.Actor{}, false
	}
	return securitystringset.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, true
}

func (s *Server) securityStringSetID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("set_id"))
	if err != nil || id == uuid.Nil {
		s.writeFieldError(w, r, "set_id", fielderr.InvalidFormat)
		return uuid.Nil, false
	}
	return id, true
}

func (s *Server) handleListSecurityStringSets(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityStringSetActor(w, r, securitystringset.PermissionRead)
	if !ok {
		return
	}
	sets, err := s.securityStringSets.ListAll(r.Context(), actor)
	if err != nil {
		s.writeSecurityStringSetError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []securitystringset.Summary `json:"items"`
	}{sets})
}

func (s *Server) handleGetSecurityStringSet(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityStringSetActor(w, r, securitystringset.PermissionRead)
	if !ok {
		return
	}
	id, ok := s.securityStringSetID(w, r)
	if !ok {
		return
	}
	set, err := s.securityStringSets.Get(r.Context(), actor, id)
	if err != nil {
		s.writeSecurityStringSetError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleListSecurityStringSetReferences(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityStringSetActor(w, r, securitystringset.PermissionRead)
	if !ok {
		return
	}
	id, ok := s.securityStringSetID(w, r)
	if !ok {
		return
	}
	references, err := s.securityStringSets.References(r.Context(), actor, id)
	if err != nil {
		s.writeSecurityStringSetError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []securitystringset.Reference `json:"items"`
	}{references})
}

// securityStringSetBody: create takes match_mode / case_sensitive; an
// update sending them is refused (fixed at creation).
type securityStringSetBody struct {
	ExpectedRevision int64    `json:"expected_revision,omitempty"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	MatchMode        *string  `json:"match_mode,omitempty"`
	CaseSensitive    *bool    `json:"case_sensitive,omitempty"`
	Entries          []string `json:"entries"`
}

func (s *Server) securityStringSetWrite(w http.ResponseWriter, r *http.Request, body, create bool) (securitystringset.Actor, securitystringset.WriteRequest, bool) {
	actor, ok := s.securityStringSetActor(w, r, securitystringset.PermissionManage)
	if !ok {
		return actor, securitystringset.WriteRequest{}, false
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return actor, securitystringset.WriteRequest{}, false
	}
	request := securitystringset.WriteRequest{IdempotencyKey: key, RequestID: requestID(r.Context()),
		SourceIP: s.requestInfo(r).SourceIP}
	if r.PathValue("set_id") != "" {
		if request.SetID, ok = s.securityStringSetID(w, r); !ok {
			return actor, request, false
		}
	}
	if !body {
		revision, err := strconv.ParseInt(r.URL.Query().Get("expected_revision"), 10, 64)
		if err != nil || revision < 1 {
			s.writeFieldError(w, r, "expected_revision", fielderr.Invalid)
			return actor, request, false
		}
		request.ExpectedRevision = revision
		return actor, request, true
	}
	var decoded securityStringSetBody
	if err := decodeJSON(w, r, &decoded); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return actor, request, false
	}
	switch {
	case create && decoded.MatchMode == nil:
		s.writeFieldError(w, r, "match_mode", fielderr.Required)
		return actor, request, false
	case create && decoded.CaseSensitive == nil:
		s.writeFieldError(w, r, "case_sensitive", fielderr.Required)
		return actor, request, false
	case !create && decoded.MatchMode != nil:
		s.writeFieldError(w, r, "match_mode", fielderr.Invalid)
		return actor, request, false
	case !create && decoded.CaseSensitive != nil:
		s.writeFieldError(w, r, "case_sensitive", fielderr.Invalid)
		return actor, request, false
	case !create && decoded.ExpectedRevision < 1:
		s.writeFieldError(w, r, "expected_revision", fielderr.Invalid)
		return actor, request, false
	}
	request.ExpectedRevision = decoded.ExpectedRevision
	request.Input = securitystringset.Input{Name: decoded.Name, Description: decoded.Description, Entries: decoded.Entries}
	if create {
		request.Input.MatchMode, request.Input.CaseSensitive = *decoded.MatchMode, *decoded.CaseSensitive
	}
	return actor, request, true
}

func (s *Server) handleCreateSecurityStringSet(w http.ResponseWriter, r *http.Request) {
	actor, request, ok := s.securityStringSetWrite(w, r, true, true)
	if !ok {
		return
	}
	set, err := s.securityStringSets.Create(r.Context(), actor, request)
	if err != nil {
		s.writeSecurityStringSetError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, set)
}

func (s *Server) handleUpdateSecurityStringSet(w http.ResponseWriter, r *http.Request) {
	actor, request, ok := s.securityStringSetWrite(w, r, true, false)
	if !ok {
		return
	}
	set, err := s.securityStringSets.Update(r.Context(), actor, request)
	if err != nil {
		s.writeSecurityStringSetError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleDeleteSecurityStringSet(w http.ResponseWriter, r *http.Request) {
	actor, request, ok := s.securityStringSetWrite(w, r, false, false)
	if !ok {
		return
	}
	if err := s.securityStringSets.Delete(r.Context(), actor, request); err != nil {
		s.writeSecurityStringSetError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeSecurityStringSetError(w http.ResponseWriter, r *http.Request, err error) {
	if located, ok := fielderr.As(err); ok {
		// entries[i] / entries with the member reason (StringSetEntryError).
		s.writeFieldError(w, r, located.Field, located.Reason)
		return
	}
	switch {
	case errors.Is(err, securitystringset.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "string set request is invalid")
	case errors.Is(err, securitystringset.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "string_set_not_found", "string set was not found")
	case errors.Is(err, securitystringset.ErrNameConflict):
		s.writeAPIError(w, r, http.StatusConflict, "string_set_name_conflict", "a string set with this name already exists")
	case errors.Is(err, securitystringset.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "string set version is stale")
	case errors.Is(err, securitystringset.ErrInUse):
		s.writeAPIError(w, r, http.StatusConflict, "string_set_in_use", "a security policy still references the string set")
	case errors.Is(err, securitystringset.ErrLimitExceeded):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "string_set_limit", "too many string sets")
	case errors.Is(err, securitystringset.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	default:
		s.writeError(w, r, err)
	}
}
