package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/google/uuid"
)

// Named IP lists (IP 名单): tenant routes
// /v1/security-ip-lists manage the caller's tenant lists and read the
// platform's; platform routes /v1/admin/security-ip-lists manage platform
// lists every tenant may reference. Reads need security_policies.read,
// writes security_policies.manage and an Idempotency-Key.
//
//	GET    {base}
//	POST   {base}                 {"name","description","entries"}
//	PUT    {base}/{list_id}       {"expected_revision","name","description","entries"}
//	DELETE {base}/{list_id}?expected_revision=
func (s *Server) securityIPListActor(w http.ResponseWriter, r *http.Request, permission string) (securityiplist.Actor, bool) {
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
		return securityiplist.Actor{}, false
	}
	return securityiplist.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, true
}

func (s *Server) handleListSecurityIPLists(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityIPListActor(w, r, securityiplist.PermissionRead)
	if !ok {
		return
	}
	lists, err := s.securityIPLists.ListAll(r.Context(), actor)
	if err != nil {
		s.writeSecurityIPListError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Items []securityiplist.List `json:"items"`
	}{lists})
}

type securityIPListBody struct {
	ExpectedRevision int64    `json:"expected_revision,omitempty"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Entries          []string `json:"entries"`
}

func (s *Server) securityIPListWrite(w http.ResponseWriter, r *http.Request, body bool) (securityiplist.Actor, securityiplist.WriteRequest, bool) {
	actor, ok := s.securityIPListActor(w, r, securityiplist.PermissionManage)
	if !ok {
		return actor, securityiplist.WriteRequest{}, false
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return actor, securityiplist.WriteRequest{}, false
	}
	request := securityiplist.WriteRequest{IdempotencyKey: key, RequestID: requestID(r.Context()),
		SourceIP: s.requestInfo(r).SourceIP}
	if raw := r.PathValue("list_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "IP list ID must be a UUID")
			return actor, request, false
		}
		request.ListID = id
	}
	if body {
		var decoded securityIPListBody
		if err := decodeJSON(w, r, &decoded); err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
			return actor, request, false
		}
		request.ExpectedRevision = decoded.ExpectedRevision
		request.Input = securityiplist.Input{Name: decoded.Name, Description: decoded.Description, Entries: decoded.Entries}
	} else {
		revision, err := strconv.ParseInt(r.URL.Query().Get("expected_revision"), 10, 64)
		if err != nil || revision < 1 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must be a positive integer")
			return actor, request, false
		}
		request.ExpectedRevision = revision
	}
	return actor, request, true
}

func (s *Server) handleCreateSecurityIPList(w http.ResponseWriter, r *http.Request) {
	actor, request, ok := s.securityIPListWrite(w, r, true)
	if !ok {
		return
	}
	list, err := s.securityIPLists.Create(r.Context(), actor, request)
	if err != nil {
		s.writeSecurityIPListError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, list)
}

func (s *Server) handleUpdateSecurityIPList(w http.ResponseWriter, r *http.Request) {
	actor, request, ok := s.securityIPListWrite(w, r, true)
	if !ok {
		return
	}
	if request.ExpectedRevision < 1 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expected_revision must be a positive integer")
		return
	}
	list, err := s.securityIPLists.Update(r.Context(), actor, request)
	if err != nil {
		s.writeSecurityIPListError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleDeleteSecurityIPList(w http.ResponseWriter, r *http.Request) {
	actor, request, ok := s.securityIPListWrite(w, r, false)
	if !ok {
		return
	}
	if err := s.securityIPLists.Delete(r.Context(), actor, request); err != nil {
		s.writeSecurityIPListError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeSecurityIPListError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, securityiplist.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "IP list request is invalid")
	case errors.Is(err, securityiplist.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "ip_list_not_found", "IP list was not found")
	case errors.Is(err, securityiplist.ErrNameConflict):
		s.writeAPIError(w, r, http.StatusConflict, "ip_list_name_conflict", "an IP list with this name already exists")
	case errors.Is(err, securityiplist.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "IP list version is stale")
	case errors.Is(err, securityiplist.ErrInUse):
		s.writeAPIError(w, r, http.StatusConflict, "ip_list_in_use", "a security policy still references the IP list")
	case errors.Is(err, securityiplist.ErrLimitExceeded):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "ip_list_limit", "too many IP lists")
	case errors.Is(err, securityiplist.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	default:
		s.writeError(w, r, err)
	}
}
