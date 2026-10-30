package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
)

// The security ban list (封禁名单): tenant routes
// /v1/security-bans reach the caller's scope, platform routes
// /v1/admin/security-bans every site. Reads need security_policies.read,
// manual bans and releases security_policies.manage.
//
//	GET  {base}?site_id=&client_ip=&state=&page=&limit=
//	POST {base}                       {"site_id","client_ip","duration_seconds","reason"} (Idempotency-Key)
//	POST {base}/{entry_id}/release

func (s *Server) securityBanActor(w http.ResponseWriter, r *http.Request, permission string) (securityban.Actor, bool) {
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
		return securityban.Actor{}, false
	}
	return securityban.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, ScopeKind: principal.ScopeKind}, true
}

func (s *Server) handleListSecurityBans(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityBanActor(w, r, "security_policies.read")
	if !ok {
		return
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 20)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	filter := securityban.ListFilter{ClientIP: r.URL.Query().Get("client_ip"), State: r.URL.Query().Get("state"),
		Page: page, Limit: limit}
	if raw := r.URL.Query().Get("site_id"); raw != "" {
		siteID, err := uuid.Parse(raw)
		if err != nil {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site_id must be a UUID")
			return
		}
		filter.SiteID = &siteID
	}
	result, err := s.securityBans.List(r.Context(), actor, filter)
	if err != nil {
		s.writeSecurityBanError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type createSecurityBanRequest struct {
	SiteID          string `json:"site_id"`
	ClientIP        string `json:"client_ip"`
	DurationSeconds int    `json:"duration_seconds"`
	Reason          string `json:"reason"`
}

func (s *Server) handleCreateSecurityBan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityBanActor(w, r, "security_policies.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createSecurityBanRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	siteID, err := uuid.Parse(body.SiteID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site_id must be a UUID")
		return
	}
	entry, err := s.securityBans.Create(r.Context(), actor, securityban.CreateRequest{
		SiteID: siteID, ClientIP: body.ClientIP, DurationSecond: body.DurationSeconds, Reason: body.Reason,
		IdempotencyKey: key, RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSecurityBanError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *Server) handleReleaseSecurityBan(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.securityBanActor(w, r, "security_policies.manage")
	if !ok {
		return
	}
	entryID, err := uuid.Parse(r.PathValue("entry_id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "ban ID must be a UUID")
		return
	}
	entry, err := s.securityBans.Release(r.Context(), actor, securityban.ReleaseRequest{
		EntryID: entryID, RequestID: requestID(r.Context()), SourceIP: s.requestInfo(r).SourceIP,
	})
	if err != nil {
		s.writeSecurityBanError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (s *Server) writeSecurityBanError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, securityban.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "security ban request is invalid")
	case errors.Is(err, securityban.ErrSiteNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "site_not_found", "site was not found")
	case errors.Is(err, securityban.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "security_ban_not_found", "security ban was not found")
	case errors.Is(err, securityban.ErrAlreadyBanned):
		s.writeAPIError(w, r, http.StatusConflict, "security_ban_exists", "the client is already banned on the site")
	case errors.Is(err, securityban.ErrNotActive):
		s.writeAPIError(w, r, http.StatusConflict, "security_ban_not_active", "the ban was already released or has expired")
	case errors.Is(err, securityban.ErrLimitExceeded):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "security_ban_limit", "the site has too many active bans")
	case errors.Is(err, securityban.ErrIdempotencyKey):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	default:
		s.writeError(w, r, err)
	}
}
