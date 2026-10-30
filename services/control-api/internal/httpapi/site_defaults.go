package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// 网站列表 > 默认设置 and 解析检测 > 同步解析 (migration 490).
// A tenant reads and changes only its own scope's rows; another tenant's ID
// is 404.

type createSiteDefaultRequest struct {
	TargetScopeID string `json:"target_scope_id"`
	OwnerID       string `json:"owner_id"`
	site.SiteUserDefaultFields
}

type updateSiteDefaultRequest struct {
	ExpectedVersion int64   `json:"expected_version"`
	Value           *string `json:"setting_value"`
	Enabled         *bool   `json:"enabled"`
}

type syncSiteAutoDNSRequest struct {
	ProviderID string `json:"provider_id,omitempty"`
}

func (s *Server) handleListSiteDefaults(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.read")
	if !ok {
		return
	}
	query := r.URL.Query()
	if !singleValueQuery(query, "page", "limit", "setting_name", "enabled") {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	page, err := positiveIntOr(query.Get("page"), 1)
	limit, limitErr := positiveIntOr(query.Get("limit"), 10)
	filter := site.SiteUserDefaultListFilter{Page: page, Limit: limit, SettingName: query.Get("setting_name")}
	if raw := query.Get("enabled"); raw != "" {
		enabled, parseErr := strconv.ParseBool(raw)
		if parseErr != nil {
			err = parseErr
		}
		filter.Enabled = &enabled
	}
	if err != nil || limitErr != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	result, err := s.sites.ListUserDefaults(r.Context(), siteActor(principal), filter)
	if err != nil {
		s.writeSiteDefaultError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCreateSiteDefault(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body createSiteDefaultRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	targetScopeID, err := optionalUUID(body.TargetScopeID)
	ownerID, ownerErr := optionalUUID(body.OwnerID)
	if err != nil || ownerErr != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "target_scope_id and owner_id must be UUIDs")
		return
	}
	item, err := s.sites.CreateUserDefault(r.Context(), siteActor(principal), site.SiteUserDefaultCreateRequest{
		TargetScopeID: targetScopeID, OwnerUserID: ownerID, Fields: body.SiteUserDefaultFields,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteDefaultError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSONStatus(w, http.StatusCreated, item)
}

func (s *Server) handleUpdateSiteDefault(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site default ID must be a UUID")
		return
	}
	var body updateSiteDefaultRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	item, err := s.sites.UpdateUserDefault(r.Context(), siteActor(principal), site.SiteUserDefaultUpdateRequest{
		ID: id, ExpectedRevision: body.ExpectedVersion, Value: body.Value, Enabled: body.Enabled,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteDefaultError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(item.Revision))
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleDeleteSiteDefault(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site default ID must be a UUID")
		return
	}
	if err := s.sites.DeleteUserDefault(r.Context(), siteActor(principal), site.SiteUserDefaultDeleteRequest{
		ID: id, IdempotencyKey: key, RequestID: requestID(r.Context()),
	}); err != nil {
		s.writeSiteDefaultError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSyncSiteAutoDNS: 解析检测 > 同步解析. Needs dns.manage as well as
// sites.manage (it writes records through the owner's DNS account).
func (s *Server) handleSyncSiteAutoDNS(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireSitePermission(w, r, "sites.manage")
	if !ok {
		return
	}
	if principal, ok = s.requireSitePermission(w, r, "dns.manage"); !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	var body syncSiteAutoDNSRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	providerID, err := optionalUUIDPointer(&body.ProviderID)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "provider_id must be a UUID")
		return
	}
	status, err := s.sites.SyncAutoDNS(r.Context(), siteActor(principal), site.SyncAutoDNSRequest{
		SiteID: id, ProviderID: providerID, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteDefaultError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, status)
}

func (s *Server) writeSiteDefaultError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, site.ErrSiteDefaultConflict):
		s.writeAPIError(w, r, http.StatusConflict, "site_default_conflict",
			"a default for this setting already exists in the same scope")
	case errors.Is(err, site.ErrAutoDNSProvider):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "dns_provider_unusable",
			"choose a verified DNS API account of the site owner")
	case errors.Is(err, site.ErrSiteDefaultPolicy):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "site_default_policy_unusable",
			"choose one of your own rule libraries of that kind")
	case errors.Is(err, site.ErrInvalidInput) && strings.Contains(r.URL.Path, "/auto-dns/"):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "choose a DNS API account for this site")
	default:
		s.writeSiteError(w, r, err)
	}
}
