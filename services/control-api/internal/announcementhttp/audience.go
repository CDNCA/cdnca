package announcementhttp

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/google/uuid"
)

// Audience helpers are read-only and authorized by the announcement manage
// permission itself, so an announcement manager does not also need user or
// role administration rights to pick recipients by name.

func (h *Handler) audienceCount(w http.ResponseWriter, r *http.Request) {
	session, ok := h.manager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if !validQuery(r, map[string]bool{}) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	result, err := h.store.AudienceCount(r.Context(), actor(session), id)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) globalAudienceCount(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if !validQuery(r, map[string]bool{}) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return
	}
	result, err := h.store.GlobalAudienceCount(r.Context(), actor(session), id)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) audienceDirectory(w http.ResponseWriter, r *http.Request) {
	session, ok := h.manager(w, r)
	if !ok {
		return
	}
	request, ok := directoryRequest(w, r, false)
	if !ok {
		return
	}
	result, err := h.store.AudienceDirectory(r.Context(), actor(session), request)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func (h *Handler) globalAudienceDirectory(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformManager(w, r)
	if !ok {
		return
	}
	request, ok := directoryRequest(w, r, true)
	if !ok {
		return
	}
	result, err := h.store.GlobalAudienceDirectory(r.Context(), actor(session), request)
	if err != nil {
		writeCoreError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, result)
}

func directoryRequest(w http.ResponseWriter, r *http.Request, global bool) (announcement.AudienceDirectoryRequest, bool) {
	allowed := map[string]bool{"kind": true, "search": true, "ids": true, "limit": true}
	if global {
		allowed["scope_id"] = true
	}
	invalid := func() (announcement.AudienceDirectoryRequest, bool) {
		writeError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
		return announcement.AudienceDirectoryRequest{}, false
	}
	if !validQuery(r, allowed) {
		return invalid()
	}
	query := r.URL.Query()
	request := announcement.AudienceDirectoryRequest{Kind: query.Get("kind"), Search: query.Get("search"), Limit: 20}
	if value := query.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil {
			return invalid()
		}
		request.Limit = limit
	}
	if value := query.Get("scope_id"); value != "" {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil {
			return invalid()
		}
		request.ScopeID = id
	}
	if value := query.Get("ids"); value != "" {
		for _, part := range strings.Split(value, ",") {
			id, err := uuid.Parse(part)
			if err != nil || id == uuid.Nil {
				return invalid()
			}
			request.IDs = append(request.IDs, id)
		}
	}
	return request, true
}
