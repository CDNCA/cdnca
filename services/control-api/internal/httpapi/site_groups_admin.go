package httpapi

import "net/http"

func (s *Server) handleListAdminSiteGroups(w http.ResponseWriter, r *http.Request) {
	if s.siteGroups == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "site_group_unavailable", "site group service is unavailable")
		return
	}
	for key, values := range r.URL.Query() {
		if (key != "page" && key != "limit") || len(values) != 1 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
			return
		}
	}
	actor, ok := s.siteGroupActor(w, r)
	if !ok {
		return
	}
	page, err := positiveIntOr(r.URL.Query().Get("page"), 1)
	if err != nil || page > 1_000_000 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page is invalid")
		return
	}
	limit, err := positiveIntOr(r.URL.Query().Get("limit"), 10)
	if err != nil || limit > 100 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit is invalid")
		return
	}
	result, err := s.siteGroups.ListAdmin(r.Context(), actor, page, limit)
	if err != nil {
		s.writeSiteGroupError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetSiteGroup(w http.ResponseWriter, r *http.Request) {
	if s.siteGroups == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "site_group_unavailable", "site group service is unavailable")
		return
	}
	id, ok := s.parseSiteGroupID(w, r)
	if !ok {
		return
	}
	actor, scope, ok := s.siteGroupActorAndScope(w, r, r.URL.Query().Get("scope_id"))
	if !ok {
		return
	}
	result, err := s.siteGroups.Get(r.Context(), actor, scope, id)
	if err != nil {
		s.writeSiteGroupError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Revision))
	writeJSON(w, http.StatusOK, result)
}
