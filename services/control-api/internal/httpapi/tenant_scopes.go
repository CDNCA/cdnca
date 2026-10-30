package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func (s *Server) handleListTenantScopes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireUserManager(w, r)
	if !ok {
		return
	}
	allowed := map[string]bool{"page": true, "limit": true, "search": true, "parent": true}
	for key, values := range r.URL.Query() {
		if !allowed[key] || len(values) != 1 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are invalid")
			return
		}
	}
	page, err := positiveQueryInt(r, "page", 1)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "page must be a positive integer")
		return
	}
	limit, err := positiveQueryInt(r, "limit", 50)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
		return
	}
	result, err := s.identity.ListTenantScopes(r.Context(), identityActor(principal), identity.ListTenantScopesInput{
		Page: page, Limit: limit, Search: r.URL.Query().Get("search"), Parent: r.URL.Query().Get("parent"),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
