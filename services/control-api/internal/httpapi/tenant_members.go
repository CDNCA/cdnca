package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// Tenant members: GET /v1/tenant/members lists the members of the caller's
// own tenant scope (CustomRolesPage picks the member a role is granted to);
// never a platform session. Creating, suspending, deleting members and
// member invitations were removed in 1.0.35.

func (s *Server) tenantMemberPrincipal(w http.ResponseWriter, r *http.Request) (identity.Principal, bool) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	if principal.ScopeKind != "tenant" {
		s.writeError(w, r, identity.ErrPermissionDenied)
		return identity.Principal{}, false
	}
	return principal, true
}

func (s *Server) handleListTenantMembers(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.tenantMemberPrincipal(w, r)
	if !ok {
		return
	}
	members, err := s.identity.ListTenantMembers(r.Context(), principal)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if members == nil {
		members = []identity.TenantMember{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": members})
}
