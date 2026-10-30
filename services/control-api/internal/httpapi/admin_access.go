package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// Platform administration access allowlist (identity.AdminAccessPolicy).

type adminAccessPolicyResponse struct {
	identity.AdminAccessPolicy
	// CurrentIP is the address this request came from, so the page can show
	// what must stay allowed.
	CurrentIP string `json:"current_ip"`
}

type updateAdminAccessPolicyRequest struct {
	ExpectedRevision *int64   `json:"expected_revision"`
	Enabled          *bool    `json:"enabled"`
	Allowlist        []string `json:"allowlist"`
}

func (s *Server) adminAccessPrincipal(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	principal, err := s.authenticatedSessionPrincipal(r)
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	if principal.ScopeKind != "platform" {
		s.writeError(w, r, identity.ErrPermissionDenied)
		return identity.Principal{}, false
	}
	if err := identity.Authorize(principal, permission); err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func (s *Server) handleGetAdminAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.adminAccessPrincipal(w, r, "system_configuration.read"); !ok {
		return
	}
	policy, err := s.identity.GetAdminAccessPolicy(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(policy.Revision, 10)+`"`)
	writeJSON(w, http.StatusOK, adminAccessPolicyResponse{AdminAccessPolicy: policy, CurrentIP: s.requestInfo(r).SourceIP})
}

func (s *Server) handleUpdateAdminAccessPolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.adminAccessPrincipal(w, r, "system_configuration.manage")
	if !ok {
		return
	}
	var body updateAdminAccessPolicyRequest
	if err := decodeJSON(w, r, &body); err != nil || body.ExpectedRevision == nil || body.Enabled == nil || body.Allowlist == nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "expected_revision, enabled and allowlist are required")
		return
	}
	for index := range body.Allowlist {
		body.Allowlist[index] = strings.TrimSpace(body.Allowlist[index])
	}
	info := s.requestInfo(r)
	policy, err := s.identity.UpdateAdminAccessPolicy(r.Context(), principal, identity.UpdateAdminAccessPolicyInput{
		ExpectedRevision: *body.ExpectedRevision, Enabled: *body.Enabled, Allowlist: body.Allowlist,
		SourceIP: info.SourceIP, RequestID: info.RequestID,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(policy.Revision, 10)+`"`)
	writeJSON(w, http.StatusOK, adminAccessPolicyResponse{AdminAccessPolicy: policy, CurrentIP: info.SourceIP})
}
