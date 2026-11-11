package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/securitystringset"
)

// POST /v1/security-policies/parse-user-agent {"user_agent"}:
// what the edge's browser / device conditions see for one User-Agent
// (edgeconfig.ParseUserAgent, the table the node's cdnca_ua.lua mirrors).
// Read only; needs security_policies.read.
func (s *Server) handleParseUserAgent(w http.ResponseWriter, r *http.Request) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil {
		err = identity.Authorize(principal, securitystringset.PermissionRead)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		UserAgent string `json:"user_agent"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if len(body.UserAgent) > 2048 {
		s.writeFieldError(w, r, "user_agent", fielderr.TooLong)
		return
	}
	info := edgeconfig.ParseUserAgent(body.UserAgent)
	var version *string
	if info.HasVersion {
		value := info.VersionString()
		version = &value
	}
	writeJSON(w, http.StatusOK, struct {
		Browser string  `json:"browser"`
		Version *string `json:"version"`
		Device  string  `json:"device"`
	}{info.Browser, version, info.Device})
}
