package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/approvalcenter"
)

// withApprovalCenter puts the platform approval gate in front of mux.
// With the center off the gate passes every request.
func (s *Server) withApprovalCenter(mux http.Handler) http.Handler {
	return approvalcenter.Gate{
		Settings:  s.approvalCenter.Settings,
		Session:   s.approvalSession,
		Submit:    s.approvalCenter.Submit,
		RequestID: requestID,
	}.Wrap(mux)
}

func (s *Server) approvalCenterRoutes(mux *http.ServeMux, target func() http.Handler) {
	approvalcenter.Handler{
		Service:   s.approvalCenter,
		Session:   s.approvalSession,
		RequestID: requestID,
		Target:    target,
	}.Routes(mux)
}

// approvalSession resolves the live Bearer session (API keys and the
// impersonation cookie are not sessions that can go through approval, Q4).
func (s *Server) approvalSession(r *http.Request) (approvalcenter.Session, bool) {
	scheme, rawToken, found := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if s.identity == nil || !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(rawToken) == "" {
		return approvalcenter.Session{}, false
	}
	session, err := s.identity.AuthenticateSession(r.Context(), strings.TrimSpace(rawToken))
	if err != nil {
		return approvalcenter.Session{}, false
	}
	return approvalcenter.Session{
		UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID, SessionID: session.SessionID,
		ScopeKind: session.Principal.ScopeKind, Permissions: session.Principal.Permissions,
	}, true
}

// approvalCenterEnabled drives the approval center menu (runtime feature
// approval_center): hidden while the center is off.
func (s *Server) approvalCenterEnabled(ctx context.Context) bool {
	if s.approvalCenter == nil {
		return false
	}
	settings, err := s.approvalCenter.Settings(ctx)
	return err == nil && settings.Enabled
}
