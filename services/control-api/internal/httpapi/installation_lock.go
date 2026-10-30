package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/installationlock"
)

// installationLockAllowedWrites are the writes a locked installation still
// serves (ADR 0014 §5.2): signing in and out, the signed-in user's own
// password and MFA, and the license page's "check again" (the lock itself is
// lifted by the license service, never through this API).
var installationLockAllowedWrites = []string{
	"POST /v1/auth/login", "POST /v1/auth/login-captchas", "POST /v1/auth/session-region-verifications",
	"POST /v1/auth/login-challenges", "POST /v1/auth/login-challenge-verifications",
	"POST /v1/auth/refresh", "POST /v1/auth/logout", "POST /v1/account/password",
	"POST /v1/installation-lock/check",
}

// installationLockAllowedWritePrefixes: the user's own MFA (enrol, step-up).
var installationLockAllowedWritePrefixes = []string{"/v1/account/mfa/", "/v1/internal/"}

func installationLockAllows(request *http.Request) bool {
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if request.URL.Path == "/v1/account/mfa" {
		return true
	}
	key := request.Method + " " + request.URL.Path
	for _, allowed := range installationLockAllowedWrites {
		if key == allowed {
			return true
		}
	}
	for _, prefix := range installationLockAllowedWritePrefixes {
		if strings.HasPrefix(request.URL.Path, prefix) {
			return true
		}
	}
	return false
}

type installationLockBody struct {
	Code       string     `json:"code"`
	Message    string     `json:"message"`
	RequestID  string     `json:"request_id"`
	Reason     string     `json:"reason"`
	BanID      string     `json:"ban_id,omitempty"`
	ReasonCode string     `json:"reason_code,omitempty"`
	ReasonText string     `json:"reason_text,omitempty"`
	Until      *time.Time `json:"until"`
}

// withInstallationLock refuses every write except the allow list with 423
// installation_locked while the installation is locked (installationlock).
func (s *Server) withInstallationLock(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock := installationlock.Current()
		if !lock.Locked || installationLockAllows(r) {
			next.ServeHTTP(w, r)
			return
		}
		writeJSONStatus(w, http.StatusLocked, struct {
			Error installationLockBody `json:"error"`
		}{installationLockBody{Code: "installation_locked",
			Message:   "this installation is read-only: its license was suspended by the license service",
			RequestID: requestID(r.Context()), Reason: lock.Reason, BanID: lock.BanID, ReasonCode: lock.ReasonCode,
			ReasonText: lock.ReasonText, Until: lock.Until}})
	})
}

// handleInstallationLock is the banner's source (any signed-in user; tenants
// see the same text, ADR 0014 §5.2).
func (s *Server) handleInstallationLock(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticatedSessionPrincipal(r); err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, installationlock.Current())
}

// handleInstallationLockCheck asks the runtime to fetch the state now (the
// license page's "check again"); it answers the resulting lock.
func (s *Server) handleInstallationLockCheck(w http.ResponseWriter, r *http.Request) {
	if _, err := s.authenticatedSessionPrincipal(r); err != nil {
		s.writeError(w, r, err)
		return
	}
	if s.installationLockCheck != nil {
		_ = s.installationLockCheck(r.Context())
	}
	writeJSON(w, http.StatusOK, installationlock.Current())
}
