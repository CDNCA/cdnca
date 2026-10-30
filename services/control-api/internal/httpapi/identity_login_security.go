package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/google/uuid"
)

var loginOTPPattern = regexp.MustCompile(`^[0-9]{6}$`)

type loginChallengeRequest struct {
	ChallengeID string `json:"challenge_id"`
	OTP         string `json:"otp"`
}
type updateManagedUserLoginSecurityRequest struct {
	ExpectedRevision  *int64   `json:"expected_revision"`
	LoginVerification *string  `json:"login_verification"`
	LoginAllowlist    []string `json:"login_allowlist"`
}

func (body *updateManagedUserLoginSecurityRequest) UnmarshalJSON(raw []byte) error {
	if err := validateL4JSONKeys(raw); err != nil {
		return err
	}
	type fields updateManagedUserLoginSecurityRequest
	var value fields
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	*body = updateManagedUserLoginSecurityRequest(value)
	return nil
}

func loginSecurityIDs(r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["tenant_scope_id"]) != 1 {
		return uuid.Nil, uuid.Nil, false
	}
	user, userErr := uuid.Parse(r.PathValue("id"))
	scope, scopeErr := uuid.Parse(query.Get("tenant_scope_id"))
	return user, scope, userErr == nil && scopeErr == nil && user != uuid.Nil && scope != uuid.Nil && user.String() == r.PathValue("id") && scope.String() == query.Get("tenant_scope_id")
}

func (s *Server) requireLoginSecuritySession(w http.ResponseWriter, r *http.Request) (identity.AuthenticatedSession, bool) {
	if _, err := r.Cookie(impersonationhttp.CookieName); err == nil {
		s.writeError(w, r, identity.ErrPermissionDenied)
		return identity.AuthenticatedSession{}, false
	}
	return s.requireManagedPasswordResetSession(w, r)
}

func (s *Server) handleGetManagedUserLoginSecurity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, ok := s.requireLoginSecuritySession(w, r)
	if !ok {
		return
	}
	userID, scopeID, ok := loginSecurityIDs(r)
	if !ok {
		s.writeAPIError(w, r, 400, "validation_error", "login security target is invalid")
		return
	}
	result, err := s.identity.GetManagedUserLoginSecurity(r.Context(), identity.Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID, ScopeKind: session.Principal.ScopeKind, SessionID: session.SessionID}, userID, scopeID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateManagedUserLoginSecurity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	session, ok := s.requireLoginSecuritySession(w, r)
	if !ok {
		return
	}
	userID, scopeID, ok := loginSecurityIDs(r)
	if !ok {
		s.writeAPIError(w, r, 400, "validation_error", "login security target is invalid")
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body updateManagedUserLoginSecurityRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, 400, "invalid_request", "request body is invalid")
		return
	}
	if body.ExpectedRevision == nil || body.LoginVerification == nil || body.LoginAllowlist == nil {
		s.writeAPIError(w, r, 400, "validation_error", "login security fields are required")
		return
	}
	result, err := s.identity.UpdateManagedUserLoginSecurity(r.Context(), identity.Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID, ScopeKind: session.Principal.ScopeKind, SessionID: session.SessionID}, identity.UpdateManagedUserLoginSecurityInput{
		UserID: userID, TenantScopeID: scopeID, ExpectedRevision: *body.ExpectedRevision, LoginVerification: *body.LoginVerification, LoginAllowlist: body.LoginAllowlist, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeLoginSecurityError(w http.ResponseWriter, r *http.Request, err error) bool {
	var throttled *identity.LoginThrottled
	if errors.As(err, &throttled) {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(throttled.RetryAfter/time.Second), 10))
		s.writeAPIError(w, r, http.StatusTooManyRequests, "login_throttled", "too many failed sign-in attempts")
		return true
	}
	var required *identity.LoginVerificationRequired
	if errors.As(err, &required) {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "login_verification_required", "message": "login verification is required", "request_id": requestID(r.Context()), "params": map[string]string{"channel": required.Channel, "scope_id": required.ScopeID.String()}}})
		return true
	}
	status, code := 0, ""
	switch {
	case errors.Is(err, identity.ErrLoginSourceDenied):
		status, code = 403, "login_source_denied"
	case errors.Is(err, identity.ErrAdminAccessDenied):
		status, code = 403, "admin_access_denied"
	case errors.Is(err, identity.ErrSessionRegionChanged):
		status, code = 401, "session_region_changed"
	case errors.Is(err, identity.ErrPasswordChangeRequired):
		status, code = 403, "password_change_required"
	case errors.Is(err, identity.ErrAdminAccessSelfLockout):
		status, code = 422, "admin_access_self_lockout"
	case errors.Is(err, identity.ErrAdminAccessInvalidInput):
		status, code = 400, "validation_error"
	case errors.Is(err, identity.ErrAdminAccessRevision):
		status, code = 409, "version_conflict"
	case errors.Is(err, identity.ErrAdminAccessUnavailable):
		status, code = 503, "admin_access_unavailable"
	case errors.Is(err, identity.ErrLoginCaptchaRequired):
		status, code = 401, "login_captcha_required"
	case errors.Is(err, identity.ErrLoginCaptchaInvalid):
		status, code = 401, "login_captcha_invalid"
	case errors.Is(err, identity.ErrLoginCaptchaRateLimited):
		status, code = 429, "login_captcha_rate_limited"
	case errors.Is(err, identity.ErrLoginChallengeInvalid), errors.Is(err, identity.ErrLoginChallengeUsed):
		status, code = 401, "account_login_verification_invalid"
	case errors.Is(err, identity.ErrLoginChallengeIdempotencyConflict):
		status, code = 409, "account_login_idempotency_conflict"
	case errors.Is(err, identity.ErrLoginMethodDisabled):
		status, code = 403, "account_login_method_disabled"
	case errors.Is(err, identity.ErrLoginSecurityContactRequired):
		status, code = 422, "login_security_contact_required"
	case errors.Is(err, identity.ErrLoginSecurityUnavailable):
		status, code = 503, "login_security_unavailable"
	default:
		return false
	}
	s.writeAPIError(w, r, status, code, "login security request could not be completed")
	return true
}
