package httpapi

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// builtin registration: without the Turnstile registration runtime (the fresh-install
// default) POST /v1/auth/register registers with the built-in image CAPTCHA
// (POST /v1/auth/login-captchas) and GET /v1/auth/login-methods advertises it
// as registration_mode "builtin" while 开放注册 is on.

// BuiltInRegistration is accountregistration.BuiltInService.
type BuiltInRegistration interface {
	Available(context.Context) (bool, error)
	Register(context.Context, accountregistration.BuiltInInput) (accountregistration.RegisterResult, error)
}

var builtInRegistrationMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type builtInRegistrationBody struct {
	Username            string               `json:"username"`
	Password            string               `json:"password"`
	DisplayName         string               `json:"display_name"`
	Email               string               `json:"email"`
	Phone               string               `json:"phone"`
	TermsAccepted       bool                 `json:"terms_accepted"`
	TermsVersion        string               `json:"terms_version"`
	VerificationChannel string               `json:"verification_channel"`
	Captcha             *loginCaptchaRequest `json:"captcha"`
}

func (s *Server) handleBuiltInRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body builtInRegistrationBody
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "account_registration_invalid_input", "request body is invalid")
		return
	}
	if !body.TermsAccepted {
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "account_registration_terms_required", "terms must be accepted")
		return
	}
	captcha, ok := s.loginCaptchaProof(w, r, body.Captcha)
	if !ok {
		return
	}
	if captcha == nil {
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "account_registration_captcha_invalid", "captcha is required")
		return
	}
	info := s.requestInfo(r)
	requestID := info.RequestID
	if !builtInRegistrationMetadataPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	result, err := s.builtInRegistration.Register(r.Context(), accountregistration.BuiltInInput{
		RegisterInput: accountregistration.RegisterInput{
			Username: body.Username, Password: body.Password, DisplayName: body.DisplayName,
			Email: body.Email, Phone: body.Phone, TermsAccepted: body.TermsAccepted,
			TermsVersion: body.TermsVersion, VerificationChannel: body.VerificationChannel,
			IdempotencyKey: key, RequestID: requestID, Source: info.SourceIP,
		},
		Captcha: identity.LoginCaptchaProof{ID: captcha.ID, Answer: captcha.Answer},
	})
	if err != nil {
		s.writeBuiltInRegistrationError(w, r, err)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, result)
}

func (s *Server) writeBuiltInRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	if details, ok := passwordpolicy.DetailsOf(err); ok {
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{
			"code": passwordpolicy.Code, "message": "password does not meet the policy",
			"request_id": requestID(r.Context()), "details": details,
		}})
		return
	}
	switch {
	case errors.Is(err, accountregistration.ErrCaptchaInvalid):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "account_registration_captcha_invalid", "captcha is invalid")
	case errors.Is(err, accountregistration.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "account_registration_invalid_input", "registration details are invalid")
	case errors.Is(err, accountregistration.ErrRegistrationDisabled):
		s.writeAPIError(w, r, http.StatusForbidden, "account_registration_disabled", "registration is closed")
	case errors.Is(err, accountregistration.ErrContactVerificationUnavailable):
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_registration_verification_unavailable",
			"contact verification needs the registration verification service")
	case errors.Is(err, accountregistration.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "account_registration_idempotency_conflict", "idempotency key reused with other details")
	default:
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_registration_unavailable", "registration is unavailable")
	}
}

// handleLoginMethodsDisabled answers GET /v1/auth/login-methods when the
// account login runtime is not mounted: same shape as
// accountloginchallengehttp, code login off, so only password sign-in shows;
// registration follows 开放注册 when built-in registration is mounted.
func (s *Server) handleLoginMethodsDisabled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	registration, mode := false, ""
	if s.accountRegistrationHandler == nil && s.builtInRegistration != nil {
		available, err := s.builtInRegistration.Available(r.Context())
		if err != nil {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "account_login_unavailable", "login methods are unavailable")
			return
		}
		registration, mode = available, "builtin"
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"registration_enabled": registration, "registration_mode": mode,
		"email_enabled": false, "sms_enabled": false,
		"email_anti_abuse_mode": "", "sms_anti_abuse_mode": "",
		"captcha_provider": "", "captcha_app_id": "",
	}})
}
