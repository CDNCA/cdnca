package accountloginchallengehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

const (
	MethodsPath      = "/v1/auth/login-methods"
	ChallengePath    = "/v1/auth/login-challenges"
	VerificationPath = "/v1/auth/login-challenge-verifications"
	refreshCookie    = "cdnca_refresh"
)

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Service interface {
	Methods(context.Context, uuid.UUID) (accountloginchallenge.Methods, error)
	Create(context.Context, accountloginchallenge.CreateInput) (accountloginchallenge.CreateResult, error)
	Verify(context.Context, accountloginchallenge.VerifyInput) (accountloginchallenge.VerifyResult, error)
}

type TrustedContext struct {
	ScopeID  uuid.UUID
	SourceIP string
}

type TrustedContextResolver interface {
	ResolveTrustedContext(*http.Request) (TrustedContext, error)
}

type TrustedContextResolverFunc func(*http.Request) (TrustedContext, error)

func (function TrustedContextResolverFunc) ResolveTrustedContext(request *http.Request) (TrustedContext, error) {
	if function == nil {
		return TrustedContext{}, accountloginchallenge.ErrUnavailable
	}
	return function(request)
}

type Config struct {
	CookieSecure     bool
	CookieDomain     string
	Timeout          time.Duration
	RetryAfter       time.Duration
	MaxRequestBytes  int64
	SourceIPResolver interface {
		ResolveSourceIP(*http.Request) (netip.Addr, error)
	}
}

type Handler struct {
	service Service
	trusted TrustedContextResolver
	config  Config
}

type challengeBody struct {
	Identifier *string               `json:"identifier"`
	Channel    *notification.Channel `json:"channel"`
	HumanToken string                `json:"human_token"`
	Username   *string               `json:"username"`
	Password   *string               `json:"password"`
	ScopeID    *string               `json:"scope_id"`
	Captcha    *captchaBody          `json:"captcha"`
}

// captchaBody is the solved built-in sign-in CAPTCHA (identity login throttle).
type captchaBody struct {
	ID     string `json:"id"`
	Answer string `json:"answer"`
}

type verificationBody struct {
	ChallengeID uuid.UUID            `json:"challenge_id"`
	Identifier  string               `json:"identifier"`
	Channel     notification.Channel `json:"channel"`
	OTP         string               `json:"otp"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func NewHandler(service Service, trusted TrustedContextResolver, config Config) (*Handler, error) {
	if service == nil || trusted == nil {
		return nil, accountloginchallenge.ErrInvalidConfig
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.RetryAfter == 0 {
		config.RetryAfter = time.Minute
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = 16 << 10
	}
	if config.Timeout <= 0 || config.Timeout > 30*time.Second || config.RetryAfter <= 0 || config.RetryAfter > time.Hour ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 64<<10 {
		return nil, accountloginchallenge.ErrInvalidConfig
	}
	return &Handler{service: service, trusted: trusted, config: config}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	requestID, requestIDOK := exactHeader(request, "X-Request-ID")
	if !requestIDOK {
		requestID = uuid.NewString()
	}
	writer.Header().Set("X-Request-ID", requestID)
	if request.URL.RawQuery != "" || (request.URL.Path != MethodsPath && request.URL.Path != ChallengePath && request.URL.Path != VerificationPath) {
		handler.writeError(writer, http.StatusUnprocessableEntity, "account_login_invalid_request", requestID)
		return
	}
	var challengeRequest *challengeBody
	if request.URL.Path == ChallengePath && request.Method == http.MethodPost {
		if values := request.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" {
			handler.writeError(writer, http.StatusUnprocessableEntity, "account_login_invalid_request", requestID)
			return
		}
		key, validKey := exactHeader(request, "Idempotency-Key")
		if !validKey || !requestIDOK {
			handler.writeError(writer, http.StatusUnprocessableEntity, "account_login_invalid_request", requestID)
			return
		}
		var body challengeBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		if body.Username != nil || body.Password != nil || body.ScopeID != nil {
			handler.servePasswordChallenge(writer, request, requestID, key, body)
			return
		}
		if body.Identifier == nil || body.Channel == nil {
			handler.writeServiceError(writer, requestID, accountloginchallenge.ErrInvalidInput)
			return
		}
		challengeRequest = &body
	}
	trusted, err := handler.trusted.ResolveTrustedContext(request)
	if err != nil || trusted.ScopeID == uuid.Nil || trusted.SourceIP == "" {
		handler.writeError(writer, http.StatusServiceUnavailable, "account_login_unavailable", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.config.Timeout)
	defer cancel()
	request = request.WithContext(ctx)
	if request.URL.Path == MethodsPath {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			handler.writeError(writer, http.StatusMethodNotAllowed, "account_login_invalid_request", requestID)
			return
		}
		methods, err := handler.service.Methods(ctx, trusted.ScopeID)
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		handler.writeJSON(writer, http.StatusOK, map[string]any{"data": map[string]any{
			"registration_enabled": methods.RegistrationEnabled,
			"email_enabled":        methods.EmailEnabled, "sms_enabled": methods.SMSEnabled,
			"email_anti_abuse_mode": methods.EmailAntiAbuseMode, "sms_anti_abuse_mode": methods.SMSAntiAbuseMode,
			"captcha_provider": methods.CaptchaProvider, "captcha_app_id": methods.CaptchaAppID,
		}})
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		handler.writeError(writer, http.StatusMethodNotAllowed, "account_login_invalid_request", requestID)
		return
	}
	if values := request.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" {
		handler.writeError(writer, http.StatusUnprocessableEntity, "account_login_invalid_request", requestID)
		return
	}
	idempotencyKey, ok := exactHeader(request, "Idempotency-Key")
	if !ok || !requestIDOK {
		handler.writeError(writer, http.StatusUnprocessableEntity, "account_login_invalid_request", requestID)
		return
	}
	if request.URL.Path == ChallengePath {
		body := *challengeRequest
		result, err := handler.service.Create(ctx, accountloginchallenge.CreateInput{
			ScopeID: trusted.ScopeID, Identifier: *body.Identifier, Channel: *body.Channel, Source: trusted.SourceIP,
			HumanToken: body.HumanToken, IdempotencyKey: idempotencyKey, RequestID: requestID,
		})
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		handler.writeJSON(writer, http.StatusAccepted, map[string]any{"data": map[string]any{
			"accepted": true, "challenge_id": result.ChallengeID, "expires_at": result.ExpiresAt.UTC().Format(time.RFC3339Nano),
			"replayed": result.Replayed,
		}})
		return
	}
	var body verificationBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	result, err := handler.service.Verify(ctx, accountloginchallenge.VerifyInput{
		ScopeID: trusted.ScopeID, ChallengeID: body.ChallengeID, Identifier: body.Identifier, Channel: body.Channel,
		Source: trusted.SourceIP, OTP: body.OTP, IdempotencyKey: idempotencyKey, RequestID: requestID,
		UserAgent: request.UserAgent(),
	})
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	handler.setRefreshCookie(writer, result.Auth.RefreshToken, result.Auth.RefreshExpiresAt)
	http.SetCookie(writer, &http.Cookie{Name: impersonationhttp.CookieName, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	expiresIn := max(int64(time.Until(result.Auth.ExpiresAt).Seconds()), 1)
	handler.writeJSON(writer, http.StatusOK, map[string]any{
		"access_token": result.Auth.AccessToken, "token_type": "Bearer", "expires_in": expiresIn,
		"principal": result.Auth.Principal,
	})
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, handler.config.MaxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || rejectDuplicateKeys(raw) != nil {
		return accountloginchallenge.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return accountloginchallenge.ErrInvalidInput
	}
	return nil
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, requestID string, err error) {
	status, code := http.StatusServiceUnavailable, "account_login_unavailable"
	var throttled *identity.LoginThrottled
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		status, code = http.StatusUnauthorized, "invalid_credentials"
	case errors.Is(err, identity.ErrAccountDisabled):
		status, code = http.StatusForbidden, "account_disabled"
	case errors.Is(err, identity.ErrMembershipDisabled):
		status, code = http.StatusForbidden, "membership_disabled"
	case errors.As(err, &throttled):
		status, code = http.StatusTooManyRequests, "login_throttled"
		writer.Header().Set("Retry-After", strconv.FormatInt(int64(throttled.RetryAfter/time.Second), 10))
	case errors.Is(err, identity.ErrAdminAccessDenied):
		status, code = http.StatusForbidden, "admin_access_denied"
	case errors.Is(err, identity.ErrLoginCaptchaRequired):
		status, code = http.StatusUnauthorized, "login_captcha_required"
	case errors.Is(err, identity.ErrLoginCaptchaInvalid):
		status, code = http.StatusUnauthorized, "login_captcha_invalid"
	case errors.Is(err, identity.ErrLoginSourceDenied):
		status, code = http.StatusForbidden, "login_source_denied"
	case errors.Is(err, identity.ErrLoginSecurityContactRequired):
		status, code = http.StatusUnprocessableEntity, "login_security_contact_required"
	case errors.Is(err, identity.ErrLoginSecurityUnavailable):
		status, code = http.StatusServiceUnavailable, "login_security_unavailable"
	case errors.Is(err, identity.ErrLoginMethodDisabled):
		status, code = http.StatusForbidden, "account_login_method_disabled"
	case errors.Is(err, identity.ErrLoginChallengeInvalid):
		status, code = http.StatusUnauthorized, "account_login_verification_invalid"
	case errors.Is(err, accountloginchallenge.ErrInvalidInput):
		status, code = http.StatusUnprocessableEntity, "account_login_invalid_request"
	case errors.Is(err, accountloginchallenge.ErrMethodDisabled):
		status, code = http.StatusForbidden, "account_login_method_disabled"
	case errors.Is(err, accountloginchallenge.ErrHumanRequired):
		status, code = http.StatusUnprocessableEntity, "account_login_human_verification_required"
	case errors.Is(err, accountloginchallenge.ErrHumanInvalid):
		status, code = http.StatusUnprocessableEntity, "account_login_human_verification_invalid"
	case errors.Is(err, accountloginchallenge.ErrRateLimited):
		status, code = http.StatusTooManyRequests, "account_login_rate_limited"
		seconds := (handler.config.RetryAfter + time.Second - 1) / time.Second
		writer.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
	case errors.Is(err, accountloginchallenge.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "account_login_idempotency_conflict"
	case errors.Is(err, accountloginchallenge.ErrOTPInvalid), errors.Is(err, accountloginchallenge.ErrChallengeUsed):
		status, code = http.StatusUnauthorized, "account_login_verification_invalid"
	}
	handler.writeError(writer, status, code, requestID)
}

func (handler *Handler) setRefreshCookie(writer http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(writer, &http.Cookie{Name: refreshCookie, Value: token, Path: "/v1/auth", Domain: handler.config.CookieDomain,
		Expires: expiresAt, MaxAge: max(int(time.Until(expiresAt).Seconds()), 1), HttpOnly: true,
		Secure: handler.config.CookieSecure, SameSite: http.SameSiteStrictMode})
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, code, requestID string) {
	handler.writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, RequestID: requestID}})
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}

func exactHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 || !metadataPattern.MatchString(values[0]) {
		return "", false
	}
	return values[0], true
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		seen := map[string]struct{}{}
		for decoder.More() {
			if delimiter == '{' {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return accountloginchallenge.ErrInvalidInput
				}
				if _, exists := seen[key]; exists {
					return accountloginchallenge.ErrInvalidInput
				}
				seen[key] = struct{}{}
			}
			if err := walk(); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return walk()
}

var _ Service = (*accountloginchallenge.Service)(nil)
