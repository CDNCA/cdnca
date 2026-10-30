package accountregistrationchallengehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/google/uuid"
)

const (
	ChallengePath          = "/v1/auth/registration-challenges"
	VerificationPath       = "/v1/auth/registration-challenge-verifications"
	defaultTimeout         = 10 * time.Second
	maximumTimeout         = 30 * time.Second
	defaultMaxRequestBytes = 16 << 10
	maximumMaxRequestBytes = 64 << 10
	defaultRetryAfter      = time.Minute
	maximumRetryAfter      = time.Hour
)

var (
	errInvalidRequest     = errors.New("invalid account registration challenge HTTP request")
	errTrustedUnavailable = errors.New("trusted account registration challenge context unavailable")
	metadataPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type ChallengeService interface {
	Create(context.Context, accountregistrationchallenge.CreateInput) (accountregistrationchallenge.CreateResult, error)
	Verify(context.Context, accountregistrationchallenge.VerifyInput) (accountregistrationchallenge.VerifyResult, error)
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
		return TrustedContext{}, errTrustedUnavailable
	}
	return function(request)
}

type Config struct {
	Timeout         time.Duration
	MaxRequestBytes int64
	RetryAfter      time.Duration
}

type Handler struct {
	service         ChallengeService
	trusted         TrustedContextResolver
	timeout         time.Duration
	maxRequestBytes int64
	retryAfter      time.Duration
}

type challengeBody struct {
	Username            string `json:"username"`
	Email               string `json:"email"`
	Phone               string `json:"phone"`
	VerificationChannel string `json:"verification_channel"`
	HumanToken          string `json:"human_token"`
}

type verificationBody struct {
	ChallengeID         uuid.UUID `json:"challenge_id"`
	Username            string    `json:"username"`
	Email               string    `json:"email"`
	Phone               string    `json:"phone"`
	VerificationChannel string    `json:"verification_channel"`
	OTP                 string    `json:"otp"`
}

type challengeResponse struct {
	Data challengeResponseData `json:"data"`
}

type challengeResponseData struct {
	Accepted    bool      `json:"accepted"`
	ChallengeID uuid.UUID `json:"challenge_id"`
	ExpiresAt   string    `json:"expires_at"`
	Replayed    bool      `json:"replayed"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

func NewHandler(service ChallengeService, trusted TrustedContextResolver, config Config) (*Handler, error) {
	if service == nil || trusted == nil {
		return nil, errInvalidRequest
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.RetryAfter == 0 {
		config.RetryAfter = defaultRetryAfter
	}
	if config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > maximumMaxRequestBytes ||
		config.RetryAfter <= 0 || config.RetryAfter > maximumRetryAfter {
		return nil, errInvalidRequest
	}
	return &Handler{
		service: service, trusted: trusted, timeout: config.Timeout,
		maxRequestBytes: config.MaxRequestBytes, retryAfter: config.RetryAfter,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	requestID, requestIDOK := exactMetadataHeader(request, "X-Request-ID")
	if !requestIDOK {
		requestID = uuid.NewString()
	}
	writer.Header().Set("X-Request-ID", requestID)
	if !requestIDOK || request.URL.RawQuery != "" ||
		(request.URL.Path != ChallengePath && request.URL.Path != VerificationPath) {
		handler.writeError(writer, http.StatusUnprocessableEntity, "account_registration_challenge_invalid", requestID)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		handler.writeError(writer, http.StatusMethodNotAllowed, "account_registration_challenge_invalid", requestID)
		return
	}
	if values := request.Header.Values("Content-Type"); len(values) != 1 || values[0] != "application/json" {
		handler.writeError(writer, http.StatusUnprocessableEntity, "account_registration_challenge_invalid", requestID)
		return
	}
	idempotencyKey, ok := exactMetadataHeader(request, "Idempotency-Key")
	if !ok {
		handler.writeError(writer, http.StatusUnprocessableEntity, "account_registration_challenge_invalid", requestID)
		return
	}
	trusted, err := handler.trusted.ResolveTrustedContext(request)
	if err != nil || trusted.ScopeID == uuid.Nil || trusted.SourceIP == "" {
		handler.writeError(writer, http.StatusServiceUnavailable, "account_registration_challenge_unavailable", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	if request.URL.Path == ChallengePath {
		handler.create(writer, request, trusted, requestID, idempotencyKey)
		return
	}
	handler.verify(writer, request, trusted, requestID, idempotencyKey)
}

func (handler *Handler) create(
	writer http.ResponseWriter,
	request *http.Request,
	trusted TrustedContext,
	requestID, idempotencyKey string,
) {
	var body challengeBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	result, err := handler.service.Create(request.Context(), accountregistrationchallenge.CreateInput{
		ScopeID: trusted.ScopeID, Username: body.Username, Email: body.Email, Phone: body.Phone,
		Channel: body.VerificationChannel, Source: trusted.SourceIP, HumanToken: body.HumanToken,
		IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	handler.writeJSON(writer, http.StatusAccepted, challengeResponse{Data: challengeResponseData{
		Accepted: true, ChallengeID: result.ChallengeID,
		ExpiresAt: result.ExpiresAt.UTC().Format(time.RFC3339Nano), Replayed: result.Replayed,
	}})
}

func (handler *Handler) verify(
	writer http.ResponseWriter,
	request *http.Request,
	trusted TrustedContext,
	requestID, idempotencyKey string,
) {
	var body verificationBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	result, err := handler.service.Verify(request.Context(), accountregistrationchallenge.VerifyInput{
		ScopeID: trusted.ScopeID, ChallengeID: body.ChallengeID, Username: body.Username,
		Email: body.Email, Phone: body.Phone, Channel: body.VerificationChannel,
		Source: trusted.SourceIP, OTP: body.OTP, IdempotencyKey: idempotencyKey, RequestID: requestID,
	})
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	cookie, err := accountregistrationproof.NewReferenceCookie(result.Reference, result.ExpiresAt)
	if err != nil {
		handler.writeServiceError(writer, requestID, accountregistrationchallenge.ErrChallengeUnavailable)
		return
	}
	http.SetCookie(writer, cookie)
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || rejectDuplicateKeys(raw) != nil {
		return errInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errInvalidRequest
	}
	return nil
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, requestID string, err error) {
	status, code := http.StatusServiceUnavailable, "account_registration_challenge_unavailable"
	switch {
	case errors.Is(err, accountregistrationchallenge.ErrInvalidInput),
		errors.Is(err, accountregistrationchallenge.ErrHumanInvalid),
		errors.Is(err, accountregistrationchallenge.ErrOTPInvalid), errors.Is(err, errInvalidRequest):
		status, code = http.StatusUnprocessableEntity, "account_registration_challenge_invalid"
	case errors.Is(err, accountregistrationchallenge.ErrRegistrationDisabled):
		status, code = http.StatusForbidden, "account_registration_disabled"
	case errors.Is(err, accountregistrationchallenge.ErrPolicyUnavailable):
		status, code = http.StatusServiceUnavailable, "account_registration_challenge_unavailable"
	case errors.Is(err, accountregistrationchallenge.ErrRateLimited):
		status, code = http.StatusTooManyRequests, "account_registration_challenge_rate_limited"
		seconds := (handler.retryAfter + time.Second - 1) / time.Second
		writer.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
	case errors.Is(err, accountregistrationchallenge.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "account_registration_challenge_conflict"
	}
	handler.writeError(writer, status, code, requestID)
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

func exactMetadataHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && metadataPattern.MatchString(returnValue)
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
					return errInvalidRequest
				}
				if _, exists := seen[key]; exists {
					return errInvalidRequest
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
