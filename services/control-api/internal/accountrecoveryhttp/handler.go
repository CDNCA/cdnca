package accountrecoveryhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/google/uuid"
)

const (
	requestPath            = "/v1/account-recovery/requests"
	confirmationPath       = "/v1/account-recovery/confirmations"
	defaultTimeout         = 10 * time.Second
	maximumTimeout         = 30 * time.Second
	defaultRetryAfter      = 15 * time.Minute
	maximumRetryAfter      = 24 * time.Hour
	defaultMaxRequestBytes = 8 << 10
	maximumRequestBytes    = 64 << 10
)

var (
	metadataPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

var (
	errInvalidRequest            = errors.New("invalid account recovery HTTP request")
	errTrustedContextUnavailable = errors.New("trusted account recovery context unavailable")
)

type RecoveryService interface {
	Request(context.Context, accountrecovery.RequestInput) (accountrecovery.RequestResult, error)
	Reset(context.Context, accountrecovery.ResetInput) (accountrecovery.ResetResult, error)
}

type TrustedContext struct {
	TenantID  uuid.UUID
	ScopeID   uuid.UUID
	RequestID string
	TraceID   string
	SourceIP  string
}

type ResolveTrustedContext func(*http.Request) (TrustedContext, error)

type Config struct {
	DigestKey       []byte
	Clock           func() time.Time
	Timeout         time.Duration
	RetryAfter      time.Duration
	MaxRequestBytes int64
	Logger          *slog.Logger
}

type Handler struct {
	service         RecoveryService
	resolve         ResolveTrustedContext
	digestKey       []byte
	now             func() time.Time
	timeout         time.Duration
	retryAfter      time.Duration
	maxRequestBytes int64
	logger          *slog.Logger
}

type requestBody struct {
	Username string `json:"username"`
}

type confirmationBody struct {
	Token           string `json:"token"`
	RecoveryContext string `json:"recovery_context"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

type requestResponse struct {
	Data requestResponseData `json:"data"`
}

type requestResponseData struct {
	Code       string `json:"code"`
	AcceptedAt string `json:"accepted_at"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
	// Details lists the unmet items of a password_policy_unmet error.
	Details *passwordpolicy.Details `json:"details,omitempty"`
}

func NewHandler(service RecoveryService, resolve ResolveTrustedContext, config Config) (*Handler, error) {
	if service == nil || resolve == nil || len(config.DigestKey) < 32 {
		return nil, errInvalidRequest
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.RetryAfter == 0 {
		config.RetryAfter = defaultRetryAfter
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		config.RetryAfter <= 0 || config.RetryAfter > maximumRetryAfter ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > maximumRequestBytes {
		return nil, errInvalidRequest
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Handler{
		service: service, resolve: resolve, digestKey: append([]byte(nil), config.DigestKey...),
		now: config.Clock, timeout: config.Timeout, retryAfter: config.RetryAfter,
		maxRequestBytes: config.MaxRequestBytes,
		logger:          config.Logger,
	}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "no-referrer")

	trusted, err := handler.resolve(request)
	requestID := trusted.RequestID
	if !metadataPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	writer.Header().Set("X-Request-ID", requestID)
	if err != nil || !validTrustedMetadata(trusted) {
		handler.writeServiceError(writer, request, requestID, errTrustedContextUnavailable)
		return
	}

	if request.URL.RawQuery != "" {
		handler.writeServiceError(writer, request, requestID, errInvalidRequest)
		return
	}
	switch request.URL.Path {
	case requestPath, confirmationPath:
	default:
		handler.writeError(writer, http.StatusNotFound, "account_recovery_route_not_found", requestID)
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		handler.writeError(writer, http.StatusMethodNotAllowed, "account_recovery_method_not_allowed", requestID)
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(ctx)
	if request.URL.Path == requestPath {
		handler.handleRequest(writer, request, trusted, requestID)
		return
	}
	handler.handleConfirmation(writer, request, trusted, requestID)
}

func (handler *Handler) handleRequest(
	writer http.ResponseWriter,
	request *http.Request,
	trusted TrustedContext,
	requestID string,
) {
	key, err := idempotencyKey(request)
	if err != nil {
		handler.writeServiceError(writer, request, requestID, errInvalidRequest)
		return
	}
	if trusted.ScopeID == uuid.Nil {
		handler.writeServiceError(writer, request, requestID, errTrustedContextUnavailable)
		return
	}
	var body requestBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		handler.writeServiceError(writer, request, requestID, err)
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" || len(username) > 1024 {
		handler.writeServiceError(writer, request, requestID, errInvalidRequest)
		return
	}
	result, err := handler.service.Request(request.Context(), accountrecovery.RequestInput{
		TenantID: trusted.TenantID, ScopeID: trusted.ScopeID, Username: username, IdempotencyKey: key,
		Context: accountrecovery.RequestContext{
			RequestID: requestID, TraceID: trusted.TraceID, SourceIP: canonicalIP(trusted.SourceIP),
		},
	})
	if err != nil {
		handler.writeServiceError(writer, request, requestID, err)
		return
	}
	handler.writeJSON(writer, http.StatusAccepted, requestResponse{Data: requestResponseData{
		Code: "account_recovery_request_accepted", AcceptedAt: result.AcceptedAt.UTC().Format(time.RFC3339Nano),
	}})
}

func (handler *Handler) handleConfirmation(
	writer http.ResponseWriter,
	request *http.Request,
	trusted TrustedContext,
	requestID string,
) {
	key, err := idempotencyKey(request)
	if err != nil {
		handler.writeServiceError(writer, request, requestID, err)
		return
	}
	var body confirmationBody
	if err := handler.decodeJSON(writer, request, &body); err != nil {
		handler.writeServiceError(writer, request, requestID, err)
		return
	}
	if body.NewPassword != body.ConfirmPassword {
		handler.writeServiceError(writer, request, requestID, errInvalidRequest)
		return
	}
	if err := passwordpolicy.Check(body.NewPassword); err != nil {
		handler.writeServiceError(writer, request, requestID, fmt.Errorf("%w: %w", accountrecovery.ErrPasswordPolicy, err))
		return
	}
	scope, err := accountrecovery.VerifyRecoveryContext(
		handler.digestKey, body.Token, body.RecoveryContext, handler.now(),
	)
	if err != nil {
		handler.writeServiceError(writer, request, requestID, accountrecovery.ErrInvalidToken)
		return
	}
	result, err := handler.service.Reset(request.Context(), accountrecovery.ResetInput{
		TenantID: scope.TenantID, ScopeID: scope.ScopeID, Token: body.Token,
		NewPassword: body.NewPassword, ConfirmPassword: body.ConfirmPassword, IdempotencyKey: key,
		Context: accountrecovery.RequestContext{
			RequestID: requestID, TraceID: trusted.TraceID, SourceIP: canonicalIP(trusted.SourceIP),
		},
	})
	if err != nil {
		handler.writeServiceError(writer, request, requestID, err)
		return
	}
	if result.Replayed {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return errInvalidRequest
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || rejectDuplicateJSONKeys(raw) != nil {
		return errInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errInvalidRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return errInvalidRequest
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errInvalidRequest
		}
	default:
		return errInvalidRequest
	}
	return nil
}

func idempotencyKey(request *http.Request) (string, error) {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !idempotencyKeyPattern.MatchString(values[0]) {
		return "", errInvalidRequest
	}
	return values[0], nil
}

func validTrustedMetadata(trusted TrustedContext) bool {
	return metadataPattern.MatchString(trusted.RequestID) &&
		metadataPattern.MatchString(trusted.TraceID) && canonicalIP(trusted.SourceIP) != ""
}

func canonicalIP(value string) string {
	parsed := net.ParseIP(strings.TrimSpace(value))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func (handler *Handler) writeServiceError(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	err error,
) {
	status, code := classifyError(err)
	if status == http.StatusTooManyRequests {
		seconds := (handler.retryAfter + time.Second - 1) / time.Second
		writer.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
	}
	if status >= 500 {
		handler.logger.ErrorContext(request.Context(), "account recovery HTTP request failed",
			"request_id", requestID, "code", code, "method", request.Method, "path", request.URL.Path)
	}
	details, _ := passwordpolicy.DetailsOf(err)
	handler.writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, RequestID: requestID, Details: details}})
}

func classifyError(err error) (int, string) {
	switch {
	case errors.Is(err, errInvalidRequest), errors.Is(err, accountrecovery.ErrInvalidInput):
		return http.StatusBadRequest, "account_recovery_invalid_request"
	case errors.Is(err, accountrecovery.ErrRateLimited):
		return http.StatusTooManyRequests, "account_recovery_rate_limited"
	case errors.Is(err, accountrecovery.ErrInvalidToken):
		return http.StatusBadRequest, "account_recovery_invalid_token"
	case errors.Is(err, accountrecovery.ErrPasswordPolicy):
		return http.StatusUnprocessableEntity, passwordpolicy.Code
	case errors.Is(err, accountrecovery.ErrPasswordReused):
		return http.StatusUnprocessableEntity, "account_recovery_password_reused"
	case errors.Is(err, accountrecovery.ErrPrincipalChanged):
		return http.StatusConflict, "account_recovery_principal_changed"
	case errors.Is(err, accountrecovery.ErrIdempotencyConflict):
		return http.StatusConflict, "account_recovery_idempotency_conflict"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "account_recovery_request_cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "account_recovery_timeout"
	case errors.Is(err, accountrecovery.ErrScopeMismatch),
		errors.Is(err, accountrecovery.ErrDispatchUnavailable):
		return http.StatusServiceUnavailable, "account_recovery_unavailable"
	default:
		return http.StatusServiceUnavailable, "account_recovery_unavailable"
	}
}

func (handler *Handler) writeError(writer http.ResponseWriter, status int, code, requestID string) {
	handler.writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, RequestID: requestID}})
}

func (*Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
