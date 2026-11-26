package accountregistrationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/google/uuid"
)

const (
	registrationPath       = "/v1/auth/register"
	defaultMaxRequestBytes = 16 << 10
	maximumRequestBytes    = 64 << 10
	defaultTimeout         = 10 * time.Second
	maximumTimeout         = 30 * time.Second
	defaultRetryAfter      = time.Minute
	maximumRetryAfter      = time.Hour
)

var (
	registrationMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	registrationProofPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	errInvalidRequest           = errors.New("invalid account registration HTTP request")
	errDependencyUnavailable    = errors.New("account registration HTTP dependency unavailable")
)

type RegistrationApplication interface {
	Register(context.Context, accountregistration.RegisterInput) (accountregistration.RegisterResult, error)
}

type SourceIPResolver interface {
	ResolveSourceIP(*http.Request) (netip.Addr, error)
}

type ScopeResolver interface {
	ResolveScope(*http.Request) (uuid.UUID, error)
}

type ScopeResolverFunc func(*http.Request) (uuid.UUID, error)

func (function ScopeResolverFunc) ResolveScope(request *http.Request) (uuid.UUID, error) {
	if function == nil {
		return uuid.Nil, errDependencyUnavailable
	}
	return function(request)
}

type ProofReferenceResolver interface {
	ResolveProofReference(*http.Request) (string, error)
}

// MultiProofReferenceResolver also returns the per-channel proof references
// (several verifications required at once), of the
// challenges the registration names.
type MultiProofReferenceResolver interface {
	ResolveProofReferences(*http.Request, map[string]uuid.UUID) (string, map[string]string, error)
}

type ProofReferenceResolverFunc func(*http.Request) (string, error)

func (function ProofReferenceResolverFunc) ResolveProofReference(request *http.Request) (string, error) {
	if function == nil {
		return "", errDependencyUnavailable
	}
	return function(request)
}

type Config struct {
	// TermsVersion is a fixed terms version set by the deployment
	// (ACCOUNT_REGISTRATION_TERMS_VERSION); empty: CurrentTermsVersion
	// answers it per request (the terms on the settings page).
	TermsVersion        string
	CurrentTermsVersion func(context.Context) (string, error)
	ScopeResolver       ScopeResolver
	MaxRequestBytes     int64
	Timeout             time.Duration
	RetryAfter          time.Duration
	Logger              *slog.Logger

	// TermsRequired: whether sign-up must accept terms now
	// (registration-config terms_required); false, the acceptance is not
	// checked. Nil: always required.
	TermsRequired func(context.Context) (bool, error)
}

type Handler struct {
	application     RegistrationApplication
	source          SourceIPResolver
	scope           ScopeResolver
	proofs          ProofReferenceResolver
	termsVersion    string
	currentTerms    func(context.Context) (string, error)
	termsRequired   func(context.Context) (bool, error)
	maxRequestBytes int64
	timeout         time.Duration
	retryAfter      time.Duration
	logger          *slog.Logger
}

type registrationBody struct {
	Username            string `json:"username"`
	Password            string `json:"password"`
	DisplayName         string `json:"display_name"`
	Email               string `json:"email"`
	Phone               string `json:"phone"`
	QQ                  string `json:"qq"`
	TermsAccepted       bool   `json:"terms_accepted"`
	TermsVersion        string `json:"terms_version"`
	VerificationChannel string `json:"verification_channel"`
	// VerificationChallengeIDs names the verified challenge of each channel
	// its proof cookie is the one spent.
	VerificationChallengeIDs map[string]uuid.UUID `json:"verification_challenge_ids"`
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

func NewHandler(
	application RegistrationApplication,
	source SourceIPResolver,
	proofs ProofReferenceResolver,
	config Config,
) (*Handler, error) {
	if application == nil || source == nil || proofs == nil ||
		!registrationMetadataPattern.MatchString(config.TermsVersion) && (config.TermsVersion != "" || config.CurrentTermsVersion == nil) {
		return nil, errInvalidRequest
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.RetryAfter == 0 {
		config.RetryAfter = defaultRetryAfter
	}
	if config.MaxRequestBytes < 1024 || config.MaxRequestBytes > maximumRequestBytes ||
		config.Timeout <= 0 || config.Timeout > maximumTimeout ||
		config.RetryAfter <= 0 || config.RetryAfter > maximumRetryAfter {
		return nil, errInvalidRequest
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Handler{
		application: application, source: source, scope: config.ScopeResolver, proofs: proofs,
		termsVersion: config.TermsVersion, currentTerms: config.CurrentTermsVersion, maxRequestBytes: config.MaxRequestBytes,
		timeout: config.Timeout, retryAfter: config.RetryAfter, logger: config.Logger, termsRequired: config.TermsRequired,
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	requestID, validRequestID := registrationRequestID(request)
	response.Header().Set("X-Request-ID", requestID)
	if !validRequestID {
		handler.writeError(response, request, http.StatusUnprocessableEntity,
			"account_registration_invalid_input", requestID)
		return
	}
	if request.URL.Path != registrationPath {
		handler.writeError(response, request, http.StatusNotFound,
			"account_registration_invalid_input", requestID)
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		handler.writeError(response, request, http.StatusMethodNotAllowed,
			"account_registration_invalid_input", requestID)
		return
	}
	if request.URL.RawQuery != "" || !exactRegistrationHeader(request, "Content-Type", "application/json") {
		handler.writeError(response, request, http.StatusUnprocessableEntity,
			"account_registration_invalid_input", requestID)
		return
	}
	idempotencyKey, ok := registrationIdempotencyKey(request)
	if !ok {
		handler.writeError(response, request, http.StatusUnprocessableEntity,
			"account_registration_invalid_input", requestID)
		return
	}
	var body registrationBody
	if err := handler.decodeJSON(response, request, &body); err != nil || !validChallengeIDs(body.VerificationChallengeIDs) {
		handler.writeError(response, request, http.StatusUnprocessableEntity,
			"account_registration_invalid_input", requestID)
		return
	}
	termsRequired := true
	if handler.termsRequired != nil {
		required, err := handler.termsRequired(request.Context())
		if err != nil {
			handler.writeError(response, request, http.StatusServiceUnavailable,
				"account_registration_unavailable", requestID)
			return
		}
		termsRequired = required
	}
	// / the version in force goes to the service,
	// which checks the acceptance after the replay read (an exact retry of a
	// completed registration replays whatever changed since)
	currentTermsVersion := ""
	if termsRequired {
		currentTermsVersion = handler.termsVersion
		if currentTermsVersion == "" {
			current, err := handler.currentTerms(request.Context())
			if err != nil || current == "" {
				handler.writeError(response, request, http.StatusServiceUnavailable,
					"account_registration_unavailable", requestID)
				return
			}
			currentTermsVersion = current
		}
	}
	source, err := handler.source.ResolveSourceIP(request)
	if err != nil || !validRegistrationSource(source) {
		handler.writeError(response, request, http.StatusServiceUnavailable,
			"account_registration_unavailable", requestID)
		return
	}
	var scopeID uuid.UUID
	if handler.scope != nil {
		scopeID, err = handler.scope.ResolveScope(request)
		if err != nil || scopeID == uuid.Nil {
			handler.writeError(response, request, http.StatusServiceUnavailable,
				"account_registration_unavailable", requestID)
			return
		}
	}
	var proofReference string
	var proofReferences map[string]string
	if multi, ok := handler.proofs.(MultiProofReferenceResolver); ok {
		proofReference, proofReferences, err = multi.ResolveProofReferences(request, body.VerificationChallengeIDs)
	} else {
		proofReference, err = handler.proofs.ResolveProofReference(request)
	}
	if err != nil || proofReference == "" && len(proofReferences) == 0 || proofReference != "" && (len(proofReference) < 22 ||
		len(proofReference) > 4096 || !registrationProofPattern.MatchString(proofReference) ||
		strings.TrimSpace(proofReference) != proofReference) {
		handler.writeError(response, request, http.StatusServiceUnavailable,
			"account_registration_unavailable", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	result, err := handler.application.Register(ctx, accountregistration.RegisterInput{
		ScopeID: scopeID, Username: body.Username, Password: body.Password, DisplayName: body.DisplayName,
		Email: body.Email, Phone: body.Phone, QQ: body.QQ, TermsAccepted: body.TermsAccepted,
		TermsVersion: body.TermsVersion, VerificationChannel: body.VerificationChannel,
		IdempotencyKey: idempotencyKey, RequestID: requestID, Source: source.Unmap().String(),
		ProofReference: proofReference, ProofReferences: proofReferences, CurrentTermsVersion: currentTermsVersion,
	})
	if err != nil {
		handler.writeServiceError(response, request, requestID, err)
		return
	}
	if !result.Accepted {
		handler.writeError(response, request, http.StatusServiceUnavailable,
			"account_registration_unavailable", requestID)
		return
	}
	handler.writeJSON(response, http.StatusAccepted, result)
}

// validChallengeIDs: verification_challenge_ids names only email / sms
// (accountregistrationproof.ValidChallengeIDs; that package's tests import this one).
func validChallengeIDs(challenges map[string]uuid.UUID) bool {
	for channel, id := range challenges {
		if channel != "email" && channel != "sms" || id == uuid.Nil {
			return false
		}
	}
	return true
}

func (handler *Handler) decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, handler.maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil || len(raw) == 0 || rejectRegistrationDuplicateKeys(raw) != nil {
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

func rejectRegistrationDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeRegistrationJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidRequest
	}
	return nil
}

func consumeRegistrationJSONValue(decoder *json.Decoder) error {
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
			if err := consumeRegistrationJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := consumeRegistrationJSONValue(decoder); err != nil {
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

func registrationRequestID(request *http.Request) (string, bool) {
	values := request.Header.Values("X-Request-ID")
	if len(values) == 1 && registrationMetadataPattern.MatchString(values[0]) {
		return values[0], true
	}
	return uuid.NewString(), false
}

func registrationIdempotencyKey(request *http.Request) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	return request.Header.Get("Idempotency-Key"), len(values) == 1 && registrationMetadataPattern.MatchString(values[0])
}

func exactRegistrationHeader(request *http.Request, name, value string) bool {
	values := request.Header.Values(name)
	return len(values) == 1 && values[0] == value
}

func validRegistrationSource(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
}

func (handler *Handler) writeServiceError(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
	err error,
) {
	status, code := http.StatusServiceUnavailable, "account_registration_unavailable"
	details, policy := passwordpolicy.DetailsOf(err)
	switch {
	case policy:
		status, code = http.StatusUnprocessableEntity, passwordpolicy.Code
	case errors.Is(err, accountregistration.ErrInvalidInput), errors.Is(err, accountregistration.ErrProofInvalid):
		status, code = http.StatusUnprocessableEntity, "account_registration_invalid_input"
	case errors.Is(err, accountregistration.ErrRegistrationDisabled):
		status, code = http.StatusForbidden, "account_registration_disabled"
	case errors.Is(err, accountregistration.ErrRegistrationPolicyUnavailable):
		status, code = http.StatusServiceUnavailable, "account_registration_unavailable"
	case errors.Is(err, accountregistration.ErrRateLimited):
		status, code = http.StatusTooManyRequests, "account_registration_rate_limited"
	case errors.Is(err, accountregistration.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "account_registration_idempotency_conflict"
	case errors.Is(err, accountregistration.ErrTermsOutdated):
		status, code = http.StatusUnprocessableEntity, "account_registration_terms_required"
	}
	if status == http.StatusTooManyRequests {
		seconds := (handler.retryAfter + time.Second - 1) / time.Second
		response.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
	}
	if details != nil {
		handler.writeJSON(response, status, errorEnvelope{Error: apiError{Code: code, RequestID: requestID, Details: details}})
		return
	}
	handler.writeError(response, request, status, code, requestID)
}

func (handler *Handler) writeError(
	response http.ResponseWriter,
	request *http.Request,
	status int,
	code string,
	requestID string,
) {
	if status >= 500 {
		handler.logger.ErrorContext(request.Context(), "account registration HTTP request failed",
			"request_id", requestID, "code", code, "method", request.Method, "path", request.URL.Path)
	}
	handler.writeJSON(response, status, errorEnvelope{Error: apiError{Code: code, RequestID: requestID}})
}

func (*Handler) writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

var _ http.Handler = (*Handler)(nil)
