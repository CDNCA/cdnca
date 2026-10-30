package mfahttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
)

const (
	apiPrefix                   = "/v1/account/mfa"
	defaultCommandTimeout       = 15 * time.Second
	maximumCommandTimeout       = 30 * time.Second
	defaultRequestBytes   int64 = 64 << 10
	maximumRequestBytes         = 1 << 20
	defaultResponseBytes        = 64 << 10
	maximumResponseBytes        = 1 << 20
	maximumHeaderBytes          = 16 << 10
	maximumQueryBytes           = 4096
	maximumPathBytes            = 512
)

var (
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	metadataPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	traceparentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$`)
)

type HandlerConfig struct {
	CommandTimeout   time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int
}

type Handler struct {
	service          mfaService
	authenticate     AuthenticateFunc
	commandTimeout   time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

type routeKind string

const (
	routeStatus          routeKind = "status"
	routeBeginEnrollment routeKind = "begin_enrollment"
	routeActivate        routeKind = "activate"
	routeCreateStepUp    routeKind = "create_step_up"
	routeDisable         routeKind = "disable"
	routeReset           routeKind = "reset"
)

type handlerRoute struct {
	kind         routeKind
	method       string
	credentialID uuid.UUID
}

type requestIDKey struct{}

// NewHandler fails closed because production authentication and service
// assembly are owned by NewRuntimeHandler.
func NewHandler(*mfa.Service, AuthenticateFunc, HandlerConfig) (*Handler, error) {
	return nil, ErrInvalidService
}

func newHandler(service mfaService, authenticate AuthenticateFunc, config HandlerConfig) (*Handler, error) {
	if !configuredDependency(service) || authenticate == nil {
		return nil, ErrInvalidService
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = defaultCommandTimeout
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultRequestBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultResponseBytes
	}
	if config.CommandTimeout <= 0 || config.CommandTimeout > maximumCommandTimeout ||
		config.MaxRequestBytes < 1024 || config.MaxRequestBytes > maximumRequestBytes ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > maximumResponseBytes {
		return nil, ErrInvalidService
	}
	return &Handler{service: service, authenticate: authenticate,
		commandTimeout: config.CommandTimeout, maxRequestBytes: config.MaxRequestBytes,
		maxResponseBytes: config.MaxResponseBytes}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header())
	if handler == nil || request == nil || request.URL == nil {
		http.NotFound(writer, request)
		return
	}
	requestID, validRequestID := requestIdentifier(request)
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, requestID))
	writer.Header().Set("X-Request-ID", requestID)
	if !validRequestID || !validRequestShape(request) {
		handler.writeError(writer, request, http.StatusBadRequest,
			"mfa_invalid_request", "request metadata is invalid")
		return
	}
	route, matched := resolveRoute(request.URL.Path)
	if !matched {
		handler.writeError(writer, request, http.StatusNotFound,
			"mfa_route_not_found", "MFA route was not found")
		return
	}
	if request.Method != route.method {
		writer.Header().Set("Allow", route.method)
		handler.writeError(writer, request, http.StatusMethodNotAllowed,
			"mfa_method_not_allowed", "request method is not allowed")
		return
	}
	if route.kind != routeStatus && request.ContentLength > handler.maxRequestBytes {
		handler.writeError(writer, request, http.StatusRequestEntityTooLarge,
			"mfa_request_too_large", "request body is too large")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.commandTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	rawSession, err := canonicalBearerSession(request)
	if err != nil || hasUntrustedPrincipalHeaders(request) {
		handler.writeServiceError(writer, request, ErrUnauthenticated)
		return
	}
	session, err := handler.authenticate(request, rawSession)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrInvalidSession), errors.Is(err, ErrUnauthenticated):
			handler.writeServiceError(writer, request, ErrUnauthenticated)
		case request.Context().Err() != nil:
			handler.writeServiceError(writer, request, request.Context().Err())
		default:
			handler.writeServiceError(writer, request, mfa.ErrUnavailable)
		}
		return
	}
	actor, ok := actorFromSession(session)
	if !ok {
		handler.writeServiceError(writer, request, ErrUnauthenticated)
		return
	}
	metadata, err := requestMetadata(request, route.kind != routeStatus)
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	handler.handle(writer, request, route, actor, metadata)
}

func (handler *Handler) handle(writer http.ResponseWriter, request *http.Request, route handlerRoute,
	actor mfa.Actor, metadata mfa.RequestContext,
) {
	switch route.kind {
	case routeStatus:
		if err := requireNoBody(writer, request); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.Status(request.Context(), actor)
		handler.writeStatus(writer, request, result, err)
	case routeBeginEnrollment:
		var body enrollmentBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.BeginEnrollment(request.Context(), actor, mfa.EnrollmentRequest{
			AccountLabel: body.AccountLabel, IdempotencyKey: idempotencyKey(request), Context: metadata,
		})
		handler.writeEnrollment(writer, request, result, err)
	case routeActivate:
		var body activationBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		result, err := handler.service.Activate(request.Context(), actor, mfa.ActivationRequest{
			CredentialID: route.credentialID, Code: body.Code,
			IdempotencyKey: idempotencyKey(request), Context: metadata,
		})
		handler.writeActivation(writer, request, result, err)
	case routeCreateStepUp:
		var body stepUpBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		// An omitted tenant_id requests a platform-scoped proof (platform
		// sessions only; the service rejects tenant sessions).
		platformScope := body.TenantID == ""
		tenantID, err := uuid.Nil, error(nil)
		if !platformScope {
			tenantID, err = canonicalUUID(body.TenantID)
		}
		if err != nil || body.TTLSeconds < 1 || body.TTLSeconds > 300 ||
			body.MaxUses < 1 || body.MaxUses > 5 {
			handler.writeServiceError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.service.CreateStepUp(request.Context(), actor, mfa.StepUpRequest{
			TenantID: tenantID, PlatformScope: platformScope, Audience: body.Audience, Action: body.Action,
			Authentication: mfa.Authentication{Method: body.Authentication.Method, Code: body.Authentication.Code},
			TTL:            time.Duration(body.TTLSeconds) * time.Second, MaxUses: body.MaxUses,
			IdempotencyKey: idempotencyKey(request), Context: metadata,
		})
		handler.writeStepUp(writer, request, result, err)
	case routeDisable, routeReset:
		var body deactivateBody
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		input := mfa.DeactivateRequest{
			Authentication: mfa.Authentication{Method: body.Authentication.Method, Code: body.Authentication.Code},
			Reason:         body.Reason, IdempotencyKey: idempotencyKey(request), Context: metadata,
		}
		var err error
		if route.kind == routeDisable {
			err = handler.service.Disable(request.Context(), actor, input)
		} else {
			err = handler.service.Reset(request.Context(), actor, input)
		}
		if err != nil {
			handler.writeServiceError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}

func resolveRoute(path string) (handlerRoute, bool) {
	switch path {
	case apiPrefix:
		return handlerRoute{kind: routeStatus, method: http.MethodGet}, true
	case apiPrefix + "/enrollments":
		return handlerRoute{kind: routeBeginEnrollment, method: http.MethodPost}, true
	case apiPrefix + "/step-up-proofs":
		return handlerRoute{kind: routeCreateStepUp, method: http.MethodPost}, true
	case apiPrefix + "/disable":
		return handlerRoute{kind: routeDisable, method: http.MethodPost}, true
	case apiPrefix + "/reset":
		return handlerRoute{kind: routeReset, method: http.MethodPost}, true
	}
	const enrollmentPrefix = apiPrefix + "/enrollments/"
	const activateSuffix = "/activate"
	if !strings.HasPrefix(path, enrollmentPrefix) || !strings.HasSuffix(path, activateSuffix) {
		return handlerRoute{}, false
	}
	rawID := strings.TrimSuffix(strings.TrimPrefix(path, enrollmentPrefix), activateSuffix)
	if strings.Contains(rawID, "/") {
		return handlerRoute{}, false
	}
	credentialID, err := canonicalUUID(rawID)
	if err != nil {
		return handlerRoute{}, false
	}
	return handlerRoute{kind: routeActivate, method: http.MethodPost, credentialID: credentialID}, true
}

func canonicalUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, ErrInvalidRequest
	}
	return value, nil
}

func canonicalBearerSession(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", ErrUnauthenticated
	}
	raw := strings.TrimPrefix(values[0], "Bearer ")
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n,") ||
		values[0] != "Bearer "+raw {
		return "", ErrUnauthenticated
	}
	return raw, nil
}

func hasUntrustedPrincipalHeaders(request *http.Request) bool {
	for _, name := range []string{
		"CdncaKey", "X-Actor-ID", "X-User-ID", "X-Scope-ID", "X-Scope-Kind",
		"X-Tenant-ID", "X-Principal-ID", "X-Session-ID", "X-Role", "X-Permissions",
	} {
		if len(request.Header.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func actorFromSession(session identity.AuthenticatedSession) (mfa.Actor, bool) {
	principal := session.Principal
	if session.SessionID == uuid.Nil || principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return mfa.Actor{}, false
	}
	switch principal.ScopeKind {
	case "platform":
		if principal.TenantID != nil {
			return mfa.Actor{}, false
		}
	case "tenant":
		if principal.TenantID == nil || *principal.TenantID == uuid.Nil {
			return mfa.Actor{}, false
		}
	default:
		return mfa.Actor{}, false
	}
	return mfa.Actor{UserID: principal.UserID, ScopeID: principal.ScopeID, SessionID: session.SessionID}, true
}

func requestMetadata(request *http.Request, mutation bool) (mfa.RequestContext, error) {
	providedRequestID, err := singleHeader(request, "X-Request-ID", true)
	if err != nil || !metadataPattern.MatchString(providedRequestID) ||
		providedRequestID != requestID(request.Context()) {
		return mfa.RequestContext{}, ErrInvalidRequest
	}
	traceparent, err := singleHeader(request, "Traceparent", true)
	match := traceparentPattern.FindStringSubmatch(traceparent)
	if err != nil || len(match) != 4 || match[1] == strings.Repeat("0", 32) ||
		match[2] == strings.Repeat("0", 16) {
		return mfa.RequestContext{}, ErrInvalidRequest
	}
	if mutation {
		key, err := singleHeader(request, "Idempotency-Key", true)
		if err != nil || !idempotencyPattern.MatchString(key) {
			return mfa.RequestContext{}, ErrInvalidRequest
		}
	}
	return mfa.RequestContext{RequestID: providedRequestID, TraceID: match[1]}, nil
}

func idempotencyKey(request *http.Request) string {
	value, _ := singleHeader(request, "Idempotency-Key", true)
	return value
}

func requestIdentifier(request *http.Request) (string, bool) {
	value, err := singleHeader(request, "X-Request-ID", true)
	if err != nil || !metadataPattern.MatchString(value) {
		return uuid.NewString(), false
	}
	return value, true
}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	if !metadataPattern.MatchString(value) {
		return uuid.NewString()
	}
	return value
}

func singleHeader(request *http.Request, name string, required bool) (string, error) {
	values := request.Header.Values(name)
	if len(values) == 0 {
		if required {
			return "", ErrInvalidRequest
		}
		return "", nil
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > 8192 ||
		strings.TrimSpace(values[0]) != values[0] {
		return "", ErrInvalidRequest
	}
	return values[0], nil
}

func validRequestShape(request *http.Request) bool {
	if request.URL.RawPath != "" || request.URL.Opaque != "" || request.URL.Fragment != "" ||
		len(request.URL.Path) > maximumPathBytes || len(request.URL.RawQuery) > maximumQueryBytes ||
		request.URL.RawQuery != "" {
		return false
	}
	total := 0
	for name, values := range request.Header {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
	}
	return total <= maximumHeaderBytes
}

func (handler *Handler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	contentType, err := singleHeader(request, "Content-Type", true)
	if err != nil || contentType != "application/json" ||
		len(request.Header.Values("Content-Encoding")) != 0 {
		return ErrInvalidRequest
	}
	if request.ContentLength > handler.maxRequestBytes {
		return &http.MaxBytesError{Limit: handler.maxRequestBytes}
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return tooLarge
		}
		return ErrInvalidRequest
	}
	if len(raw) == 0 || !utf8.Valid(raw) || !validJSONUnicodeEscapes(raw) || rejectDuplicateJSONKeys(raw) != nil {
		return ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return tooLarge
		}
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return tooLarge
		}
		return ErrInvalidRequest
	}
	return nil
}

func validJSONUnicodeEscapes(raw []byte) bool {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(raw) {
				continue
			}
			index++
			if raw[index] != 'u' {
				continue
			}
			if index+4 >= len(raw) {
				return false
			}
			value, err := strconv.ParseUint(string(raw[index+1:index+5]), 16, 16)
			if err != nil {
				return false
			}
			index += 4
			switch {
			case value >= 0xd800 && value <= 0xdbff:
				if index+6 >= len(raw) || raw[index+1] != '\\' || raw[index+2] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(raw[index+3:index+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				index += 6
			case value >= 0xdc00 && value <= 0xdfff:
				return false
			}
		}
	}
	return true
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
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
				return ErrInvalidRequest
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidRequest
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func requireNoBody(writer http.ResponseWriter, request *http.Request) error {
	if request.ContentLength > 0 || len(request.TransferEncoding) != 0 ||
		len(request.Header.Values("Content-Type")) != 0 ||
		len(request.Header.Values("Content-Encoding")) != 0 {
		return ErrInvalidRequest
	}
	if request.Body == nil || request.Body == http.NoBody {
		return nil
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	var buffer [1]byte
	count, err := request.Body.Read(buffer[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}

func (handler *Handler) writeStatus(writer http.ResponseWriter, request *http.Request,
	result mfa.StatusResult, err error,
) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	view := statusView{Status: result.Status}
	switch result.Status {
	case mfa.StatusInactive:
	case mfa.StatusPending:
		if result.CredentialID == uuid.Nil || result.Method != mfa.MethodTOTP ||
			result.EnrollmentExpiresAt == nil || result.EnrollmentExpiresAt.IsZero() {
			handler.writeServiceError(writer, request, ErrInvalidServiceResult)
			return
		}
		credentialID, expiresAt := result.CredentialID, *result.EnrollmentExpiresAt
		view.CredentialID, view.Method, view.EnrollmentExpiresAt = &credentialID, result.Method, &expiresAt
	case mfa.StatusActive:
		if result.CredentialID == uuid.Nil || result.Method != mfa.MethodTOTP {
			handler.writeServiceError(writer, request, ErrInvalidServiceResult)
			return
		}
		credentialID := result.CredentialID
		view.CredentialID, view.Method = &credentialID, result.Method
	default:
		handler.writeServiceError(writer, request, ErrInvalidServiceResult)
		return
	}
	handler.writeJSON(writer, request, http.StatusOK, view)
}

func (handler *Handler) writeEnrollment(writer http.ResponseWriter, request *http.Request,
	result mfa.EnrollmentResult, err error,
) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	if result.CredentialID == uuid.Nil || result.ExpiresAt.IsZero() ||
		(!result.Replayed && (result.Secret == "" || result.ProvisioningURI == "")) {
		handler.writeServiceError(writer, request, ErrInvalidServiceResult)
		return
	}
	view := enrollmentView{CredentialID: result.CredentialID, ExpiresAt: result.ExpiresAt,
		Replayed: result.Replayed}
	status := http.StatusOK
	if !result.Replayed {
		status = http.StatusCreated
		secret, uri := result.Secret, result.ProvisioningURI
		view.Secret, view.ProvisioningURI = &secret, &uri
	}
	handler.writeJSON(writer, request, status, view)
}

func (handler *Handler) writeActivation(writer http.ResponseWriter, request *http.Request,
	result mfa.ActivationResult, err error,
) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	if result.CredentialID == uuid.Nil || result.ActivatedAt.IsZero() ||
		(!result.Replayed && len(result.RecoveryCodes) == 0) {
		handler.writeServiceError(writer, request, ErrInvalidServiceResult)
		return
	}
	view := activationView{CredentialID: result.CredentialID, ActivatedAt: result.ActivatedAt,
		Replayed: result.Replayed}
	status := http.StatusOK
	if !result.Replayed {
		status = http.StatusCreated
		view.RecoveryCodes = append([]string(nil), result.RecoveryCodes...)
	}
	handler.writeJSON(writer, request, status, view)
}

func (handler *Handler) writeStepUp(writer http.ResponseWriter, request *http.Request,
	result mfa.StepUpResult, err error,
) {
	if err != nil {
		handler.writeServiceError(writer, request, err)
		return
	}
	if result.ProofID == uuid.Nil || result.IssuedAt.IsZero() || result.ExpiresAt.IsZero() ||
		(result.Method != mfa.MethodTOTP && result.Method != mfa.MethodRecoveryCode) ||
		result.MaxUses < 1 || result.MaxUses > mfa.MaxProofUses || (!result.Replayed && result.Token == "") {
		handler.writeServiceError(writer, request, ErrInvalidServiceResult)
		return
	}
	view := stepUpView{ProofID: result.ProofID, Method: result.Method, IssuedAt: result.IssuedAt,
		ExpiresAt: result.ExpiresAt, MaxUses: result.MaxUses, Replayed: result.Replayed}
	status := http.StatusOK
	if !result.Replayed {
		status = http.StatusCreated
		token := result.Token
		view.Token = &token
	}
	handler.writeJSON(writer, request, status, view)
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, request *http.Request, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > handler.maxResponseBytes {
		handler.writeServiceError(writer, request, ErrResponseTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func (handler *Handler) writeServiceError(writer http.ResponseWriter, request *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		handler.writeError(writer, request, http.StatusRequestEntityTooLarge,
			"mfa_request_too_large", "request body is too large")
		return
	}
	status, code, message := publicError(err)
	handler.writeError(writer, request, status, code, message)
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request,
	status int, code, message string,
) {
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{Code: code, Message: message,
		RequestID: requestID(request.Context())}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func publicError(err error) (int, string, string) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, mfa.ErrInvalidInput):
		return http.StatusBadRequest, "mfa_invalid_request", "request is invalid"
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, mfa.ErrInvalidSession):
		return http.StatusUnauthorized, "mfa_unauthenticated", "authentication is required"
	case errors.Is(err, mfa.ErrPrincipalChanged):
		return http.StatusForbidden, "mfa_principal_changed", "authenticated principal changed"
	case errors.Is(err, mfa.ErrProofBinding):
		return http.StatusForbidden, "mfa_proof_binding", "MFA proof binding is invalid"
	case errors.Is(err, mfa.ErrTenantUnavailable):
		return http.StatusForbidden, "mfa_tenant_unavailable", "tenant is unavailable"
	case errors.Is(err, mfa.ErrAlreadyEnabled):
		return http.StatusConflict, "mfa_already_enabled", "MFA is already enabled"
	case errors.Is(err, mfa.ErrEnrollmentPending):
		return http.StatusConflict, "mfa_enrollment_pending", "MFA enrollment is pending"
	case errors.Is(err, mfa.ErrAlreadyActive):
		return http.StatusConflict, "mfa_already_active", "MFA enrollment is already active"
	case errors.Is(err, mfa.ErrIdempotencyConflict):
		return http.StatusConflict, "mfa_idempotency_conflict", "idempotency key payload conflicts"
	case errors.Is(err, mfa.ErrCodeReplayed):
		return http.StatusConflict, "mfa_code_replayed", "MFA code was already used"
	case errors.Is(err, mfa.ErrRecoveryCodeUsed):
		return http.StatusConflict, "mfa_recovery_code_used", "recovery code was already used"
	case errors.Is(err, mfa.ErrProofConsumed):
		return http.StatusConflict, "mfa_proof_consumed", "step-up proof use limit was reached"
	case errors.Is(err, mfa.ErrEnrollmentExpired):
		return http.StatusGone, "mfa_enrollment_expired", "MFA enrollment expired"
	case errors.Is(err, mfa.ErrProofExpired):
		return http.StatusGone, "mfa_proof_expired", "step-up proof expired"
	case errors.Is(err, mfa.ErrNotActive):
		return http.StatusPreconditionFailed, "mfa_not_active", "MFA is not active"
	case errors.Is(err, mfa.ErrInvalidCode):
		return http.StatusUnprocessableEntity, "mfa_invalid_code", "MFA code is invalid"
	case errors.Is(err, mfa.ErrInvalidProof):
		return http.StatusUnprocessableEntity, "mfa_invalid_proof", "step-up proof is invalid"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "mfa_request_canceled", "request was canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "mfa_request_timeout", "request timed out"
	case errors.Is(err, mfa.ErrEncryptionUnavailable):
		return http.StatusServiceUnavailable, "mfa_encryption_unavailable", "MFA encryption is unavailable"
	case errors.Is(err, ErrResponseTooLarge):
		return http.StatusServiceUnavailable, "mfa_response_too_large", "response could not be returned"
	default:
		return http.StatusServiceUnavailable, "mfa_unavailable", "MFA service is unavailable"
	}
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", "default-src 'none'")
	header.Set("X-Frame-Options", "DENY")
}
