package identityverificationhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

type providerRouteKind string

const (
	providerRouteStart    providerRouteKind = "start"
	providerRouteUpload   providerRouteKind = "upload"
	providerRouteFinalize providerRouteKind = "finalize"
	providerRouteCallback providerRouteKind = "callback"
)

type providerRoute struct {
	kind      providerRouteKind
	method    string
	sessionID uuid.UUID
	uploadID  uuid.UUID
	provider  string
	callback  bool
}

type ProviderHandler struct {
	workflow         *ProviderWorkflow
	authenticate     AuthenticateFunc
	commandTimeout   time.Duration
	maxRequestBytes  int64
	maxResponseBytes int
}

func newProviderHandler(workflow *ProviderWorkflow, authenticate AuthenticateFunc, config HandlerConfig) (*ProviderHandler, error) {
	if workflow == nil || authenticate == nil {
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
	if config.CommandTimeout <= 0 || config.CommandTimeout > maximumHandlerTimeout || config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 ||
		config.MaxResponseBytes < 512 || config.MaxResponseBytes > maximumResponseBytes {
		return nil, ErrInvalidService
	}
	return &ProviderHandler{workflow: workflow, authenticate: authenticate, commandTimeout: config.CommandTimeout, maxRequestBytes: config.MaxRequestBytes, maxResponseBytes: config.MaxResponseBytes}, nil
}

func (handler *ProviderHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	requestIDValue, validRequestID := requestIdentifier(request)
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, requestIDValue))
	writer.Header().Set("X-Request-ID", requestIDValue)
	if !validRequestID || !validRequestShape(request) {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	route, matched := resolveProviderRoute(request.URL.Path)
	if !matched {
		handler.writeError(writer, request, ErrNotFound)
		return
	}
	if request.Method != route.method {
		writer.Header().Set("Allow", route.method)
		handler.writeStatusError(writer, request, http.StatusMethodNotAllowed, "identity_verification_method_not_allowed", "request method is not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.commandTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	if route.callback {
		handler.handleCallback(writer, request, route)
		return
	}
	rawSession, err := canonicalBearerSession(request)
	if err != nil || hasActorHeaders(request) {
		handler.writeError(writer, request, ErrUnauthenticated)
		return
	}
	session, err := handler.authenticate(request, rawSession)
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			handler.writeError(writer, request, ErrUnauthenticated)
		} else {
			handler.writeError(writer, request, ErrStoreUnavailable)
		}
		return
	}
	actor, ok := actorFromSession(session, rawSession)
	if !ok {
		handler.writeError(writer, request, ErrUnauthenticated)
		return
	}
	handler.handleAuthorized(writer, request, route, actor)
}

func (handler *ProviderHandler) handleAuthorized(writer http.ResponseWriter, request *http.Request, route providerRoute, actor identityverification.Actor) {
	if request.URL.RawQuery != "" {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	metadata, err := writeMetadata(request)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	switch route.kind {
	case providerRouteStart:
		var body struct {
			Kind     string `json:"kind"`
			Provider string `json:"provider"`
		}
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeError(writer, request, err)
			return
		}
		result, err := handler.workflow.StartSession(request.Context(), actor, StartProviderSessionRequest{Kind: body.Kind, Provider: body.Provider, IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID})
		status := http.StatusCreated
		if result.Replayed {
			status = http.StatusOK
		}
		handler.writeResult(writer, request, status, result, err)
	case providerRouteUpload:
		var body struct {
			MaterialKind string `json:"material_kind"`
			ContentType  string `json:"content_type"`
			SizeBytes    int64  `json:"size_bytes"`
			SHA256       string `json:"sha256"`
		}
		if err := handler.decodeJSON(writer, request, &body); err != nil {
			handler.writeError(writer, request, err)
			return
		}
		digest, err := decodeLowerHexDigest(body.SHA256)
		if err != nil {
			handler.writeError(writer, request, ErrInvalidRequest)
			return
		}
		result, err := handler.workflow.CreateUpload(request.Context(), actor, CreateProviderUploadRequest{SessionID: route.sessionID, MaterialKind: body.MaterialKind, ContentType: body.ContentType, SizeBytes: body.SizeBytes, SHA256: digest, IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID})
		status := http.StatusCreated
		if result.Replayed {
			status = http.StatusOK
		}
		handler.writeResult(writer, request, status, result, err)
	case providerRouteFinalize:
		if !handler.requireNoBody(writer, request) {
			return
		}
		revision, err := parseIfMatch(request)
		if err != nil {
			handler.writeError(writer, request, err)
			return
		}
		result, err := handler.workflow.FinalizeUpload(request.Context(), actor, FinalizeProviderUploadRequest{SessionID: route.sessionID, UploadID: route.uploadID, ExpectedRevision: revision, IdempotencyKey: metadata.IdempotencyKey, RequestID: metadata.RequestID})
		handler.writeResult(writer, request, http.StatusOK, result, err)
	default:
		handler.writeError(writer, request, ErrNotFound)
	}
}

func (handler *ProviderHandler) handleCallback(writer http.ResponseWriter, request *http.Request, route providerRoute) {
	if request.URL.RawQuery != "" || len(request.Header.Values("Authorization")) != 0 || hasActorHeaders(request) {
		handler.writeError(writer, request, ErrProviderCallbackAuth)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maximumProviderResponseBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 || len(body) > int(maximumProviderResponseBytes) {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	result, err := handler.workflow.ApplyCallback(request.Context(), ProviderCallbackEnvelope{Provider: route.provider, Header: request.Header.Clone(), Body: body})
	handler.writeResult(writer, request, http.StatusOK, result, err)
}

func resolveProviderRoute(path string) (providerRoute, bool) {
	if path == apiPrefix+"/provider-sessions" {
		return providerRoute{kind: providerRouteStart, method: http.MethodPost}, true
	}
	if strings.HasPrefix(path, apiPrefix+"/provider-callbacks/") && !strings.HasSuffix(path, "/") {
		provider := strings.TrimPrefix(path, apiPrefix+"/provider-callbacks/")
		if resolverNamePattern.MatchString(provider) && !strings.Contains(provider, "/") {
			return providerRoute{kind: providerRouteCallback, method: http.MethodPost, provider: provider, callback: true}, true
		}
		return providerRoute{}, false
	}
	prefix := apiPrefix + "/provider-sessions/"
	if !strings.HasPrefix(path, prefix) || strings.HasSuffix(path, "/") {
		return providerRoute{}, false
	}
	segments := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(segments) != 2 && len(segments) != 4 {
		return providerRoute{}, false
	}
	sessionID, err := canonicalUUID(segments[0])
	if err != nil || segments[1] != "uploads" {
		return providerRoute{}, false
	}
	if len(segments) == 2 {
		return providerRoute{kind: providerRouteUpload, method: http.MethodPost, sessionID: sessionID}, true
	}
	uploadID, err := canonicalUUID(segments[2])
	if err != nil || segments[3] != "finalize" {
		return providerRoute{}, false
	}
	return providerRoute{kind: providerRouteFinalize, method: http.MethodPost, sessionID: sessionID, uploadID: uploadID}, true
}

func (handler *ProviderHandler) decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	contentType, err := singleHeader(request, "Content-Type", true)
	if err != nil {
		return ErrInvalidRequest
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return ErrInvalidRequest
	}
	request.Body = http.MaxBytesReader(writer, request.Body, handler.maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}
func (handler *ProviderHandler) requireNoBody(writer http.ResponseWriter, request *http.Request) bool {
	if len(request.Header.Values("Content-Type")) != 0 {
		handler.writeError(writer, request, ErrInvalidRequest)
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	count, err := io.Copy(io.Discard, request.Body)
	if err != nil || count != 0 {
		handler.writeError(writer, request, ErrInvalidRequest)
		return false
	}
	return true
}
func (handler *ProviderHandler) writeResult(writer http.ResponseWriter, request *http.Request, status int, value any, err error) {
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > handler.maxResponseBytes {
		handler.writeError(writer, request, ErrResponseTooLarge)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}
func (handler *ProviderHandler) writeError(writer http.ResponseWriter, request *http.Request, err error) {
	status, code, message := providerPublicError(err)
	handler.writeStatusError(writer, request, status, code, message)
}
func (handler *ProviderHandler) writeStatusError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	encoded, _ := json.Marshal(errorEnvelope{Error: apiError{Code: code, Message: message, RequestID: requestID(request.Context())}})
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(encoded, '\n'))
}

func providerPublicError(err error) (int, string, string) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrProviderInvalid), errors.Is(err, identityverification.ErrInvalidInput):
		return http.StatusBadRequest, "identity_verification_invalid_request", "request is invalid"
	case errors.Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized, "identity_verification_unauthenticated", "authentication is required"
	case errors.Is(err, identityverification.ErrPermissionDenied):
		return http.StatusForbidden, "identity_verification_permission_denied", "permission is denied"
	case errors.Is(err, identityverification.ErrNotFound), errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "identity_verification_provider_not_found", "identity verification provider resource was not found"
	case errors.Is(err, identityverification.ErrRevisionConflict):
		return http.StatusConflict, "identity_verification_revision_conflict", "resource revision is stale"
	case errors.Is(err, ErrProviderConflict):
		return http.StatusConflict, "identity_verification_provider_conflict", "provider workflow state conflicts"
	case errors.Is(err, ErrProviderCallbackReplay):
		return http.StatusConflict, "identity_verification_provider_callback_replay_conflict", "provider callback replay conflicts"
	case errors.Is(err, ErrProviderCallbackAuth):
		return http.StatusUnauthorized, "identity_verification_provider_callback_authentication_failed", "provider callback authentication failed"
	case errors.Is(err, ErrProviderObjectMismatch), errors.Is(err, ErrProviderMaterialsIncomplete):
		return http.StatusUnprocessableEntity, "identity_verification_provider_evidence_invalid", "private evidence facts are invalid"
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout, "identity_verification_request_canceled", "request was canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "identity_verification_request_timeout", "request timed out"
	default:
		return http.StatusServiceUnavailable, "identity_verification_provider_unavailable", "identity verification provider is unavailable"
	}
}
func decodeLowerHexDigest(raw string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != raw {
		return [sha256.Size]byte{}, ErrInvalidRequest
	}
	var value [sha256.Size]byte
	copy(value[:], decoded)
	return value, nil
}
func providerRevisionETag(revision int64) string { return `"` + strconv.FormatInt(revision, 10) + `"` }
