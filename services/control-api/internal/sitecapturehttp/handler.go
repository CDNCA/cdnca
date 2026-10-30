package sitecapturehttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"

	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/google/uuid"
)

const maxRequestBytes = 32 << 10

var metadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service interface {
	Get(context.Context, sitecapture.Actor, uuid.UUID, uuid.UUID) (sitecapture.Policy, error)
	Update(context.Context, sitecapture.Actor, sitecapture.UpdateRequest) (sitecapture.WriteResult, error)
}

type Authenticator interface {
	Authenticate(*http.Request) (sitecapture.Actor, error)
}

type AuthenticatorFunc func(*http.Request) (sitecapture.Actor, error)

func (function AuthenticatorFunc) Authenticate(request *http.Request) (sitecapture.Actor, error) {
	return function(request)
}

type Handler struct {
	service       Service
	authenticator Authenticator
	mux           *http.ServeMux
}

type unconfiguredPolicy struct {
	ScopeID  uuid.UUID                  `json:"scope_id"`
	SiteID   uuid.UUID                  `json:"site_id"`
	State    string                     `json:"state"`
	Revision int64                      `json:"revision"`
	Document sitecapture.PolicyDocument `json:"document"`
}

type updateBody struct {
	ExpectedRevision int64                      `json:"expected_revision"`
	Document         sitecapture.PolicyDocument `json:"document"`
}

func NewHandler(service Service, authenticator Authenticator) (*Handler, error) {
	if service == nil || authenticator == nil {
		return nil, sitecapture.ErrInvalidConfig
	}
	handler := &Handler{service: service, authenticator: authenticator, mux: http.NewServeMux()}
	handler.mux.HandleFunc("/v1/tenant-scopes/{scope_id}/sites/{site_id}/telemetry-capture-policy", handler.policy)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := request.Header.Get("X-Request-ID")
	if !metadataPattern.MatchString(requestID) {
		requestID = uuid.NewString()
	}
	response.Header().Set("X-Request-ID", requestID)
	request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, requestID))
	handler.mux.ServeHTTP(response, request)
}

type requestIDKey struct{}

func (handler *Handler) policy(response http.ResponseWriter, request *http.Request) {
	requestID := request.Context().Value(requestIDKey{}).(string)
	if request.URL.RawQuery != "" || duplicateHeaders(request) {
		writeError(response, http.StatusBadRequest, "site_capture_invalid_request", requestID)
		return
	}
	actor, err := handler.authenticator.Authenticate(request)
	if err != nil {
		writeDomainError(response, requestID, sitecapture.ErrUnauthenticated)
		return
	}
	scopeID, scopeErr := strictUUID(request.PathValue("scope_id"))
	siteID, siteErr := strictUUID(request.PathValue("site_id"))
	if scopeErr != nil || siteErr != nil {
		writeDomainError(response, requestID, sitecapture.ErrInvalidInput)
		return
	}
	switch request.Method {
	case http.MethodGet:
		policy, err := handler.service.Get(request.Context(), actor, scopeID, siteID)
		if errors.Is(err, sitecapture.ErrUnconfigured) {
			// Readable site that never saved a policy: answer the explicit
			// unconfigured state so the client can create with expected_revision 0.
			// Missing, deleted or foreign sites still answer 404.
			response.Header().Set("ETag", `"0"`)
			writeJSON(response, http.StatusOK, unconfiguredPolicy{ScopeID: scopeID, SiteID: siteID,
				State: "unconfigured", Revision: 0, Document: sitecapture.DefaultDocument()})
			return
		}
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		response.Header().Set("ETag", `"`+strconv.FormatInt(policy.Revision, 10)+`"`)
		writeJSON(response, http.StatusOK, policy)
	case http.MethodPut:
		var body updateBody
		if err := decodeJSON(request, &body); err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		idempotencyKey, traceID := request.Header.Get("Idempotency-Key"), request.Header.Get("X-Trace-ID")
		if !metadataPattern.MatchString(idempotencyKey) || !metadataPattern.MatchString(traceID) {
			writeDomainError(response, requestID, sitecapture.ErrInvalidInput)
			return
		}
		result, err := handler.service.Update(request.Context(), actor, sitecapture.UpdateRequest{
			ScopeID: scopeID, SiteID: siteID, ExpectedRevision: body.ExpectedRevision,
			IdempotencyKey: idempotencyKey, RequestID: requestID, TraceID: traceID, Document: body.Document,
		})
		if err != nil {
			writeDomainError(response, requestID, err)
			return
		}
		if result.Replayed {
			response.Header().Set("X-Idempotent-Replay", "true")
		}
		response.Header().Set("ETag", `"`+strconv.FormatInt(result.Policy.Revision, 10)+`"`)
		writeJSON(response, http.StatusOK, result)
	default:
		response.Header().Set("Allow", "GET, PUT")
		writeError(response, http.StatusMethodNotAllowed, "site_capture_method_not_allowed", requestID)
	}
}

func duplicateHeaders(request *http.Request) bool {
	for _, name := range []string{"Authorization", "X-Request-ID", "X-Trace-ID", "Idempotency-Key"} {
		if len(request.Header.Values(name)) > 1 {
			return true
		}
	}
	return false
}

func strictUUID(raw string) (uuid.UUID, error) {
	value, err := uuid.Parse(raw)
	if err != nil || value == uuid.Nil || value.String() != raw {
		return uuid.Nil, sitecapture.ErrInvalidInput
	}
	return value, nil
}

func decodeJSON(request *http.Request, output any) error {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return sitecapture.ErrInvalidInput
	}
	limited := &io.LimitedReader{R: request.Body, N: maxRequestBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil || decoder.Decode(&struct{}{}) != io.EOF || limited.N == 0 {
		return sitecapture.ErrInvalidInput
	}
	return nil
}

func writeDomainError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, sitecapture.ErrInvalidInput):
		writeError(response, http.StatusBadRequest, "site_capture_invalid_request", requestID)
	case errors.Is(err, sitecapture.ErrUnauthenticated):
		writeError(response, http.StatusUnauthorized, "authentication_required", requestID)
	case errors.Is(err, sitecapture.ErrPermissionDenied):
		writeError(response, http.StatusForbidden, "permission_denied", requestID)
	case errors.Is(err, sitecapture.ErrNotFound):
		writeError(response, http.StatusNotFound, "site_capture_not_found", requestID)
	case errors.Is(err, sitecapture.ErrRevisionConflict):
		writeError(response, http.StatusPreconditionFailed, "site_capture_revision_conflict", requestID)
	case errors.Is(err, sitecapture.ErrIdempotencyConflict):
		writeError(response, http.StatusConflict, "site_capture_idempotency_conflict", requestID)
	default:
		writeError(response, http.StatusServiceUnavailable, "site_capture_unavailable", requestID)
	}
}

func writeError(response http.ResponseWriter, status int, code, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{"code": code, "request_id": requestID}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
