package controlplaneupgradehttp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const managePermission = "control.upgrades.manage"

type AuthenticateFunc func(*http.Request) (identity.AuthenticatedSession, error)

type Publisher interface {
	Publish(context.Context, controlplaneupgrade.PublishRequest) (controlplaneupgrade.PublicationReceipt, error)
}

type Coordinator interface {
	BeginDrain(context.Context, string) (controlplaneupgrade.ControlSnapshot, error)
	Resume(context.Context, string) (controlplaneupgrade.ControlReceipt, error)
	Observe(context.Context) (controlplaneupgrade.ControlSnapshot, error)
	Snapshot(context.Context) (controlplaneupgrade.ControlSnapshot, error)
	Facts() controlplaneupgrade.ReplicaFacts
}

type Dependencies struct {
	AuthenticateSession AuthenticateFunc
	Publisher           Publisher
	Coordinator         Coordinator
	InternalToken       []byte
	MaxBodyBytes        int64
}

type Handler struct {
	authenticate  AuthenticateFunc
	publisher     Publisher
	coordinator   Coordinator
	internalToken []byte
	maxBodyBytes  int64
}

func New(dependencies Dependencies) (*Handler, error) {
	if dependencies.AuthenticateSession == nil || dependencies.Publisher == nil ||
		len(dependencies.InternalToken) < 32 || len(dependencies.InternalToken) > 256 {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	if dependencies.MaxBodyBytes <= 0 {
		dependencies.MaxBodyBytes = 1 << 20
	}
	if dependencies.MaxBodyBytes < 1024 || dependencies.MaxBodyBytes > 2<<20 {
		return nil, controlplaneupgrade.ErrInvalidConfig
	}
	return &Handler{authenticate: dependencies.AuthenticateSession, publisher: dependencies.Publisher,
		coordinator: dependencies.Coordinator, internalToken: append([]byte(nil), dependencies.InternalToken...),
		maxBodyBytes: dependencies.MaxBodyBytes}, nil
}

func (handler *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/admin/control-upgrade-plan", handler.publish)
	mux.HandleFunc("POST /v1/internal/control-upgrade/drain", handler.drain)
	mux.HandleFunc("POST /v1/internal/control-upgrade/resume", handler.resume)
	mux.HandleFunc("GET /v1/internal/control-upgrade/health", handler.health)
	mux.HandleFunc("GET /v1/internal/control-upgrade/version", handler.version)
	return mux
}

func (handler *Handler) Gate(next http.Handler) http.Handler {
	if handler == nil || handler.coordinator == nil {
		return next
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/health/ready" {
			if _, err := handler.coordinator.Observe(request.Context()); err != nil {
				writeError(response, request, http.StatusServiceUnavailable, "control_upgrade_state_unavailable")
				return
			}
			next.ServeHTTP(response, request)
			return
		}
		if request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodOptions ||
			strings.HasPrefix(request.URL.Path, "/v1/internal/control-upgrade/") {
			next.ServeHTTP(response, request)
			return
		}
		snapshot, err := handler.coordinator.Snapshot(request.Context())
		if err != nil || snapshot.Phase == controlplaneupgrade.ControlDraining {
			response.Header().Set("Retry-After", "5")
			writeError(response, request, http.StatusServiceUnavailable, "control_upgrade_draining")
			return
		}
		next.ServeHTTP(response, request)
	})
}

func (handler *Handler) publish(response http.ResponseWriter, request *http.Request) {
	session, ok := handler.manager(response, request)
	if !ok {
		return
	}
	expected, ok := quotedRevision(request.Header.Get("If-Match"), true)
	if !ok {
		writeError(response, request, http.StatusBadRequest, "invalid_revision")
		return
	}
	idempotency := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	requestID := stableRequestID(request)
	if !validMeta(idempotency, 128) {
		writeError(response, request, http.StatusBadRequest, "invalid_idempotency_key")
		return
	}
	bundle, ok := handler.rawJSON(response, request)
	if !ok {
		return
	}
	receipt, err := handler.publisher.Publish(request.Context(), controlplaneupgrade.PublishRequest{
		Bundle: bundle, ExpectedRevision: expected, IdempotencyKey: idempotency, RequestID: requestID,
		ActorUserID: session.Principal.UserID, ActorScopeID: session.Principal.ScopeID,
	})
	if err != nil {
		handler.writeDomainError(response, request, err)
		return
	}
	status := http.StatusCreated
	if receipt.Replayed {
		status = http.StatusOK
	}
	response.Header().Set("ETag", `"`+strconv.FormatUint(receipt.PublicationRevision, 10)+`"`)
	writeJSON(response, status, receipt)
}

func (handler *Handler) drain(response http.ResponseWriter, request *http.Request) {
	if !handler.internal(response, request) {
		return
	}
	if handler.coordinator == nil {
		writeError(response, request, http.StatusServiceUnavailable, "control_upgrade_state_unavailable")
		return
	}
	planID, ok := handler.planRequest(response, request)
	if !ok {
		return
	}
	snapshot, err := handler.coordinator.BeginDrain(request.Context(), planID)
	if err != nil {
		if errors.Is(err, controlplaneupgrade.ErrQuorumUnavailable) {
			response.Header().Set("Retry-After", "2")
			writeJSON(response, http.StatusServiceUnavailable, map[string]any{
				"error": map[string]string{"code": "control_upgrade_quorum_unavailable", "request_id": stableRequestID(request)},
				"state": snapshot})
			return
		}
		handler.writeDomainError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, snapshot)
}

func (handler *Handler) resume(response http.ResponseWriter, request *http.Request) {
	if !handler.internal(response, request) {
		return
	}
	if handler.coordinator == nil {
		writeError(response, request, http.StatusServiceUnavailable, "control_upgrade_state_unavailable")
		return
	}
	planID, ok := handler.planRequest(response, request)
	if !ok {
		return
	}
	receipt, err := handler.coordinator.Resume(request.Context(), planID)
	if err != nil {
		handler.writeDomainError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, receipt)
}

func (handler *Handler) health(response http.ResponseWriter, request *http.Request) {
	if !handler.internal(response, request) {
		return
	}
	if handler.coordinator == nil {
		writeError(response, request, http.StatusServiceUnavailable, "control_upgrade_state_unavailable")
		return
	}
	snapshot, err := handler.coordinator.Observe(request.Context())
	if err != nil {
		handler.writeDomainError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, snapshot)
}

func (handler *Handler) version(response http.ResponseWriter, request *http.Request) {
	if !handler.internal(response, request) {
		return
	}
	if handler.coordinator == nil {
		writeError(response, request, http.StatusServiceUnavailable, "control_upgrade_state_unavailable")
		return
	}
	writeJSON(response, http.StatusOK, handler.coordinator.Facts())
}

func (handler *Handler) manager(response http.ResponseWriter, request *http.Request) (identity.AuthenticatedSession, bool) {
	session, err := handler.authenticate(request)
	if err != nil || session.SessionID == uuid.Nil || session.Principal.UserID == uuid.Nil || session.Principal.ScopeID == uuid.Nil {
		writeError(response, request, http.StatusUnauthorized, "invalid_session")
		return identity.AuthenticatedSession{}, false
	}
	if session.Principal.ScopeKind != "platform" || session.Principal.TenantID != nil ||
		identity.Authorize(session.Principal, managePermission) != nil {
		writeError(response, request, http.StatusForbidden, "permission_denied")
		return identity.AuthenticatedSession{}, false
	}
	return session, true
}

func (handler *Handler) internal(response http.ResponseWriter, request *http.Request) bool {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		writeError(response, request, http.StatusUnauthorized, "invalid_internal_credential")
		return false
	}
	scheme, raw, found := strings.Cut(strings.TrimSpace(values[0]), " ")
	provided := []byte(strings.TrimSpace(raw))
	if !found || !strings.EqualFold(scheme, "Bearer") || len(provided) != len(handler.internalToken) ||
		subtle.ConstantTimeCompare(provided, handler.internalToken) != 1 {
		writeError(response, request, http.StatusUnauthorized, "invalid_internal_credential")
		return false
	}
	return true
}

func (handler *Handler) planRequest(response http.ResponseWriter, request *http.Request) (string, bool) {
	var body struct {
		PlanID string `json:"plan_id"`
	}
	if !handler.decode(response, request, &body, 4096) {
		return "", false
	}
	parsed, err := uuid.Parse(body.PlanID)
	if err != nil || parsed == uuid.Nil || parsed.String() != body.PlanID {
		writeError(response, request, http.StatusBadRequest, "invalid_plan_id")
		return "", false
	}
	return body.PlanID, true
}

func (handler *Handler) rawJSON(response http.ResponseWriter, request *http.Request) ([]byte, bool) {
	if !validJSONMediaType(request.Header.Values("Content-Type")) {
		writeError(response, request, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return nil, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, handler.maxBodyBytes)
	encoded, err := io.ReadAll(request.Body)
	if err != nil || len(encoded) == 0 {
		writeError(response, request, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(response, request, http.StatusBadRequest, "invalid_request")
		return nil, false
	}
	return encoded, true
}

func (handler *Handler) decode(response http.ResponseWriter, request *http.Request, destination any, limit int64) bool {
	if !validJSONMediaType(request.Header.Values("Content-Type")) {
		writeError(response, request, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(response, request, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (handler *Handler) writeDomainError(response http.ResponseWriter, request *http.Request, err error) {
	status, code := http.StatusServiceUnavailable, "control_upgrade_state_unavailable"
	switch {
	case errors.Is(err, controlplaneupgrade.ErrInvalidPlan):
		status, code = http.StatusBadRequest, "invalid_control_upgrade_plan"
	case errors.Is(err, controlplaneupgrade.ErrRevisionConflict):
		status, code = http.StatusConflict, "version_conflict"
	case errors.Is(err, controlplaneupgrade.ErrIdempotencyConflict):
		status, code = http.StatusConflict, "idempotency_conflict"
	case errors.Is(err, controlplaneupgrade.ErrPlanConflict):
		status, code = http.StatusConflict, "control_upgrade_plan_conflict"
	case errors.Is(err, controlplaneupgrade.ErrQuorumUnavailable):
		status, code = http.StatusServiceUnavailable, "control_upgrade_quorum_unavailable"
	}
	writeError(response, request, status, code)
}

func quotedRevision(value string, allowZero bool) (uint64, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, false
	}
	revision, err := strconv.ParseUint(value[1:len(value)-1], 10, 64)
	return revision, err == nil && (allowZero || revision > 0)
}

func validJSONMediaType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	return err == nil && mediaType == "application/json" &&
		(len(parameters) == 0 || len(parameters) == 1 && strings.EqualFold(parameters["charset"], "utf-8"))
}

func validMeta(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index, character := range value {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if !alphaNumeric && character != '.' && character != '_' && character != ':' && character != '-' ||
			index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func stableRequestID(request *http.Request) string {
	value := strings.TrimSpace(request.Header.Get("X-Request-ID"))
	if !validMeta(value, 128) {
		return "control-upgrade-http-request"
	}
	return value
}

func writeError(response http.ResponseWriter, request *http.Request, status int, code string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{
		"code": code, "request_id": stableRequestID(request),
	}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		encoded = []byte(`{"error":{"code":"internal_error"}}`)
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(append(encoded, '\n'))
}
