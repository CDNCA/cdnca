package dnspupprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const maxBodyBytes = 16 << 10

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Handler serves (platform scope, system.probe_dnspup.manage):
//
//	GET  /v1/admin/probe-dnspup          settings, account, pause
//	PUT  /v1/admin/probe-dnspup          save (Idempotency-Key)
//	POST /v1/admin/probe-dnspup/tests    connection / capability test (Idempotency-Key)
type Handler struct {
	service      *Service
	authenticate AuthenticateSessionFunc
	nodes        NodeProbeSettings
	// apiKey authenticates the plugin probe API (nil: those routes answer 401).
	apiKey AuthenticateAPIKeyFunc
	mux    *http.ServeMux
}

// AuthenticateAPIKeyFunc authenticates `CdncaKey <key_id>.<secret>`
// (apikey.Service.AuthenticateWithKeyID: scopes ∩ the owner's live RBAC).
type AuthenticateAPIKeyFunc func(context.Context, string) (identity.Principal, uuid.UUID, error)

// NodeProbeSettings is the node availability probe settings page
// (internal/nodednspupprobe.Store; nil: routes answer 503). Errors are
// mapped by NodeProbeError.
type NodeProbeSettings interface {
	NodeProbeStatus(ctx context.Context, actor Actor) (any, error)
	UpdateNodeProbe(ctx context.Context, actor Actor, key string, body []byte) (any, error)
	// Overrides lists, PutOverride saves and DeleteOverride removes the
	// per node / line group overrides.
	Overrides(ctx context.Context, actor Actor) (any, error)
	PutOverride(ctx context.Context, actor Actor, key string, body []byte) (any, error)
	DeleteOverride(ctx context.Context, actor Actor, key string, id uuid.UUID) error
}

// Node probe settings errors the handler maps.
var (
	ErrNodeProbeInvalid = errors.New("invalid dnspup node probe settings")
)

// Patterns are the routes the control-api server forwards here.
var Patterns = []string{
	"GET /v1/admin/probe-dnspup",
	"PUT /v1/admin/probe-dnspup",
	"POST /v1/admin/probe-dnspup/tests",
	"GET /v1/admin/probe-dnspup/node-monitoring",
	"PUT /v1/admin/probe-dnspup/node-monitoring",
	"GET /v1/admin/probe-dnspup/purposes",
	"PUT /v1/admin/probe-dnspup/purposes",
	"GET /v1/admin/probe-dnspup/matrix",
	"GET /v1/admin/probe-dnspup/edge-subjects",
	"GET /v1/admin/probe-dnspup/node-monitoring/overrides",
	"PUT /v1/admin/probe-dnspup/node-monitoring/overrides",
	"DELETE /v1/admin/probe-dnspup/node-monitoring/overrides/{id}",
	"POST /v1/admin/probe-dnspup/diagnoses",
	"GET /v1/admin/probe-dnspup/diagnoses/{id}",
	"GET /v1/probe-dnspup/plugin/status",
	"POST /v1/probe-dnspup/plugin/requests",
	"GET /v1/probe-dnspup/plugin/requests/{id}",
}

func NewHandler(service *Service, authenticate AuthenticateSessionFunc, nodes NodeProbeSettings,
	apiKey AuthenticateAPIKeyFunc) (*Handler, error) {
	if service == nil || authenticate == nil {
		return nil, ErrInvalidInput
	}
	handler := &Handler{service: service, authenticate: authenticate, nodes: nodes, apiKey: apiKey, mux: http.NewServeMux()}
	for index, route := range []http.HandlerFunc{handler.status, handler.update, handler.test, handler.nodeStatus,
		handler.nodeUpdate, handler.purposes, handler.purposesUpdate, handler.matrix, handler.edgeSubjects,
		handler.overrides, handler.overridePut, handler.overrideDelete, handler.diagnoseCreate, handler.diagnoseGet,
		handler.pluginStatus, handler.pluginCreate, handler.pluginGet} {
		handler.mux.HandleFunc(Patterns[index], route)
	}
	return handler, nil
}

func (handler *Handler) nodeStatus(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	if handler.nodes == nil {
		writeError(response, http.StatusServiceUnavailable, "probe_dnspup_node_monitoring_unavailable")
		return
	}
	status, err := handler.nodes.NodeProbeStatus(request.Context(), actor)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (handler *Handler) nodeUpdate(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	if handler.nodes == nil {
		writeError(response, http.StatusServiceUnavailable, "probe_dnspup_node_monitoring_unavailable")
		return
	}
	var raw json.RawMessage
	if !decode(response, request, &raw) {
		return
	}
	status, err := handler.nodes.UpdateNodeProbe(request.Context(), actor, key, raw)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

func (handler *Handler) actor(response http.ResponseWriter, request *http.Request) (Actor, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || values[0][7:] == "" ||
		strings.TrimSpace(values[0][7:]) != values[0][7:] {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return Actor{}, false
	}
	session, err := handler.authenticate(request.Context(), values[0][7:])
	if err != nil {
		writeError(response, http.StatusUnauthorized, "unauthorized")
		return Actor{}, false
	}
	if session.Principal.UserID == uuid.Nil || session.SessionID == uuid.Nil || session.Principal.ScopeKind != "platform" ||
		identity.Authorize(session.Principal, PermissionManage) != nil {
		writeError(response, http.StatusForbidden, "permission_denied")
		return Actor{}, false
	}
	return Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID, SessionID: session.SessionID,
		IP: apikeycredential.ClientIP(request.Context())}, true
}

func idempotencyKey(response http.ResponseWriter, request *http.Request) (string, bool) {
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !validKey(keys[0]) {
		writeError(response, http.StatusBadRequest, "idempotency_key_required")
		return "", false
	}
	return keys[0], true
}

func decode(response http.ResponseWriter, request *http.Request, target any) bool {
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !strings.HasPrefix(strings.ToLower(contentTypes[0]), "application/json") {
		writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxBodyBytes))
	if err != nil {
		writeError(response, http.StatusRequestEntityTooLarge, "request_too_large")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.More() {
		writeError(response, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func (handler *Handler) status(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	status, err := handler.service.Status(request.Context(), actor)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (handler *Handler) update(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input SettingsInput
	if !decode(response, request, &input) {
		return
	}
	status, err := handler.service.UpdateSettings(request.Context(), actor, key, input)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (handler *Handler) test(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var input SettingsInput
	if !decode(response, request, &input) {
		return
	}
	result, err := handler.service.TestConnection(request.Context(), actor, key, input)
	if err != nil {
		writeServiceError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func writeServiceError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		writeError(response, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, ErrPermissionDenied):
		writeError(response, http.StatusForbidden, "permission_denied")
	case errors.Is(err, ErrFeatureDenied):
		writeError(response, http.StatusForbidden, "entitlement_feature_denied")
	case errors.Is(err, ErrIdempotency):
		writeError(response, http.StatusConflict, "idempotency_conflict")
	case errors.Is(err, ErrSecretRequired):
		writeError(response, http.StatusUnprocessableEntity, "probe_dnspup_secret_required")
	case errors.Is(err, ErrSecretUnavailable):
		writeError(response, http.StatusServiceUnavailable, "probe_dnspup_credential_unavailable")
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrNodeProbeInvalid):
		writeError(response, http.StatusUnprocessableEntity, "invalid_input")
	default:
		writeError(response, http.StatusInternalServerError, "internal_error")
	}
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

// writeError writes the control-api ErrorEnvelope.
func writeError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]any{"error": map[string]any{"code": code, "message": http.StatusText(status),
		"request_id": uuid.NewString()}})
}
