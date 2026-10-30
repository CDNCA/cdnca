package nodeisolationhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeisolation"
	"github.com/google/uuid"
)

const (
	defaultMaxRequestBytes = int64(64 << 10)
	defaultTimeout         = 8 * time.Second
	adminPath              = "/v1/admin/node-isolations"
	resultPathPrefix       = "/v1/internal/node-isolation/results/"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Handler struct {
	dependencies Dependencies
	maxBody      int64
	timeout      time.Duration
}

func NewNodeIsolationHandler(dependencies Dependencies, config Config) (*Handler, error) {
	if nilDependency(dependencies.Service) || nilDependency(dependencies.Sessions) || nilDependency(dependencies.Workloads) {
		return nil, ErrInvalidConfig
	}
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = defaultMaxRequestBytes
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.MaxRequestBytes < 1024 || config.MaxRequestBytes > 1<<20 || config.Timeout <= 0 || config.Timeout > time.Minute {
		return nil, ErrInvalidConfig
	}
	return &Handler{dependencies: dependencies, maxBody: config.MaxRequestBytes, timeout: config.Timeout}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	requestID, ok := requestIdentifier(request)
	writer.Header().Set("X-Request-ID", requestID)
	if handler == nil || request == nil || request.URL == nil || !ok || request.URL.RawPath != "" || request.URL.Opaque != "" || request.URL.Fragment != "" {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	request = request.WithContext(context.WithValue(ctx, requestIDKey{}, requestID))
	switch {
	case request.URL.Path == adminPath:
		handler.list(writer, request)
	case strings.HasPrefix(request.URL.Path, resultPathPrefix):
		handler.record(writer, request)
	default:
		handler.writeAPIError(writer, request, http.StatusNotFound, "node_isolation_route_not_found", "Node isolation route was not found")
	}
}

func (handler *Handler) list(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		handler.writeAPIError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "Request method is not allowed")
		return
	}
	principal, err := handler.dependencies.Sessions.Authenticate(request)
	if errors.Is(err, ErrAuthenticationUnavailable) {
		handler.writeError(writer, request, err)
		return
	}
	if err != nil || !validPrincipal(principal) {
		handler.writeError(writer, request, ErrUnauthenticated)
		return
	}
	if principal.ScopeKind != ScopeKindPlatform || !hasPermission(principal.Permissions, PermissionRead) {
		handler.writeError(writer, request, ErrPermissionDenied)
		return
	}
	query := request.URL.Query()
	for key := range query {
		if key != "node_id" {
			handler.writeError(writer, request, ErrInvalidRequest)
			return
		}
	}
	rawNodeIDs := query["node_id"]
	if len(rawNodeIDs) > 100 {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	nodeIDs := make([]uuid.UUID, len(rawNodeIDs))
	seen := make(map[uuid.UUID]struct{}, len(rawNodeIDs))
	for index, raw := range rawNodeIDs {
		nodeID, err := canonicalUUID(raw)
		if err != nil {
			handler.writeError(writer, request, ErrInvalidRequest)
			return
		}
		if _, exists := seen[nodeID]; exists {
			handler.writeError(writer, request, ErrInvalidRequest)
			return
		}
		seen[nodeID] = struct{}{}
		nodeIDs[index] = nodeID
	}
	states, err := handler.dependencies.Service.ListIsolationStates(request.Context(), principal.ScopeID, nodeIDs)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	items := make([]stateDTO, len(states))
	for index, state := range states {
		items[index] = stateView(state)
	}
	handler.writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) record(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		handler.writeAPIError(writer, request, http.StatusMethodNotAllowed, "method_not_allowed", "Request method is not allowed")
		return
	}
	if request.URL.RawQuery != "" {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	rawNodeID := strings.TrimPrefix(request.URL.Path, resultPathPrefix)
	if rawNodeID == "" || strings.Contains(rawNodeID, "/") {
		handler.writeAPIError(writer, request, http.StatusNotFound, "node_isolation_route_not_found", "Node isolation route was not found")
		return
	}
	nodeID, err := canonicalUUID(rawNodeID)
	if err != nil {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	principal, err := handler.dependencies.Workloads.Authenticate(request)
	if errors.Is(err, ErrAuthenticationUnavailable) {
		handler.writeError(writer, request, err)
		return
	}
	if err != nil || !validWorkload(principal) {
		handler.writeError(writer, request, ErrUnauthenticated)
		return
	}
	if principal.NodeID != nodeID || !hasPermission(principal.Permissions, PermissionReport) {
		handler.writeError(writer, request, ErrPermissionDenied)
		return
	}
	var body reportBody
	if !handler.decode(writer, request, &body) {
		return
	}
	value, err := reportFromBody(principal.ScopeID, nodeID, body)
	if err != nil {
		handler.writeError(writer, request, ErrInvalidRequest)
		return
	}
	result, err := handler.dependencies.Service.RecordSyncResult(request.Context(), value)
	if err != nil {
		handler.writeError(writer, request, err)
		return
	}
	if result.Replay {
		writer.Header().Set("Idempotency-Replayed", "true")
	}
	handler.writeJSON(writer, http.StatusOK, map[string]any{
		"state": stateView(result.State), "publication_allowed": result.PublicationAllowed,
		"reason_code": result.ReasonCode, "replayed": result.Replay,
	})
}

func reportFromBody(scopeID, nodeID uuid.UUID, body reportBody) (nodeisolation.SyncResult, error) {
	if body.Desired == nil {
		return nodeisolation.SyncResult{}, ErrInvalidRequest
	}
	reportID, err := canonicalUUID(body.ReportID)
	if err != nil {
		return nodeisolation.SyncResult{}, err
	}
	desired, err := identityFromDTO(*body.Desired)
	if err != nil {
		return nodeisolation.SyncResult{}, err
	}
	result := nodeisolation.SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: reportID,
		Desired: desired, Outcome: nodeisolation.Outcome(body.Outcome), ErrorCode: body.ErrorCode}
	if body.Health != nil {
		active, err := identityFromDTO(body.Health.Active)
		if err != nil {
			return nodeisolation.SyncResult{}, err
		}
		result.Health = &nodeisolation.HealthEvidence{SessionEpoch: body.Health.SessionEpoch,
			Sequence: body.Health.Sequence, ObservedAt: body.Health.ObservedAt, Active: active}
	}
	return result, nil
}

func identityFromDTO(value identityDTO) (nodeisolation.ConfigIdentity, error) {
	versionID, err := canonicalUUID(value.ConfigVersionID)
	if err != nil || len(value.ArtifactSHA256) != 64 || strings.ToLower(value.ArtifactSHA256) != value.ArtifactSHA256 {
		return nodeisolation.ConfigIdentity{}, ErrInvalidRequest
	}
	digest, err := hex.DecodeString(value.ArtifactSHA256)
	if err != nil {
		return nodeisolation.ConfigIdentity{}, ErrInvalidRequest
	}
	result := nodeisolation.ConfigIdentity{Schema: value.Schema, ConfigVersionID: versionID}
	copy(result.ArtifactSHA256[:], digest)
	return result, nil
}

func stateView(state nodeisolation.State) stateDTO {
	return stateDTO{ScopeID: state.ScopeID.String(), NodeID: state.NodeID.String(), Status: string(state.Status),
		Desired: identityDTO{Schema: state.Desired.Schema, ConfigVersionID: state.Desired.ConfigVersionID.String(),
			ArtifactSHA256: hex.EncodeToString(state.Desired.ArtifactSHA256[:])},
		ConsecutiveFailures: state.ConsecutiveFailures, ConsecutiveHealthy: state.ConsecutiveHealthy,
		LastSessionEpoch: state.LastSessionEpoch, LastHealthSequence: state.LastHealthSequence,
		LastReportID: state.LastReportID.String(), LastOutcome: string(state.LastOutcome),
		LastErrorCode: state.LastErrorCode, ReasonCode: state.ReasonCode, Revision: state.Revision,
		IsolatedAt: state.IsolatedAt, RecoveredAt: state.RecoveredAt, UpdatedAt: state.UpdatedAt}
}

func (handler *Handler) decode(writer http.ResponseWriter, request *http.Request, target any) bool {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 {
		handler.writeError(writer, request, ErrInvalidRequest)
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		handler.writeError(writer, request, ErrInvalidRequest)
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, handler.maxBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		handler.writeError(writer, request, ErrInvalidRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		handler.writeError(writer, request, ErrInvalidRequest)
		return false
	}
	return true
}

type requestIDKey struct{}

func requestIdentifier(request *http.Request) (string, bool) {
	if request == nil {
		return randomRequestID(), false
	}
	values := request.Header.Values("X-Request-ID")
	if len(values) == 0 {
		return randomRequestID(), true
	}
	if len(values) != 1 || !requestIDPattern.MatchString(values[0]) {
		return randomRequestID(), false
	}
	return values[0], true
}

func randomRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "request-unavailable"
	}
	return hex.EncodeToString(value[:])
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, ErrInvalidRequest
	}
	return parsed, nil
}

func validPrincipal(value Principal) bool {
	return value.SubjectID != uuid.Nil && value.ScopeID != uuid.Nil && value.SessionID != uuid.Nil
}

func validWorkload(value WorkloadPrincipal) bool {
	return value.WorkloadID != "" && value.ScopeID != uuid.Nil && value.NodeID != uuid.Nil
}

func hasPermission(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (handler *Handler) writeError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrUnauthenticated):
		handler.writeAPIError(writer, request, http.StatusUnauthorized, "node_isolation_unauthenticated", "Authentication is required")
	case errors.Is(err, ErrPermissionDenied):
		handler.writeAPIError(writer, request, http.StatusForbidden, "node_isolation_permission_denied", "Permission is denied")
	case errors.Is(err, nodeisolation.ErrInvalidInput), errors.Is(err, ErrInvalidRequest):
		handler.writeAPIError(writer, request, http.StatusBadRequest, "node_isolation_invalid_request", "Request is invalid")
	case errors.Is(err, nodeisolation.ErrConflict):
		handler.writeAPIError(writer, request, http.StatusConflict, "node_isolation_conflict", "Report conflicts with current desired identity or prior receipt")
	case errors.Is(err, nodeisolation.ErrNotFound):
		handler.writeAPIError(writer, request, http.StatusNotFound, "node_isolation_node_not_found", "Node was not found")
	default:
		handler.writeAPIError(writer, request, http.StatusServiceUnavailable, "node_isolation_unavailable", "Node isolation state is unavailable")
	}
}

func (handler *Handler) writeAPIError(writer http.ResponseWriter, request *http.Request, status int, code, message string) {
	handler.writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, Message: message, RequestID: requestIDFrom(request)}})
}

func requestIDFrom(request *http.Request) string {
	if request == nil {
		return "request-unavailable"
	}
	if value, ok := request.Context().Value(requestIDKey{}).(string); ok {
		return value
	}
	if value := request.Header.Get("X-Request-ID"); requestIDPattern.MatchString(value) {
		return value
	}
	return "request-unavailable"
}

func (handler *Handler) writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
