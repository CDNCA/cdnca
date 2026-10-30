package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/nodetrafficpolicy"
	"github.com/google/uuid"
)

type NodeTrafficPolicyApplication interface {
	Get(context.Context, nodetrafficpolicy.Actor, uuid.UUID, uuid.UUID) (nodetrafficpolicy.PolicyState, error)
	Put(context.Context, nodetrafficpolicy.Actor, nodetrafficpolicy.PutRequest) (nodetrafficpolicy.WriteResult, error)
	Evaluate(context.Context, nodetrafficpolicy.Actor, nodetrafficpolicy.EvaluateRequest) (nodetrafficpolicy.EvaluationRecord, error)
	GetSyncTask(context.Context, nodetrafficpolicy.Actor, uuid.UUID) (nodetrafficpolicy.SyncTask, error)
}

type NodeTrafficPolicyAuthenticateFunc func(*http.Request) (nodetrafficpolicy.Actor, error)

type NodeTrafficPolicyHandler struct {
	application  NodeTrafficPolicyApplication
	authenticate NodeTrafficPolicyAuthenticateFunc
	mux          *http.ServeMux
}

type nodeTrafficPolicyWriteBody struct {
	MonthlyLimitBytes uint64                             `json:"monthly_limit_bytes"`
	Timezone          string                             `json:"timezone"`
	Windows           []nodetrafficpolicy.ScheduleWindow `json:"windows"`
	ManualOverride    nodetrafficpolicy.ManualOverride   `json:"manual_override"`
}

type nodeTrafficPolicyErrorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func NewNodeTrafficPolicyHandler(application NodeTrafficPolicyApplication, authenticate NodeTrafficPolicyAuthenticateFunc) (*NodeTrafficPolicyHandler, error) {
	if application == nil || authenticate == nil {
		return nil, nodetrafficpolicy.ErrInvalidConfig
	}
	handler := &NodeTrafficPolicyHandler{application: application, authenticate: authenticate, mux: http.NewServeMux()}
	handler.mux.HandleFunc("/v1/admin/node-traffic-policies/{node_id}", handler.policy)
	handler.mux.HandleFunc("/v1/admin/node-traffic-policies/{node_id}/evaluate", handler.evaluate)
	handler.mux.HandleFunc("/v1/admin/node-traffic-sync-tasks/{task_id}", handler.syncTask)
	return handler, nil
}

func (handler *NodeTrafficPolicyHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := uuid.NewString()
	if values := request.Header.Values("X-Request-ID"); len(values) == 1 && validNodeTrafficMetadata(values[0]) {
		requestID = values[0]
	} else if len(values) > 0 {
		handler.writeError(response, request, http.StatusBadRequest, "invalid_request", "request metadata is invalid", requestID)
		return
	}
	request.Header.Set("X-Request-ID", requestID)
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

func (handler *NodeTrafficPolicyHandler) policy(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	scopeID, nodeID, ok := handler.boundResource(response, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		state, err := handler.application.Get(request.Context(), actor, scopeID, nodeID)
		if err != nil {
			handler.writeDomainError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteVersion(state.Policy.Revision))
		writeJSON(response, http.StatusOK, state)
	case http.MethodPut:
		expectedRevision, ok := handler.writeMetadata(response, request)
		if !ok {
			return
		}
		var body nodeTrafficPolicyWriteBody
		if !handler.decodeBody(response, request, &body) {
			return
		}
		policy := nodetrafficpolicy.Policy{
			ScopeID: scopeID, NodeID: nodeID, MonthlyLimitBytes: body.MonthlyLimitBytes,
			Timezone: body.Timezone, Windows: body.Windows, Override: body.ManualOverride,
		}
		if err := nodetrafficpolicy.ValidatePolicy(policy); err != nil {
			handler.writeDomainError(response, request, err)
			return
		}
		result, err := handler.application.Put(request.Context(), actor, nodetrafficpolicy.PutRequest{
			Policy:           policy,
			ExpectedRevision: expectedRevision,
			IdempotencyKey:   request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
		})
		if err != nil {
			handler.writeDomainError(response, request, err)
			return
		}
		response.Header().Set("ETag", quoteVersion(result.State.Policy.Revision))
		response.Header().Set("Idempotency-Replayed", strconv.FormatBool(result.Replayed))
		writeJSON(response, http.StatusOK, result.State)
	default:
		response.Header().Set("Allow", "GET, PUT")
		handler.writeError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed", request.Header.Get("X-Request-ID"))
	}
}

func (handler *NodeTrafficPolicyHandler) evaluate(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", "POST")
		handler.writeError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed", request.Header.Get("X-Request-ID"))
		return
	}
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	scopeID, nodeID, ok := handler.boundResource(response, request)
	if !ok || !handler.emptyBody(response, request) {
		return
	}
	if !handler.metadata(response, request) {
		return
	}
	result, err := handler.application.Evaluate(request.Context(), actor, nodetrafficpolicy.EvaluateRequest{
		ScopeID: scopeID, NodeID: nodeID,
		IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestID: request.Header.Get("X-Request-ID"),
	})
	if err != nil {
		handler.writeDomainError(response, request, err)
		return
	}
	response.Header().Set("Idempotency-Replayed", strconv.FormatBool(result.Replayed))
	writeJSON(response, http.StatusOK, result)
}

func (handler *NodeTrafficPolicyHandler) syncTask(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", "GET")
		handler.writeError(response, request, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed", request.Header.Get("X-Request-ID"))
		return
	}
	actor, ok := handler.actor(response, request)
	if !ok {
		return
	}
	taskID, ok := canonicalNodeTrafficUUID(request.PathValue("task_id"))
	if !ok {
		handler.writeError(response, request, http.StatusBadRequest, "validation_error", "sync task ID is invalid", request.Header.Get("X-Request-ID"))
		return
	}
	task, err := handler.application.GetSyncTask(request.Context(), actor, taskID)
	if err != nil {
		handler.writeDomainError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, task)
}

func (handler *NodeTrafficPolicyHandler) actor(response http.ResponseWriter, request *http.Request) (nodetrafficpolicy.Actor, bool) {
	actor, err := handler.authenticate(request)
	if err != nil {
		handler.writeDomainError(response, request, nodetrafficpolicy.ErrUnauthenticated)
		return nodetrafficpolicy.Actor{}, false
	}
	return actor, true
}

func (handler *NodeTrafficPolicyHandler) boundResource(response http.ResponseWriter, request *http.Request) (uuid.UUID, uuid.UUID, bool) {
	values := request.URL.Query()["scope_id"]
	if len(values) != 1 || len(request.URL.Query()) != 1 {
		handler.writeError(response, request, http.StatusBadRequest, "validation_error", "scope binding is invalid", request.Header.Get("X-Request-ID"))
		return uuid.Nil, uuid.Nil, false
	}
	scopeID, scopeOK := canonicalNodeTrafficUUID(values[0])
	nodeID, nodeOK := canonicalNodeTrafficUUID(request.PathValue("node_id"))
	if !scopeOK || !nodeOK {
		handler.writeError(response, request, http.StatusBadRequest, "validation_error", "scope or node ID is invalid", request.Header.Get("X-Request-ID"))
		return uuid.Nil, uuid.Nil, false
	}
	return scopeID, nodeID, true
}

func (handler *NodeTrafficPolicyHandler) writeMetadata(response http.ResponseWriter, request *http.Request) (int64, bool) {
	if !handler.metadata(response, request) {
		return 0, false
	}
	values := request.Header.Values("If-Match")
	if len(values) != 1 || len(values[0]) < 3 || values[0][0] != '"' || values[0][len(values[0])-1] != '"' {
		handler.writeError(response, request, http.StatusBadRequest, "validation_error", "If-Match is invalid", request.Header.Get("X-Request-ID"))
		return 0, false
	}
	revision, err := strconv.ParseInt(values[0][1:len(values[0])-1], 10, 64)
	if err != nil || revision < 0 {
		handler.writeError(response, request, http.StatusBadRequest, "validation_error", "If-Match is invalid", request.Header.Get("X-Request-ID"))
		return 0, false
	}
	return revision, true
}

func (handler *NodeTrafficPolicyHandler) metadata(response http.ResponseWriter, request *http.Request) bool {
	values := request.Header.Values("Idempotency-Key")
	if len(values) != 1 || !validNodeTrafficMetadata(values[0]) {
		handler.writeError(response, request, http.StatusBadRequest, "invalid_idempotency_key", "idempotency key is invalid", request.Header.Get("X-Request-ID"))
		return false
	}
	return true
}

func (handler *NodeTrafficPolicyHandler) decodeBody(response http.ResponseWriter, request *http.Request, destination any) bool {
	if mediaType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0])); mediaType != "application/json" {
		handler.writeError(response, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", request.Header.Get("X-Request-ID"))
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		handler.writeError(response, request, http.StatusBadRequest, "invalid_request", "request body is invalid", request.Header.Get("X-Request-ID"))
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		handler.writeError(response, request, http.StatusBadRequest, "invalid_request", "request body is invalid", request.Header.Get("X-Request-ID"))
		return false
	}
	return true
}

func (handler *NodeTrafficPolicyHandler) emptyBody(response http.ResponseWriter, request *http.Request) bool {
	content, err := io.ReadAll(http.MaxBytesReader(response, request.Body, 1))
	if err != nil || len(strings.TrimSpace(string(content))) != 0 {
		handler.writeError(response, request, http.StatusBadRequest, "invalid_request", "request body must be empty", request.Header.Get("X-Request-ID"))
		return false
	}
	return true
}

func (handler *NodeTrafficPolicyHandler) writeDomainError(response http.ResponseWriter, request *http.Request, err error) {
	status, code, message := http.StatusInternalServerError, "node_traffic_policy_unavailable", "node traffic policy is unavailable"
	switch {
	case errors.Is(err, nodetrafficpolicy.ErrUnauthenticated):
		status, code, message = http.StatusUnauthorized, "invalid_session", "authentication is required"
	case errors.Is(err, nodetrafficpolicy.ErrPermissionDenied):
		status, code, message = http.StatusForbidden, "permission_denied", "permission is required"
	case errors.Is(err, nodetrafficpolicy.ErrInvalidInput):
		status, code, message = http.StatusBadRequest, "validation_error", "request fields are invalid"
	case errors.Is(err, nodetrafficpolicy.ErrNotFound):
		status, code, message = http.StatusNotFound, "node_traffic_policy_not_found", "node traffic policy was not found"
	case errors.Is(err, nodetrafficpolicy.ErrRevisionConflict):
		status, code, message = http.StatusPreconditionFailed, "revision_conflict", "resource revision changed"
	case errors.Is(err, nodetrafficpolicy.ErrIdempotencyConflict):
		status, code, message = http.StatusConflict, "idempotency_conflict", "idempotency key was used for another request"
	case errors.Is(err, nodetrafficpolicy.ErrUsageUnavailable):
		status, code, message = http.StatusServiceUnavailable, "node_traffic_usage_unavailable", "traffic evidence is unavailable"
	case errors.Is(err, nodetrafficpolicy.ErrConfigUnavailable):
		status, code, message = http.StatusConflict, "node_config_unavailable", "node configuration cannot be synchronized"
	}
	handler.writeError(response, request, status, code, message, request.Header.Get("X-Request-ID"))
}

func (handler *NodeTrafficPolicyHandler) writeError(response http.ResponseWriter, _ *http.Request, status int, code, message, requestID string) {
	var envelope nodeTrafficPolicyErrorEnvelope
	envelope.Error.Code = code
	envelope.Error.Message = message
	envelope.Error.RequestID = requestID
	writeJSON(response, status, envelope)
}

func canonicalNodeTrafficUUID(value string) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(value)
	return parsed, err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validNodeTrafficMetadata(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}
