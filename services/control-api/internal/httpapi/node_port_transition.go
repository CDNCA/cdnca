package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeporttransition"
	"github.com/google/uuid"
)

type nodePortTransitionCreateBody struct {
	ExpectedNodeRevision  int64                       `json:"expected_node_revision"`
	OldEndpoint           nodeporttransition.Endpoint `json:"old_endpoint"`
	NewEndpoint           nodeporttransition.Endpoint `json:"new_endpoint"`
	CompatibilityDeadline string                      `json:"compatibility_deadline"`
	RollbackDeadline      string                      `json:"rollback_deadline"`
}

func (s *Server) handleCreateNodePortTransition(response http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireNodePermission(response, request, "nodes.manage")
	if !ok {
		return
	}
	if !s.requireNodePortTransitionRuntime(response, request) {
		return
	}
	key, ok := s.idempotencyKey(response, request)
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(request.PathValue("id"))
	if err != nil || nodeID == uuid.Nil {
		s.writeAPIError(response, request, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	var body nodePortTransitionCreateBody
	if err := decodeJSON(response, request, &body); err != nil {
		s.writeAPIError(response, request, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	compatibility, compatibilityErr := time.Parse(time.RFC3339Nano, body.CompatibilityDeadline)
	rollback, rollbackErr := time.Parse(time.RFC3339Nano, body.RollbackDeadline)
	if compatibilityErr != nil || rollbackErr != nil {
		s.writeAPIError(response, request, http.StatusBadRequest, "validation_error", "transition deadlines must be RFC3339 timestamps")
		return
	}
	transition, err := s.nodePortTransitions.Create(request.Context(), nodeporttransition.Actor{
		ScopeID: principal.ScopeID, UserID: principal.UserID,
	}, nodeporttransition.CreateRequest{
		NodeID: nodeID, ExpectedNodeRevision: body.ExpectedNodeRevision, OldEndpoint: body.OldEndpoint,
		NewEndpoint: body.NewEndpoint, CompatibilityDeadline: compatibility, RollbackDeadline: rollback,
		RequestID: requestID(request.Context()), IdempotencyKey: key,
	})
	if err != nil {
		s.writeNodePortTransitionError(response, request, err)
		return
	}
	response.Header().Set("Location", "/v1/nodes/"+nodeID.String()+"/gateway-port-transitions/"+transition.ID.String())
	writeJSONStatus(response, http.StatusCreated, nodePortTransitionView(transition))
}

func (s *Server) handleGetNodePortTransition(response http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireNodePermission(response, request, "nodes.read")
	if !ok {
		return
	}
	nodeID, transitionID, ok := s.nodePortTransitionPath(response, request)
	if !ok {
		return
	}
	transition, err := s.nodePortTransitions.Get(request.Context(), transitionID)
	if err != nil || transition.ScopeID != principal.ScopeID || transition.NodeID != nodeID {
		if err == nil {
			err = nodeporttransition.ErrNotFound
		}
		s.writeNodePortTransitionError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, nodePortTransitionView(transition))
}

func (s *Server) handleFinalizeNodePortTransition(response http.ResponseWriter, request *http.Request) {
	s.handleNodePortTransitionAction(response, request, true)
}

func (s *Server) handleRollbackNodePortTransition(response http.ResponseWriter, request *http.Request) {
	s.handleNodePortTransitionAction(response, request, false)
}

func (s *Server) handleNodePortTransitionAction(response http.ResponseWriter, request *http.Request, finalize bool) {
	principal, ok := s.requireNodePermission(response, request, "nodes.manage")
	if !ok {
		return
	}
	if !s.requireNodePortTransitionRuntime(response, request) {
		return
	}
	key, ok := s.idempotencyKey(response, request)
	if !ok {
		return
	}
	nodeID, transitionID, ok := s.nodePortTransitionPath(response, request)
	if !ok {
		return
	}
	action := nodeporttransition.ActionRequest{
		TransitionID: transitionID, NodeID: nodeID, RequestID: requestID(request.Context()), IdempotencyKey: key,
	}
	var transition nodeporttransition.Transition
	var err error
	if finalize {
		transition, err = s.nodePortTransitions.Finalize(request.Context(), nodeporttransition.Actor{ScopeID: principal.ScopeID, UserID: principal.UserID}, action)
	} else {
		transition, err = s.nodePortTransitions.Rollback(request.Context(), nodeporttransition.Actor{ScopeID: principal.ScopeID, UserID: principal.UserID}, action)
	}
	if err != nil {
		s.writeNodePortTransitionError(response, request, err)
		return
	}
	writeJSON(response, http.StatusAccepted, nodePortTransitionView(transition))
}

func (s *Server) requireNodePortTransitionRuntime(response http.ResponseWriter, request *http.Request) bool {
	if s.nodePortTransitionReady == nil || s.nodePortTransitionReady() != nil {
		s.writeAPIError(response, request, http.StatusServiceUnavailable, "node_port_transition_runtime_unavailable", "gateway port transition runtime is unavailable")
		return false
	}
	return true
}

func (s *Server) nodePortTransitionPath(response http.ResponseWriter, request *http.Request) (uuid.UUID, uuid.UUID, bool) {
	nodeID, nodeErr := uuid.Parse(request.PathValue("id"))
	transitionID, transitionErr := uuid.Parse(request.PathValue("transition_id"))
	if nodeErr != nil || transitionErr != nil || nodeID == uuid.Nil || transitionID == uuid.Nil {
		s.writeAPIError(response, request, http.StatusBadRequest, "validation_error", "node and transition IDs must be UUIDs")
		return uuid.Nil, uuid.Nil, false
	}
	return nodeID, transitionID, true
}

func nodePortTransitionView(value nodeporttransition.Transition) map[string]any {
	return map[string]any{
		"id": value.ID, "scope_id": value.ScopeID, "node_id": value.NodeID, "revision": value.Revision,
		"expected_node_revision": value.ExpectedNodeRevision, "old_endpoint": value.OldEndpoint,
		"new_endpoint": value.NewEndpoint, "compatibility_deadline": value.CompatibilityDeadline,
		"rollback_deadline": value.RollbackDeadline, "state": value.State, "status_revision": value.StatusRevision,
		"active_endpoint": value.ActiveEndpoint, "error_code": value.ErrorCode, "created_at": value.CreatedAt, "updated_at": value.UpdatedAt,
	}
}

func (s *Server) writeNodePortTransitionError(response http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, nodeporttransition.ErrInvalidInput):
		s.writeAPIError(response, request, http.StatusBadRequest, "node_port_transition_invalid", "gateway port transition input is invalid")
	case errors.Is(err, nodeporttransition.ErrConflict):
		s.writeAPIError(response, request, http.StatusConflict, "node_port_transition_conflict", "gateway port transition conflicts with current state")
	case errors.Is(err, nodeporttransition.ErrUnauthenticated):
		s.writeAPIError(response, request, http.StatusUnauthorized, "unauthenticated", "node identity is not authenticated")
	case errors.Is(err, nodeporttransition.ErrNotFound):
		s.writeAPIError(response, request, http.StatusNotFound, "node_port_transition_not_found", "gateway port transition was not found")
	default:
		s.writeError(response, request, err)
	}
}
