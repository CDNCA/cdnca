package httpapi

import (
	"errors"
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
)

type batchNodeAdminStateRequest struct {
	AdminState string                     `json:"admin_state"`
	Items      []node.BatchAdminStateItem `json:"items"`
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	nodeID, ok := s.pathUUID(w, r, "node ID")
	if !ok {
		return
	}
	revision, err := parseIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "If-Match must contain a quoted positive revision")
		return
	}
	var fields node.UpdateFields
	if err := decodeJSON(w, r, &fields); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.nodes.UpdateNode(r.Context(), node.Actor{
		UserID:  principal.UserID,
		ScopeID: principal.ScopeID,
	}, node.UpdateRequest{
		ID:               nodeID,
		ExpectedRevision: revision,
		Fields:           fields,
		IdempotencyKey:   key,
		RequestID:        requestID(r.Context()),
	})
	if err != nil {
		s.writeNodeLifecycleError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Node.Revision))
	writeJSON(w, http.StatusOK, result.Node)
}

func (s *Server) handleBatchNodeAdminState(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.manage")
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	var body batchNodeAdminStateRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	result, err := s.nodes.BatchAdminState(r.Context(), node.Actor{
		UserID:  principal.UserID,
		ScopeID: principal.ScopeID,
	}, node.BatchAdminStateRequest{
		AdminState:     body.AdminState,
		Items:          body.Items,
		IdempotencyKey: key,
		RequestID:      requestID(r.Context()),
	})
	if err != nil {
		s.writeNodeLifecycleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) requireNodePermission(w http.ResponseWriter, r *http.Request, permission string) (identity.Principal, bool) {
	principal, err := s.authenticatedPrincipal(r)
	if err == nil && principal.ScopeKind != "platform" {
		err = identity.ErrPermissionDenied
	}
	if err == nil {
		err = identity.Authorize(principal, permission)
	}
	if err != nil {
		s.writeError(w, r, err)
		return identity.Principal{}, false
	}
	return principal, true
}

func (s *Server) writeNodeLifecycleError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, node.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, node.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "node revision is stale")
	case errors.Is(err, node.ErrStateTransition):
		s.writeAPIError(w, r, http.StatusConflict, "node_state_transition_denied", "node state transition is not allowed")
	case errors.Is(err, node.ErrIdentityRequired):
		s.writeAPIError(w, r, http.StatusConflict, "node_identity_required", "node enrollment authorization is required")
	case errors.Is(err, node.ErrIPConflict):
		s.writeAPIError(w, r, http.StatusConflict, "node_ip_conflict", "node IP is already used by an enabled node")
	case errors.Is(err, node.ErrRetired):
		s.writeAPIError(w, r, http.StatusConflict, "node_retired", "retired node is immutable")
	case errors.Is(err, node.ErrAddressInUse):
		s.writeAPIError(w, r, http.StatusConflict, "node_address_in_use", "node address is still used by a line group endpoint")
	case errors.Is(err, node.ErrRegionInUse):
		s.writeAPIError(w, r, http.StatusConflict, "node_region_in_use", "node is used by a line group of another region")
	case errors.Is(err, node.ErrSupplyInUse):
		var inUse *marketsupplyguard.InUseError
		details := &supplyInUseDetails{}
		if errors.As(err, &inUse) {
			details.OnlineAvailable, details.NormalSubscriptions = inUse.OnlineAvailable, inUse.NormalSubscriptions
		}
		writeJSONStatus(w, http.StatusConflict, errorEnvelope{Error: apiError{Code: "supply_in_use",
			Message:   "the node is the last online node of a market supply that still has normal subscribers",
			RequestID: requestID(r.Context()), Details: details}})
	case errors.Is(err, node.ErrInUse):
		s.writeAPIError(w, r, http.StatusConflict, "node_in_use", "node is still used by a line group, an L2 configuration or unfinished multi-node work")
	default:
		s.writeError(w, r, err)
	}
}

// supplyInUseDetails: the online available nodes the change would leave (0)
// and the normal subscriptions of the supply (ADR 0012 ML-18).
type supplyInUseDetails struct {
	OnlineAvailable     int `json:"online_available"`
	NormalSubscriptions int `json:"normal_subscriptions"`
}
