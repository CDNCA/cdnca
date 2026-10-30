package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoverride"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nodeMonitoringOverrideRequest struct {
	ExpectedRevision *int64                         `json:"expected_revision"`
	Override         *nodemonitoringoverride.Fields `json:"override"`
}

func (s *Server) handleGetNodeMonitoringOverride(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, ok := s.pathUUID(w, r, "node ID")
	if !ok {
		return
	}
	if len(r.URL.Query()) != 0 {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "query parameters are not supported")
		return
	}
	if s.nodeMonitoringOverrides == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	view, err := s.nodeMonitoringOverrides.Get(r.Context(), nodemonitoringoverride.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID}, nodeID)
	if err != nil {
		s.writeNodeMonitoringOverrideError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handlePutNodeMonitoringOverride(w http.ResponseWriter, r *http.Request) {
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
	var body nodeMonitoringOverrideRequest
	if err := decodeJSON(w, r, &body); err != nil || body.ExpectedRevision == nil || body.Override == nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	if s.nodeMonitoringOverrides == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	view, _, err := s.nodeMonitoringOverrides.Put(r.Context(), nodemonitoringoverride.Actor{
		UserID: principal.UserID, ScopeID: principal.ScopeID}, nodemonitoringoverride.PutRequest{
		NodeID: nodeID, ExpectedRevision: *body.ExpectedRevision, Fields: *body.Override,
		IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeNodeMonitoringOverrideError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) writeNodeMonitoringOverrideError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, nodemonitoringoverride.ErrNotFound):
		s.writeAPIError(w, r, http.StatusNotFound, "node_not_found", "node was not found")
	case errors.Is(err, nodemonitoringoverride.ErrRevisionConflict):
		s.writeAPIError(w, r, http.StatusConflict, "version_conflict", "node monitoring override revision is stale")
	case errors.Is(err, nodemonitoringoverride.ErrIdempotencyConflict):
		s.writeAPIError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input")
	case errors.Is(err, nodemonitoringoverride.ErrRevisionExhausted):
		s.writeAPIError(w, r, http.StatusConflict, "node_monitoring_override_exhausted", "node monitoring override revision limit reached")
	case errors.Is(err, nodemonitoringoverride.ErrTimeoutTooLong):
		s.writeAPIError(w, r, http.StatusUnprocessableEntity, "probe_timeout_exceeds_interval", "probe timeout exceeds the platform probe interval")
	case errors.Is(err, nodemonitoringoverride.ErrInvalidInput):
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node monitoring override is invalid")
	default:
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
	}
}

func newNodeMonitoringOverrideStore(pool *pgxpool.Pool, now func() time.Time) *nodemonitoringoverride.Store {
	if pool == nil {
		return nil
	}
	store, err := nodemonitoringoverride.NewStore(pool, now)
	if err != nil {
		return nil
	}
	return store
}
