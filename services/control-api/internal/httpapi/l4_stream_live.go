package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/cdnca/cdnca/services/control-api/internal/l4live"
	"github.com/google/uuid"
)

// StreamLiveConnections is the 实时连接 service (internal/l4live).
type StreamLiveConnections interface {
	List(ctx context.Context, scopeID, streamID uuid.UUID, clientIP string, limit uint32) (l4live.ListResponse, error)
	Close(ctx context.Context, scopeID, streamID, nodeID uuid.UUID, keys []string) (l4live.CloseResponse, error)
	ListAll(ctx context.Context, filter l4live.AllFilter) (l4live.AllResponse, error)
}

// handleAllLiveConnections is 实时连接 without a picked forward
// (streams.read): platform sessions see every forward (tenant_id narrows),
// tenant sessions their own; stream_id, node_id, listen_port and client_ip
// narrow further. Connections are newest first and bounded (l4live.ListAll).
func (s *Server) handleAllLiveConnections(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	query := r.URL.Query()
	allowed := map[string]bool{"tenant_id": true, "stream_id": true, "node_id": true, "listen_port": true, "client_ip": true, "limit": true}
	filter := l4live.AllFilter{Limit: 200, ClientIP: query.Get("client_ip")}
	invalid := func(message string) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", message)
	}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			invalid("query parameters are invalid")
			return
		}
	}
	ids := map[string]*uuid.UUID{"tenant_id": &filter.TenantID, "stream_id": &filter.StreamID, "node_id": &filter.NodeID}
	for key, target := range ids {
		if raw := query.Get(key); raw != "" {
			value, err := uuid.Parse(raw)
			if err != nil || value == uuid.Nil || value.String() != raw {
				invalid(key + " must be a UUID")
				return
			}
			*target = value
		}
	}
	if raw := query.Get("listen_port"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
			invalid("listen_port must be 1-65535")
			return
		}
		filter.ListenPort = uint16(value)
	}
	if raw := query.Get("limit"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || value < 1 || value > 1000 {
			invalid("limit must be 1-1000")
			return
		}
		filter.Limit = uint32(value)
	}
	switch principal.ScopeKind {
	case "platform":
		filter.Platform = true
	case "tenant":
		if filter.TenantID != uuid.Nil {
			s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "tenant_id is only for platform sessions")
			return
		}
		filter.OwnerScopeID, filter.OwnerUserID = principal.ScopeID, principal.UserID
	default:
		s.writeAPIError(w, r, http.StatusForbidden, "forbidden", "permission denied")
		return
	}
	response, err := s.streamLive.ListAll(r.Context(), filter)
	if errors.Is(err, l4live.ErrInvalidInput) {
		invalid("client_ip must be an address or CIDR")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "l4_live_unavailable", "live connections are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// handleStreamLiveConnections lists a stream's live TCP sessions on every
// node of its scope (streams.read; the stream must be the caller's).
func (s *Server) handleStreamLiveConnections(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.read")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "forwarding rule ID must be a UUID")
		return
	}
	item, err := s.streams.Get(r.Context(), streamActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	query := r.URL.Query()
	limit := uint64(200)
	if raw := query.Get("limit"); raw != "" {
		if limit, err = strconv.ParseUint(raw, 10, 16); err != nil || limit < 1 || limit > 1000 {
			s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "limit must be 1-1000")
			return
		}
	}
	response, err := s.streamLive.List(r.Context(), item.ScopeID, item.ID, query.Get("client_ip"), uint32(limit))
	if errors.Is(err, l4live.ErrInvalidInput) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "client_ip must be an address or CIDR")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "l4_live_unavailable", "live connections are unavailable")
		return
	}
	response.StreamID = item.ID.String()
	writeJSON(w, http.StatusOK, response)
}

// handleCloseStreamLiveConnections closes sessions on one node
// (streams.manage).
func (s *Server) handleCloseStreamLiveConnections(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireStreamPermission(w, r, "streams.manage")
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "forwarding rule ID must be a UUID")
		return
	}
	item, err := s.streams.Get(r.Context(), streamActor(principal), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var body struct {
		NodeID      uuid.UUID `json:"node_id"`
		SessionKeys []string  `json:"session_keys"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || body.NodeID == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node_id and session_keys are required")
		return
	}
	response, err := s.streamLive.Close(r.Context(), item.ScopeID, item.ID, body.NodeID, body.SessionKeys)
	if errors.Is(err, l4live.ErrInvalidInput) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node_id must serve the stream and 1-1000 session_keys are required")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "l4_live_unavailable", "live connections are unavailable")
		return
	}
	writeJSON(w, http.StatusOK, response)
}
