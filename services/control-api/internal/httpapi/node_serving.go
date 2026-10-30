package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newNodeServingStore(pool *pgxpool.Pool) *nodeserving.Store {
	if pool == nil {
		return nil
	}
	store, err := nodeserving.NewStore(pool)
	if err != nil {
		return nil
	}
	return store
}

// handleGetNodeServingEvents pages one node's serving hold transitions
// (monitoring pause, auto-disable, last-endpoint protection), newest first.
func (s *Server) handleGetNodeServingEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil || nodeID == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	from, to, page, limit, err := nodeServingEventsQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node serving events query")
		return
	}
	if s.nodeServing == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	result, err := s.nodeServing.Events(r.Context(), principal.ScopeID, nodeID, from, to, page, limit)
	if errors.Is(err, nodeserving.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_monitoring_not_found", "node monitoring was not found")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func nodeServingEventsQuery(r *http.Request) (time.Time, time.Time, int, int, error) {
	invalid := errors.New("invalid node serving events query")
	query := r.URL.Query()
	for key, values := range query {
		if (key != "from" && key != "to" && key != "page" && key != "limit") || len(values) != 1 {
			return time.Time{}, time.Time{}, 0, 0, invalid
		}
	}
	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	for _, field := range []struct {
		name   string
		target *time.Time
	}{{"from", &from}, {"to", &to}} {
		if raw := query.Get(field.name); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return time.Time{}, time.Time{}, 0, 0, invalid
			}
			*field.target = parsed.UTC()
		}
	}
	page, limit := 1, 10
	for _, field := range []struct {
		name   string
		target *int
		max    int
	}{{"page", &page, nodeserving.MaxEventPage}, {"limit", &limit, nodeserving.MaxEventLimit}} {
		if raw := query.Get(field.name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > field.max || strconv.Itoa(parsed) != raw {
				return time.Time{}, time.Time{}, 0, 0, invalid
			}
			*field.target = parsed
		}
	}
	if !from.Before(to) || to.Sub(from) > nodeserving.MaxEventWindow {
		return time.Time{}, time.Time{}, 0, 0, invalid
	}
	return from, to, page, limit, nil
}

// handleListScopeServingEvents pages the switch log of every node in the
// caller's scope (A10/N06): when a node was removed from or restored to DNS,
// by which source and why. Filters: source, event, node_id, ip.
func (s *Server) handleListScopeServingEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	query := r.URL.Query()
	filters := url.Values{}
	for key, values := range query {
		switch key {
		case "source", "event", "node_id", "ip":
			if len(values) != 1 || values[0] == "" {
				s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node serving events query")
				return
			}
			filters[key] = values
			query.Del(key)
		}
	}
	r2 := r.Clone(r.Context())
	r2.URL.RawQuery = query.Encode()
	from, to, page, limit, err := nodeServingEventsQuery(r2)
	var nodeID uuid.UUID
	if err == nil && filters.Get("node_id") != "" {
		nodeID, err = uuid.Parse(filters.Get("node_id"))
		if err == nil && (nodeID == uuid.Nil || nodeID.String() != filters.Get("node_id")) {
			err = errors.New("invalid node id")
		}
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node serving events query")
		return
	}
	if s.nodeServing == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	result, err := s.nodeServing.ScopeEvents(r.Context(), principal.ScopeID, nodeserving.ScopeEventQuery{
		From: from, To: to, Source: filters.Get("source"), Event: filters.Get("event"), NodeID: nodeID, IP: filters.Get("ip"),
		Page: page, Limit: limit,
	})
	if errors.Is(err, nodeserving.ErrInvalidInput) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node serving events query")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
