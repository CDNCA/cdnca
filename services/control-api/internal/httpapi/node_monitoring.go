package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
)

type nodeMonitoringReader interface {
	MonitoringLatest(context.Context, uuid.UUID, []uuid.UUID) (nodemetrics.MonitoringSnapshot, error)
}

func (s *Server) handleGetLatestNodeMonitoring(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	ids, err := nodeMetricsBatchQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node monitoring batch query")
		return
	}
	reader, ok := s.nodeMetrics.(nodeMonitoringReader)
	if !ok || reader == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	result, err := reader.MonitoringLatest(r.Context(), principal.ScopeID, ids)
	if errors.Is(err, nodemetrics.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_monitoring_not_found", "node monitoring was not found")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type nodeMonitoringHistoryReader interface {
	MonitoringHistory(context.Context, uuid.UUID, uuid.UUID, time.Time, time.Time, int, int) (nodemetrics.MonitoringHistoryPage, error)
}

// nodeDNSPupHistoryReader is the dnspup checkpoints log (source=dnspup).
type nodeDNSPupHistoryReader interface {
	DNSPupMonitoringHistory(context.Context, uuid.UUID, uuid.UUID, string, time.Time, time.Time, int, int) (nodemetrics.DNSPupHistoryPage, error)
}

// nodePeerHistoryReader is the controller + peer node probe log (source=peer).
type nodePeerHistoryReader interface {
	PeerMonitoringHistory(context.Context, uuid.UUID, uuid.UUID, time.Time, time.Time, int, int) (nodemetrics.PeerHistoryPage, error)
}

func (s *Server) handleGetNodeMonitoringHistory(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil || nodeID == uuid.Nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	source, group, err := nodeMonitoringHistorySource(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node monitoring history query")
		return
	}
	from, to, page, limit, err := nodeMonitoringHistoryQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node monitoring history query")
		return
	}
	if source == "peer" {
		reader, ok := s.nodeMetrics.(nodePeerHistoryReader)
		if !ok || reader == nil {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
			return
		}
		result, err := reader.PeerMonitoringHistory(r.Context(), principal.ScopeID, nodeID, from, to, page, limit)
		if errors.Is(err, nodemetrics.ErrNotFound) {
			s.writeAPIError(w, r, http.StatusNotFound, "node_monitoring_not_found", "node monitoring was not found")
			return
		}
		if err != nil {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	if source == "dnspup" {
		reader, ok := s.nodeMetrics.(nodeDNSPupHistoryReader)
		if !ok || reader == nil {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
			return
		}
		result, err := reader.DNSPupMonitoringHistory(r.Context(), principal.ScopeID, nodeID, group, from, to, page, limit)
		if errors.Is(err, nodemetrics.ErrNotFound) {
			s.writeAPIError(w, r, http.StatusNotFound, "node_monitoring_not_found", "node monitoring was not found")
			return
		}
		if err != nil {
			s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	reader, ok := s.nodeMetrics.(nodeMonitoringHistoryReader)
	if !ok || reader == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	result, err := reader.MonitoringHistory(r.Context(), principal.ScopeID, nodeID, from, to, page, limit)
	if errors.Is(err, nodemetrics.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_monitoring_not_found", "node monitoring was not found")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_monitoring_unavailable", "node monitoring is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// nodeMonitoringHistorySource reads source ("" local Agent probe, "dnspup"
// carrier checkpoints, "peer" controller + peer nodes) and group (dnspup
// only: a monitoring group filter).
func nodeMonitoringHistorySource(r *http.Request) (string, string, error) {
	invalid := errors.New("invalid node monitoring history query")
	query := r.URL.Query()
	if len(query["source"]) > 1 || len(query["group"]) > 1 {
		return "", "", invalid
	}
	source, group := query.Get("source"), query.Get("group")
	switch {
	case source != "" && source != "local" && source != "dnspup" && source != "peer":
		return "", "", invalid
	case source != "dnspup" && query.Has("group"):
		return "", "", invalid
	case source == "dnspup" && !slices.Contains(nodemetrics.DNSPupHistoryGroups, group):
		return "", "", invalid
	}
	return source, group, nil
}

// nodeMonitoringHistoryQuery accepts RFC 3339 from/to (default: the last hour),
// a 1-based page and a page size (plus source/group, read separately);
// unknown parameters are rejected.
func nodeMonitoringHistoryQuery(r *http.Request) (time.Time, time.Time, int, int, error) {
	invalid := errors.New("invalid node monitoring history query")
	query := r.URL.Query()
	for key, values := range query {
		if (key != "from" && key != "to" && key != "page" && key != "limit" && key != "source" && key != "group") ||
			len(values) != 1 {
			return time.Time{}, time.Time{}, 0, 0, invalid
		}
	}
	to := time.Now().UTC()
	from := to.Add(-time.Hour)
	if raw := query.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, time.Time{}, 0, 0, invalid
		}
		from = parsed.UTC()
	}
	if raw := query.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, time.Time{}, 0, 0, invalid
		}
		to = parsed.UTC()
	}
	page, limit := 1, 10
	for _, field := range []struct {
		name   string
		target *int
		max    int
	}{{"page", &page, nodemetrics.MaxMonitoringHistoryPage}, {"limit", &limit, nodemetrics.MaxMonitoringHistoryLimit}} {
		if raw := query.Get(field.name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > field.max || strconv.Itoa(parsed) != raw {
				return time.Time{}, time.Time{}, 0, 0, invalid
			}
			*field.target = parsed
		}
	}
	if !from.Before(to) || to.Sub(from) > nodemetrics.MaxMonitoringHistoryWindow {
		return time.Time{}, time.Time{}, 0, 0, invalid
	}
	return from, to, page, limit, nil
}
