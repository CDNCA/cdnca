package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
)

type NodeMetricsReader interface {
	Latest(context.Context, uuid.UUID, uuid.UUID) (nodemetrics.LatestView, error)
	History(context.Context, uuid.UUID, uuid.UUID, time.Time, time.Time, int) ([]nodemetrics.HistoryView, error)
}

type nodeMetricsBatchReader interface {
	LatestBatch(context.Context, uuid.UUID, []uuid.UUID) ([]nodemetrics.LatestView, []uuid.UUID, error)
}

type nodeMetricsBatchResponse struct {
	ObservedAt         time.Time             `json:"observed_at"`
	Items              []nodeMetricsResponse `json:"items"`
	NotReportedNodeIDs []uuid.UUID           `json:"not_reported_node_ids"`
}

type nodeMetricsResponse struct {
	RecordKind           string                      `json:"record_kind,omitempty"`
	NodeID               uuid.UUID                   `json:"node_id"`
	NodeName             string                      `json:"node_name"`
	ConfigRevision       uint64                      `json:"config_revision"`
	PublicationSequence  uint64                      `json:"publication_sequence"`
	ObservedAt           time.Time                   `json:"observed_at"`
	ActiveConfigRevision uint64                      `json:"active_config_revision"`
	ProbePort            uint16                      `json:"probe_port"`
	Healthy              bool                        `json:"healthy"`
	ProbeSucceeded       bool                        `json:"probe_succeeded"`
	ConsecutiveFailures  uint8                       `json:"consecutive_failures"`
	ConsecutiveSuccesses uint8                       `json:"consecutive_successes"`
	ProbesTotal          uint64                      `json:"probes_total"`
	ProbeFailuresTotal   uint64                      `json:"probe_failures_total"`
	Recovered            bool                        `json:"recovered"`
	RecoveryNotified     bool                        `json:"recovery_notified"`
	RolledBack           bool                        `json:"rolled_back"`
	Known                bool                        `json:"known"`
	CPUPercent           *float64                    `json:"cpu_percent"`
	MemoryUsedBytes      *uint64                     `json:"memory_used_bytes"`
	MemoryTotalBytes     *uint64                     `json:"memory_total_bytes"`
	ActiveConnections    *uint64                     `json:"active_connections"`
	RXBandwidthBPS       *uint64                     `json:"rx_bandwidth_bps"`
	TXBandwidthBPS       *uint64                     `json:"tx_bandwidth_bps"`
	Telemetry            *nodemetrics.Telemetry      `json:"telemetry,omitempty"`
	TotalRXBytes         *uint64                     `json:"total_rx_bytes"`
	TotalTXBytes         *uint64                     `json:"total_tx_bytes"`
	PubAckStream         string                      `json:"puback_stream"`
	PubAckSequence       uint64                      `json:"puback_sequence"`
	ConsumerDurable      string                      `json:"consumer_durable"`
	ConsumerSequence     uint64                      `json:"consumer_sequence"`
	IngestedAt           time.Time                   `json:"ingested_at"`
	LatestRecovery       *nodeRecoveryResponse       `json:"latest_recovery,omitempty"`
	MonthlyTraffic       *nodemetrics.MonthlyTraffic `json:"monthly_traffic,omitempty"`
	// TelemetryDetail: the node's latest session declares
	// NODE_TELEMETRY_DETAIL v1 (telemetry mounts / port_group_overrides).
	TelemetryDetail bool `json:"telemetry_detail"`
	// StorageSupported: the node's latest session declares NODE_STORAGE v1
	// (cache directory, cache limit and log directory are editable).
	StorageSupported bool `json:"storage_supported"`
}

type nodeRecoveryResponse struct {
	ConfigRevision      uint64    `json:"config_revision"`
	PublicationSequence uint64    `json:"publication_sequence"`
	RecoveredAt         time.Time `json:"recovered_at"`
	ReasonCode          string    `json:"reason_code"`
	PubAckStream        string    `json:"puback_stream"`
	PubAckSequence      uint64    `json:"puback_sequence"`
}

type nodeMetricsHistoryResponse struct {
	Items []nodeMetricsHistoryPoint `json:"items"`
}

type nodeMetricsHistoryPoint struct {
	NodeID              uuid.UUID              `json:"node_id"`
	NodeName            string                 `json:"node_name"`
	PublicationSequence uint64                 `json:"publication_sequence"`
	ObservedAt          time.Time              `json:"observed_at"`
	Known               bool                   `json:"known"`
	CPUPercent          *float64               `json:"cpu_percent"`
	MemoryUsedBytes     *uint64                `json:"memory_used_bytes"`
	MemoryTotalBytes    *uint64                `json:"memory_total_bytes"`
	ActiveConnections   *uint64                `json:"active_connections"`
	RXBandwidthBPS      *uint64                `json:"rx_bandwidth_bps"`
	TXBandwidthBPS      *uint64                `json:"tx_bandwidth_bps"`
	Telemetry           *nodemetrics.Telemetry `json:"telemetry,omitempty"`
	TotalRXBytes        *uint64                `json:"total_rx_bytes"`
	TotalTXBytes        *uint64                `json:"total_tx_bytes"`
}

func nodeMetricsResponseFromView(view nodemetrics.LatestView) nodeMetricsResponse {
	response := nodeMetricsResponse{
		RecordKind: view.RecordKind,
		NodeID:     view.NodeID, NodeName: view.NodeName,
		ConfigRevision: view.ConfigRevision, PublicationSequence: view.PublicationSequence,
		ObservedAt: view.ObservedAt, ActiveConfigRevision: view.ActiveConfigRevision,
		ProbePort: view.ProbePort, Healthy: view.Healthy, ProbeSucceeded: view.ProbeSucceeded,
		ConsecutiveFailures: view.ConsecutiveFailures, ConsecutiveSuccesses: view.ConsecutiveSuccesses,
		ProbesTotal: view.ProbesTotal, ProbeFailuresTotal: view.ProbeFailuresTotal,
		Recovered: view.Recovered, RecoveryNotified: view.RecoveryNotified, RolledBack: view.RolledBack,
		Known: view.Known, CPUPercent: view.CPUPercent, MemoryUsedBytes: view.MemoryUsedBytes,
		MemoryTotalBytes: view.MemoryTotalBytes, ActiveConnections: view.ActiveConnections,
		RXBandwidthBPS: view.RXBandwidthBPS, TXBandwidthBPS: view.TXBandwidthBPS,
		Telemetry: view.Telemetry, TotalRXBytes: view.TotalRXBytes, TotalTXBytes: view.TotalTXBytes,
		PubAckStream: view.PubAckStream, PubAckSequence: view.PubAckSequence,
		ConsumerDurable: view.ConsumerDurable, ConsumerSequence: view.ConsumerSequence,
		IngestedAt:     view.IngestedAt,
		MonthlyTraffic: view.MonthlyTraffic, TelemetryDetail: view.TelemetryDetail, StorageSupported: view.StorageSupported,
	}
	if view.LatestRecovery != nil {
		response.LatestRecovery = &nodeRecoveryResponse{
			ConfigRevision:      view.LatestRecovery.ConfigRevision,
			PublicationSequence: view.LatestRecovery.PublicationSequence,
			RecoveredAt:         view.LatestRecovery.RecoveredAt, ReasonCode: view.LatestRecovery.ReasonCode,
			PubAckStream: view.LatestRecovery.PubAckStream, PubAckSequence: view.LatestRecovery.PubAckSequence,
		}
	}
	return response
}

func nodeMetricsHistoryResponseFromViews(views []nodemetrics.HistoryView) nodeMetricsHistoryResponse {
	items := make([]nodeMetricsHistoryPoint, len(views))
	for index, view := range views {
		items[index] = nodeMetricsHistoryPoint{
			NodeID: view.NodeID, NodeName: view.NodeName, PublicationSequence: view.PublicationSequence,
			ObservedAt: view.ObservedAt, Known: view.Known, CPUPercent: view.CPUPercent,
			MemoryUsedBytes: view.MemoryUsedBytes, MemoryTotalBytes: view.MemoryTotalBytes,
			ActiveConnections: view.ActiveConnections, RXBandwidthBPS: view.RXBandwidthBPS,
			TXBandwidthBPS: view.TXBandwidthBPS, Telemetry: view.Telemetry,
			TotalRXBytes: view.TotalRXBytes, TotalTXBytes: view.TotalTXBytes,
		}
	}
	return nodeMetricsHistoryResponse{Items: items}
}

func (s *Server) handleGetLatestNodeMetrics(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	if s.nodeMetrics == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_metrics_unavailable", "node metrics are unavailable")
		return
	}
	view, err := s.nodeMetrics.Latest(r.Context(), principal.ScopeID, nodeID)
	if errors.Is(err, nodemetrics.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_metrics_not_found", "node metrics were not found")
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeMetricsResponseFromView(view))
}

func (s *Server) handleGetLatestNodeMetricsBatch(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	ids, err := nodeMetricsBatchQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node metrics batch query")
		return
	}
	reader, ok := s.nodeMetrics.(nodeMetricsBatchReader)
	if !ok || reader == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_metrics_unavailable", "node metrics are unavailable")
		return
	}
	views, notReported, err := reader.LatestBatch(r.Context(), principal.ScopeID, ids)
	if errors.Is(err, nodemetrics.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_metrics_not_found", "node metrics were not found")
		return
	}
	if err != nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_metrics_unavailable", "node metrics are unavailable")
		return
	}
	items := make([]nodeMetricsResponse, len(views))
	for index, view := range views {
		items[index] = nodeMetricsResponseFromView(view)
	}
	writeJSON(w, http.StatusOK, nodeMetricsBatchResponse{ObservedAt: time.Now().UTC(), Items: items, NotReportedNodeIDs: notReported})
}

func nodeMetricsBatchQuery(r *http.Request) ([]uuid.UUID, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	values := query["node_id"]
	if err != nil || len(query) != 1 || len(values) < 1 || len(values) > nodemetrics.MaxLatestBatch {
		return nil, errors.New("invalid batch query")
	}
	ids := make([]uuid.UUID, 0, len(values))
	seen := make(map[uuid.UUID]struct{}, len(values))
	for _, raw := range values {
		id, err := uuid.Parse(raw)
		if _, duplicate := seen[id]; err != nil || id == uuid.Nil || id.String() != raw || duplicate {
			return nil, errors.New("invalid batch node identifier")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Server) handleGetNodeMetricsHistory(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	nodeID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node ID must be a UUID")
		return
	}
	from, to, limit, err := nodeMetricsHistoryQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node metrics history query")
		return
	}
	if s.nodeMetrics == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_metrics_unavailable", "node metrics are unavailable")
		return
	}
	views, err := s.nodeMetrics.History(r.Context(), principal.ScopeID, nodeID, from, to, limit)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeMetricsHistoryResponseFromViews(views))
}

func nodeMetricsHistoryQuery(r *http.Request) (time.Time, time.Time, int, error) {
	now := time.Now().UTC()
	from, to := now.Add(-time.Hour), now
	query := r.URL.Query()
	if raw := query.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, time.Time{}, 0, err
		}
		from = parsed.UTC()
	}
	if raw := query.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return time.Time{}, time.Time{}, 0, err
		}
		to = parsed.UTC()
	}
	limit := 240
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return time.Time{}, time.Time{}, 0, err
		}
		limit = parsed
	}
	if from.IsZero() || to.IsZero() || to.Before(from) || to.Sub(from) > 31*24*time.Hour || limit < 1 || limit > 2000 {
		return time.Time{}, time.Time{}, 0, errors.New("invalid node metrics history query")
	}
	return from, to, limit, nil
}
