package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
)

var realtimeDurationPattern = regexp.MustCompile(`^[1-9][0-9]{0,3}(s|m|h)$`)

type nodeRealtimeTopItem struct {
	Inbound  float64   `json:"inbound"`
	NIC      string    `json:"nic"`
	NodeID   uuid.UUID `json:"node_id"`
	NodeName string    `json:"node_name"`
	Outbound float64   `json:"outbound"`
}

type nodeRealtimeTopResponse struct {
	Data []nodeRealtimeTopItem `json:"data"`
	Msg  string                `json:"msg"`
	Code int                   `json:"code"`
}

type nodeRealtimeSeries struct {
	Data [][2]float64 `json:"data"`
	Name string       `json:"name"`
}

type nodeRealtimeResponse struct {
	Data map[string][]nodeRealtimeSeries `json:"data"`
	Msg  string                          `json:"msg"`
	Code int                             `json:"code"`
}

type nodeTrafficItem struct {
	BytesReceived uint64 `json:"bytes_received"`
	BytesSent     uint64 `json:"bytes_sent"`
	CreateAt      string `json:"create_at"`
}

type nodeTrafficResponse struct {
	Count int               `json:"count"`
	Data  []nodeTrafficItem `json:"data"`
	Msg   string            `json:"msg"`
	Code  int               `json:"code"`
}

func (s *Server) analyticsReader(w http.ResponseWriter, r *http.Request) (nodemetrics.NodeMetricsAnalyticsReader, bool) {
	if s.nodeMetrics == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_metrics_unavailable", "node metrics are unavailable")
		return nil, false
	}
	reader, ok := s.nodeMetrics.(nodemetrics.NodeMetricsAnalyticsReader)
	if !ok || reader == nil {
		s.writeAPIError(w, r, http.StatusServiceUnavailable, "node_metrics_unavailable", "node metrics are unavailable")
		return nil, false
	}
	return reader, true
}

func (s *Server) handleGetNodeRealtimeTop(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	reader, ok := s.analyticsReader(w, r)
	if !ok {
		return
	}
	metric := r.URL.Query().Get("type")
	if metric == "" {
		metric = "bandwidth"
	}
	if !validRealtimeMetric(metric) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node realtime metric")
		return
	}
	duration, err := parseRealtimeDuration(r.URL.Query().Get("recent_time"), time.Minute)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node realtime window")
		return
	}
	limit, err := parseRealtimeLimit(r.URL.Query().Get("limit"), 100, 300)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node realtime limit")
		return
	}
	to := time.Now().UTC()
	externalOnly, err := networkScopeQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid network scope")
		return
	}
	items, err := reader.Top(r.Context(), principal.ScopeID, to.Add(-duration), to, metric, limit, externalOnly)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	data := make([]nodeRealtimeTopItem, len(items))
	for index, item := range items {
		data[index] = nodeRealtimeTopItem{Inbound: item.Inbound, NIC: item.NIC, NodeID: item.NodeID,
			NodeName: item.NodeName, Outbound: item.Outbound}
	}
	writeJSON(w, http.StatusOK, nodeRealtimeTopResponse{Data: data, Msg: "", Code: 0})
}

func (s *Server) handleGetNodeRealtimeSeries(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	reader, ok := s.analyticsReader(w, r)
	if !ok {
		return
	}
	nodeID, err := parseRealtimeNodeID(r.URL.Query().Get("node"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node must be a UUID")
		return
	}
	metric := r.URL.Query().Get("type")
	if metric == "" {
		metric = "bandwidth"
	}
	if !validRealtimeMetric(metric) {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node realtime metric")
		return
	}
	from, to, err := parseRealtimeWindow(r, time.Hour, 31*24*time.Hour)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node realtime window")
		return
	}
	limit, err := parseRealtimeLimit(r.URL.Query().Get("limit"), 2000, 2000)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node realtime limit")
		return
	}
	externalOnly, err := networkScopeQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid network scope")
		return
	}
	view, err := reader.Realtime(r.Context(), principal.ScopeID, nodeID, from, to, metric, limit, externalOnly)
	if errors.Is(err, nodemetrics.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_metrics_not_found", "node metrics were not found")
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	data := make(map[string][]nodeRealtimeSeries, len(view.Data))
	for nic, named := range view.Data {
		series := make([]nodeRealtimeSeries, len(named))
		for index, item := range named {
			points := make([][2]float64, len(item.Points))
			for pointIndex, point := range item.Points {
				points[pointIndex] = [2]float64{float64(point.ObservedAt.UnixMilli()), point.Value}
			}
			series[index] = nodeRealtimeSeries{Data: points, Name: item.Name}
		}
		data[nic] = series
	}
	writeJSON(w, http.StatusOK, nodeRealtimeResponse{Data: data, Msg: "", Code: 0})
}

func (s *Server) handleGetNodeTraffic(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNodePermission(w, r, "nodes.read")
	if !ok {
		return
	}
	reader, ok := s.analyticsReader(w, r)
	if !ok {
		return
	}
	nodeID, err := parseRealtimeNodeID(r.URL.Query().Get("node"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "node must be a UUID")
		return
	}
	from, to, err := parseRealtimeWindow(r, 24*time.Hour, 31*24*time.Hour)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node traffic window")
		return
	}
	limit, err := parseRealtimeLimit(r.URL.Query().Get("limit"), 2000, 2000)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid node traffic limit")
		return
	}
	excluded := parseExcludedNICs(r.URL.Query().Get("excluded_nic"), r.URL.Query().Get("excl_nic"))
	externalOnly, err := networkScopeQuery(r)
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "invalid network scope")
		return
	}
	items, err := reader.Traffic(r.Context(), principal.ScopeID, nodeID, from, to, excluded, limit, externalOnly)
	if errors.Is(err, nodemetrics.ErrNotFound) {
		s.writeAPIError(w, r, http.StatusNotFound, "node_metrics_not_found", "node metrics were not found")
		return
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	data := make([]nodeTrafficItem, len(items))
	for index, item := range items {
		data[index] = nodeTrafficItem{BytesReceived: item.BytesReceived, BytesSent: item.BytesSent,
			CreateAt: item.ObservedAt.UTC().Format("2006-01-02 15:04:05")}
	}
	writeJSON(w, http.StatusOK, nodeTrafficResponse{Count: len(data), Data: data, Msg: "", Code: 0})
}

func validRealtimeMetric(value string) bool {
	switch value {
	case "bandwidth", "connections", "load", "disk":
		return true
	default:
		return false
	}
}

func networkScopeQuery(r *http.Request) (bool, error) {
	values, exists := r.URL.Query()["external_only"]
	if !exists {
		return false, nil
	}
	if len(values) != 1 || values[0] != "true" && values[0] != "false" {
		return false, errors.New("invalid network scope")
	}
	return values[0] == "true", nil
}

func parseRealtimeNodeID(raw string) (uuid.UUID, error) {
	if raw == "" {
		return uuid.Nil, errors.New("node is required")
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw {
		return uuid.Nil, errors.New("invalid node")
	}
	return id, nil
}

func parseRealtimeDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	if !realtimeDurationPattern.MatchString(raw) {
		return 0, errors.New("invalid duration")
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration <= 0 || duration > 31*24*time.Hour {
		return 0, errors.New("invalid duration")
	}
	return duration, nil
}

func parseRealtimeLimit(raw string, fallback, maximum int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > maximum || strings.TrimSpace(raw) != strconv.Itoa(limit) {
		return 0, errors.New("invalid limit")
	}
	return limit, nil
}

func parseRealtimeWindow(r *http.Request, fallback, maximum time.Duration) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	from, to := now.Add(-fallback), now
	if raw := r.URL.Query().Get("start"); raw != "" {
		parsed, err := parseRealtimeTime(raw)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		from = parsed
	}
	if raw := r.URL.Query().Get("end"); raw != "" {
		parsed, err := parseRealtimeTime(raw)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		to = parsed
	}
	if from.IsZero() || to.IsZero() || to.Before(from) || to.Sub(from) > maximum {
		return time.Time{}, time.Time{}, errors.New("invalid window")
	}
	return from, to, nil
}

func parseRealtimeTime(raw string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed.UTC(), nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("invalid timestamp")
}

func parseExcludedNICs(values ...string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, 8)
	for _, value := range values {
		for _, nic := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' }) {
			if nic == "" || len(nic) > 128 {
				continue
			}
			if _, exists := seen[nic]; exists {
				continue
			}
			seen[nic] = struct{}{}
			result = append(result, nic)
		}
	}
	return result
}
