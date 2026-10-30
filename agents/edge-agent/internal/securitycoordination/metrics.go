package securitycoordination

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
)

const MetricsSchemaVersion = "cdnca.edge.cc-metrics/v1"

var ErrInvalidMetrics = errors.New("invalid security coordination metrics")

type MetricsIdentity struct {
	NodeID        string
	TenantScopeID string
	SiteID        string
	PolicyID      string
	PolicyVersion uint64
}

type Metrics struct {
	SchemaVersion       string `json:"schema_version"`
	NodeID              string `json:"node_id"`
	TenantScopeID       string `json:"tenant_scope_id"`
	SiteID              string `json:"site_id"`
	PolicyID            string `json:"policy_id"`
	PolicyVersion       uint64 `json:"policy_version"`
	CapacityFailures    uint64 `json:"capacity_failures"`
	SharedDictEvictions uint64 `json:"shared_dict_evictions"`
	Degraded            bool   `json:"degraded"`
	// JA4Unavailable counts requests a ja4 counting rule skipped for lack of a
	// TLS fingerprint (CC v4 count_by); absent (0) from the legacy engine.
	JA4Unavailable uint64 `json:"ja4_unavailable"`
}

const maxRequestDedup = 4096

type MetricsRecorder struct {
	mu                  sync.Mutex
	seenRequests        map[string]struct{}
	requestOrder        []string
	capacityFailures    atomic.Uint64
	sharedDictEvictions atomic.Uint64
	transportHealthy    atomic.Bool
}

func NewMetricsRecorder() *MetricsRecorder {
	recorder := &MetricsRecorder{seenRequests: make(map[string]struct{}, maxRequestDedup)}
	return recorder
}

// RecordCapacityFailure keeps one observation per request ID. It remains usable
// while telemetry is unavailable; the degraded bit is maintained separately.
func (recorder *MetricsRecorder) RecordCapacityFailure(eviction bool, requestID string) {
	if recorder == nil {
		return
	}
	if requestID != "" {
		recorder.mu.Lock()
		if _, exists := recorder.seenRequests[requestID]; exists {
			recorder.mu.Unlock()
			return
		}
		recorder.seenRequests[requestID] = struct{}{}
		recorder.requestOrder = append(recorder.requestOrder, requestID)
		if len(recorder.requestOrder) > maxRequestDedup {
			oldest := recorder.requestOrder[0]
			recorder.requestOrder = recorder.requestOrder[1:]
			delete(recorder.seenRequests, oldest)
		}
		recorder.mu.Unlock()
	}
	recorder.capacityFailures.Add(1)
	if eviction {
		recorder.sharedDictEvictions.Add(1)
	}
}

func (recorder *MetricsRecorder) SetTransportHealthy(healthy bool) {
	if recorder != nil {
		recorder.transportHealthy.Store(healthy)
	}
}

func (recorder *MetricsRecorder) Snapshot(identity MetricsIdentity) Metrics {
	if recorder == nil {
		return Metrics{}
	}
	return Metrics{
		SchemaVersion: MetricsSchemaVersion, NodeID: identity.NodeID, TenantScopeID: identity.TenantScopeID,
		SiteID: identity.SiteID, PolicyID: identity.PolicyID, PolicyVersion: identity.PolicyVersion,
		CapacityFailures: recorder.capacityFailures.Load(), SharedDictEvictions: recorder.sharedDictEvictions.Load(),
		Degraded: !recorder.transportHealthy.Load(),
	}
}

func DecodeMetrics(payload []byte) (Metrics, error) {
	if len(payload) == 0 || len(payload) > 16<<10 {
		return Metrics{}, ErrInvalidMetrics
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var metrics Metrics
	if decoder.Decode(&metrics) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Metrics{}, ErrInvalidMetrics
	}
	if !validMetricsUUID(metrics.NodeID) || !validMetricsUUID(metrics.TenantScopeID) ||
		!validMetricsUUID(metrics.SiteID) || !validMetricsPolicyID(metrics.PolicyID) || metrics.PolicyVersion == 0 ||
		metrics.SchemaVersion != MetricsSchemaVersion {
		return Metrics{}, ErrInvalidMetrics
	}
	return metrics, nil
}

func validMetricsUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && strings.ToLower(value) == value && parsed.String() == value
}

func validMetricsPolicyID(value string) bool {
	return value == "legacy-cc" || validMetricsUUID(value)
}
