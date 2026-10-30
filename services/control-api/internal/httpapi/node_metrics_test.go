package httpapi

import (
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodemetrics"
	"github.com/google/uuid"
)

func TestNode07MetricsResponsePreservesProbeAndRecoveryEvidence(t *testing.T) {
	now := time.Unix(900, 0).UTC()
	view := nodemetrics.LatestView{
		ScopeID: uuid.MustParse("01990000-0000-7000-8000-000000000001"),
		NodeID:  uuid.MustParse("01990000-0000-7000-8000-000000000007"), NodeName: "edge-7",
		ConfigRevision: 7, PublicationSequence: 41, ObservedAt: now,
		ActiveConfigRevision: 7, ProbePort: 8443, Healthy: false, ProbeSucceeded: true,
		ConsecutiveSuccesses: 2, ProbesTotal: 9, ProbeFailuresTotal: 4,
		LatestRecovery: &nodemetrics.RecoveryView{ConfigRevision: 6, PublicationSequence: 40,
			RecoveredAt: now.Add(-time.Minute), ReasonCode: nodemetrics.RecoveryReasonProbeRecovered,
			PubAckStream: nodemetrics.NodeMonitoringStatusStream, PubAckSequence: 90},
		TelemetryDetail: true,
	}
	response := nodeMetricsResponseFromView(view)
	if !response.TelemetryDetail {
		t.Fatal("telemetry_detail (NODE_TELEMETRY_DETAIL declared) dropped")
	}
	if response.ActiveConfigRevision != 7 || response.ProbePort != 8443 || response.Healthy ||
		!response.ProbeSucceeded || response.ConsecutiveSuccesses != 2 || response.ProbesTotal != 9 ||
		response.ProbeFailuresTotal != 4 || response.LatestRecovery == nil ||
		response.LatestRecovery.ReasonCode != nodemetrics.RecoveryReasonProbeRecovered ||
		response.LatestRecovery.PubAckSequence != 90 {
		t.Fatalf("response = %#v", response)
	}
}

func TestNodeMetricsHistoryQueryDefaultsAndBoundsWindow(t *testing.T) {
	from, to, limit, err := nodeMetricsHistoryQuery(httptest.NewRequest("GET", "/v1/nodes/id/metrics/history", nil))
	if err != nil || limit != 240 || to.Before(from) || to.Sub(from) != time.Hour {
		t.Fatalf("defaults = (%v, %v, %d, %v)", from, to, limit, err)
	}
	request := httptest.NewRequest("GET", "/v1/nodes/id/metrics/history?from=2026-08-01T08:00:00Z&to=2026-08-01T09:00:00Z&limit=12", nil)
	from, to, limit, err = nodeMetricsHistoryQuery(request)
	if err != nil || !from.Equal(time.Date(2026, 8, 1, 8, 0, 0, 0, time.UTC)) ||
		!to.Equal(time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)) || limit != 12 {
		t.Fatalf("explicit query = (%v, %v, %d, %v)", from, to, limit, err)
	}
	for _, target := range []string{
		"/v1/nodes/id/metrics/history?from=2026-08-01T09:00:00Z&to=2026-08-01T08:00:00Z",
		"/v1/nodes/id/metrics/history?limit=2001",
		"/v1/nodes/id/metrics/history?from=not-a-time",
	} {
		if _, _, _, err := nodeMetricsHistoryQuery(httptest.NewRequest("GET", target, nil)); err == nil {
			t.Errorf("query %q unexpectedly accepted", target)
		}
	}
}

func TestNodeMetricsHistoryResponsePreservesMetricValues(t *testing.T) {
	now := time.Unix(900, 0).UTC()
	cpu, rx, tx := 25.0, uint64(1600), uint64(800)
	response := nodeMetricsHistoryResponseFromViews([]nodemetrics.HistoryView{{
		NodeID: uuid.MustParse("01990000-0000-7000-8000-000000000007"), NodeName: "edge-7",
		PublicationSequence: 41, ObservedAt: now, Known: true, CPUPercent: &cpu,
		RXBandwidthBPS: &rx, TXBandwidthBPS: &tx,
	}})
	if len(response.Items) != 1 || response.Items[0].NodeName != "edge-7" ||
		response.Items[0].PublicationSequence != 41 || response.Items[0].RXBandwidthBPS == nil ||
		*response.Items[0].RXBandwidthBPS != 1600 || response.Items[0].TXBandwidthBPS == nil ||
		*response.Items[0].TXBandwidthBPS != 800 {
		t.Fatalf("history response = %#v", response)
	}
}

func TestNodeMetricsBatchQuery(t *testing.T) {
	ids := make([]uuid.UUID, 300)
	query := url.Values{}
	for index := range ids {
		ids[index] = uuid.New()
		query.Add("node_id", ids[index].String())
	}
	request := httptest.NewRequest("GET", "/v1/nodes/metrics/latest?"+query.Encode(), nil)
	if got, err := nodeMetricsBatchQuery(request); err != nil || !reflect.DeepEqual(got, ids) {
		t.Fatalf("300 unique node IDs: count=%d err=%v", len(got), err)
	}
	query.Add("node_id", uuid.NewString())
	for _, raw := range []string{
		query.Encode(), "node_id=%zz", "node_id=" + ids[0].String() + "&broken=%zz",
		"node_id=" + ids[0].String() + ";ignored=1", "node_id=" + ids[0].String() + "&node_id=" + ids[0].String(),
		"node_id=" + ids[0].String() + "&node_id", "node_id=" + ids[0].String() + "," + ids[1].String(),
		"node_id=" + ids[0].String() + "&unknown=", "node_id=" + ids[0].String() + "&=", "", "node_id=" + uuid.Nil.String(),
	} {
		request.URL.RawQuery = raw
		if _, err := nodeMetricsBatchQuery(request); err == nil {
			t.Fatalf("invalid query accepted: %q", raw)
		}
	}
}
