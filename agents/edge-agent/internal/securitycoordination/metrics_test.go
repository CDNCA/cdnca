package securitycoordination

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMetricsRecorderCountsOneEvictionPerRequestAndStaysDegradedOffline(t *testing.T) {
	recorder := NewMetricsRecorder()
	recorder.RecordCapacityFailure(true, "request-1")
	recorder.RecordCapacityFailure(true, "request-1")
	recorder.RecordCapacityFailure(false, "request-2")

	recorder.SetTransportHealthy(false)
	snapshot := recorder.Snapshot(MetricsIdentity{
		NodeID: "10000000-0000-4000-8000-000000000001", TenantScopeID: "20000000-0000-4000-8000-000000000001",
		SiteID: "30000000-0000-4000-8000-000000000001", PolicyID: "40000000-0000-4000-8000-000000000001", PolicyVersion: 7,
	})
	if snapshot.CapacityFailures != 2 || snapshot.SharedDictEvictions != 1 || !snapshot.Degraded {
		t.Fatalf("offline snapshot = %+v", snapshot)
	}
}

func TestDecodeMetricsRequiresBoundIdentityAndRejectsUnknownFields(t *testing.T) {
	valid := `{"schema_version":"cdnca.edge.cc-metrics/v1","node_id":"10000000-0000-4000-8000-000000000001","tenant_scope_id":"20000000-0000-4000-8000-000000000001","site_id":"30000000-0000-4000-8000-000000000001","policy_id":"40000000-0000-4000-8000-000000000001","policy_version":7,"capacity_failures":2,"shared_dict_evictions":1,"degraded":true}`
	decoded, err := DecodeMetrics([]byte(valid))
	if err != nil || decoded.PolicyVersion != 7 || !decoded.Degraded {
		t.Fatalf("DecodeMetrics() = %+v, %v", decoded, err)
	}
	for _, payload := range []string{
		strings.Replace(valid, `"node_id":"10000000-0000-4000-8000-000000000001"`, `"node_id":"00000000-0000-0000-0000-000000000000"`, 1),
		strings.TrimSuffix(valid, "}") + `,"unexpected":1}`,
		valid + ` {}`,
	} {
		if _, err := DecodeMetrics([]byte(payload)); err == nil {
			t.Fatalf("DecodeMetrics accepted invalid payload %s", payload)
		}
	}
	withJA4 := strings.TrimSuffix(valid, "}") + `,"ja4_unavailable":6}`
	if decoded, err := DecodeMetrics([]byte(withJA4)); err != nil || decoded.JA4Unavailable != 6 {
		t.Fatalf("DecodeMetrics(ja4_unavailable) = %+v, %v", decoded, err)
	}
	if encoded, err := json.Marshal(decoded); err != nil || len(encoded) == 0 {
		t.Fatalf("snapshot is not JSON serializable: %s %v", encoded, err)
	}
}
