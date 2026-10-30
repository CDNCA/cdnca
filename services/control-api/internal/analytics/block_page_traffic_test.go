package analytics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// FX60/NF38：拦截页标记从节点进 ClickHouse，用量查询按开关排除。
func TestAccessEventBlockedReachesInsertRow(t *testing.T) {
	event := AccessEvent{Blocked: true, InstallationID: "installation-1"}
	row, err := accessInsertFrom(event)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(row)
	if !strings.Contains(string(encoded), `"blocked":true`) {
		t.Fatalf("insert row lost blocked: %s", encoded)
	}
	var decoded AccessEvent
	if err := decodeStrictJSON([]byte(`{"blocked":true}`), &decoded); err != nil || !decoded.Blocked {
		t.Fatalf("decode blocked=%v err=%v", decoded.Blocked, err)
	}
	found := false
	for _, column := range accessIngestSchema {
		if column.Name == "blocked" && column.Type == "Bool" && column.DefaultKind == "DEFAULT" {
			found = true
		}
	}
	if !found {
		t.Fatal("access ingest schema lacks blocked Bool DEFAULT")
	}
}

func TestPackageUsageQueriesBindExcludeBlocked(t *testing.T) {
	var mu sync.Mutex
	var bodies, flags []string
	respond := `{"value":10,"observed_at_ms":1760500800000,"finalized_through_ms":1760504400000,"source_evidence_digest":"` +
		strings.Repeat("ab", 32) + `"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies, flags = append(bodies, string(raw)), append(flags, r.URL.Query().Get("param_exclude_blocked"))
		mu.Unlock()
		if strings.Contains(string(raw), "bucket_start") {
			_, _ = io.WriteString(w, `{"bucket_start":1760500800,"bytes_out":1,"requests":1}`)
			return
		}
		_, _ = io.WriteString(w, respond)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	start := time.Unix(1760500800, 0).UTC()
	sub := "33333333-3333-4333-8333-333333333333"
	for _, exclude := range []bool{false, true} {
		if _, err := client.PackageMetric(context.Background(), PackageMetricRequest{TenantScopeID: testTenantID,
			SubscriptionID: sub, Metric: "traffic_bytes", PeriodStart: start, PeriodEnd: start.Add(time.Hour), ExcludeBlocked: exclude}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.PackageTrafficBucketsFiltered(context.Background(), testTenantID, sub, start, start.Add(time.Hour), exclude); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(flags, ",") != "0,0,1,1" {
		t.Fatalf("exclude_blocked params=%v", flags)
	}
	for _, body := range bodies {
		if !strings.Contains(body, "NOT ({exclude_blocked:UInt8}=1 AND blocked)") {
			t.Fatalf("usage query does not filter blocked: %s", body)
		}
	}
	if !strings.Contains(packageBandwidthFinalizedSQL, "NOT ({exclude_blocked:UInt8}=1 AND blocked)") {
		t.Fatal("bandwidth query does not filter blocked")
	}
}
