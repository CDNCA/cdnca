package analytics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FX36: the home page peak is the busiest 5-minute window (max of per-bucket
// sums), not the busiest hourly average.
func TestPeakBandwidthUsesFiveMinuteBuckets(t *testing.T) {
	t.Parallel()
	var observedBody string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observedBody = string(body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"peak_bucket_bytes":37500000}`)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	peak, err := client.PeakBandwidth(context.Background(), scope, validFilter())
	if err != nil || peak.BucketSeconds != 300 || peak.PeakBandwidthBPS != 1_000_000 {
		t.Fatalf("PeakBandwidth() = %#v, %v", peak, err)
	}
	for _, token := range []string{"toStartOfFiveMinutes", "max(bucket_bytes)", "{snapshot_ms:UInt64}", "access_hourly_facts_v1"} {
		if !strings.Contains(observedBody, token) {
			t.Fatalf("query missing %q: %s", token, observedBody)
		}
	}
	if strings.Contains(observedBody, testTenantID) {
		t.Fatal("query SQL interpolated the tenant id")
	}
}

// FX36: the blocked-IP metric also counts IPs auto-banned by CC rules.
func TestBlockedIPMetricsIncludeCCTemporaryBans(t *testing.T) {
	for name, query := range map[string]string{"count": blockedIPCountSQL, "trend": blockedIPTrendSQL} {
		for _, token := range []string{"(event_type = 'global_firewall' AND action = 'block')", "(event_type = 'cc' AND action = 'temporary_ban')"} {
			if !strings.Contains(query, token) {
				t.Errorf("%s query missing %q", name, token)
			}
		}
	}
}

type peakHandlerStore struct {
	QueryStore
	peak PeakBandwidth
}

func (store *peakHandlerStore) PeakBandwidth(context.Context, Scope, Filter) (PeakBandwidth, error) {
	return store.peak, nil
}

func TestPeakBandwidthHandlerRoute(t *testing.T) {
	store := &peakHandlerStore{QueryStore: &recordingQueryStore{}, peak: PeakBandwidth{PeakBandwidthBPS: 8000, BucketSeconds: 300}}
	handler := mustHandler(t, store, Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, handlerURL("/v1/admin/analytics/peak-bandwidth", ""), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Data PeakBandwidth `json:"data"`
		Meta queryMetadata `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Data.PeakBandwidthBPS != 8000 ||
		body.Data.BucketSeconds != 300 || body.Meta.Timezone != "UTC" {
		t.Fatalf("body = %s (%v)", response.Body.String(), err)
	}
}
