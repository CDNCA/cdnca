package analytics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPackageUsageUsesFrozenSnapshotsAndExactBandwidth(t *testing.T) {
	from := time.Date(2026, 8, 1, 16, 0, 0, 0, time.UTC)
	to := from.Add(48 * time.Hour)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		parameters := request.URL.Query()
		for key, want := range map[string]string{
			"param_tenant_id": testTenantID, "param_subscription_id": testPackageSubscriptionID,
			"param_site_id": testSiteID, "param_from": clickHouseTime(from),
			"param_to": clickHouseTime(to), "param_timezone": "Asia/Shanghai",
		} {
			if got := parameters.Get(key); got != want {
				t.Errorf("%s = %q, want %q", key, got, want)
			}
		}
		switch calls {
		case 1:
			for _, token := range []string{"package_metric_access_facts_v1 FINAL", "connections_ingest_receipts_v1 FINAL", "max(ingested_at)", "max(updated_at)"} {
				if !strings.Contains(query, token) {
					t.Errorf("snapshot query missing %q", token)
				}
			}
			_, _ = io.WriteString(writer, "{\"access_snapshot_ms\":1785600000000,\"connection_snapshot_ms\":1785600001000}\n")
		case 2:
			for _, token := range []string{"package_metric_access_facts_v1 FINAL", "quantileExactWeighted(0.95)(v, w)", "toInt64(1000) AS unit_ms", "toInt64(300000) AS unit_ms", "duration_us", "source_watermark", "finalized_through", "ingested_at<=", "updated_at<="} {
				if !strings.Contains(query, token) {
					t.Errorf("summary query missing %q", token)
				}
			}
			_, _ = io.WriteString(writer, "{\"traffic_bytes\":9007199254740993,\"peak_bandwidth_bps\":8000,\"bandwidth_95th_bps\":6400,\"connections\":77,\"source_watermark\":19,\"finalized_through_ms\":1785772799000}\n")
		case 3:
			for _, token := range []string{"toStartOfInterval", "{timezone:String}", "ORDER BY bucket", "LIMIT {row_limit:UInt16}"} {
				if !strings.Contains(query, token) {
					t.Errorf("series query missing %q", token)
				}
			}
			_, _ = io.WriteString(writer,
				"{\"bucket_ms\":1785600000000,\"traffic_bytes\":1024,\"bandwidth_bps\":8192,\"connections\":12}\n"+
					"{\"bucket_ms\":1785603600000,\"traffic_bytes\":2048,\"bandwidth_bps\":16384,\"connections\":14}\n"+
					"{\"bucket_ms\":1785607200000,\"traffic_bytes\":4096,\"bandwidth_bps\":32768,\"connections\":16}\n")
		default:
			t.Errorf("unexpected request %d", calls)
		}
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	result, err := client.PackageUsage(context.Background(), PackageUsageRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, SiteID: testSiteID,
		From: from, To: to, Timezone: "Asia/Shanghai", Bucket: PackageUsageBucketHour, Limit: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || result.TrafficBytes != 9007199254740993 || result.PeakBandwidthBPS != 8000 ||
		result.Bandwidth95thBPS != 6400 || result.Connections != 77 || len(result.Series) != 2 ||
		result.SourceWatermark != 19 || !result.Delayed || !result.HasMore {
		t.Fatalf("PackageUsage() = %#v, calls=%d", result, calls)
	}
}

func TestPackageUsageRejectsUnboundAndUnsafeQueries(t *testing.T) {
	client := mustClient(t, Config{Endpoint: "https://localhost", Database: "analytics_test"}, &http.Client{})
	valid := PackageUsageRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID,
		From:     time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		To:       time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		Timezone: "Asia/Shanghai", Bucket: PackageUsageBucketHour, Limit: 48,
	}
	for name, mutate := range map[string]func(*PackageUsageRequest){
		"tenant":       func(request *PackageUsageRequest) { request.TenantScopeID = "bad" },
		"subscription": func(request *PackageUsageRequest) { request.SubscriptionID = nilUUIDValue },
		"site":         func(request *PackageUsageRequest) { request.SiteID = "BAD" },
		"timezone":     func(request *PackageUsageRequest) { request.Timezone = "../UTC" },
		"bucket":       func(request *PackageUsageRequest) { request.Bucket = "minute" },
		"range":        func(request *PackageUsageRequest) { request.To = request.From.Add(401 * 24 * time.Hour) },
		"limit":        func(request *PackageUsageRequest) { request.Limit = 0 },
		"cursor snapshots": func(request *PackageUsageRequest) {
			request.AfterBucket = request.From
			request.AccessSnapshotAt = request.To
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := client.PackageUsage(context.Background(), request); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

// Usage, peak and 95th must not read raw access_events: their TTL follows the
// access log retention (default 7 days), billing periods are longer.
func TestPackageUsageNeverReadsRawAccessEvents(t *testing.T) {
	for name, query := range map[string]string{
		"snapshot": packageUsageSnapshotSQL, "summary": packageUsageSummarySQL,
		"hour": packageUsageSeriesHourSQL, "day": packageUsageSeriesDaySQL,
		"finalized peak": packageBandwidthFinalizedSQL,
	} {
		if strings.Contains(query, "FROM access_events") {
			t.Errorf("%s query reads raw access_events", name)
		}
	}
}

// Without a site filter every query still binds {site_id:UUID}: ClickHouse
// parses the parameter even when has_site=0, so "" answered HTTP 400
// (CANNOT_PARSE_UUID) and the unfiltered usage page always failed.
func TestPackageUsageWithoutSiteBindsNilSiteUUID(t *testing.T) {
	from := time.Date(2026, 8, 1, 16, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parameters := request.URL.Query()
		if got := parameters.Get("param_site_id"); got != nilUUIDValue || parameters.Get("param_has_site") != "0" {
			t.Errorf("param_site_id = %q has_site = %q, want %q and 0", got, parameters.Get("param_has_site"), nilUUIDValue)
		}
		_, _ = io.WriteString(writer, "{\"access_snapshot_ms\":1785600000000,\"connection_snapshot_ms\":1785600001000}\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	_, _ = client.PackageUsage(context.Background(), PackageUsageRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID,
		From: from, To: from.Add(time.Hour), Timezone: "UTC", Bucket: PackageUsageBucketHour, Limit: 2,
	})
}
