package analytics

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// applyAllClickHouseMigrations applies, after database.reset (001..004), every
// later up migration in order, the way the installer does.
func applyAllClickHouseMigrations(t *testing.T, database *rankTestDatabase) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate analytics integration test")
	}
	root := filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "..", "infra", "clickhouse", "migrations")
	names, err := filepath.Glob(filepath.Join(root, "*.up.sql"))
	if err != nil || len(names) == 0 {
		t.Fatalf("list ClickHouse migrations: %v", err)
	}
	sort.Strings(names)
	for _, name := range names {
		if filepath.Base(name) < "005" {
			continue
		}
		migration, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range realtimeFinalizerMigrationStatements(string(migration)) {
			if err := database.execute(context.Background(), statement, true, nil); err != nil {
				t.Fatalf("apply ClickHouse migration %s: %v", filepath.Base(name), err)
			}
		}
	}
}

type spreadAccessRow struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	OccurredAt            time.Time `json:"occurred_at"`
	IngestedAt            time.Time `json:"ingested_at"`
	TenantID              string    `json:"tenant_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	Host                  string    `json:"host"`
	Path                  string    `json:"path"`
	ClientIP              string    `json:"client_ip"`
	Method                string    `json:"method"`
	Protocol              string    `json:"protocol"`
	CacheStatus           string    `json:"cache_status"`
	StatusCode            uint16    `json:"status_code"`
	RequestBytes          uint64    `json:"request_bytes"`
	ResponseBytes         uint64    `json:"response_bytes"`
	DurationUS            uint64    `json:"duration_us"`
}

// TestBandwidthSpreadClickHouseIntegration: a 1 GB download over 100 s is
// 80 Mbit/s, not 8 Gbit/s in its last second; usage older than the access
// log TTL still comes from the 400-day facts.
func TestBandwidthSpreadClickHouseIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)

	const (
		tenantID       = "10000000-0000-4000-8000-0000000000e1"
		subscriptionID = "20000000-0000-4000-8000-0000000000e1"
		siteID         = "30000000-0000-4000-8000-0000000000e1"
		nodeID         = "40000000-0000-4000-8000-0000000000e1"
	)
	periodStart := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	periodEnd := periodStart.Add(time.Hour)
	row := func(id string, end time.Time, bytes, durationUS uint64) spreadAccessRow {
		return spreadAccessRow{
			MetricVersion: 1, EventID: id, OccurredAt: end, IngestedAt: end.Add(time.Second), TenantID: tenantID,
			PackageSubscriptionID: subscriptionID, SiteID: siteID, NodeID: nodeID, Host: "spread.example.test",
			Path: "/big", ClientIP: "192.0.2.10", Method: "GET", Protocol: "HTTP/1.1", CacheStatus: "HIT",
			StatusCode: 200, RequestBytes: 100, ResponseBytes: bytes, DurationUS: durationUS,
		}
	}
	rows := []spreadAccessRow{
		// 1 GB over 100 s ending 10 minutes into the period.
		row("big", periodStart.Add(10*time.Minute), 1_000_000_000, 100_000_000),
		// A small instant response.
		row("small", periodStart.Add(30*time.Minute), 1000, 0),
		// A transfer that started before the period: only its in-period part counts.
		row("straddle", periodStart.Add(50*time.Second), 100_000_000, 100_000_000),
	}
	insertRankRows(t, database, `INSERT INTO access_events
		(metric_version,event_id,occurred_at,ingested_at,tenant_id,package_subscription_id,site_id,node_id,
		 host,path,client_ip,method,protocol,cache_status,status_code,request_bytes,response_bytes,duration_us)
		FORMAT JSONEachRow`, rows)

	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 5 * time.Second,
	}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.WithTenantResolver(sameTenant{})

	finalized, err := client.PackageBandwidthFinalized(t.Context(), PackageMetricRequest{
		TenantScopeID: tenantID, SubscriptionID: subscriptionID, Metric: "bandwidth_bps",
		PeriodStart: periodStart, PeriodEnd: periodEnd,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 1e9 B / 100 s * 8 = 80 Mbit/s; putting it all in its last second gave 8 Gbit/s.
	if finalized.Value != 80_000_000 {
		t.Fatalf("finalized peak = %d, want 80000000", finalized.Value)
	}

	// Raw access events gone (access log TTL): usage comes from the facts.
	if err := database.execute(context.Background(), "TRUNCATE TABLE access_events", true, nil); err != nil {
		t.Fatal(err)
	}
	usage, err := client.PackageUsage(t.Context(), PackageUsageRequest{
		TenantScopeID: tenantID, SubscriptionID: subscriptionID, SiteID: siteID,
		From: periodStart, To: periodEnd, Timezone: "UTC", Bucket: PackageUsageBucketHour, Limit: 24,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantTraffic := uint64(1_000_000_100 + 1100 + 100_000_100)
	if usage.TrafficBytes != wantTraffic || usage.PeakBandwidthBPS != 80_000_000 {
		t.Fatalf("usage = traffic %d peak %d, want %d 80000000", usage.TrafficBytes, usage.PeakBandwidthBPS, wantTraffic)
	}
	// 12 five-minute samples; the transfer runs 8m20s..10m so the [5m,10m)
	// sample holds all 1e9 B: 1e9*8/300 = 26666666 bit/s, and the 95th of
	// 12 samples is the top one.
	if usage.Bandwidth95thBPS != 26_666_666 {
		t.Fatalf("usage 95th = %d, want 26666666", usage.Bandwidth95thBPS)
	}
	if len(usage.Series) != 1 || usage.Series[0].TrafficBytes != wantTraffic {
		t.Fatalf("usage series = %#v", usage.Series)
	}

	search, err := client.SearchPackageUsage(t.Context(), UsageSearchRequest{
		From: periodStart, To: periodEnd, Timezone: "UTC", Bucket: PackageUsageBucketHour, ServiceType: "site",
		Domains: []string{"spread.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if search.TrafficBytes != wantTraffic || search.PeakBandwidthBPS == 0 {
		t.Fatalf("usage search traffic = %d, want %d", search.TrafficBytes, wantTraffic)
	}
	// The site traffic limit reads the same 400-day metering facts.
	traffic, err := client.SiteTraffic(t.Context(), SiteTrafficRequest{
		TenantScopeID: tenantID, SiteID: siteID, From: periodStart, To: periodEnd,
	})
	if err != nil || traffic != wantTraffic {
		t.Fatalf("site traffic = %d %v, want %d", traffic, err, wantTraffic)
	}
	if traffic, err := client.SiteTraffic(t.Context(), SiteTrafficRequest{
		TenantScopeID: tenantID, SiteID: "30000000-0000-4000-8000-0000000000e9", From: periodStart, To: periodEnd,
	}); err != nil || traffic != 0 {
		t.Fatalf("other site traffic = %d %v", traffic, err)
	}
}
