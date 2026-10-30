package analytics

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type staticClientGeo map[string]ClientGeo

func (geo staticClientGeo) LookupClientGeo(_ context.Context, addresses []string) map[string]ClientGeo {
	result := map[string]ClientGeo{}
	for _, address := range addresses {
		if value, ok := geo[address]; ok {
			result[address] = value
		}
	}
	return result
}

// ge-analytics: cache hit ratio, unique client IPs and the province/browser/
// OS/region/carrier/domain rankings come from the history facts (they survive
// the access log TTL), and the ingest writer fills country/province/carrier
// from the IP library.
func TestReportDimensionsClickHouseIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 5 * time.Second,
	}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenantID = "10000000-0000-4000-8000-0000000000f1"
		siteID   = "30000000-0000-4000-8000-0000000000f1"
		nodeID   = "40000000-0000-4000-8000-0000000000f1"
	)
	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := from.Add(time.Hour)
	event := func(id, ip, cache, browser, os string) AccessEvent {
		return AccessEvent{
			MetricVersion: 1, EventID: id, OccurredAt: from.Add(10 * time.Minute), TenantID: tenantID, SiteID: siteID,
			NodeID: nodeID, Host: "report.example.test", Path: "/", ClientIP: ip, Method: "GET", Protocol: "HTTP/1.1",
			CacheStatus: cache, StatusCode: 200, RequestBytes: 10, ResponseBytes: 90, InstallationID: "report-install",
			ClientBrowser: browser, ClientOS: os,
		}
	}
	writer := GeoEnrichingWriter{Writer: client, Lookup: staticClientGeo{
		"192.0.2.1": {Country: "CN", Province: "440000", Carrier: "carrier:cn-telecom"},
		"192.0.2.2": {Country: "CN", Province: "110000", Carrier: "carrier:cn-unicom"},
	}}
	if err := writer.WriteAccessEvents(t.Context(), "report-batch-1", []AccessEvent{
		event("r1", "192.0.2.1", "HIT", "chrome", "windows"),
		event("r2", "192.0.2.1", "MISS", "chrome", "android"),
		event("r3", "192.0.2.2", "HIT", "safari", "ios"),
		event("r4", "198.51.100.9", "BYPASS", "", ""),
	}); err != nil {
		t.Fatal(err)
	}
	// The access log is gone (access_logs_days); the reports are not.
	if err := database.execute(context.Background(), "TRUNCATE TABLE access_events", true, nil); err != nil {
		t.Fatal(err)
	}
	scope, err := TenantScope(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: from, To: to}
	summary, err := client.Summary(t.Context(), scope, filter)
	if err != nil {
		t.Fatal(err)
	}
	if summary.RequestCount != 4 || summary.CacheHitRequests != 2 || summary.CacheHitBytes != 200 || summary.UniqueClientIPs != 3 {
		t.Fatalf("summary = %#v", summary)
	}
	for dimension, want := range map[RankDimension][]string{
		RankByProvince: {"440000", "110000", "__unknown__"},
		RankByBrowser:  {"chrome", "__unknown__", "safari"},
		RankByOS:       {"__unknown__", "android", "ios", "windows"},
		RankByRegion:   {"CN", "__unknown__"},
		RankByCarrier:  {"carrier:cn-telecom", "__unknown__", "carrier:cn-unicom"},
		RankByDomain:   {"report.example.test"},
		RankByIP:       {"::ffff:192.0.2.1", "::ffff:192.0.2.2", "::ffff:198.51.100.9"},
	} {
		page, rankErr := client.Rank(t.Context(), scope, filter, dimension, 10, "")
		if rankErr != nil {
			t.Fatalf("%s rank: %v", dimension, rankErr)
		}
		keys := make([]string, len(page.Items))
		for index, item := range page.Items {
			keys[index] = item.Key
		}
		if len(keys) != len(want) {
			t.Fatalf("%s rank keys = %q, want %q", dimension, keys, want)
		}
		for index := range want {
			if keys[index] != want[index] {
				t.Fatalf("%s rank keys = %q, want %q", dimension, keys, want)
			}
		}
	}
}
