package analytics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type usageSearchFixtureTransport struct{ t *testing.T }

func (transport usageSearchFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err == nil && response.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
		_ = response.Body.Close()
		transport.t.Logf("isolated ClickHouse error: %s", body)
		response.Body = io.NopCloser(bytes.NewReader(body))
	}
	return response, err
}

func TestUsageSearchClickHouseFiltersAndAggregation(t *testing.T) {
	endpoint := os.Getenv("USAGE_SEARCH_TEST_CH_URL")
	if endpoint == "" {
		t.Skip("USAGE_SEARCH_TEST_CH_URL required for isolated ClickHouse integration")
	}
	database := fmt.Sprintf("usage_search_test_%d", time.Now().UnixNano())
	exec := func(query string) {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, endpoint+"/?database=default", strings.NewReader(query))
		if err != nil {
			t.Fatal(err)
		}
		request.SetBasicAuth("usage_test", "usage_test_fixture")
		r, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("ClickHouse status %d: %s", r.StatusCode, body)
		}
	}
	exec("CREATE DATABASE " + database)
	t.Cleanup(func() { exec("DROP DATABASE " + database + " SYNC") })
	// Usage search reads the 400-day metering facts (CH 019), not raw access_events.
	exec("CREATE TABLE " + database + ".access_metering_facts_v1 (metric_version UInt16, tenant_id UUID, package_subscription_id UUID, site_id UUID, event_id String, occurred_at DateTime64(3,'UTC'), host String, request_bytes UInt64, response_bytes UInt64, duration_us UInt64, blocked Bool, ingested_at DateTime64(3,'UTC')) ENGINE=ReplacingMergeTree(ingested_at) ORDER BY (tenant_id,event_id)")
	exec("CREATE TABLE " + database + ".l4_session_facts_v1 (tenant_id UUID,stream_id UUID,event_id String,finalized_at DateTime64(3,'UTC'),listen_port UInt16,bytes_up UInt64,bytes_down UInt64,source_watermark UInt64) ENGINE=ReplacingMergeTree(source_watermark) ORDER BY (tenant_id,event_id)")
	tenantA, tenantB, subA, subB, streamA, streamB := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"
	exec(fmt.Sprintf("INSERT INTO %s.access_metering_facts_v1 (metric_version,event_id,tenant_id,package_subscription_id,occurred_at,host,request_bytes,response_bytes,ingested_at) VALUES (1,'a','%s','%s','2026-09-01 00:10:00','a.example.test',100,3600,'2026-09-01 01:00:00'),(1,'b','%s','%s','2026-09-01 00:10:00','b.example.test',200,7200,'2026-09-01 01:00:00'),(1,'a','%s','%s','2026-09-01 00:10:00','a.example.test',100,3600,'2026-09-01 01:01:00')", database, tenantA, subA, tenantB, subB, tenantA, subA))
	exec(fmt.Sprintf("INSERT INTO %s.l4_session_facts_v1 VALUES ('%s','%s','c','2026-09-01 00:20:00',443,300,10800,1),('%s','%s','d','2026-09-01 00:20:00',8443,400,14400,1)", database, tenantA, streamA, tenantB, streamB))
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	client := mustClient(t, Config{Endpoint: parsed.String(), Database: database, Username: "usage_test", Password: "usage_test_fixture"}, &http.Client{Timeout: 5 * time.Second, Transport: usageSearchFixtureTransport{t}})
	base := UsageSearchRequest{From: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 1, 1, 0, 0, 0, time.UTC), Timezone: "Asia/Shanghai", Bucket: PackageUsageBucketHour, ServiceType: "all"}
	for _, tc := range []struct {
		name       string
		modify     func(*UsageSearchRequest)
		bytes, bps uint64
	}{
		{"all and dedup", func(*UsageSearchRequest) {}, 37000, 80},
		{"site", func(q *UsageSearchRequest) { q.ServiceType = "site" }, 11100, 24},
		{"stream", func(q *UsageSearchRequest) { q.ServiceType = "stream" }, 25900, 56},
		{"domain", func(q *UsageSearchRequest) { q.Domains = []string{"a.example.test"} }, 3700, 8},
		{"port", func(q *UsageSearchRequest) { q.ListenPorts = []uint16{443} }, 11100, 24},
		{"user", func(q *UsageSearchRequest) {
			q.Restricted = true
			q.Subscriptions = []UsageTarget{{tenantA, subA}}
			q.Streams = []UsageTarget{{tenantA, streamA}}
		}, 14800, 32},
		{"empty target", func(q *UsageSearchRequest) { q.Restricted = true }, 0, 0},
		{"tenant scope", func(q *UsageSearchRequest) { q.TenantID = tenantA }, 14800, 32},
		{"tenant pairs", func(q *UsageSearchRequest) {
			q.Restricted = true
			q.Subscriptions = []UsageTarget{{tenantB, subA}}
			q.Streams = []UsageTarget{{tenantB, streamA}}
		}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := base
			tc.modify(&q)
			got, err := client.SearchPackageUsage(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			if got.TrafficBytes != tc.bytes || got.PeakBandwidthBPS != tc.bps || got.Bandwidth95thBPS != tc.bps {
				t.Fatalf("got=%#v", got)
			}
			if tc.bytes > 0 && (len(got.Series) != 1 || got.Series[0].BandwidthBPS != tc.bps) {
				t.Fatalf("series=%#v", got.Series)
			}
		})
	}

	exec(fmt.Sprintf(`INSERT INTO %s.access_metering_facts_v1 (metric_version,event_id,tenant_id,package_subscription_id,occurred_at,host,request_bytes,response_bytes,ingested_at)
 SELECT 1,concat('extra-',toString(number)),'%s','%s',
        toDateTime('2026-09-01 00:00:00','UTC')+toIntervalHour(number+1),
        'a.example.test',100,3600,toDateTime('2026-09-02 00:00:00','UTC') FROM numbers(20)`, database, tenantA, subA))
	base.To = base.From.Add(24 * time.Hour)
	result, err := client.SearchPackageUsage(context.Background(), base)
	if err != nil || len(result.Series) != 21 || result.TrafficBytes != 111000 || result.PeakBandwidthBPS != 80 || result.Bandwidth95thBPS != 8 {
		t.Fatalf("combined percentile must exclude the single spike: result=%#v err=%v", result, err)
	}
}
