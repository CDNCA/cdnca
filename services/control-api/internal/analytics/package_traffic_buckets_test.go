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

func TestPackageTrafficBucketsBindsParametersAndValidates(t *testing.T) {
	t.Parallel()
	var body string
	var subscription string
	response := `{"bucket_start":1760500800,"bytes_out":1000,"requests":3}` + "\n" + `{"bucket_start":1760501100,"bytes_out":5,"requests":1}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body, subscription = string(raw), r.URL.Query().Get("param_subscription_id")
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	start := time.Unix(1760500800, 0).UTC()
	sub := "33333333-3333-4333-8333-333333333333"
	buckets, err := client.PackageTrafficBuckets(context.Background(), testTenantID, sub, start, start.Add(time.Hour))
	if err != nil || len(buckets) != 2 || buckets[0].BytesOut != 1000 || buckets[1].Start != start.Add(5*time.Minute) {
		t.Fatalf("buckets = %+v, %v", buckets, err)
	}
	if subscription != sub || strings.Contains(body, sub) || !strings.Contains(body, "INTERVAL 5 MINUTE") {
		t.Fatalf("query must bind, not interpolate: %s", body)
	}
	for name, call := range map[string]func() error{
		"unaligned": func() error {
			_, err := client.PackageTrafficBuckets(context.Background(), testTenantID, sub, start.Add(time.Minute), start.Add(time.Hour))
			return err
		},
		"too long": func() error {
			_, err := client.PackageTrafficBuckets(context.Background(), testTenantID, sub, start, start.Add(8*24*time.Hour))
			return err
		},
		"bad id": func() error {
			_, err := client.PackageTrafficBuckets(context.Background(), testTenantID, "x", start, start.Add(time.Hour))
			return err
		},
	} {
		if call() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	response = `{"bucket_start":1760500860,"bytes_out":1,"requests":1}`
	if _, err := client.PackageTrafficBuckets(context.Background(), testTenantID, sub, start, start.Add(time.Hour)); err == nil {
		t.Fatal("unaligned bucket from the store accepted")
	}
}

func TestSubscriptionPeakBucketsSumsNodesPerMinute(t *testing.T) {
	t.Parallel()
	var body, subscription, from string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body, subscription, from = string(raw), r.URL.Query().Get("param_subscription_id"), r.URL.Query().Get("param_period_start")
		_, _ = io.WriteString(w, `{"bucket_start":1760500800,"peak_bps":80,"max_concurrent":7,"max_requests":6,"max_qps":50,"max_new_cps":4}`)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	start := time.Unix(1760500800, 0).UTC()
	sub := "33333333-3333-4333-8333-333333333333"
	buckets, err := client.SubscriptionPeakBuckets(context.Background(), sub, start, start.Add(time.Hour))
	if err != nil || len(buckets) != 1 || buckets[0].MaxQPS != 50 || buckets[0].MaxConcurrent != 7 || buckets[0].PeakBPS != 80 ||
		buckets[0].MaxRequests != 6 || buckets[0].MaxNewCPS != 4 || !buckets[0].Start.Equal(start) {
		t.Fatalf("buckets = %+v, %v", buckets, err)
	}
	if subscription != sub || strings.Contains(body, sub) || from != "2025-10-15 04:00:00" ||
		!strings.Contains(body, "subscription_minutes_v1 FINAL") || !strings.Contains(body, "GROUP BY minute") {
		t.Fatalf("query must bind and sum nodes per minute: %s %s", from, body)
	}
	if _, err := client.SubscriptionPeakBuckets(context.Background(), sub, start.Add(time.Minute), start.Add(time.Hour)); err == nil {
		t.Fatal("unaligned accepted")
	}
}
