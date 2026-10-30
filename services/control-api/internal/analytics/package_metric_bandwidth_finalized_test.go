package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testPackageSubscriptionID = "40000000-0000-4000-8000-000000000001"

func TestPackageBandwidthFinalizedUsesSpreadSecondPeak(t *testing.T) {
	periodStart := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	periodEnd := periodStart.Add(time.Hour)
	observedAt := periodEnd.Add(-500 * time.Millisecond)
	digest := sha256.Sum256([]byte("finalized one-second bandwidth evidence"))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		query := string(body)
		for _, required := range []string{
			"duration_us", "toInt64(1000) AS unit_ms", "max(v) AS peak_milli_bytes", "'peak_1s_spread_v1'",
			"package_metric_access_facts_v1 FINAL", "{metric:String}",
		} {
			if !strings.Contains(query, required) {
				t.Errorf("finalized bandwidth query missing %q: %s", required, query)
			}
		}
		for _, periodAverage := range []string{"dateDiff('millisecond'", "/ 3600.0", "/3600.0"} {
			if strings.Contains(query, periodAverage) {
				t.Errorf("finalized bandwidth query contains period average %q", periodAverage)
			}
		}
		parameters := request.URL.Query()
		wantParameters := map[string]string{
			"param_tenant_id":       testTenantID,
			"param_subscription_id": testPackageSubscriptionID,
			"param_metric":          "bandwidth_bps",
			"param_period_start":    clickHouseTime(periodStart),
			"param_period_end":      clickHouseTime(periodEnd),
		}
		for key, want := range wantParameters {
			if got := parameters.Get(key); got != want {
				t.Errorf("query parameter %s = %q, want %q", key, got, want)
			}
		}
		_, _ = io.WriteString(writer, `{"value":16384,"observed_at_ms":`+
			strconv.FormatInt(observedAt.UnixMilli(), 10)+`,"finalized_through_ms":`+
			strconv.FormatInt(periodEnd.UnixMilli(), 10)+`,"source_evidence_digest":"`+hex.EncodeToString(digest[:])+`"}`+"\n")
	}))
	defer server.Close()

	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	result, err := client.PackageBandwidthFinalized(context.Background(), PackageMetricRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: "bandwidth_bps",
		PeriodStart: periodStart, PeriodEnd: periodEnd,
	})
	if err != nil {
		t.Fatalf("PackageBandwidthFinalized() error = %v", err)
	}
	if result.Value != 16384 || !result.ObservedAt.Equal(observedAt) ||
		!result.FinalizedThrough.Equal(periodEnd) || result.SourceEvidenceDigest != digest {
		t.Fatalf("PackageBandwidthFinalized() = %#v", result)
	}
}

func TestPackageBandwidthFinalizedFailsClosedAtContractBoundaries(t *testing.T) {
	periodStart := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	periodEnd := periodStart.Add(time.Hour)
	client := mustClient(t, Config{Endpoint: "https://localhost", Database: "analytics_test"}, &http.Client{})
	valid := PackageMetricRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: "bandwidth_bps",
		PeriodStart: periodStart, PeriodEnd: periodEnd,
	}
	for name, mutate := range map[string]func(*PackageMetricRequest){
		"nil tenant":       func(request *PackageMetricRequest) { request.TenantScopeID = nilUUIDValue },
		"bad subscription": func(request *PackageMetricRequest) { request.SubscriptionID = "not-a-uuid" },
		"wrong metric":     func(request *PackageMetricRequest) { request.Metric = "traffic_bytes" },
		"non UTC start": func(request *PackageMetricRequest) {
			request.PeriodStart = request.PeriodStart.In(time.FixedZone("offset", 3600))
		},
		"submillisecond":  func(request *PackageMetricRequest) { request.PeriodEnd = request.PeriodEnd.Add(time.Nanosecond) },
		"reversed period": func(request *PackageMetricRequest) { request.PeriodStart = request.PeriodEnd },
	} {
		t.Run(name, func(t *testing.T) {
			request := valid
			mutate(&request)
			if _, err := client.PackageBandwidthFinalized(context.Background(), request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("PackageBandwidthFinalized() error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
	if _, err := client.PackageBandwidthFinalized(nil, valid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("x", 257))
	}))
	defer server.Close()
	bounded := mustClient(t, Config{
		Endpoint: server.URL, Database: "analytics_test", MaxResponseBytes: 256,
	}, server.Client())
	if _, err := bounded.PackageBandwidthFinalized(context.Background(), valid); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response error = %v, want %v", err, ErrResponseTooLarge)
	}
}
