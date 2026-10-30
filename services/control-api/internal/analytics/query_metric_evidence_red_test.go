package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPackageMetricRejectsInvalidEvidenceAndTimes(t *testing.T) {
	periodStart := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	periodEnd := periodStart.Add(time.Hour)
	validDigest := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		observedAt time.Time
		finalized  time.Time
		digest     string
	}{
		{name: "all-zero digest", observedAt: periodStart, finalized: periodEnd, digest: strings.Repeat("0", 64)},
		{name: "invalid hex digest", observedAt: periodStart, finalized: periodEnd, digest: strings.Repeat("z", 64)},
		{name: "observed before period", observedAt: periodStart.Add(-time.Millisecond), finalized: periodEnd, digest: validDigest},
		{name: "finalized before period end", observedAt: periodStart, finalized: periodEnd.Add(-time.Millisecond), digest: validDigest},
		{name: "observed after finalized", observedAt: periodEnd.Add(time.Millisecond), finalized: periodEnd, digest: validDigest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, `{"value":1,"observed_at_ms":`+
					formatUnixMilli(test.observedAt)+`,"finalized_through_ms":`+
					formatUnixMilli(test.finalized)+`,"source_evidence_digest":"`+test.digest+`"}`+"\n")
			}))
			t.Cleanup(server.Close)
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			result, err := client.PackageMetric(context.Background(), PackageMetricRequest{
				TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: "traffic_bytes",
				PeriodStart: periodStart, PeriodEnd: periodEnd,
			})
			if !errors.Is(err, ErrInvalidResponse) || result != (PackageMetricResult{}) {
				t.Fatalf("PackageMetric() = %#v, %v; want zero result and ErrInvalidResponse", result, err)
			}
		})
	}
}
