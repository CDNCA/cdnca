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

func TestPackageBandwidthFinalizedRejectsZeroEvidenceDigest(t *testing.T) {
	periodStart := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	periodEnd := periodStart.Add(time.Hour)
	observedAt := periodEnd.Add(-500 * time.Millisecond)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"value":16384,"observed_at_ms":`+
			strconv.FormatInt(observedAt.UnixMilli(), 10)+`,"finalized_through_ms":`+
			strconv.FormatInt(periodEnd.UnixMilli(), 10)+`,"source_evidence_digest":"`+
			strings.Repeat("0", 64)+`"}`+"\n")
	}))
	defer server.Close()

	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	_, err := client.PackageBandwidthFinalized(context.Background(), PackageMetricRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: "bandwidth_bps",
		PeriodStart: periodStart, PeriodEnd: periodEnd,
	})
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("zero evidence digest error = %v, want %v", err, ErrInvalidResponse)
	}
}

func TestPackageBandwidthFinalizedRejectsInvalidEvidenceAndTimeBoundaries(t *testing.T) {
	periodStart := time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC)
	periodEnd := periodStart.Add(time.Hour)
	evidence := sha256.Sum256([]byte("finalized evidence"))
	validDigest := hex.EncodeToString(evidence[:])
	for _, test := range []struct {
		name       string
		digest     string
		observedAt time.Time
		finalized  time.Time
	}{
		{name: "uppercase digest", digest: strings.ToUpper(validDigest), observedAt: periodEnd.Add(-time.Millisecond), finalized: periodEnd},
		{name: "malformed digest", digest: strings.Repeat("g", 64), observedAt: periodEnd.Add(-time.Millisecond), finalized: periodEnd},
		{name: "observed before period", digest: validDigest, observedAt: periodStart.Add(-time.Millisecond), finalized: periodEnd},
		{name: "observed after finalized", digest: validDigest, observedAt: periodEnd.Add(time.Millisecond), finalized: periodEnd},
		{name: "finalized before request end", digest: validDigest, observedAt: periodEnd.Add(-time.Millisecond), finalized: periodEnd.Add(-time.Millisecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, `{"value":16384,"observed_at_ms":`+
					strconv.FormatInt(test.observedAt.UnixMilli(), 10)+`,"finalized_through_ms":`+
					strconv.FormatInt(test.finalized.UnixMilli(), 10)+`,"source_evidence_digest":"`+
					test.digest+`"}`+"\n")
			}))
			defer server.Close()
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			_, err := client.PackageBandwidthFinalized(context.Background(), PackageMetricRequest{
				TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, Metric: "bandwidth_bps",
				PeriodStart: periodStart, PeriodEnd: periodEnd,
			})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("invalid evidence/time error = %v, want %v", err, ErrInvalidResponse)
			}
		})
	}
}
