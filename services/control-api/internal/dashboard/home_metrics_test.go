package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

type homeMetricsReader struct {
	parallelAnalyticsReader
	peak     analytics.PeakBandwidth
	blocked  uint64
	extraErr error
}

func (reader *homeMetricsReader) PeakBandwidth(context.Context, analytics.Actor, analytics.QueryRequest) (analytics.PeakBandwidth, error) {
	return reader.peak, reader.extraErr
}

func (reader *homeMetricsReader) BlockedIPCount(context.Context, analytics.Actor, analytics.QueryRequest) (uint64, error) {
	return reader.blocked, reader.extraErr
}

// FX36: the tenant home overview carries the 5-minute peak and the blocked-IP
// count (firewall + CC auto-bans); a failure of these extras leaves the rest
// of the overview available and simply omits them.
func TestAnalyticsOverviewCarriesHomeMetrics(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	snapshot := to.Add(time.Second)
	for _, test := range []struct {
		name     string
		extraErr error
		want     []string
		absent   []string
	}{
		{name: "available", want: []string{`"peak_bandwidth_bps":"8000"`, `"blocked_ip_count":"4"`}},
		{name: "extras unavailable", extraErr: analytics.ErrTransport, absent: []string{"peak_bandwidth_bps", "blocked_ip_count"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := &homeMetricsReader{
				parallelAnalyticsReader: parallelAnalyticsReader{snapshot: snapshot, errors: map[string]error{}},
				peak:                    analytics.PeakBandwidth{PeakBandwidthBPS: 8000, BucketSeconds: 300}, blocked: 4,
				extraErr: test.extraErr,
			}
			finalizedThrough := to
			store := &Store{analytics: reader, parallelAnalytics: true,
				finalization: &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{
					ExpectedTenants: 1, AccessTenants: 1, SecurityTenants: 1,
					Rows: 2, ReadyRows: 2, FinalizedThrough: &finalizedThrough,
				}}}
			actor := Actor{ScopeKind: "tenant", TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001")}
			section, err := store.readAnalytics(context.Background(), nil, actor, AudienceTenant,
				Query{Range: "custom", Timezone: "UTC", From: from, To: to, AsOf: snapshot})
			if err != nil || !section.Available || section.Value == nil {
				t.Fatalf("readAnalytics() = %#v, %v", section, err)
			}
			encoded, err := json.Marshal(section.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(string(encoded), want) {
					t.Errorf("overview missing %s: %s", want, encoded)
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(string(encoded), absent) {
					t.Errorf("overview should omit %s: %s", absent, encoded)
				}
			}
		})
	}
	if !errors.Is(analytics.ErrTransport, analytics.ErrTransport) {
		t.Fatal("unreachable")
	}
}
