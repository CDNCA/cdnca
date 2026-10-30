package dashboard

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

func TestReadAnalyticsShowsEmptyDatasetWithoutWatermarks(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	reader := emptyDashboardAnalyticsStub(to)
	store := &Store{
		analytics:    reader,
		finalization: &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{ExpectedTenants: 1}},
	}

	section, err := store.readAnalytics(t.Context(), nil, Actor{
		ScopeKind: "tenant", TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001"),
	}, AudienceTenant, Query{From: from, To: to, AsOf: to})
	if err != nil {
		t.Fatal(err)
	}
	if !section.Available || section.Value == nil || section.Value.Summary.RequestCount != 0 ||
		len(section.Value.Trend) != 0 || len(section.Value.TopExtended) != 5 || section.Value.SettlingMinutes != nil {
		t.Fatalf("empty analytics = %#v, want available empty overview", section)
	}
}

func TestReadAnalyticsKeepsDependencyFailureForKnownEmptyDataset(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	reader := emptyDashboardAnalyticsStub(to)
	reader.err = errors.New("clickhouse unavailable")
	store := &Store{
		analytics: reader,
		finalization: &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{ExpectedTenants: 1}},
	}

	section, err := store.readAnalytics(t.Context(), nil, Actor{
		ScopeKind: "tenant", TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001"),
	}, AudienceTenant, Query{From: from, To: to, AsOf: to})
	if err != nil {
		t.Fatal(err)
	}
	if section.Available || section.Value != nil || section.Reason != ReasonDependencyUnavailable {
		t.Fatalf("dependency failure = %#v, want dependency unavailable", section)
	}
}

func emptyDashboardAnalyticsStub(snapshot time.Time) *analyticsStub {
	return &analyticsStub{
		summary: analytics.Summary{MetricVersion: analytics.MetricVersion},
		ranks: map[analytics.RankDimension]analytics.RankPage{
			analytics.RankByDomain:  {SnapshotAt: snapshot, Items: []analytics.RankItem{}},
			analytics.RankByURL:     {SnapshotAt: snapshot, Items: []analytics.RankItem{}},
			analytics.RankByIP:      {SnapshotAt: snapshot, Items: []analytics.RankItem{}},
			analytics.RankByRegion:  {SnapshotAt: snapshot, Items: []analytics.RankItem{}},
			analytics.RankByCarrier: {SnapshotAt: snapshot, Items: []analytics.RankItem{}},
		},
	}
}
