package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type analyticsFinalizationStub struct {
	snapshot analyticsFinalizationSnapshot
	err      error
	calls    []analyticsFinalizationCall
}

type analyticsFinalizationCall struct {
	audience Audience
	tenantID uuid.UUID
}

func (stub *analyticsFinalizationStub) Read(
	_ context.Context,
	_ pgx.Tx,
	audience Audience,
	tenantID uuid.UUID,
) (analyticsFinalizationSnapshot, error) {
	stub.calls = append(stub.calls, analyticsFinalizationCall{audience: audience, tenantID: tenantID})
	return stub.snapshot, stub.err
}

// 107 水位全仓无写入方（73 整表 0 行），概览不能再被它拦住；
// 水位缺失、依赖未就绪或落后都照常直查 ClickHouse 展示，只是带上结算提示。
func TestReadAnalyticsShowsClickHouseDataWhateverTheWatermarkState(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	ready := analyticsFinalizationSnapshot{
		ExpectedTenants:  1,
		AccessTenants:    1,
		SecurityTenants:  1,
		Rows:             2,
		ReadyRows:        2,
		FinalizedThrough: &to,
	}
	tests := []struct {
		name     string
		snapshot analyticsFinalizationSnapshot
	}{
		{name: "no watermark rows (production 107 table is empty)", snapshot: analyticsFinalizationSnapshot{ExpectedTenants: 1}},
		{name: "missing access kind", snapshot: func() analyticsFinalizationSnapshot {
			value := ready
			value.AccessTenants = 0
			value.Rows = 1
			return value
		}()},
		{name: "dependency not ready", snapshot: func() analyticsFinalizationSnapshot {
			value := ready
			value.ReadyRows = 1
			return value
		}()},
		{name: "window not finalized", snapshot: func() analyticsFinalizationSnapshot {
			value := ready
			unfinalized := to.Add(-time.Nanosecond)
			value.FinalizedThrough = &unfinalized
			return value
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			analyticsReader := validDashboardAnalyticsStub(from)
			finalization := &analyticsFinalizationStub{snapshot: test.snapshot}
			store := &Store{analytics: analyticsReader, finalization: finalization}
			section, err := store.readAnalytics(t.Context(), nil, Actor{
				ScopeKind: "tenant", TenantID: tenantID,
			}, AudienceTenant, Query{From: from, To: to})
			if err != nil {
				t.Fatal(err)
			}
			if !section.Available || section.Value == nil || section.Value.Summary.RequestCount != 7 ||
				len(section.Value.Trend) != 1 || len(section.Value.TopExtended) != 5 {
				t.Fatalf("analytics section = %#v, want ClickHouse data shown", section)
			}
			if len(analyticsReader.requests) != 7 {
				t.Fatalf("ClickHouse calls = %d, want 7", len(analyticsReader.requests))
			}
			if len(finalization.calls) != 1 || finalization.calls[0].audience != AudienceTenant ||
				finalization.calls[0].tenantID != tenantID {
				t.Fatalf("finalization calls = %#v", finalization.calls)
			}
		})
	}
}

func TestReadAnalyticsWatermarkReadTimeoutStaysExplicit(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	store := &Store{analytics: validDashboardAnalyticsStub(from),
		finalization: &analyticsFinalizationStub{err: context.DeadlineExceeded}}
	section, err := store.readAnalytics(t.Context(), nil, Actor{ScopeKind: "tenant", TenantID: uuid.New()},
		AudienceTenant, Query{From: from, To: from.Add(time.Hour)})
	if err != nil || section.Available || section.Reason != ReasonDependencyTimeout {
		t.Fatalf("section = %#v, %v", section, err)
	}
}

func TestSettlingMinutesHintsOnlyWhenRecentDataIsUnsettled(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	asOf := from.Add(10 * time.Hour)
	at := func(d time.Duration) *time.Time { value := from.Add(d); return &value }
	full := func(through *time.Time) analyticsFinalizationSnapshot {
		return analyticsFinalizationSnapshot{ExpectedTenants: 1, AccessTenants: 1, SecurityTenants: 1, Rows: 2, ReadyRows: 2, FinalizedThrough: through}
	}
	for _, test := range []struct {
		name     string
		snapshot analyticsFinalizationSnapshot
		query    Query
		want     uint32
	}{
		{name: "watermark lags now by 7m30s", snapshot: full(at(10*time.Hour - 450*time.Second)), query: Query{From: from, To: to, AsOf: asOf}, want: 8},
		{name: "watermark covers now", snapshot: full(at(10 * time.Hour)), query: Query{From: from, To: to, AsOf: asOf}},
		{name: "closed window fully settled", snapshot: full(&to), query: Query{From: from, To: to, AsOf: to.Add(time.Hour)}},
		{name: "closed window lags its end", snapshot: full(at(23 * time.Hour)), query: Query{From: from, To: to, AsOf: to.Add(time.Hour)}, want: 60},
		{name: "no watermark, window open: grace", snapshot: analyticsFinalizationSnapshot{ExpectedTenants: 1}, query: Query{From: from, To: to, AsOf: asOf}, want: 2},
		{name: "no watermark, window closed", snapshot: analyticsFinalizationSnapshot{ExpectedTenants: 1}, query: Query{From: from, To: to, AsOf: to}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := test.snapshot.settlingMinutes(test.query)
			if test.want == 0 && got != nil || test.want != 0 && (got == nil || *got != test.want) {
				t.Fatalf("settlingMinutes = %v, want %d", got, test.want)
			}
		})
	}
}

func TestReadAnalyticsUsesExactAudienceScopeAfterDurableFinalization(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	for _, test := range []struct {
		name     string
		audience Audience
		actor    Actor
		tenantID uuid.UUID
	}{
		{name: "tenant", audience: AudienceTenant, actor: Actor{ScopeKind: "tenant", TenantID: tenantID}, tenantID: tenantID},
		{name: "platform", audience: AudienceAdmin, actor: Actor{ScopeKind: "platform"}, tenantID: uuid.Nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyticsReader := validDashboardAnalyticsStub(from)
			finalization := &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{
				ExpectedTenants: 1, AccessTenants: 1, SecurityTenants: 1,
				Rows: 2, ReadyRows: 2, FinalizedThrough: &to,
			}}
			store := &Store{analytics: analyticsReader, finalization: finalization}
			section, err := store.readAnalytics(t.Context(), nil, test.actor, test.audience, Query{From: from, To: to})
			if err != nil {
				t.Fatal(err)
			}
			if !section.Available || section.Value == nil {
				t.Fatalf("analytics section = %#v", section)
			}
			if len(section.Value.TopExtended) != 5 {
				t.Fatalf("extended ranks = %d, want 5", len(section.Value.TopExtended))
			}
			wantCalls := 7
			if len(analyticsReader.requests) != wantCalls {
				t.Fatalf("ClickHouse calls = %d, want %d", len(analyticsReader.requests), wantCalls)
			}
			if len(finalization.calls) != 1 || finalization.calls[0].audience != test.audience ||
				finalization.calls[0].tenantID != test.tenantID {
				t.Fatalf("finalization calls = %#v", finalization.calls)
			}
		})
	}
}

func validDashboardAnalyticsStub(hour time.Time) *analyticsStub {
	return &analyticsStub{
		summary: analytics.Summary{
			MetricVersion: analytics.MetricVersion, RequestCount: 7, ResponseBytes: 11,
			TotalBytes: 11, SecurityEvents: 3,
		},
		trend: []analytics.TrendPoint{{
			Hour: hour, MetricVersion: analytics.MetricVersion, RequestCount: 7,
			ResponseBytes: 11, TotalBytes: 11, SecurityEvents: 3,
		}},
		ranks: map[analytics.RankDimension]analytics.RankPage{
			analytics.RankByDomain:  {Items: []analytics.RankItem{{Key: "example.test", RequestCount: 7, ResponseBytes: 11}}},
			analytics.RankByURL:     {Items: []analytics.RankItem{{Key: "/asset.js", RequestCount: 7, ResponseBytes: 11}}},
			analytics.RankByIP:      {Items: []analytics.RankItem{{Key: "192.0.2.1", RequestCount: 7, ResponseBytes: 11}}},
			analytics.RankByRegion:  {Items: []analytics.RankItem{{Key: "unassigned", RequestCount: 7, ResponseBytes: 11}}},
			analytics.RankByCarrier: {Items: []analytics.RankItem{}},
		},
	}
}

var _ analyticsFinalizationReader = (*analyticsFinalizationStub)(nil)

func TestAnalyticsTotalsConsistentFailsClosedForDriftAndOverflow(t *testing.T) {
	from := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	summary := analytics.Summary{
		MetricVersion: analytics.MetricVersion, RequestCount: 3, ResponseBytes: 7,
		TotalBytes: 7, Status2xx: 3,
	}
	trend := []analytics.TrendPoint{
		{Hour: from, MetricVersion: analytics.MetricVersion, RequestCount: 1, ResponseBytes: 2, TotalBytes: 2, Status2xx: 1},
		{Hour: from.Add(time.Hour), MetricVersion: analytics.MetricVersion, RequestCount: 2, ResponseBytes: 5, TotalBytes: 5, Status2xx: 2},
	}
	if !analyticsTotalsConsistent(summary, trend) {
		t.Fatal("matching summary and trend were rejected")
	}
	trend[1].ResponseBytes++
	if analyticsTotalsConsistent(summary, trend) {
		t.Fatal("summary/trend drift was accepted")
	}
	if addUint64(new(uint64), ^uint64(0)) == false {
		t.Fatal("maximum uint64 should fit in an empty accumulator")
	}
	total := ^uint64(0)
	if addUint64(&total, 1) {
		t.Fatal("uint64 overflow was accepted")
	}
}

func TestNewFilteredQueryRequiresCanonicalNonZeroDrilldownIDs(t *testing.T) {
	now := time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)
	siteID := "018f0000-0000-7000-8000-000000000001"
	nodeID := "018f0000-0000-7000-8000-000000000002"
	query, err := NewFilteredQuery(AudienceTenant, "today", "UTC", siteID, nodeID, now)
	if err != nil || query.SiteID != siteID || query.NodeID != nodeID {
		t.Fatalf("filtered query = %#v, %v", query, err)
	}
	for _, invalid := range []string{"00000000-0000-0000-0000-000000000000", "018F0000-0000-7000-8000-000000000001", "not-a-uuid"} {
		if _, err := NewFilteredQuery(AudienceTenant, "today", "UTC", invalid, "", now); err == nil {
			t.Fatalf("invalid site id %q was accepted", invalid)
		}
	}
}
