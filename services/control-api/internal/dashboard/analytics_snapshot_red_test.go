package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

func TestReadAnalyticsSharesOneExplicitIngestionSnapshot(t *testing.T) {
	query, actor, store, reader, snapshotAt := snapshotAnalyticsFixture()

	section, err := store.readAnalytics(t.Context(), nil, actor, AudienceTenant, query)
	if err != nil {
		t.Fatal(err)
	}
	if !section.Available || section.Value == nil {
		t.Fatalf("analytics section = %#v, want available", section)
	}
	if len(reader.requests) != 7 || len(reader.actors) != 7 {
		t.Fatalf("analytics calls = %d requests/%d actors, want summary + trend + 5 ranks", len(reader.requests), len(reader.actors))
	}
	wantRequest := analytics.QueryRequest{
		Audience: analytics.AudienceTenant,
		From:     query.From, To: query.To, SiteID: query.SiteID, NodeID: query.NodeID,
		Timezone: query.Timezone, SnapshotAt: snapshotAt,
	}
	for index, request := range reader.requests {
		if request != wantRequest {
			t.Fatalf("analytics call %d request = %#v, want one frozen request %#v", index, request, wantRequest)
		}
		callActor := reader.actors[index]
		if callActor.ScopeKind != "tenant" || callActor.TenantID != actor.TenantID.String() ||
			len(callActor.Permissions) != 1 || callActor.Permissions[0] != analytics.ReadPermission {
			t.Fatalf("analytics call %d actor = %#v, want tenant-scoped reader", index, callActor)
		}
	}
	for index, dimension := range []analytics.RankDimension{
		analytics.RankByDomain, analytics.RankByRegion, analytics.RankByCarrier,
	} {
		if section.Value.Top[index].Dimension != string(dimension) || section.Value.Top[index].SnapshotAt != snapshotAt {
			t.Fatalf("rank result %d = %#v, want dimension %q at %s", index, section.Value.Top[index], dimension, snapshotAt)
		}
	}
	for index, dimension := range []analytics.RankDimension{
		analytics.RankByDomain, analytics.RankByURL, analytics.RankByIP, analytics.RankByRegion, analytics.RankByCarrier,
	} {
		if section.Value.TopExtended[index].Dimension != string(dimension) || section.Value.TopExtended[index].SnapshotAt != snapshotAt {
			t.Fatalf("extended rank result %d = %#v, want dimension %q at %s", index, section.Value.TopExtended[index], dimension, snapshotAt)
		}
	}
}

func TestReadAnalyticsFailsClosedOnSnapshotOrContractMismatch(t *testing.T) {
	t.Run("rank snapshot mismatch", func(t *testing.T) {
		query, actor, store, reader, snapshotAt := snapshotAnalyticsFixture()
		page := reader.ranks[analytics.RankByRegion]
		page.SnapshotAt = snapshotAt.Add(time.Millisecond)
		reader.ranks[analytics.RankByRegion] = page

		section, err := store.readAnalytics(t.Context(), nil, actor, AudienceTenant, query)
		assertAnalyticsFailureClosed(t, section, err)
		if len(reader.requests) != 6 {
			t.Fatalf("analytics calls = %d, want stop at mismatched region rank", len(reader.requests))
		}
	})

	for _, contractErr := range []error{analytics.ErrInvalidInput, analytics.ErrInvalidResponse} {
		t.Run(contractErr.Error(), func(t *testing.T) {
			query, actor, store, reader, _ := snapshotAnalyticsFixture()
			reader.err = contractErr

			section, err := store.readAnalytics(t.Context(), nil, actor, AudienceTenant, query)
			assertAnalyticsFailureClosed(t, section, err)
			if len(reader.requests) != 1 {
				t.Fatalf("analytics calls = %d, want stop after invalid summary contract", len(reader.requests))
			}
		})
	}
}

func TestReadAnalyticsDegradesOnlyForDependencyFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		reason string
	}{
		{name: "transport", err: analytics.ErrTransport, reason: ReasonDependencyUnavailable},
		{name: "timeout", err: context.DeadlineExceeded, reason: ReasonDependencyTimeout},
	} {
		t.Run(test.name, func(t *testing.T) {
			query, actor, store, reader, _ := snapshotAnalyticsFixture()
			reader.err = test.err

			section, err := store.readAnalytics(t.Context(), nil, actor, AudienceTenant, query)
			if err != nil {
				t.Fatalf("readAnalytics() error = %v, want explicit degraded section", err)
			}
			if section.Available || section.Value != nil || section.Reason != test.reason {
				t.Fatalf("analytics section = %#v, want unavailable reason %q", section, test.reason)
			}
		})
	}
}

func snapshotAnalyticsFixture() (Query, Actor, *Store, *analyticsStub, time.Time) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	asOf := time.Date(2026, 8, 8, 1, 2, 3, 987654321, time.FixedZone("fixture", 8*60*60))
	snapshotAt := asOf.UTC().Truncate(time.Millisecond)
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	query := Query{
		Range: "custom", Timezone: "Asia/Shanghai", From: from, To: to, AsOf: asOf,
		SiteID: "018f0000-0000-7000-8000-000000000002",
		NodeID: "018f0000-0000-7000-8000-000000000003",
	}
	reader := validDashboardAnalyticsStub(from)
	for _, dimension := range []analytics.RankDimension{
		analytics.RankByDomain, analytics.RankByURL, analytics.RankByIP, analytics.RankByRegion, analytics.RankByCarrier,
	} {
		page := reader.ranks[dimension]
		page.SnapshotAt = snapshotAt
		reader.ranks[dimension] = page
	}
	finalizedThrough := to
	store := &Store{
		analytics: reader,
		finalization: &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{
			ExpectedTenants: 1, AccessTenants: 1, SecurityTenants: 1,
			Rows: 2, ReadyRows: 2, FinalizedThrough: &finalizedThrough,
		}},
	}
	return query, Actor{ScopeKind: "tenant", TenantID: tenantID}, store, reader, snapshotAt
}

func assertAnalyticsFailureClosed(t *testing.T, section Section[AnalyticsOverview], err error) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("readAnalytics() error = %v, want stable %v", err, ErrUnavailable)
	}
	if section.Available || section.Value != nil || section.Reason != "" {
		t.Fatalf("analytics section = %#v, want no degraded response on contract mismatch", section)
	}
}
