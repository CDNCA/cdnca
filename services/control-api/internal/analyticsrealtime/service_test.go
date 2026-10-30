package analyticsrealtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	testTenant = "018f0000-0000-7000-8000-000000000001"
	testSite   = "018f0000-0000-7000-8000-000000000002"
	testNode   = "018f0000-0000-7000-8000-000000000003"
)

type sourceFixture struct {
	snapshot Snapshot
	filters  []Filter
	quality  error
}

func (source *sourceFixture) ResolveSnapshot(_ context.Context, _ Scope, filter Filter) (Snapshot, error) {
	source.filters = append(source.filters, filter)
	return source.snapshot, nil
}
func (source *sourceFixture) LoadBasic(_ context.Context, _ Scope, filter Filter) (Basic, error) {
	source.filters = append(source.filters, filter)
	return Basic{FactCount: 3, Requests: 3, TrafficBytes: 30, BandwidthBPS: 40,
		Connections: 2, Series: []BasicPoint{{Bucket: filter.From, Requests: 3, TrafficBytes: 30, BandwidthBPS: 40, Connections: 2}}}, nil
}
func (source *sourceFixture) LoadQuality(_ context.Context, _ Scope, filter Filter) (Quality, error) {
	source.filters = append(source.filters, filter)
	if source.quality != nil {
		return Quality{}, source.quality
	}
	return Quality{FactCount: 3, Status2xx: 3, CacheHits: 2, CacheMisses: 1,
		Series: []QualityPoint{{Bucket: filter.From, Status2xx: 3}}}, nil
}
func (source *sourceFixture) LoadOrigin(_ context.Context, _ Scope, filter Filter) (Origin, error) {
	source.filters = append(source.filters, filter)
	return Origin{FactCount: 3, ConnectUS: 1, FirstByteUS: 2, TotalUS: 3,
		Series: []OriginPoint{{Bucket: filter.From, ConnectUS: 1, FirstByteUS: 2, TotalUS: 3}}}, nil
}
func (source *sourceFixture) LoadRank(_ context.Context, _ Scope, filter Filter) (RankResult, error) {
	source.filters = append(source.filters, filter)
	return RankResult{FactCount: 3, Items: []RankItem{{Key: "cdn.example.test:443", Label: "cdn.example.test", Requests: 3, TrafficBytes: 30}}, HasMore: true}, nil
}

func TestQueryBindsEverySectionToOneSnapshotAndStableCursor(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	snapshot := Snapshot{At: now, SourceWatermark: 42, FinalizedThrough: now, ExpiresAt: now.Add(time.Minute)}
	source := &sourceFixture{snapshot: snapshot}
	service, err := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	query := Query{Audience: AudienceTenant, Range: "6h", Timezone: "Asia/Shanghai", SiteID: testSite,
		NodeID: testNode, Domain: "cdn.example.test", ListenPort: 443, RankBy: RankByHost, Limit: 10}
	actor := Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}
	response, err := service.Query(t.Context(), actor, query)
	if err != nil {
		t.Fatal(err)
	}
	if response.Meta.Snapshot != snapshot || response.Meta.From != now.Add(-6*time.Hour) || response.Meta.To != now ||
		response.Meta.Bucket != 5*time.Minute || response.Meta.Downsample || !response.Basic.Available ||
		!response.Quality.Available || !response.Origin.Available || !response.Rank.Available || response.Rank.Value.NextCursor == "" {
		t.Fatalf("response = %#v", response)
	}
	if len(source.filters) != 5 {
		t.Fatalf("source calls = %d", len(source.filters))
	}
	for index, filter := range source.filters[1:] {
		if filter.Snapshot != snapshot {
			t.Fatalf("section %d snapshot = %#v", index, filter.Snapshot)
		}
	}

	query.Cursor = response.Rank.Value.NextCursor
	query.SiteID = "018f0000-0000-7000-8000-000000000004"
	if _, err := service.Query(t.Context(), actor, query); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cursor replay error = %v", err)
	}
}

func TestQueryAllowsOnlyExplicitSectionDependencyDegradation(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	source := &sourceFixture{snapshot: Snapshot{At: now, SourceWatermark: 42, FinalizedThrough: now, ExpiresAt: now.Add(time.Minute)}, quality: ErrDependencyUnavailable}
	service, _ := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: []byte("0123456789abcdef0123456789abcdef")})
	response, err := service.Query(t.Context(), Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}},
		Query{Audience: AudienceTenant, Range: "1h", Timezone: "UTC", RankBy: RankByHost, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if response.Quality.Available || response.Quality.Reason != ReasonDependencyUnavailable ||
		!response.Basic.Available || !response.Origin.Available || !response.Rank.Available {
		t.Fatalf("sections = %#v", response)
	}

	source.snapshot.ExpiresAt = now
	if _, err := service.Query(t.Context(), Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}},
		Query{Audience: AudienceTenant, Range: "1h", Timezone: "UTC", RankBy: RankByHost, Limit: 10}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("expired snapshot error = %v", err)
	}
}

func TestQueryRejectsInvalidScopeRangeAndFabricatedEmptyFacts(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	source := &sourceFixture{snapshot: Snapshot{At: now, SourceWatermark: 42, FinalizedThrough: now, ExpiresAt: now.Add(time.Minute)}}
	service, _ := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: []byte("0123456789abcdef0123456789abcdef")})
	actor := Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}
	for _, query := range []Query{
		{Audience: AudiencePlatform, TenantID: testTenant, Range: "1h", Timezone: "UTC", RankBy: RankByHost, Limit: 10},
		{Audience: AudienceTenant, Range: "2h", Timezone: "UTC", RankBy: RankByHost, Limit: 10},
		{Audience: AudienceTenant, Range: "custom", From: now.Add(-32 * 24 * time.Hour), To: now, Timezone: "UTC", RankBy: RankByHost, Limit: 10},
	} {
		if _, err := service.Query(t.Context(), actor, query); err == nil {
			t.Fatalf("Query(%#v) succeeded", query)
		}
	}

	source.snapshot.FinalizedThrough = now.Add(-time.Minute)
	if _, err := service.Query(t.Context(), actor, Query{Audience: AudienceTenant, Range: "1h", Timezone: "UTC", RankBy: RankByHost, Limit: 10}); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("unfinalized snapshot error = %v", err)
	}
}
