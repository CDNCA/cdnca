package analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

type recordingQueryStore struct {
	scope       Scope
	filter      Filter
	dimension   RankDimension
	limit       uint16
	cursor      string
	summary     Summary
	trend       []TrendPoint
	rank        RankPage
	err         error
	queryCalled bool
}

func (store *recordingQueryStore) Summary(_ context.Context, scope Scope, filter Filter) (Summary, error) {
	store.record(scope, filter)
	return store.summary, store.err
}

func (store *recordingQueryStore) Trend(_ context.Context, scope Scope, filter Filter) ([]TrendPoint, error) {
	store.record(scope, filter)
	return store.trend, store.err
}

func (store *recordingQueryStore) Rank(
	_ context.Context,
	scope Scope,
	filter Filter,
	dimension RankDimension,
	limit uint16,
	cursor string,
) (RankPage, error) {
	store.record(scope, filter)
	store.dimension = dimension
	store.limit = limit
	store.cursor = cursor
	return store.rank, store.err
}

func (store *recordingQueryStore) record(scope Scope, filter Filter) {
	store.queryCalled = true
	store.scope = scope
	store.filter = filter
}

func TestServiceDerivesPlatformAndTenantScopes(t *testing.T) {
	t.Parallel()

	platformStore := &recordingQueryStore{summary: Summary{MetricVersion: MetricVersion}}
	platformService, err := NewService(platformStore)
	if err != nil {
		t.Fatal(err)
	}
	request := serviceQueryRequest(AudiencePlatform)
	request.TenantID = testTenantID
	request.SiteID = testSiteID
	request.NodeID = testNodeID
	request.From = time.Date(2099, 1, 1, 8, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	request.To = request.From.Add(2 * time.Hour)
	if _, err := platformService.Summary(context.Background(), Actor{
		ScopeKind: "platform", Permissions: []string{"platform.admin"},
	}, request); err != nil {
		t.Fatal(err)
	}
	if platformStore.scope.kind != scopeTenant || platformStore.scope.tenantID != testTenantID {
		t.Fatalf("platform target scope = %#v", platformStore.scope)
	}
	if platformStore.filter.From.Location() != time.UTC || platformStore.filter.From.Hour() != 0 {
		t.Fatalf("normalized filter = %#v", platformStore.filter)
	}

	tenantStore := &recordingQueryStore{}
	tenantService, err := NewService(tenantStore)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenantService.Trend(context.Background(), Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, serviceQueryRequest(AudienceTenant)); err != nil {
		t.Fatal(err)
	}
	if tenantStore.scope.kind != scopeTenant || tenantStore.scope.tenantID != testTenantID {
		t.Fatalf("tenant scope = %#v", tenantStore.scope)
	}
}

func TestServiceRejectsCrossScopeAndPermissionBypass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		actor   Actor
		request QueryRequest
		want    error
	}{
		{
			name:  "tenant supplies tenant id",
			actor: Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}},
			request: func() QueryRequest {
				request := serviceQueryRequest(AudienceTenant)
				request.TenantID = testTenantID
				return request
			}(),
			want: ErrScopeForbidden,
		},
		{
			name:    "tenant calls platform route",
			actor:   Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}},
			request: serviceQueryRequest(AudiencePlatform),
			want:    ErrScopeForbidden,
		},
		{
			name:    "platform calls tenant route",
			actor:   Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}},
			request: serviceQueryRequest(AudienceTenant),
			want:    ErrScopeForbidden,
		},
		{
			name:    "missing permission",
			actor:   Actor{ScopeKind: "tenant", TenantID: testTenantID},
			request: serviceQueryRequest(AudienceTenant),
			want:    ErrPermissionDenied,
		},
		{
			name:    "invalid actor tenant",
			actor:   Actor{ScopeKind: "tenant", TenantID: "not-a-uuid", Permissions: []string{ReadPermission}},
			request: serviceQueryRequest(AudienceTenant),
			want:    ErrInvalidInput,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingQueryStore{}
			service, err := NewService(store)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.Summary(context.Background(), test.actor, test.request)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if store.queryCalled {
				t.Fatal("store was called after authorization failure")
			}
		})
	}
}

func TestServicePassesRankContract(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{rank: RankPage{Items: []RankItem{{Key: "/a"}}}}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.Rank(context.Background(), Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, serviceQueryRequest(AudienceTenant), RankByURL, 25, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || store.dimension != RankByURL || store.limit != 25 || store.cursor != "cursor" {
		t.Fatalf("page=%#v dimension=%q limit=%d cursor=%q", page, store.dimension, store.limit, store.cursor)
	}
}

func TestServiceAllowsMinuteAlignedRankWindow(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{rank: RankPage{Items: []RankItem{{Key: "example.test"}}}}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	request := serviceQueryRequest(AudienceTenant)
	request.From = time.Date(2099, 1, 1, 0, 10, 0, 0, time.UTC)
	request.To = request.From.Add(10 * time.Minute)
	if _, err := service.Rank(context.Background(), Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, request, RankByDomain, 10, ""); err != nil {
		t.Fatalf("minute-aligned rank error = %v", err)
	}
}

func TestServiceBindsRankOnlyFiltersAndRejectsThemForSummary(t *testing.T) {
	t.Parallel()
	store := &recordingQueryStore{rank: RankPage{SnapshotAt: time.Date(2099, 1, 1, 2, 0, 0, 0, time.UTC)}}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	request := serviceQueryRequest(AudienceTenant)
	request.Domain = "cdn.example.test static.example.test"
	request.ListenPort = 443
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	if _, err := service.Rank(context.Background(), actor, request, RankByReferer, 10, ""); err != nil {
		t.Fatalf("rank error = %v", err)
	}
	if store.filter.Domain != request.Domain || store.filter.ListenPort != 443 || store.dimension != RankByReferer {
		t.Fatalf("rank filter = %#v dimension = %q", store.filter, store.dimension)
	}
	store.queryCalled = false
	if _, err := service.Summary(context.Background(), actor, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("summary rank-filter error = %v", err)
	}
	if store.queryCalled {
		t.Fatal("summary store was called with rank-only filters")
	}
}

func TestNewServiceRejectsMissingStore(t *testing.T) {
	t.Parallel()
	if _, err := NewService(nil); !errors.Is(err, ErrInvalidServiceConfig) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateScopeFilterAllowsDSTCivilMonthMaximum(t *testing.T) {
	scope := AdminScope()
	tests := []struct {
		name string
		from time.Time
		to   time.Time
		want error
	}{
		{
			name: "spring forward civil month",
			from: time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
			to:   time.Date(2026, time.March, 31, 23, 0, 0, 0, time.UTC),
		},
		{
			name: "fall back civil month",
			from: time.Date(2026, time.September, 30, 23, 0, 0, 0, time.UTC),
			to:   time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "more than civil month maximum",
			from: time.Date(2026, time.September, 30, 23, 0, 0, 0, time.UTC),
			to:   time.Date(2026, time.November, 1, 1, 0, 0, 0, time.UTC),
			want: ErrInvalidInput,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateScopeFilter(scope, Filter{From: test.from, To: test.to})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func serviceQueryRequest(audience Audience) QueryRequest {
	return QueryRequest{
		Audience: audience,
		From:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		To:       time.Date(2099, 1, 1, 2, 0, 0, 0, time.UTC),
	}
}
