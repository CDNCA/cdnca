package ja4block

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestAnalyticsAuthorityBindsExactTenantSiteFilterSnapshotAndPublication(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	snapshotAt := now.Add(-time.Minute)
	tenantID, siteID := uuid.New(), uuid.New()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	ranker := &analyticsRankerStub{pages: map[string]analytics.RankPage{
		"":     {Items: []analytics.RankItem{{Key: "other", RequestCount: 90}}, NextCursor: "next", SnapshotAt: snapshotAt},
		"next": {Items: []analytics.RankItem{{Key: "t13d1516h2_8daaf6152771_e5627efa2ab1", RequestCount: 41, ResponseBytes: 8192}}, SnapshotAt: snapshotAt},
	}}
	targets := &publicationTargetStub{target: PublicationTarget{
		TenantScopeID: tenantID, SiteID: siteID, ExpectedBindingRevision: 4,
		ExpectedActiveVersion: 7, TargetSnapshotID: uuid.New(), TargetSnapshotRevision: 1,
		TargetSnapshotSHA256: nodescheduler.CanonicalNodeSetDigest(nodes), TargetNodeIDs: nodes,
		CurrentPolicy: &securitypolicy.Policy{ID: uuid.New(), ScopeID: tenantID, Kind: securitypolicy.KindWAF, Revision: 7},
	}}
	authority, err := NewAnalyticsAuthority(ranker, targets, AnalyticsAuthorityConfig{
		Actor:  analytics.Actor{ScopeKind: "platform", Permissions: []string{"platform.admin", analytics.ReadPermission}},
		Window: 6 * time.Hour, SnapshotTTL: 5 * time.Minute, PageSize: 1, MaxPages: 2,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := authority.Resolve(t.Context(), AuthorityRequest{
		TenantScopeID: tenantID, SiteID: siteID, JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1", SnapshotAt: snapshotAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ranker.calls) != 2 || ranker.calls[0].dimension != analytics.RankByJA4 ||
		ranker.calls[0].limit != 1 || ranker.calls[0].cursor != "" || ranker.calls[1].cursor != "next" {
		t.Fatalf("rank calls = %#v", ranker.calls)
	}
	request := ranker.calls[0].request
	if request.Audience != analytics.AudiencePlatform || request.TenantID != tenantID.String() ||
		request.SiteID != siteID.String() || request.NodeID != "" || request.Timezone != "UTC" ||
		!request.SnapshotAt.Equal(snapshotAt) ||
		!request.From.Equal(time.Date(2026, 8, 8, 4, 0, 0, 0, time.UTC)) ||
		!request.To.Equal(time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("rank request = %#v", request)
	}
	if result.TenantScopeID != tenantID || result.SiteID != siteID || result.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" ||
		result.Consistency != "latest_event_id_at_snapshot" || !result.FilterFrom.Equal(request.From) ||
		!result.FilterTo.Equal(request.To) || result.FilterTimezone != "UTC" ||
		!result.SnapshotAt.Equal(snapshotAt) || !result.SnapshotExpiresAt.Equal(snapshotAt.Add(5*time.Minute)) ||
		result.RequestCount != 41 || result.ResponseBytes != 8192 || result.ExpectedBindingRevision != 4 ||
		result.ExpectedActiveVersion != 7 || result.CurrentPolicy == nil || result.CurrentPolicy.Revision != 7 ||
		len(result.TargetNodeIDs) != 2 || result.RolloutID == uuid.Nil {
		t.Fatalf("authority result = %#v", result)
	}
}

func TestAnalyticsAuthorityFailsClosedForExpiredMissingAndMismatchedFacts(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	tenantID, siteID := uuid.New(), uuid.New()
	nodes := []uuid.UUID{uuid.New()}
	validTarget := PublicationTarget{TenantScopeID: tenantID, SiteID: siteID,
		TargetSnapshotID: uuid.New(), TargetSnapshotRevision: 1,
		TargetSnapshotSHA256: nodescheduler.CanonicalNodeSetDigest(nodes),
		TargetNodeIDs:        nodes, ExpectedActiveVersion: 0}
	for name, test := range map[string]struct {
		snapshotAt time.Time
		page       analytics.RankPage
		target     PublicationTarget
		want       error
	}{
		"expired":            {now.Add(-6 * time.Minute), analytics.RankPage{}, validTarget, ErrSnapshotExpired},
		"missing":            {now.Add(-time.Minute), analytics.RankPage{SnapshotAt: now.Add(-time.Minute)}, validTarget, ErrSnapshotStale},
		"snapshot mismatch":  {now.Add(-time.Minute), analytics.RankPage{Items: []analytics.RankItem{{Key: "t13d1516h2_8daaf6152771_e5627efa2ab1", RequestCount: 1}}, SnapshotAt: now.Add(-2 * time.Minute)}, validTarget, ErrSnapshotStale},
		"cross scope target": {now.Add(-time.Minute), analytics.RankPage{Items: []analytics.RankItem{{Key: "t13d1516h2_8daaf6152771_e5627efa2ab1", RequestCount: 1}}, SnapshotAt: now.Add(-time.Minute)}, PublicationTarget{TenantScopeID: uuid.New(), SiteID: siteID, TargetNodeIDs: []uuid.UUID{uuid.New()}}, ErrScopeConflict},
	} {
		t.Run(name, func(t *testing.T) {
			ranker := &analyticsRankerStub{pages: map[string]analytics.RankPage{"": test.page}}
			authority, err := NewAnalyticsAuthority(ranker, &publicationTargetStub{target: test.target}, AnalyticsAuthorityConfig{
				Actor:  analytics.Actor{ScopeKind: "platform", Permissions: []string{"platform.admin", analytics.ReadPermission}},
				Window: time.Hour, SnapshotTTL: 5 * time.Minute, PageSize: 100, MaxPages: 1,
				Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = authority.Resolve(t.Context(), AuthorityRequest{
				TenantScopeID: tenantID, SiteID: siteID, JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1", SnapshotAt: test.snapshotAt,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", err, test.want)
			}
		})
	}
}

type analyticsRankCall struct {
	actor     analytics.Actor
	request   analytics.QueryRequest
	dimension analytics.RankDimension
	limit     uint16
	cursor    string
}

type analyticsRankerStub struct {
	pages map[string]analytics.RankPage
	calls []analyticsRankCall
}

func (stub *analyticsRankerStub) Rank(_ context.Context, actor analytics.Actor, request analytics.QueryRequest,
	dimension analytics.RankDimension, limit uint16, cursor string,
) (analytics.RankPage, error) {
	stub.calls = append(stub.calls, analyticsRankCall{actor, request, dimension, limit, cursor})
	return stub.pages[cursor], nil
}

type publicationTargetStub struct {
	target PublicationTarget
	err    error
}

func (stub *publicationTargetStub) LoadPublicationTarget(context.Context, uuid.UUID, uuid.UUID) (PublicationTarget, error) {
	return stub.target, stub.err
}
