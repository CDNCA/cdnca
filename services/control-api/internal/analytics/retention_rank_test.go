package analytics

import (
	"context"
	"testing"
	"time"
)

type fixedRetention Retention

func (retention fixedRetention) AnalyticsRetention(context.Context) (Retention, error) {
	return Retention(retention), nil
}

type rankOnlyStore struct{ QueryStore }

func (rankOnlyStore) Rank(context.Context, Scope, Filter, RankDimension, uint16, string) (RankPage, error) {
	return RankPage{SnapshotAt: time.Now().UTC()}, nil
}

// A ranking over a range older than its source's retention says so
// (RetainedFrom) instead of looking complete.
func TestRankReportsRetainedFromPerSource(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	service, err := NewService(rankOnlyStore{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	service.SetRetentionReader(fixedRetention{AccessLogDays: 7, HistoryDays: 90})
	actor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	request := QueryRequest{Audience: AudiencePlatform, From: now.Add(-30 * 24 * time.Hour), To: now}
	for dimension, want := range map[RankDimension]time.Time{
		RankByURL: now.Add(-7 * 24 * time.Hour), RankByJA4: now.Add(-7 * 24 * time.Hour),
		RankByDomain: {}, RankByProvince: {}, RankByBrowser: {},
	} {
		page, err := service.Rank(context.Background(), actor, request, dimension, 10, "")
		if err != nil {
			t.Fatal(err)
		}
		if !page.RetainedFrom.Equal(want) {
			t.Errorf("%s retained from = %s, want %s", dimension, page.RetainedFrom, want)
		}
	}
	service.SetRetentionReader(fixedRetention{AccessLogDays: 0, HistoryDays: 90})
	if page, _ := service.Rank(context.Background(), actor, request, RankByURL, 10, ""); !page.RetainedFrom.IsZero() {
		t.Fatalf("kept forever must not report a retention start: %s", page.RetainedFrom)
	}
}
