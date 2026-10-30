package dashboard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

type parallelAnalyticsReader struct {
	mu        sync.Mutex
	active    int
	maxActive int
	started   chan struct{}
	release   chan struct{}
	actors    []analytics.Actor
	requests  []analytics.QueryRequest
	errors    map[string]error
	snapshot  time.Time
}

func (reader *parallelAnalyticsReader) enter(
	ctx context.Context,
	kind string,
	actor analytics.Actor,
	request analytics.QueryRequest,
) error {
	reader.mu.Lock()
	reader.active++
	if reader.active > reader.maxActive {
		reader.maxActive = reader.active
	}
	reader.actors = append(reader.actors, actor)
	reader.requests = append(reader.requests, request)
	err := reader.errors[kind]
	reader.mu.Unlock()
	if reader.started != nil {
		reader.started <- struct{}{}
	}
	if reader.release != nil {
		select {
		case <-reader.release:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	reader.mu.Lock()
	reader.active--
	reader.mu.Unlock()
	return err
}

func (reader *parallelAnalyticsReader) Summary(
	ctx context.Context,
	actor analytics.Actor,
	request analytics.QueryRequest,
) (analytics.Summary, error) {
	err := reader.enter(ctx, "summary", actor, request)
	return analytics.Summary{
		MetricVersion: analytics.MetricVersion, RequestCount: 7, ResponseBytes: 11,
		TotalBytes: 11, SecurityEvents: 3,
	}, err
}

func (reader *parallelAnalyticsReader) Trend(
	ctx context.Context,
	actor analytics.Actor,
	request analytics.QueryRequest,
) ([]analytics.TrendPoint, error) {
	err := reader.enter(ctx, "trend", actor, request)
	return []analytics.TrendPoint{{
		Hour: request.From, MetricVersion: analytics.MetricVersion, RequestCount: 7,
		ResponseBytes: 11, TotalBytes: 11, SecurityEvents: 3,
	}}, err
}

func (reader *parallelAnalyticsReader) Rank(
	ctx context.Context,
	actor analytics.Actor,
	request analytics.QueryRequest,
	dimension analytics.RankDimension,
	_ uint16,
	_ string,
) (analytics.RankPage, error) {
	err := reader.enter(ctx, "rank:"+string(dimension), actor, request)
	item := analytics.RankItem{Key: string(dimension), RequestCount: 7, ResponseBytes: 11}
	switch dimension {
	case analytics.RankByDomain:
		item.Key, item.Host, item.Port = "www.example.com:8080", "www.example.com", 8080
	case analytics.RankByURL:
		item.Key, item.Host, item.Port, item.Path, item.Scheme = "www.example.com:443/a?b", "www.example.com", 443, "/a?b", "https"
	}
	return analytics.RankPage{SnapshotAt: reader.snapshot, Items: []analytics.RankItem{item}}, err
}

func TestProductionAnalyticsReadsSevenIndependentSectionsAtOneSnapshot(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	snapshot := to.Add(time.Second)
	reader := &parallelAnalyticsReader{
		started: make(chan struct{}, 7), release: make(chan struct{}), snapshot: snapshot,
		errors: map[string]error{},
	}
	finalizedThrough := to
	store := &Store{
		analytics: reader, parallelAnalytics: true,
		finalization: &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{
			ExpectedTenants: 1, AccessTenants: 1, SecurityTenants: 1,
			Rows: 2, ReadyRows: 2, FinalizedThrough: &finalizedThrough,
		}},
	}
	actor := Actor{ScopeKind: "tenant", TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001")}
	query := Query{
		Range: "custom", Timezone: "Asia/Shanghai", From: from, To: to, AsOf: snapshot,
		SiteID: "018f0000-0000-7000-8000-000000000002",
		NodeID: "018f0000-0000-7000-8000-000000000003",
	}

	type result struct {
		section Section[AnalyticsOverview]
		err     error
	}
	done := make(chan result, 1)
	go func() {
		section, err := store.readAnalytics(context.Background(), nil, actor, AudienceTenant, query)
		done <- result{section: section, err: err}
	}()
	for index := 0; index < 7; index++ {
		select {
		case <-reader.started:
		case <-time.After(time.Second):
			t.Fatalf("only %d analytics reads started before release", index)
		}
	}
	close(reader.release)
	got := <-done
	if got.err != nil || !got.section.Available || got.section.Value == nil {
		t.Fatalf("readAnalytics() = %#v, %v", got.section, got.err)
	}
	if reader.maxActive != 7 || len(reader.requests) != 7 || len(reader.actors) != 7 {
		t.Fatalf("analytics concurrency=%d requests=%d actors=%d", reader.maxActive, len(reader.requests), len(reader.actors))
	}
	wantRequest := analytics.QueryRequest{
		Audience: analytics.AudienceTenant, From: from, To: to, SiteID: query.SiteID, NodeID: query.NodeID,
		Timezone: query.Timezone, SnapshotAt: snapshot,
	}
	// AUDIT-FINAL-1027 P8: the home page ranks carry the address parts so it
	// shows host:port and scheme://host:port/path like the analytics page.
	for _, snapshot := range got.section.Value.TopExtended {
		item := snapshot.Items[0]
		switch snapshot.Dimension {
		case "domain":
			if item.Host != "www.example.com" || item.Port != 8080 || item.Path != "" || item.Scheme != "" {
				t.Fatalf("domain rank item = %#v", item)
			}
		case "url":
			if item.Host != "www.example.com" || item.Port != 443 || item.Path != "/a?b" || item.Scheme != "https" {
				t.Fatalf("url rank item = %#v", item)
			}
		default:
			if item.Host != "" || item.Port != 0 {
				t.Fatalf("%s rank item = %#v", snapshot.Dimension, item)
			}
		}
	}
	for index, request := range reader.requests {
		if request != wantRequest {
			t.Fatalf("analytics request %d = %#v, want %#v", index, request, wantRequest)
		}
		if reader.actors[index].ScopeKind != "tenant" || reader.actors[index].TenantID != actor.TenantID.String() {
			t.Fatalf("analytics actor %d = %#v", index, reader.actors[index])
		}
	}
}

func TestProductionAnalyticsUsesStableDegradedReasonsWithoutZeroValues(t *testing.T) {
	from := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	for _, test := range []struct {
		name   string
		err    error
		reason string
		fatal  bool
	}{
		{name: "dependency", err: analytics.ErrTransport, reason: ReasonDependencyUnavailable},
		{name: "timeout", err: context.DeadlineExceeded, reason: ReasonDependencyTimeout},
		{name: "invalid contract", err: analytics.ErrInvalidResponse, fatal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			finalizedThrough := to
			reader := &parallelAnalyticsReader{snapshot: to, errors: map[string]error{"summary": test.err}}
			store := &Store{
				analytics: reader, parallelAnalytics: true,
				finalization: &analyticsFinalizationStub{snapshot: analyticsFinalizationSnapshot{
					ExpectedTenants: 1, AccessTenants: 1, SecurityTenants: 1,
					Rows: 2, ReadyRows: 2, FinalizedThrough: &finalizedThrough,
				}},
			}
			section, err := store.readAnalytics(t.Context(), nil, Actor{
				ScopeKind: "tenant", TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001"),
			}, AudienceTenant, Query{From: from, To: to, AsOf: to, Timezone: "UTC"})
			if test.fatal {
				if !errors.Is(err, ErrUnavailable) || section.Available || section.Value != nil || section.Reason != "" {
					t.Fatalf("contract failure = %#v, %v", section, err)
				}
				return
			}
			if err != nil || section.Available || section.Value != nil || section.Reason != test.reason {
				t.Fatalf("degraded section = %#v, %v, want %q", section, err, test.reason)
			}
		})
	}
}
