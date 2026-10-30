package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDashboardQueriesShareExplicitSnapshot(t *testing.T) {
	snapshot := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	filter := Filter{
		From:   snapshot.Truncate(time.Hour).Add(-2 * time.Hour),
		To:     snapshot.Truncate(time.Hour),
		SiteID: testSiteID, NodeID: testNodeID,
		Timezone: "Asia/Shanghai", SnapshotAt: snapshot,
	}
	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}

	type call struct {
		query      string
		parameters url.Values
	}
	var calls []call
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		query := string(encoded)
		calls = append(calls, call{query: query, parameters: request.URL.Query()})
		switch {
		case strings.Contains(query, "ORDER BY response_bytes DESC, request_count DESC, key ASC"):
			_, _ = io.WriteString(writer, `{"key":"/asset.js","request_count":1,"response_bytes":800}`+"\n")
		case strings.Contains(query, "GROUP BY hour"):
			_, _ = io.WriteString(writer, `{"bucket_unix":`+strconv.FormatInt(filter.From.Unix(), 10)+`,"metric_version":1,"request_count":1,"request_bytes":100,"response_bytes":800,"total_bytes":900,"average_bandwidth_bps":1.7777777777777777,"status_2xx":1,"status_3xx":0,"status_4xx":0,"status_5xx":0,"security_events":0,"security_event_rows":0,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":1}`+"\n")
		default:
			_, _ = io.WriteString(writer, `{"metric_version":1,"request_count":1,"request_bytes":100,"response_bytes":800,"total_bytes":900,"average_bandwidth_bps":0.8888888888888888,"status_2xx":1,"status_3xx":0,"status_4xx":0,"status_5xx":0,"security_events":0,"security_event_rows":0,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":1}`+"\n")
		}
	}))
	t.Cleanup(server.Close)
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())

	if _, err := client.Summary(context.Background(), scope, filter); err != nil {
		t.Fatalf("Summary() error = %v", err)
	}
	if _, err := client.Trend(context.Background(), scope, filter); err != nil {
		t.Fatalf("Trend() error = %v", err)
	}
	page, err := client.Rank(context.Background(), scope, filter, RankByURL, 10, "")
	if err != nil {
		t.Fatalf("Rank() error = %v", err)
	}
	if !page.SnapshotAt.Equal(snapshot) {
		t.Fatalf("Rank() snapshot = %v, want %v", page.SnapshotAt, snapshot)
	}
	if len(calls) != 3 {
		t.Fatalf("query calls = %d, want 3", len(calls))
	}
	wantSnapshot := strconv.FormatInt(snapshot.UnixMilli(), 10)
	for index, call := range calls {
		if got := call.parameters.Get("param_snapshot_ms"); got != wantSnapshot {
			t.Errorf("call %d snapshot parameter = %q, want %q", index, got, wantSnapshot)
		}
		for key, want := range map[string]string{
			"param_tenant_scoped": "1", "param_tenant_id": testTenantID,
			"param_site_id": testSiteID, "param_node_id": testNodeID,
		} {
			if got := call.parameters.Get(key); got != want {
				t.Errorf("call %d %s = %q, want %q", index, key, got, want)
			}
		}
	}
}

func TestDashboardSummaryAndTrendUseSnapshotFencedFacts(t *testing.T) {
	for name, query := range map[string]string{"summary": summarySQL, "trend": trendSQL} {
		t.Run(name, func(t *testing.T) {
			for _, table := range []string{"access_hourly_facts_v1", "security_hourly_facts_v1"} {
				if !strings.Contains(query, "FROM "+table) {
					t.Errorf("query does not read %s", table)
				}
			}
			for _, view := range []string{"access_hourly_v1", "security_hourly_v1"} {
				if strings.Contains(query, "FROM "+view) {
					t.Errorf("query reads advancing view %s", view)
				}
			}
			if count := strings.Count(query, "ingested_at <= fromUnixTimestamp64Milli({snapshot_ms:UInt64}, 'UTC')"); count != 2 {
				t.Errorf("snapshot fences = %d, want 2", count)
			}
			if count := strings.Count(query, "GROUP BY tenant_id, event_id"); count != 2 {
				t.Errorf("event-version groups = %d, want 2", count)
			}
			if count := strings.Count(query, "argMax("); count < 2 {
				t.Errorf("latest-version projections = %d, want at least 2", count)
			}
			for _, fence := range []string{
				"{tenant_scoped:UInt8}", "{tenant_id:String}", "{has_site:UInt8}",
				"{site_id:String}", "{has_node:UInt8}", "{node_id:String}",
				"{from_ms:UInt64}", "{to_ms:UInt64}",
			} {
				if !strings.Contains(query, fence) {
					t.Errorf("query missing scope/filter fence %q", fence)
				}
			}
		})
	}
}

func TestDashboardSnapshotAuthorizationCarriesAuthority(t *testing.T) {
	snapshot := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	request := QueryRequest{
		Audience: AudienceTenant,
		From:     snapshot.Truncate(time.Hour).Add(-2 * time.Hour),
		To:       snapshot.Truncate(time.Hour),
		SiteID:   testSiteID, NodeID: testNodeID,
		Timezone: "Asia/Shanghai", SnapshotAt: snapshot,
	}
	scope, filter, err := authorizeQuery(Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, request)
	if err != nil {
		t.Fatalf("authorizeQuery() error = %v", err)
	}
	if scope.kind != scopeTenant || scope.tenantID != testTenantID || filter.Timezone != request.Timezone ||
		!filter.SnapshotAt.Equal(snapshot) || filter.SiteID != testSiteID || filter.NodeID != testNodeID {
		t.Fatalf("authorized scope/filter = %#v / %#v", scope, filter)
	}
}

func TestDashboardRankCursorRejectsAuthorityDrift(t *testing.T) {
	snapshot := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	filter := Filter{
		From:   snapshot.Truncate(time.Hour).Add(-2 * time.Hour),
		To:     snapshot.Truncate(time.Hour),
		SiteID: testSiteID, Timezone: "Asia/Shanghai", SnapshotAt: snapshot,
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = io.WriteString(writer,
			`{"key":"/a","request_count":2,"response_bytes":200}`+"\n"+
				`{"key":"/b","request_count":1,"response_bytes":100}`+"\n")
	}))
	t.Cleanup(server.Close)
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	page, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 1, "")
	if err != nil || page.NextCursor == "" {
		t.Fatalf("first Rank() = %#v, %v", page, err)
	}

	tenantScope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		scope  Scope
		filter Filter
	}{
		{name: "scope", scope: tenantScope, filter: filter},
		{name: "timezone", scope: AdminScope(), filter: func() Filter { changed := filter; changed.Timezone = "UTC"; return changed }()},
		{name: "site", scope: AdminScope(), filter: func() Filter { changed := filter; changed.SiteID = testNodeID; return changed }()},
		{name: "snapshot", scope: AdminScope(), filter: func() Filter { changed := filter; changed.SnapshotAt = snapshot.Add(-time.Millisecond); return changed }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Rank(context.Background(), test.scope, test.filter, RankByURL, 1, page.NextCursor); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Rank() error = %v, want ErrInvalidInput", err)
			}
		})
	}
	if requests != 1 {
		t.Fatalf("storage requests = %d, want 1", requests)
	}
}

func TestDashboardSnapshotRejectsExpiredOrNonCanonicalAuthority(t *testing.T) {
	now := time.Now().UTC()
	base := Filter{From: now.Truncate(time.Hour).Add(-2 * time.Hour), To: now.Truncate(time.Hour), Timezone: "UTC"}
	tests := []struct {
		name     string
		snapshot time.Time
	}{
		{name: "expired", snapshot: now.Add(-packageMetricFactRetention - time.Hour).Truncate(time.Millisecond)},
		{name: "future", snapshot: now.Add(2 * time.Minute).Truncate(time.Millisecond)},
		{name: "sub-millisecond", snapshot: now.Truncate(time.Millisecond).Add(time.Nanosecond)},
		{name: "non-UTC", snapshot: now.In(time.FixedZone("UTC+8", 8*60*60)).Truncate(time.Millisecond)},
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	t.Cleanup(server.Close)
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filter := base
			filter.SnapshotAt = test.snapshot
			if _, err := client.Summary(context.Background(), AdminScope(), filter); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Summary() error = %v, want ErrInvalidInput", err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("storage requests = %d, want 0", requests)
	}
}

func TestDashboardSnapshotLegacyZeroRemainsCompatible(t *testing.T) {
	request := QueryRequest{
		Audience: AudienceTenant,
		From:     time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		To:       time.Date(2099, 1, 1, 2, 0, 0, 0, time.UTC),
	}
	_, filter, err := authorizeQuery(Actor{
		ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission},
	}, request)
	if err != nil {
		t.Fatalf("authorizeQuery() error = %v", err)
	}
	if filter.Timezone != "" || !filter.SnapshotAt.IsZero() {
		t.Fatalf("legacy filter = %#v", filter)
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"key":"/legacy","request_count":1,"response_bytes":1}`+"\n")
	}))
	t.Cleanup(server.Close)
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	page, err := client.Rank(context.Background(), AdminScope(), filter, RankByURL, 10, "")
	if err != nil || page.SnapshotAt.IsZero() {
		t.Fatalf("legacy Rank() = %#v, %v", page, err)
	}
}
