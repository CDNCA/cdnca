package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	analyticslog "github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

const (
	rankTenantA = "10000000-0000-4000-8000-00000000000a"
	rankTenantB = "10000000-0000-4000-8000-00000000000b"
	rankTenantC = "10000000-0000-4000-8000-00000000000c"
	rankSiteA1  = "20000000-0000-4000-8000-0000000000a1"
	rankSiteA2  = "20000000-0000-4000-8000-0000000000a2"
	rankSiteA3  = "20000000-0000-4000-8000-0000000000a3"
	rankSiteB   = "20000000-0000-4000-8000-00000000000b"
	rankSiteC   = "20000000-0000-4000-8000-00000000000c"
	rankNodeA1  = "30000000-0000-4000-8000-0000000000a1"
	rankNodeA2  = "30000000-0000-4000-8000-0000000000a2"
	rankNodeA3  = "30000000-0000-4000-8000-0000000000a3"
	rankNodeB   = "30000000-0000-4000-8000-00000000000b"
	rankNodeC   = "30000000-0000-4000-8000-00000000000c"
	rankConfigA = "40000000-0000-4000-8000-00000000000a"

	insertRankAccessSQL = `INSERT INTO access_events
	(metric_version, event_id, occurred_at, ingested_at, tenant_id, site_id, node_id, request_id, trace_id,
	 config_version_id, request_headers, host, listen_port, path, client_ip, country_code, carrier, method, protocol, cache_status,
	 upstream_result, status_code, request_bytes, response_bytes, duration_us)
FORMAT JSONEachRow`
	insertRankSecuritySQL = `INSERT INTO security_events
(metric_version, event_id, occurred_at, ingested_at, tenant_id, site_id, node_id, request_id, trace_id,
 config_version_id, host, path, client_ip, country_code, carrier, event_type, action, severity, rule_id,
 status_code, request_bytes, response_bytes)
FORMAT JSONEachRow`
)

func TestAnalyticsClickHouseQueryIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)

	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := from.Add(3 * time.Hour)
	seedRankTestData(t, database, from)

	target, err := url.Parse(database.endpoint)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newRankFaultProxy(target)
	server := httptest.NewServer(proxy)
	defer server.Close()
	defer close(proxy.release)

	client, err := NewClient(Config{
		Endpoint: server.URL, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 2 * time.Second,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scopeA, err := TenantScope(rankTenantA)
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: from, To: to}

	summary, err := client.Summary(context.Background(), scopeA, filter)
	if err != nil {
		t.Fatal(err)
	}
	assertRankSummary(t, summary, Summary{
		MetricVersion: MetricVersion, RequestCount: 4, RequestBytes: 330, ResponseBytes: 3300,
		TotalBytes: 3630, AverageBandwidthBPS: 3300 * 8.0 / (3 * 3600), Status2xx: 1,
		Status3xx: 1, Status4xx: 1, Status5xx: 1, SecurityEvents: 2, SecurityEventRows: 2,
		CacheHitRequests: 4, CacheHitBytes: 3630, UniqueClientIPs: 4,
	})
	trend, err := client.Trend(context.Background(), scopeA, filter)
	if err != nil {
		t.Fatal(err)
	}
	assertRankTrend(t, trend, from)

	service, err := NewService(client)
	if err != nil {
		t.Fatal(err)
	}
	tenantActor := Actor{ScopeKind: "tenant", TenantID: rankTenantA, Permissions: []string{ReadPermission}}
	platformActor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	request := QueryRequest{Audience: AudienceTenant, From: from, To: to}
	serviceSummary, err := service.Summary(context.Background(), tenantActor, request)
	if err != nil {
		t.Fatal(err)
	}
	assertRankSummary(t, serviceSummary, summary)
	serviceTrend, err := service.Trend(context.Background(), tenantActor, request)
	if err != nil {
		t.Fatal(err)
	}
	assertRankTrend(t, serviceTrend, from)
	request.Audience = AudiencePlatform
	request.TenantID = rankTenantA
	platformSummary, err := service.Summary(context.Background(), platformActor, request)
	if err != nil {
		t.Fatal(err)
	}
	assertRankSummary(t, platformSummary, summary)

	tenantHandler := newRankIntegrationHandler(t, service, tenantActor, HandlerConfig{})
	platformHandler := newRankIntegrationHandler(t, service, platformActor, HandlerConfig{})
	assertRankHandlerQueries(t, database, tenantHandler, platformHandler, from, to, summary)
	assertRankStorageFailures(t, service, tenantActor, proxy, from, to)
}

func TestAnalyticsClickHouseRankReplacementWindowIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	if err := database.execute(context.Background(), "SYSTEM STOP MERGES access_events", true, nil); err != nil {
		t.Fatal(err)
	}
	mergesStopped := true
	t.Cleanup(func() {
		if mergesStopped {
			_ = database.execute(context.Background(), "SYSTEM START MERGES access_events", true, nil)
		}
	})

	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := from.Add(time.Hour)
	ingested := time.Now().UTC().Add(-10 * time.Second).Truncate(time.Millisecond)
	tombstonedOld := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-window-tombstoned", from.Add(10*time.Minute), rankTenantA, rankSiteA3, rankNodeA3,
			"stale.example", "/stale", "2001:db8::10", "ZZ", "stale-carrier", 200, 10, 100),
		IngestedAt: ingested,
	}
	tombstone := tombstonedOld
	tombstone.OccurredAt = to.Add(time.Minute)
	tombstone.SiteID = rankSiteA2
	tombstone.NodeID = rankNodeA2
	tombstone.Host = "outside.example"
	tombstone.Path = "/outside"
	tombstone.ClientIP = "2001:db8::20"
	tombstone.CountryCode = "GB"
	tombstone.Carrier = "outside-carrier"
	tombstone.ResponseBytes = 1000
	tombstone.IngestedAt = ingested.Add(time.Second)

	promotedOld := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-window-promoted", from.Add(-time.Minute), rankTenantA, rankSiteA2, rankNodeA2,
			"old.example", "/old", "2001:db8::30", "FR", "old-carrier", 200, 20, 200),
		IngestedAt: ingested,
	}
	promoted := promotedOld
	promoted.OccurredAt = from.Add(20 * time.Minute)
	promoted.SiteID = rankSiteA1
	promoted.NodeID = rankNodeA1
	promoted.Host = "latest.example"
	promoted.Path = "/latest"
	promoted.ClientIP = "2001:db8::40"
	promoted.CountryCode = "CN"
	promoted.Carrier = "latest-carrier"
	promoted.ResponseBytes = 222
	promoted.IngestedAt = ingested.Add(2 * time.Second)

	foreign := promoted
	foreign.TenantID = rankTenantB
	foreign.SiteID = rankSiteB
	foreign.NodeID = rankNodeB
	foreign.Host = "foreign.example"
	foreign.Path = "/foreign"
	foreign.ClientIP = "2001:db8::b"
	foreign.CountryCode = "US"
	foreign.Carrier = "foreign-carrier"
	foreign.ResponseBytes = 9999
	foreign.IngestedAt = ingested.Add(3 * time.Second)
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{tombstonedOld, promotedOld})
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{tombstone, promoted, foreign})

	client := newRankIntegrationClient(t, database)
	scope, err := TenantScope(rankTenantA)
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: from, To: to}
	want := map[RankDimension]string{
		RankByURL: "/latest", RankByIP: "2001:db8::40", RankByDomain: "latest.example",
		RankByRegion: "CN", RankByCarrier: "latest-carrier",
	}
	for dimension, key := range want {
		page, rankErr := client.Rank(context.Background(), scope, filter, dimension, 1, "")
		if rankErr != nil || len(page.Items) != 1 || page.Items[0].Key != key ||
			page.Items[0].RequestCount != 1 || page.Items[0].ResponseBytes != 222 || page.NextCursor != "" {
			t.Fatalf("%s replacement rank = %#v, error = %v", dimension, page, rankErr)
		}
	}
	tombstoneFilter := Filter{From: from, To: to, SiteID: rankSiteA3, NodeID: rankNodeA3}
	for dimension := range want {
		page, rankErr := client.Rank(context.Background(), scope, tombstoneFilter, dimension, 10, "")
		if rankErr != nil || len(page.Items) != 0 {
			t.Fatalf("%s tombstoned rank = %#v, error = %v", dimension, page, rankErr)
		}
	}
	for _, authorityFilter := range []Filter{
		{From: from, To: to, SiteID: rankSiteA3},
		{From: from, To: to, NodeID: rankNodeA3},
		{From: from, To: to, SiteID: rankSiteA2},
		{From: from, To: to, NodeID: rankNodeA2},
	} {
		page, rankErr := client.Rank(context.Background(), scope, authorityFilter, RankByURL, 10, "")
		if rankErr != nil || len(page.Items) != 0 {
			t.Fatalf("stale authority rank = %#v, error = %v", page, rankErr)
		}
	}

	logClient, err := analyticslog.NewClient(analyticslog.ClientConfig{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 3 * time.Second,
		CursorKeyring: analyticslog.CursorKeyring{ActiveKID: "rank-test", Keys: map[string][]byte{
			"rank-test": bytes.Repeat([]byte{0x52}, 32),
		}},
	}, database.http)
	if err != nil {
		t.Fatal(err)
	}
	logService, err := analyticslog.NewService(logClient)
	if err != nil {
		t.Fatal(err)
	}
	actor := analyticslog.Actor{
		ScopeKind: "tenant", TenantID: rankTenantA, Permissions: []string{analyticslog.ReadPermission},
	}
	tombstonedRaw, err := logService.ListAccess(context.Background(), actor, analyticslog.QueryRequest{
		Audience: analyticslog.AudienceTenant,
		Filter: analyticslog.Filter{
			From: from, To: to, SiteID: rankSiteA3, NodeID: rankNodeA3,
		},
		Limit: 10,
	})
	if err != nil || len(tombstonedRaw.Items) != 0 {
		t.Fatalf("tombstoned raw page = %#v, error = %v", tombstonedRaw, err)
	}
	raw, err := logService.ListAccess(context.Background(), actor, analyticslog.QueryRequest{
		Audience: analyticslog.AudienceTenant,
		Filter:   analyticslog.Filter{From: from, To: to},
		Limit:    10,
	})
	if err != nil || len(raw.Items) != 1 || raw.Items[0].EventID != promoted.EventID || raw.Items[0].URIPath != "/latest" {
		t.Fatalf("replacement raw page = %#v, error = %v", raw, err)
	}

	equalOld := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-equal-version", from.Add(-time.Minute), rankTenantC, rankSiteC, rankNodeC,
			"equal-old.example", "/equal-old", "2001:db8::50", "DE", "equal-old-carrier", 200, 30, 300),
		IngestedAt: ingested.Add(4 * time.Second),
	}
	equalLatest := equalOld
	equalLatest.OccurredAt = from.Add(30 * time.Minute)
	equalLatest.Host = "equal-latest.example"
	equalLatest.Path = "/equal-latest"
	equalLatest.ClientIP = "2001:db8::60"
	equalLatest.CountryCode = "JP"
	equalLatest.Carrier = "equal-latest-carrier"
	equalLatest.ResponseBytes = 333
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{equalOld})
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{equalLatest})
	equalScope, err := TenantScope(rankTenantC)
	if err != nil {
		t.Fatal(err)
	}
	equalPage, err := client.Rank(context.Background(), equalScope, filter, RankByURL, 10, "")
	if err != nil || len(equalPage.Items) != 1 || equalPage.Items[0].Key != "/equal-latest" ||
		equalPage.Items[0].ResponseBytes != 333 {
		t.Fatalf("equal-ingested-at deterministic replacement = %#v, error = %v", equalPage, err)
	}
}

func TestAnalyticsClickHouseRefererFiltersIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	if err := database.execute(context.Background(), "SYSTEM STOP MERGES access_events", true, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.execute(context.Background(), "SYSTEM START MERGES access_events", true, nil) })

	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := from.Add(time.Hour)
	ingested := time.Now().UTC().Add(-10 * time.Second).Truncate(time.Millisecond)
	latest := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-referer-replaced", from.Add(10*time.Minute), rankTenantA, rankSiteA1, rankNodeA1,
			"cdn.example.test", "/latest", "2001:db8::71", "CN", "carrier-a", 200, 10, 222),
		IngestedAt: ingested.Add(time.Second),
	}
	latest.ListenPort = 443
	latest.RequestHeaders = map[string]string{"rEfErEr": "https://source.example/latest"}
	stale := latest
	stale.ResponseBytes = 999
	stale.RequestHeaders = map[string]string{"Referer": "https://source.example/stale"}
	stale.IngestedAt = ingested
	missing := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-referer-missing", from.Add(20*time.Minute), rankTenantA, rankSiteA2, rankNodeA2,
			"static.example.test", "/missing", "2001:db8::72", "US", "carrier-b", 200, 10, 100),
		IngestedAt: ingested.Add(2 * time.Second),
	}
	missing.ListenPort = 443
	wrongPort := latest
	wrongPort.EventID = "rank-referer-port-80"
	wrongPort.ListenPort = 80
	wrongPort.ResponseBytes = 500
	wrongPort.IngestedAt = ingested.Add(3 * time.Second)
	foreign := latest
	foreign.EventID = "rank-referer-foreign"
	foreign.TenantID = rankTenantB
	foreign.SiteID = rankSiteB
	foreign.NodeID = rankNodeB
	foreign.ResponseBytes = 1000
	foreign.IngestedAt = ingested.Add(4 * time.Second)
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{stale, latest, missing, wrongPort, foreign})

	client := newRankIntegrationClient(t, database)
	scope, err := TenantScope(rankTenantA)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Rank(context.Background(), scope, Filter{
		From: from, To: to, Domain: "CDN.example.test. static.example.test", ListenPort: 443,
	}, RankByReferer, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(page.Items, []RankItem{
		{Key: "https://source.example/latest", RequestCount: 1, ResponseBytes: 222},
		{Key: "__unknown__", RequestCount: 1, ResponseBytes: 100},
	}) {
		t.Fatalf("referer page = %#v", page)
	}
}

func newRankIntegrationClient(t *testing.T, database *rankTestDatabase) *Client {
	t.Helper()
	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 3 * time.Second,
	}, database.http)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func assertRankHandlerQueries(
	t *testing.T,
	database *rankTestDatabase,
	tenantHandler, platformHandler *Handler,
	from, to time.Time,
	wantSummary Summary,
) {
	t.Helper()
	base := rankQueryValues(from, to)

	response := rankGET(t, tenantHandler, "/v1/analytics/summary", base)
	var summaryResponse analyticsSummaryResponse
	rankDecodeOK(t, response, &summaryResponse)
	assertRankSummary(t, summaryResponse.Data, wantSummary)
	if summaryResponse.Meta.Timezone != "UTC" || summaryResponse.Meta.From != from.Format(time.RFC3339) {
		t.Fatalf("summary metadata = %#v", summaryResponse.Meta)
	}

	response = rankGET(t, tenantHandler, "/v1/analytics/hourly-trend", base)
	var trend trendResponse
	rankDecodeOK(t, response, &trend)
	if len(trend.Data) != 2 || trend.Data[0].Hour != from.Format(time.RFC3339) ||
		trend.Data[1].Hour != from.Add(time.Hour).Format(time.RFC3339) {
		t.Fatalf("handler trend = %#v", trend.Data)
	}

	adminValues := rankQueryValues(from, to)
	adminValues.Set("tenant_id", rankTenantA)
	response = rankGET(t, platformHandler, "/v1/admin/analytics/summary", adminValues)
	var targeted analyticsSummaryResponse
	rankDecodeOK(t, response, &targeted)
	assertRankSummary(t, targeted.Data, wantSummary)

	response = rankGET(t, platformHandler, "/v1/admin/analytics/summary", rankQueryValues(from, to))
	var all analyticsSummaryResponse
	rankDecodeOK(t, response, &all)
	if all.Data.RequestCount != 5 || all.Data.ResponseBytes != 12300 || all.Data.SecurityEvents != 3 {
		t.Fatalf("platform summary = %#v", all.Data)
	}

	for key, value := range map[string]string{"site_id": rankSiteB, "node_id": rankNodeB} {
		values := rankQueryValues(from, to)
		values.Set(key, value)
		response = rankGET(t, tenantHandler, "/v1/analytics/summary", values)
		var isolated analyticsSummaryResponse
		rankDecodeOK(t, response, &isolated)
		if isolated.Data.RequestCount != 0 || isolated.Data.SecurityEvents != 0 {
			t.Fatalf("tenant query with foreign %s leaked data: %#v", key, isolated.Data)
		}
	}

	values := rankQueryValues(from, to)
	values.Set("site_id", rankSiteA1)
	values.Set("node_id", rankNodeA1)
	response = rankGET(t, tenantHandler, "/v1/analytics/summary", values)
	var filtered analyticsSummaryResponse
	rankDecodeOK(t, response, &filtered)
	if filtered.Data.RequestCount != 3 || filtered.Data.ResponseBytes != 2600 || filtered.Data.SecurityEvents != 1 {
		t.Fatalf("site/node filtered summary = %#v", filtered.Data)
	}

	dimensions := []struct {
		name string
		keys []string
	}{
		{name: "url", keys: []string{"/alpha", "/beta", "/tie-a", "/tie-b"}},
		{name: "ip", keys: []string{"2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"}},
		{name: "domain", keys: []string{"alpha.example", "beta.example", "tie-a.example", "tie-b.example"}},
		{name: "region", keys: []string{"CN", "US", "DE", "JP"}},
		{name: "carrier", keys: []string{"carrier-a", "carrier-b", "carrier-c", "carrier-d"}},
	}
	for _, dimension := range dimensions {
		values = rankQueryValues(from, to)
		values.Set("limit", "100")
		response = rankGET(t, tenantHandler, "/v1/analytics/top/"+dimension.name, values)
		page := rankDecodePage(t, response)
		if page.Dimension != RankDimension(dimension.name) || page.Page.NextCursor != "" {
			t.Fatalf("%s page metadata = %#v", dimension.name, page)
		}
		if got := rankItemKeys(page.Data); !reflect.DeepEqual(got, dimension.keys) {
			t.Fatalf("%s rank keys = %v, want %v", dimension.name, got, dimension.keys)
		}
		if page.Data[2].ResponseBytes != 700 || page.Data[3].ResponseBytes != 700 ||
			page.Data[2].RequestCount != 1 || page.Data[3].RequestCount != 1 {
			t.Fatalf("%s tie ordering was not exercised: %#v", dimension.name, page.Data)
		}
	}

	values = rankQueryValues(from, to)
	values.Set("site_id", rankSiteA1)
	values.Set("node_id", rankNodeA1)
	values.Set("limit", "100")
	response = rankGET(t, tenantHandler, "/v1/analytics/top/url", values)
	filteredRank := rankDecodePage(t, response)
	if got := rankItemKeys(filteredRank.Data); !reflect.DeepEqual(got, []string{"/alpha", "/beta", "/tie-a"}) {
		t.Fatalf("site/node filtered rank = %v", got)
	}

	values = rankQueryValues(from, to)
	values.Set("limit", "2")
	first := rankDecodePage(t, rankGET(t, tenantHandler, "/v1/analytics/top/url", values))
	if got := rankItemKeys(first.Data); !reflect.DeepEqual(got, []string{"/alpha", "/beta"}) || first.Page.NextCursor == "" {
		t.Fatalf("first rank page = %#v", first)
	}
	snapshot, err := time.Parse(time.RFC3339Nano, first.Page.SnapshotAt)
	if err != nil {
		t.Fatal(err)
	}
	late := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-late", from.Add(10*time.Minute), rankTenantA, rankSiteA1, rankNodeA1,
			"late.example", "/late", "2001:db8::99", "GB", "carrier-late", 200, 1000, 10000),
		IngestedAt: snapshot.Add(time.Millisecond),
	}
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{late})

	values.Set("cursor", first.Page.NextCursor)
	second := rankDecodePage(t, rankGET(t, tenantHandler, "/v1/analytics/top/url", values))
	if got := rankItemKeys(second.Data); !reflect.DeepEqual(got, []string{"/tie-a", "/tie-b"}) || second.Page.NextCursor != "" {
		t.Fatalf("second rank page = %#v", second)
	}
	if first.Page.SnapshotAt != second.Page.SnapshotAt {
		t.Fatalf("snapshot changed across pages: %q != %q", first.Page.SnapshotAt, second.Page.SnapshotAt)
	}
	combined := append(rankItemKeys(first.Data), rankItemKeys(second.Data)...)
	if !reflect.DeepEqual(combined, []string{"/alpha", "/beta", "/tie-a", "/tie-b"}) {
		t.Fatalf("two rank pages contain gaps or duplicates: %v", combined)
	}
}

func assertRankStorageFailures(
	t *testing.T,
	service *Service,
	actor Actor,
	proxy *rankFaultProxy,
	from, to time.Time,
) {
	t.Helper()
	path := "/v1/analytics/summary"
	values := rankQueryValues(from, to)

	proxy.mode.Store(rankProxyUnavailable)
	handler := newRankIntegrationHandler(t, service, actor, HandlerConfig{})
	assertRankHandlerError(t, rankGET(t, handler, path, values), http.StatusServiceUnavailable, "analytics_storage_unavailable")

	proxy.mode.Store(rankProxyBlocked)
	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, path+"?"+values.Encode(), nil).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-proxy.entered:
	case <-time.After(time.Second):
		t.Fatal("cancel test did not reach ClickHouse proxy")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled analytics query did not stop")
	}
	assertRankHandlerError(t, response, http.StatusRequestTimeout, "analytics_request_cancelled")

	timeoutHandler := newRankIntegrationHandler(t, service, actor, HandlerConfig{QueryTimeout: 40 * time.Millisecond})
	assertRankHandlerError(t, rankGET(t, timeoutHandler, path, values), http.StatusGatewayTimeout, "analytics_query_timeout")
}

type rankTestDatabase struct {
	endpoint string
	name     string
	username string
	password string
	http     *http.Client
}

func newRankTestDatabase(t *testing.T) *rankTestDatabase {
	t.Helper()
	endpoint := strings.TrimSpace(os.Getenv("TEST_CLICKHOUSE_URL"))
	database := strings.TrimSpace(os.Getenv("TEST_CLICKHOUSE_DATABASE"))
	if endpoint == "" && database == "" {
		t.Skip("set TEST_CLICKHOUSE_URL and TEST_CLICKHOUSE_DATABASE to run the ClickHouse query integration test")
	}
	if endpoint == "" || database == "" {
		t.Fatal("TEST_CLICKHOUSE_URL and TEST_CLICKHOUSE_DATABASE must both be set")
	}
	lowerDatabase := strings.ToLower(database)
	taskOwned := strings.HasPrefix(lowerDatabase, "test_") || strings.HasPrefix(lowerDatabase, "task_") ||
		strings.Contains(lowerDatabase, "_test_") || strings.Contains(lowerDatabase, "_task_") ||
		strings.HasSuffix(lowerDatabase, "_test") || strings.HasSuffix(lowerDatabase, "_task")
	if !validIdentifier(database) || !taskOwned {
		t.Fatal("TEST_CLICKHOUSE_DATABASE must be a valid task-owned identifier with a delimited test or task marker")
	}
	username := os.Getenv("TEST_CLICKHOUSE_USERNAME")
	password := os.Getenv("TEST_CLICKHOUSE_PASSWORD")
	httpClient := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if _, err := NewClient(Config{
		Endpoint: endpoint, Database: database, Username: username, Password: password,
	}, httpClient); err != nil {
		t.Fatalf("invalid TEST_CLICKHOUSE configuration: %v", err)
	}
	return &rankTestDatabase{
		endpoint: endpoint, name: database, username: username, password: password, http: httpClient,
	}
}

func (database *rankTestDatabase) reset(t *testing.T) {
	t.Helper()
	parameters := url.Values{"param_database": {database.name}}
	if err := database.execute(context.Background(),
		"DROP DATABASE IF EXISTS {database:Identifier} SYNC", false, parameters); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := database.execute(ctx, "DROP DATABASE IF EXISTS {database:Identifier} SYNC", false, parameters); err != nil {
			t.Errorf("cleanup task-owned ClickHouse database: %v", err)
		}
	})
	if err := database.execute(context.Background(),
		"CREATE DATABASE {database:Identifier}", false, parameters); err != nil {
		t.Fatal(err)
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate analytics integration test")
	}
	controlAPIRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	migrationRoot := filepath.Join(controlAPIRoot, "..", "..", "infra", "clickhouse", "migrations")
	if override := os.Getenv("ANALYTICS_TEST_CH_MIGRATIONS"); override != "" {
		migrationRoot = override
	}
	for _, name := range []string{
		"001_analytics.up.sql", "002_analytics_authority_capture.up.sql", "003_analytics_hourly_rollup.up.sql", "004_analytics_version_evidence.up.sql",
	} {
		migration, err := os.ReadFile(filepath.Join(migrationRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range strings.Split(string(migration), ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			if err := database.execute(context.Background(), statement, true, nil); err != nil {
				t.Fatalf("apply analytics schema %s: %v", name, err)
			}
		}
	}
}

func (database *rankTestDatabase) execute(
	ctx context.Context,
	query string,
	useDatabase bool,
	parameters url.Values,
) error {
	target, err := url.Parse(database.endpoint)
	if err != nil {
		return errors.New("parse ClickHouse test endpoint")
	}
	values := target.Query()
	if useDatabase {
		values.Set("database", database.name)
	}
	values.Set("max_execution_time", "10")
	values.Set("timeout_overflow_mode", "throw")
	values.Set("date_time_input_format", "best_effort")
	for key, entries := range parameters {
		for _, entry := range entries {
			values.Add(key, entry)
		}
	}
	target.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(query))
	if err != nil {
		return errors.New("build ClickHouse test request")
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("Accept-Encoding", "identity")
	if database.username != "" {
		request.SetBasicAuth(database.username, database.password)
	}
	response, err := database.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("execute ClickHouse test request")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("ClickHouse test request returned HTTP %d", response.StatusCode)
	}
	return nil
}

func insertRankRows[T any](t *testing.T, database *rankTestDatabase, query string, rows []T) {
	t.Helper()
	var body bytes.Buffer
	body.WriteString(query)
	body.WriteByte('\n')
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.execute(context.Background(), body.String(), true, nil); err != nil {
		t.Fatal(err)
	}
}

type rankAccessRow struct {
	AccessEvent
	IngestedAt time.Time `json:"ingested_at"`
}

type rankSecurityRow struct {
	SecurityEvent
	IngestedAt time.Time `json:"ingested_at"`
}

func seedRankTestData(t *testing.T, database *rankTestDatabase, from time.Time) {
	t.Helper()
	ingested := time.Now().UTC().Add(-10 * time.Second).Truncate(time.Millisecond)
	oldAlpha := rankAccessRow{
		AccessEvent: rankAccessEvent("rank-alpha", from.Add(15*time.Minute), rankTenantA, rankSiteA1, rankNodeA1,
			"stale.example", "/stale", "2001:db8::10", "ZZ", "stale-carrier", 500, 1, 10),
		IngestedAt: ingested,
	}
	rows := []rankAccessRow{
		oldAlpha,
		{
			AccessEvent: rankAccessEvent("rank-alpha", from.Add(15*time.Minute), rankTenantA, rankSiteA1, rankNodeA1,
				"alpha.example", "/alpha", "2001:db8::1", "CN", "carrier-a", 200, 100, 1000),
			IngestedAt: ingested.Add(time.Second),
		},
		{
			AccessEvent: rankAccessEvent("rank-beta", from.Add(25*time.Minute), rankTenantA, rankSiteA1, rankNodeA1,
				"beta.example", "/beta", "2001:db8::2", "US", "carrier-b", 302, 90, 900),
			IngestedAt: ingested.Add(2 * time.Second),
		},
		{
			AccessEvent: rankAccessEvent("rank-tie-a", from.Add(75*time.Minute), rankTenantA, rankSiteA1, rankNodeA1,
				"tie-a.example", "/tie-a", "2001:db8::3", "DE", "carrier-c", 404, 70, 700),
			IngestedAt: ingested.Add(3 * time.Second),
		},
		{
			AccessEvent: rankAccessEvent("rank-tie-b", from.Add(85*time.Minute), rankTenantA, rankSiteA2, rankNodeA2,
				"tie-b.example", "/tie-b", "2001:db8::4", "JP", "carrier-d", 503, 70, 700),
			IngestedAt: ingested.Add(4 * time.Second),
		},
		{
			AccessEvent: rankAccessEvent("rank-tenant-b", from.Add(35*time.Minute), rankTenantB, rankSiteB, rankNodeB,
				"tenant-b.example", "/tenant-b", "2001:db8::b", "GB", "carrier-b2", 200, 900, 9000),
			IngestedAt: ingested.Add(5 * time.Second),
		},
	}
	insertRankRows(t, database, insertRankAccessSQL, rows)

	securityRows := []rankSecurityRow{
		{
			SecurityEvent: rankSecurityEvent("rank-security-a1", from.Add(20*time.Minute), rankTenantA, rankSiteA1, rankNodeA1, "block"),
			IngestedAt:    ingested.Add(6 * time.Second),
		},
		{
			SecurityEvent: rankSecurityEvent("rank-security-a2", from.Add(80*time.Minute), rankTenantA, rankSiteA2, rankNodeA2, "challenge"),
			IngestedAt:    ingested.Add(7 * time.Second),
		},
		{
			SecurityEvent: rankSecurityEvent("rank-security-b", from.Add(40*time.Minute), rankTenantB, rankSiteB, rankNodeB, "block"),
			IngestedAt:    ingested.Add(8 * time.Second),
		},
	}
	insertRankRows(t, database, insertRankSecuritySQL, securityRows)
}

func rankAccessEvent(
	eventID string,
	occurredAt time.Time,
	tenantID, siteID, nodeID, host, path, clientIP, countryCode, carrier string,
	status uint16,
	requestBytes, responseBytes uint64,
) AccessEvent {
	return AccessEvent{
		MetricVersion: MetricVersion, EventID: eventID, OccurredAt: occurredAt, TenantID: tenantID,
		SiteID: siteID, NodeID: nodeID, RequestID: eventID + "-request", TraceID: eventID + "-trace",
		ConfigVersion: rankConfigA, Host: host, Path: path, ClientIP: clientIP, CountryCode: countryCode,
		Carrier: carrier, Method: "GET", Protocol: "HTTP/2", CacheStatus: "HIT", UpstreamResult: "ok",
		StatusCode: status, RequestBytes: requestBytes, ResponseBytes: responseBytes, DurationUS: 1000,
	}
}

func rankSecurityEvent(
	eventID string,
	occurredAt time.Time,
	tenantID, siteID, nodeID, action string,
) SecurityEvent {
	return SecurityEvent{
		MetricVersion: MetricVersion, EventID: eventID, OccurredAt: occurredAt, TenantID: tenantID,
		SiteID: siteID, NodeID: nodeID, RequestID: eventID + "-request", TraceID: eventID + "-trace",
		ConfigVersion: "config-v1", Host: "security.example", Path: "/protected", ClientIP: "2001:db8::f",
		CountryCode: "CN", Carrier: "carrier-security", EventType: "waf", Action: action, Severity: "medium",
		RuleID: "rule-1", StatusCode: 403, RequestBytes: 10, ResponseBytes: 20,
	}
}

func assertRankSummary(t *testing.T, got, want Summary) {
	t.Helper()
	delta := got.AverageBandwidthBPS - want.AverageBandwidthBPS
	if delta < 0 {
		delta = -delta
	}
	got.AverageBandwidthBPS = 0
	want.AverageBandwidthBPS = 0
	if !reflect.DeepEqual(got, want) || delta > 0.000001 {
		t.Fatalf("summary = %#v, want %#v, bandwidth delta=%f", got, want, delta)
	}
}

func assertRankTrend(t *testing.T, trend []TrendPoint, from time.Time) {
	t.Helper()
	if len(trend) != 2 {
		t.Fatalf("trend points = %#v", trend)
	}
	want := []TrendPoint{
		{
			Hour: from, MetricVersion: MetricVersion, RequestCount: 2, RequestBytes: 190, ResponseBytes: 1900,
			TotalBytes: 2090, AverageBandwidthBPS: 1900 * 8.0 / 3600, Status2xx: 1, Status3xx: 1,
			SecurityEvents: 1, SecurityEventRows: 1, CacheHitRequests: 2, CacheHitBytes: 2090, UniqueClientIPs: 2,
		},
		{
			Hour: from.Add(time.Hour), MetricVersion: MetricVersion, RequestCount: 2, RequestBytes: 140,
			ResponseBytes: 1400, TotalBytes: 1540, AverageBandwidthBPS: 1400 * 8.0 / 3600,
			Status4xx: 1, Status5xx: 1, SecurityEvents: 1, SecurityEventRows: 1, CacheHitRequests: 2, CacheHitBytes: 1540, UniqueClientIPs: 2,
		},
	}
	for index := range want {
		actualBandwidth := trend[index].AverageBandwidthBPS
		wantedBandwidth := want[index].AverageBandwidthBPS
		trend[index].AverageBandwidthBPS = 0
		want[index].AverageBandwidthBPS = 0
		if !reflect.DeepEqual(trend[index], want[index]) || actualBandwidth-wantedBandwidth > 0.000001 ||
			wantedBandwidth-actualBandwidth > 0.000001 {
			t.Fatalf("trend[%d] = %#v, want %#v", index, trend[index], want[index])
		}
	}
}

func newRankIntegrationHandler(t *testing.T, service *Service, actor Actor, config HandlerConfig) *Handler {
	t.Helper()
	config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) { return actor, nil }, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func rankQueryValues(from, to time.Time) url.Values {
	return url.Values{"from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}}
}

func rankGET(t *testing.T, handler http.Handler, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path+"?"+values.Encode(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func rankDecodeOK(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatal(err)
	}
}

func rankDecodePage(t *testing.T, response *httptest.ResponseRecorder) rankResponse {
	t.Helper()
	var page rankResponse
	rankDecodeOK(t, response, &page)
	return page
}

func rankItemKeys(items []RankItem) []string {
	keys := make([]string, len(items))
	for index, item := range items {
		keys[index] = item.Key
	}
	return keys
}

func assertRankHandlerError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, status, response.Body.String())
	}
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error = %#v, want code %q", envelope.Error, code)
	}
	if strings.Contains(response.Body.String(), "ClickHouse") || strings.Contains(response.Body.String(), "127.0.0.1") {
		t.Fatalf("error response leaked storage detail: %s", response.Body.String())
	}
}

const (
	rankProxyForward int32 = iota
	rankProxyUnavailable
	rankProxyBlocked
)

type rankFaultProxy struct {
	reverseProxy *httputil.ReverseProxy
	mode         atomic.Int32
	entered      chan struct{}
	release      chan struct{}
}

func newRankFaultProxy(target *url.URL) *rankFaultProxy {
	return &rankFaultProxy{
		reverseProxy: httputil.NewSingleHostReverseProxy(target),
		entered:      make(chan struct{}, 1),
		release:      make(chan struct{}),
	}
}

func (proxy *rankFaultProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch proxy.mode.Load() {
	case rankProxyUnavailable:
		writer.WriteHeader(http.StatusServiceUnavailable)
	case rankProxyBlocked:
		select {
		case proxy.entered <- struct{}{}:
		default:
		}
		select {
		case <-request.Context().Done():
		case <-proxy.release:
		}
	default:
		proxy.reverseProxy.ServeHTTP(writer, request)
	}
}
