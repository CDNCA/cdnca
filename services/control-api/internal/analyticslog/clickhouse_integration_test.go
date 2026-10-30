package analyticslog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const requiredClickHouseVersion = "25.3.6.56"

type integrationDatabase struct {
	endpoint string
	name     string
	username string
	password string
	http     *http.Client
}

type integrationAccessRow struct {
	MetricVersion  uint16    `json:"metric_version"`
	EventID        string    `json:"event_id"`
	OccurredAt     time.Time `json:"occurred_at"`
	IngestedAt     time.Time `json:"ingested_at"`
	TenantID       string    `json:"tenant_id"`
	SiteID         string    `json:"site_id"`
	NodeID         string    `json:"node_id"`
	RequestID      string    `json:"request_id"`
	TraceID        string    `json:"trace_id"`
	ConfigVersion  string    `json:"config_version_id"`
	Host           string    `json:"host"`
	ListenPort     uint16    `json:"listen_port"`
	Path           string    `json:"path"`
	ClientIP       string    `json:"client_ip"`
	CountryCode    string    `json:"country_code"`
	Carrier        string    `json:"carrier"`
	Method         string    `json:"method"`
	Protocol       string    `json:"protocol"`
	CacheStatus    string    `json:"cache_status"`
	UpstreamResult string    `json:"upstream_result"`
	UpstreamAddr   string    `json:"upstream_addr,omitempty"`
	StatusCode     uint16    `json:"status_code"`
	RequestBytes   uint64    `json:"request_bytes"`
	ResponseBytes  uint64    `json:"response_bytes"`
	DurationUS     uint64    `json:"duration_us"`
}

type integrationSecurityRow struct {
	MetricVersion uint16    `json:"metric_version"`
	EventID       string    `json:"event_id"`
	OccurredAt    time.Time `json:"occurred_at"`
	IngestedAt    time.Time `json:"ingested_at"`
	TenantID      string    `json:"tenant_id"`
	SiteID        string    `json:"site_id"`
	NodeID        string    `json:"node_id"`
	RequestID     string    `json:"request_id"`
	TraceID       string    `json:"trace_id"`
	ConfigVersion string    `json:"config_version_id"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	ClientIP      string    `json:"client_ip"`
	CountryCode   string    `json:"country_code"`
	Carrier       string    `json:"carrier"`
	EventType     string    `json:"event_type"`
	Action        string    `json:"action"`
	Severity      string    `json:"severity"`
	RuleID        string    `json:"rule_id"`
	StatusCode    uint16    `json:"status_code"`
	RequestBytes  uint64    `json:"request_bytes"`
	ResponseBytes uint64    `json:"response_bytes"`
	// Attack evidence (021); omitted rows keep the column defaults.
	PolicyID           string `json:"policy_id,omitempty"`
	Detector           string `json:"detector,omitempty"`
	Matched            string `json:"matched,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	RequestBodyExcerpt string `json:"request_body_excerpt,omitempty"`
	EventCount         uint32 `json:"event_count,omitempty"`
}

type countingHTTPClient struct {
	base  *http.Client
	calls atomic.Int64
}

func (client *countingHTTPClient) Do(request *http.Request) (*http.Response, error) {
	client.calls.Add(1)
	return client.base.Do(request)
}

func TestClickHouseAnalyticsLogIntegration(t *testing.T) {
	database := newIntegrationDatabase(t)
	database.create(t)
	assertClickHouseVersion(t, database)

	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	to := from.Add(2 * time.Hour)
	ingested := time.Now().UTC().Add(-20 * time.Second).Truncate(time.Millisecond)
	seedIntegrationRows(t, database, from, ingested)
	debugParameters := filterParameters(scope{tenantID: tenantA}, Filter{From: from, To: to}, 10)
	debugParameters.Set("param_has_snapshot", "0")
	debugParameters.Set("param_snapshot_ms", "0")
	debugParameters.Set("param_has_cursor", "0")
	debugParameters.Set("param_cursor_occurred_at_ms", "0")
	debugParameters.Set("param_cursor_event_id", "")
	if _, err := database.execute(context.Background(), accessPageSQL, true, debugParameters); err != nil {
		t.Fatalf("execute access page SQL: %v", err)
	}

	counter := &countingHTTPClient{base: database.http}
	client, err := NewClient(ClientConfig{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 3 * time.Second, CursorKeyring: testLogCursorKeyring(),
	}, counter)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, client)
	tenantActor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	platformActor := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	tenantHandler := newIntegrationHandler(t, service, tenantActor)
	platformHandler := newIntegrationHandler(t, service, platformActor)

	first := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", queryValues(from, to)))
	if got := integrationAccessIDs(first.Data); strings.Join(got, ",") != "tie-z,tie-y,replace-me,event-b,event-a" {
		t.Fatalf("ordered ids=%v", got)
	}
	for _, item := range first.Data {
		if item.RequestID != item.EventID+"-request" || item.TraceID != item.EventID+"-trace" || item.ConfigVersion != configA {
			t.Fatalf("access authority fields=%#v", item)
		}
		if item.ListenPort != 443 {
			t.Fatalf("access listen_port=%d event_id=%s, want 443", item.ListenPort, item.EventID)
		}
		// fix-upstreamaddr (CH 028): the origin address comes from upstream_addr_state,
		// the diagnostic upstream_result is unchanged; rows without it read "".
		if wantAddr := map[bool]string{true: "10.0.0.1:80, 10.0.0.2:80"}[item.EventID == "replace-me"]; item.UpstreamAddr != wantAddr || item.UpstreamResult != "ok" {
			t.Fatalf("access upstream_addr=%q upstream_result=%q event_id=%s", item.UpstreamAddr, item.UpstreamResult, item.EventID)
		}
		if item.EventID == "replace-me" && (item.URIPath != "/new" || item.StatusCode != 503) {
			t.Fatalf("replacement row=%#v", item)
		}
	}
	if first.Meta.SnapshotAt == "" || first.Meta.NextCursor != "" || first.Meta.Consistency != "snapshot" ||
		first.Meta.ReplacementConsistency != "latest_event_id_at_snapshot" || first.Meta.Pagination != "keyset" {
		t.Fatalf("access metadata=%#v", first.Meta)
	}

	filtered := queryValues(from, to)
	filtered.Set("site_id", siteA)
	filtered.Set("node_id", nodeA)
	filtered.Set("client_ip", "2001:db8::3")
	filtered.Set("uri_path", "/new")
	filtered.Set("status_code", "503")
	filtered.Set("method", "POST")
	filtered.Set("protocol", "HTTP/3")
	filtered.Set("cache_status", "MISS")
	filtered.Set("country_code", "CN")
	filtered.Set("carrier", "carrier-match")
	filteredPage := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", filtered))
	if got := integrationAccessIDs(filteredPage.Data); len(got) != 1 || got[0] != "replace-me" {
		t.Fatalf("all-filter result=%v", got)
	}
	filtered.Set("uri_path", "/ne")
	filtered.Set("uri_path_match", "prefix")
	if got := integrationAccessIDs(decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", filtered)).Data); len(got) != 1 || got[0] != "replace-me" {
		t.Fatalf("prefix filter result=%v", got)
	}
	encodedFiltered, _ := json.Marshal(filteredPage)
	for _, secret := range []string{"query-secret", "cookie-secret", "authorization-secret", "old-secret"} {
		if bytes.Contains(encodedFiltered, []byte(secret)) {
			t.Fatalf("access response leaked %q: %s", secret, encodedFiltered)
		}
	}

	foreign := queryValues(from, to)
	foreign.Set("site_id", "20000000-0000-4000-8000-00000000000b")
	if page := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", foreign)); len(page.Data) != 0 {
		t.Fatalf("tenant query leaked foreign site: %#v", page.Data)
	}
	platformValues := queryValues(from, to)
	platformValues.Set("tenant_id", tenantB)
	platformPage := decodeIntegrationAccessPage(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", platformValues))
	if got := integrationAccessIDs(platformPage.Data); len(got) != 1 || got[0] != "tenant-b" {
		t.Fatalf("platform explicit tenant result=%v", got)
	}
	capacityValues := queryValues(from, to)
	capacityValues.Set("tenant_id", "10000000-0000-4000-8000-00000000000c")
	capacityValues.Set("limit", "100")
	capacityFirst := decodeIntegrationAccessPage(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", capacityValues))
	if len(capacityFirst.Data) != 100 || capacityFirst.Meta.NextCursor == "" {
		t.Fatalf("capacity first page items=%d meta=%#v", len(capacityFirst.Data), capacityFirst.Meta)
	}
	capacityValues.Set("cursor", capacityFirst.Meta.NextCursor)
	capacitySecond := decodeIntegrationAccessPage(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", capacityValues))
	if len(capacitySecond.Data) != 1 || capacitySecond.Meta.NextCursor != "" ||
		capacitySecond.Meta.SnapshotAt != capacityFirst.Meta.SnapshotAt {
		t.Fatalf("capacity second page items=%d meta=%#v", len(capacitySecond.Data), capacitySecond.Meta)
	}
	capacityIDs := append(integrationAccessIDs(capacityFirst.Data), integrationAccessIDs(capacitySecond.Data)...)
	if len(capacityIDs) != 101 || len(uniqueStrings(capacityIDs)) != 101 {
		t.Fatalf("capacity pagination ids=%d unique=%d", len(capacityIDs), len(uniqueStrings(capacityIDs)))
	}

	values := queryValues(from, to)
	values.Set("limit", "2")
	pageOne := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", values))
	values.Set("cursor", pageOne.Meta.NextCursor)
	pageTwo := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", values))
	values.Set("cursor", pageTwo.Meta.NextCursor)
	pageThree := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", values))
	pagedIDs := append(integrationAccessIDs(pageOne.Data), integrationAccessIDs(pageTwo.Data)...)
	pagedIDs = append(pagedIDs, integrationAccessIDs(pageThree.Data)...)
	if strings.Join(pagedIDs, ",") != "tie-z,tie-y,replace-me,event-b,event-a" ||
		len(uniqueStrings(pagedIDs)) != 5 || pageThree.Meta.NextCursor != "" ||
		pageOne.Meta.SnapshotAt != pageTwo.Meta.SnapshotAt || pageOne.Meta.SnapshotAt != pageThree.Meta.SnapshotAt {
		t.Fatalf("paged ids=%v metadata=%#v/%#v/%#v", pagedIDs, pageOne.Meta, pageTwo.Meta, pageThree.Meta)
	}
	beforeCursor := counter.calls.Load()
	values.Set("cursor", "payload.invalid-mac")
	assertHandlerError(t, doGET(tenantHandler, "/v1/analytics/logs/access", values), 422,
		"analytics_logs_capability_unsupported")
	if counter.calls.Load() != beforeCursor {
		t.Fatalf("unsupported cursor reached ClickHouse: before=%d after=%d", beforeCursor, counter.calls.Load())
	}

	lateBackdated := integrationAccess("late-backdated", from.Add(55*time.Minute), ingested.Add(-time.Hour), tenantA,
		siteA, nodeA, "/late", "2001:db8::99")
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{lateBackdated})
	afterInsert := decodeIntegrationAccessPage(t, doGET(tenantHandler, "/v1/analytics/logs/access", queryValues(from, to)))
	if got := integrationAccessIDs(afterInsert.Data); len(got) != 6 || got[0] != "late-backdated" {
		t.Fatalf("later backdated insert current view=%v", got)
	}

	clockTenant := "10000000-0000-4000-8000-00000000000d"
	clockRows := []integrationAccessRow{
		integrationAccess("clock-after", from.Add(15*time.Minute), time.Now().UTC().Add(24*time.Hour), clockTenant,
			"20000000-0000-4000-8000-00000000000d", "30000000-0000-4000-8000-00000000000d", "/after", "2001:db8::d"),
		integrationAccess("clock-before", from.Add(10*time.Minute), time.Now().UTC().Add(-24*time.Hour), clockTenant,
			"20000000-0000-4000-8000-00000000000d", "30000000-0000-4000-8000-00000000000d", "/before", "2001:db8::d"),
	}
	insertIntegrationRows(t, database, "access_events", clockRows)
	clockValues := queryValues(from, to)
	clockValues.Set("tenant_id", clockTenant)
	clockPage := decodeIntegrationAccessPage(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", clockValues))
	if got := integrationAccessIDs(clockPage.Data); strings.Join(got, ",") != "clock-before" {
		t.Fatalf("snapshot-filtered current view=%v", got)
	}

	equalTenant := "10000000-0000-4000-8000-00000000000e"
	equalVersion := ingested.Add(10 * time.Second)
	if _, err := database.execute(context.Background(), "SYSTEM STOP MERGES access_events", true, nil); err != nil {
		t.Fatal(err)
	}
	mergesStopped := true
	t.Cleanup(func() {
		if mergesStopped {
			_, _ = database.execute(context.Background(), "SYSTEM START MERGES access_events", true, nil)
		}
	})
	equalA := integrationAccess("equal-version", from.Add(20*time.Minute), equalVersion, equalTenant,
		"20000000-0000-4000-8000-00000000000e", "30000000-0000-4000-8000-00000000000e", "/one", "2001:db8::e")
	equalB := equalA
	equalB.Path = "/two"
	insertIntegrationRowsWithSettings(t, database, "access_events", []integrationAccessRow{equalA, equalB},
		url.Values{"optimize_on_insert": {"0"}})
	equalCountBody, err := database.execute(context.Background(), `SELECT toUInt32(count()) AS row_count
FROM access_events
WHERE tenant_id = toUUID({tenant_id:String}) AND event_id = {event_id:String}
FORMAT JSONEachRow`, true, url.Values{
		"param_tenant_id": {equalTenant}, "param_event_id": {equalA.EventID},
	})
	if err != nil {
		t.Fatal(err)
	}
	var equalCount struct {
		RowCount uint32 `json:"row_count"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(equalCountBody), &equalCount); err != nil || equalCount.RowCount != 2 {
		t.Fatalf("equal-version physical rows=%d decode=%v", equalCount.RowCount, err)
	}
	equalValues := queryValues(from, to)
	equalValues.Set("tenant_id", equalTenant)
	assertHandlerError(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", equalValues), 422,
		"analytics_logs_capability_unsupported")
	if _, err := database.execute(context.Background(), "SYSTEM START MERGES access_events", true, nil); err != nil {
		t.Fatal(err)
	}
	mergesStopped = false
	if _, err := database.execute(context.Background(), "OPTIMIZE TABLE access_events FINAL", true, nil); err != nil {
		t.Fatal(err)
	}
	equalCountBody, err = database.execute(context.Background(), `SELECT toUInt32(count()) AS row_count
FROM access_events
WHERE tenant_id = toUUID({tenant_id:String}) AND event_id = {event_id:String}
FORMAT JSONEachRow`, true, url.Values{
		"param_tenant_id": {equalTenant}, "param_event_id": {equalA.EventID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(equalCountBody), &equalCount); err != nil || equalCount.RowCount != 1 {
		t.Fatalf("merged equal-version physical rows=%d decode=%v", equalCount.RowCount, err)
	}
	assertHandlerError(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", equalValues), 422,
		"analytics_logs_capability_unsupported")

	boundaryTenant := "10000000-0000-4000-8000-00000000000f"
	boundaryRows := []integrationAccessRow{
		integrationAccess("boundary-c", from.Add(30*time.Minute), ingested, boundaryTenant,
			"20000000-0000-4000-8000-00000000000f", "30000000-0000-4000-8000-00000000000f", "/c", "2001:db8::f"),
		integrationAccess("boundary-b", from.Add(20*time.Minute), ingested.Add(time.Millisecond), boundaryTenant,
			"20000000-0000-4000-8000-00000000000f", "30000000-0000-4000-8000-00000000000f", "/b", "2001:db8::f"),
		integrationAccess("boundary-a", from.Add(10*time.Minute), ingested.Add(2*time.Millisecond), boundaryTenant,
			"20000000-0000-4000-8000-00000000000f", "30000000-0000-4000-8000-00000000000f", "/a", "2001:db8::f"),
	}
	insertIntegrationRows(t, database, "access_events", boundaryRows)
	boundaryValues := queryValues(from, to)
	boundaryValues.Set("tenant_id", boundaryTenant)
	boundaryValues.Set("limit", "2")
	boundaryFirst := decodeIntegrationAccessPage(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", boundaryValues))
	if got := integrationAccessIDs(boundaryFirst.Data); strings.Join(got, ",") != "boundary-c,boundary-b" ||
		boundaryFirst.Meta.NextCursor == "" {
		t.Fatalf("boundary first page ids=%v meta=%#v", got, boundaryFirst.Meta)
	}
	replacement := boundaryRows[2]
	replacement.IngestedAt = time.Now().UTC().Add(time.Second)
	replacement.OccurredAt = from.Add(40 * time.Minute)
	replacement.Path = "/a-new"
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{replacement})
	boundaryValues.Set("cursor", boundaryFirst.Meta.NextCursor)
	boundarySecond := decodeIntegrationAccessPage(t, doGET(platformHandler, "/v1/admin/analytics/logs/access", boundaryValues))
	if got := integrationAccessIDs(boundarySecond.Data); strings.Join(got, ",") != "boundary-a" ||
		boundarySecond.Data[0].URIPath != "/a" || boundarySecond.Meta.NextCursor != "" ||
		boundarySecond.Meta.SnapshotAt != boundaryFirst.Meta.SnapshotAt {
		t.Fatalf("boundary second page ids=%v data=%#v meta=%#v", got, boundarySecond.Data, boundarySecond.Meta)
	}

	blockValues := queryValues(from, to)
	blockValues.Set("uri_path", "/blocked")
	blockPage := decodeIntegrationBlockEventPage(t, doGET(tenantHandler, "/v1/analytics/logs/block-events", blockValues))
	if len(blockPage.Data) != 1 || blockPage.Data[0].EventID != "block-a" || blockPage.Data[0].URIPath != "/blocked" ||
		blockPage.Data[0].RequestID != "block-a-request" || blockPage.Data[0].TraceID != "block-a-trace" ||
		blockPage.Data[0].ConfigVersion != configA ||
		blockPage.Meta.Consistency != "snapshot" || blockPage.Meta.Pagination != "keyset" {
		t.Fatalf("tenant block page=%#v", blockPage)
	}
	// FX29/NF17: prefix match uses ClickHouse startsWith on the origin-form path.
	blockValues.Set("uri_path", "/bloc")
	if prefixMiss := decodeIntegrationBlockEventPage(t, doGET(tenantHandler, "/v1/analytics/logs/block-events", blockValues)); len(prefixMiss.Data) != 0 {
		t.Fatalf("exact /bloc matched %#v", prefixMiss.Data)
	}
	blockValues.Set("uri_path_match", "prefix")
	if prefixHit := decodeIntegrationBlockEventPage(t, doGET(tenantHandler, "/v1/analytics/logs/block-events", blockValues)); len(prefixHit.Data) != 1 || prefixHit.Data[0].EventID != "block-a" {
		t.Fatalf("prefix /bloc = %#v", prefixHit.Data)
	}
	platformBlockValues := queryValues(from, to)
	platformBlockValues.Set("tenant_id", tenantA)
	platformBlockPage := decodeIntegrationBlockEventPage(t,
		doGET(platformHandler, "/v1/admin/analytics/logs/block-events", platformBlockValues))
	// sec-log-agg: block and challenge events are listed; action narrows
	if len(platformBlockPage.Data) != 2 || platformBlockPage.Data[0].EventID != "block-a" || platformBlockPage.Data[1].EventID != "challenge-a" {
		t.Fatalf("platform block page=%#v", platformBlockPage)
	}
	platformBlockValues.Set("action", "block")
	platformBlockOnly := decodeIntegrationBlockEventPage(t,
		doGET(platformHandler, "/v1/admin/analytics/logs/block-events", platformBlockValues))
	if len(platformBlockOnly.Data) != 1 || platformBlockOnly.Data[0].EventID != "block-a" {
		t.Fatalf("platform block-only page=%#v", platformBlockOnly)
	}
	securityTenant := "10000000-0000-4000-8000-000000000019"
	securityRows := []integrationSecurityRow{
		integrationSecurity("security-z", from.Add(40*time.Minute), ingested.Add(10*time.Second), securityTenant, "block", "/security-z"),
		integrationSecurity("security-y", from.Add(40*time.Minute), ingested.Add(11*time.Second), securityTenant, "block", "/security-y"),
		integrationSecurity("security-a", from.Add(30*time.Minute), ingested.Add(12*time.Second), securityTenant, "block", "/security-a"),
	}
	insertIntegrationRows(t, database, "security_events", securityRows)
	securityValues := queryValues(from, to)
	securityValues.Set("tenant_id", securityTenant)
	securityValues.Set("limit", "2")
	securityFirst := decodeIntegrationBlockEventPage(t,
		doGET(platformHandler, "/v1/admin/analytics/logs/block-events", securityValues))
	if got := integrationBlockEventIDs(securityFirst.Data); strings.Join(got, ",") != "security-z,security-y" ||
		securityFirst.Meta.NextCursor == "" {
		t.Fatalf("security first page ids=%v meta=%#v", got, securityFirst.Meta)
	}
	securityReplacement := securityRows[2]
	securityReplacement.IngestedAt = time.Now().UTC()
	securityReplacement.OccurredAt = from.Add(50 * time.Minute)
	securityReplacement.Path = "/security-a-replaced"
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{securityReplacement})
	securityValues.Set("cursor", securityFirst.Meta.NextCursor)
	securitySecond := decodeIntegrationBlockEventPage(t,
		doGET(platformHandler, "/v1/admin/analytics/logs/block-events", securityValues))
	securityIDs := append(integrationBlockEventIDs(securityFirst.Data), integrationBlockEventIDs(securitySecond.Data)...)
	if strings.Join(securityIDs, ",") != "security-z,security-y,security-a" ||
		len(uniqueStrings(securityIDs)) != 3 || securitySecond.Meta.NextCursor != "" ||
		securitySecond.Meta.SnapshotAt != securityFirst.Meta.SnapshotAt ||
		len(securitySecond.Data) != 1 || securitySecond.Data[0].URIPath != "/security-a" {
		t.Fatalf("security paged ids=%v second=%#v metadata=%#v/%#v",
			securityIDs, securitySecond.Data, securityFirst.Meta, securitySecond.Meta)
	}
	beforeUnsupported := counter.calls.Load()
	assertHandlerError(t, doGET(tenantHandler, "/v1/analytics/logs/blocks/current", nil), 422,
		"analytics_logs_capability_unsupported")
	assertHandlerError(t, doGET(tenantHandler, "/v1/analytics/logs/blocks/history", nil), 422,
		"analytics_logs_capability_unsupported")
	if counter.calls.Load() != beforeUnsupported {
		t.Fatalf("unsupported block state reached ClickHouse: before=%d after=%d", beforeUnsupported, counter.calls.Load())
	}

	missingClient, err := NewClient(ClientConfig{
		Endpoint: database.endpoint, Database: database.name + "_missing", Username: database.username,
		Password: database.password, QueryTimeout: time.Second, CursorKeyring: testLogCursorKeyring(),
	}, database.http)
	if err != nil {
		t.Fatal(err)
	}
	missingHandler := newIntegrationHandler(t, newTestService(t, missingClient), tenantActor)
	assertHandlerError(t, doGET(missingHandler, "/v1/analytics/logs/access", queryValues(from, to)), 503,
		"analytics_logs_storage_unavailable")
}

func TestClickHouseMutableOccurredAtCandidateResolution(t *testing.T) {
	database := newIntegrationDatabase(t)
	database.create(t)
	assertClickHouseVersion(t, database)
	for _, table := range []string{"access_events", "security_events"} {
		if _, err := database.execute(context.Background(), "SYSTEM STOP MERGES "+table, true, nil); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	currentMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	from := currentMonth.AddDate(0, 1, 0)
	to := from.Add(24 * time.Hour)
	ingested := now.Add(-10 * time.Second).Truncate(time.Millisecond)
	accessTenant := "10000000-0000-4000-8000-00000000001a"
	securityTenant := "10000000-0000-4000-8000-00000000001b"

	accessInOutOld := integrationAccess("access-in-out", from.Add(time.Hour), ingested, accessTenant, siteA, nodeA, "/in", "2001:db8::1a")
	accessInOutLatest := accessInOutOld
	accessInOutLatest.OccurredAt = from.Add(-time.Hour)
	accessInOutLatest.IngestedAt = ingested.Add(time.Second)
	accessInOutLatest.Path = "/out"
	accessOutInOld := integrationAccess("access-out-in", from.Add(-2*time.Hour), ingested.Add(2*time.Second), accessTenant, siteA, nodeA, "/out", "2001:db8::1a")
	accessOutInLatest := accessOutInOld
	accessOutInLatest.OccurredAt = from.Add(2 * time.Hour)
	accessOutInLatest.IngestedAt = ingested.Add(3 * time.Second)
	accessOutInLatest.Path = "/in"
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{
		accessInOutOld, accessInOutLatest, accessOutInOld, accessOutInLatest,
	})

	securityInOutOld := integrationSecurity("security-in-out", from.Add(time.Hour), ingested, securityTenant, "block", "/in")
	securityInOutLatest := securityInOutOld
	securityInOutLatest.OccurredAt = from.Add(-time.Hour)
	securityInOutLatest.IngestedAt = ingested.Add(time.Second)
	securityInOutLatest.Path = "/out"
	securityOutInOld := integrationSecurity("security-out-in", from.Add(-2*time.Hour), ingested.Add(2*time.Second), securityTenant, "block", "/out")
	securityOutInLatest := securityOutInOld
	securityOutInLatest.OccurredAt = from.Add(2 * time.Hour)
	securityOutInLatest.IngestedAt = ingested.Add(3 * time.Second)
	securityOutInLatest.Path = "/in"
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{
		securityInOutOld, securityInOutLatest, securityOutInOld, securityOutInLatest,
	})

	client, err := NewClient(ClientConfig{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 3 * time.Second, CursorKeyring: testLogCursorKeyring(),
	}, database.http)
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: from, To: to}
	accessPage, err := client.ListAccess(context.Background(), scope{tenantID: accessTenant}, filter, 10, "")
	if err != nil || len(accessPage.Items) != 1 || accessPage.Items[0].EventID != "access-out-in" || accessPage.Items[0].URIPath != "/in" {
		t.Fatalf("access mutable occurred_at page=%#v err=%v", accessPage, err)
	}
	securityPage, err := client.ListBlockEvents(context.Background(), scope{tenantID: securityTenant}, filter, 10, "")
	if err != nil || len(securityPage.Items) != 1 || securityPage.Items[0].EventID != "security-out-in" || securityPage.Items[0].URIPath != "/in" {
		t.Fatalf("security mutable occurred_at page=%#v err=%v", securityPage, err)
	}

	ambiguousTenant := "10000000-0000-4000-8000-00000000001c"
	ambiguousAt := ingested.Add(4 * time.Second)
	accessAmbiguousA := integrationAccess("access-ambiguous", from.Add(3*time.Hour), ambiguousAt, ambiguousTenant, siteA, nodeA, "/a", "2001:db8::1c")
	accessAmbiguousB := accessAmbiguousA
	accessAmbiguousB.Path = "/b"
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{accessAmbiguousA, accessAmbiguousB})
	if _, err := client.ListAccess(context.Background(), scope{tenantID: ambiguousTenant}, filter, 10, ""); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("access equal-ingested ambiguity error=%v", err)
	}
	securityAmbiguousA := integrationSecurity("security-ambiguous", from.Add(3*time.Hour), ambiguousAt, ambiguousTenant, "block", "/a")
	securityAmbiguousB := securityAmbiguousA
	securityAmbiguousB.Path = "/b"
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{securityAmbiguousA, securityAmbiguousB})
	if _, err := client.ListBlockEvents(context.Background(), scope{tenantID: ambiguousTenant}, filter, 10, ""); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("security equal-ingested ambiguity error=%v", err)
	}

	retryTenant := "10000000-0000-4000-8000-00000000001d"
	retryAccess := integrationAccess("access-retry", from.Add(4*time.Hour), ingested.Add(5*time.Second), retryTenant, siteA, nodeA, "/retry", "2001:db8::1d")
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{retryAccess, retryAccess})
	if page, err := client.ListAccess(context.Background(), scope{tenantID: retryTenant}, filter, 10, ""); err != nil || len(page.Items) != 1 || page.Items[0].EventID != retryAccess.EventID {
		t.Fatalf("access byte-identical retry page=%#v error=%v", page, err)
	}
	retrySecurity := integrationSecurity("security-retry", from.Add(4*time.Hour), ingested.Add(5*time.Second), retryTenant, "block", "/retry")
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{retrySecurity, retrySecurity})
	if page, err := client.ListBlockEvents(context.Background(), scope{tenantID: retryTenant}, filter, 10, ""); err != nil || len(page.Items) != 1 || page.Items[0].EventID != retrySecurity.EventID {
		t.Fatalf("security byte-identical retry page=%#v error=%v", page, err)
	}

	historicalConflictTenant := "10000000-0000-4000-8000-00000000001e"
	accessConflictA := integrationAccess("access-historical-conflict", from.Add(5*time.Hour), ingested.Add(6*time.Second), historicalConflictTenant, siteA, nodeA, "/old-a", "2001:db8::1e")
	accessConflictB := accessConflictA
	accessConflictB.Path = "/old-b"
	accessConflictLatest := accessConflictA
	accessConflictLatest.IngestedAt = accessConflictA.IngestedAt.Add(time.Second)
	accessConflictLatest.Path = "/latest"
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{accessConflictA, accessConflictB, accessConflictLatest})
	if _, err := client.ListAccess(context.Background(), scope{tenantID: historicalConflictTenant}, filter, 10, ""); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("access historical equal-ingested ambiguity error=%v", err)
	}
	securityConflictA := integrationSecurity("security-historical-conflict", from.Add(5*time.Hour), ingested.Add(6*time.Second), historicalConflictTenant, "block", "/old-a")
	securityConflictB := securityConflictA
	securityConflictB.Path = "/old-b"
	securityConflictLatest := securityConflictA
	securityConflictLatest.IngestedAt = securityConflictA.IngestedAt.Add(time.Second)
	securityConflictLatest.Path = "/latest"
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{securityConflictA, securityConflictB, securityConflictLatest})
	if _, err := client.ListBlockEvents(context.Background(), scope{tenantID: historicalConflictTenant}, filter, 10, ""); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("security historical equal-ingested ambiguity error=%v", err)
	}

	accessCursorTenant := "10000000-0000-4000-8000-00000000001f"
	accessCursorRows := []integrationAccessRow{
		integrationAccess("access-cursor-c", from.Add(30*time.Minute), ingested.Add(8*time.Second), accessCursorTenant, siteA, nodeA, "/c", "2001:db8::1f"),
		integrationAccess("access-cursor-b", from.Add(20*time.Minute), ingested.Add(8*time.Second), accessCursorTenant, siteA, nodeA, "/b", "2001:db8::1f"),
		integrationAccess("access-cursor-a", from.Add(10*time.Minute), ingested.Add(8*time.Second), accessCursorTenant, siteA, nodeA, "/a", "2001:db8::1f"),
	}
	insertIntegrationRows(t, database, "access_events", accessCursorRows)
	accessCursorFirst, err := client.ListAccess(context.Background(), scope{tenantID: accessCursorTenant}, filter, 2, "")
	if err != nil || strings.Join(integrationAccessItemIDs(accessCursorFirst.Items), ",") != "access-cursor-c,access-cursor-b" || accessCursorFirst.NextCursor == "" {
		t.Fatalf("access default-ingested first page=%#v error=%v", accessCursorFirst, err)
	}
	insertDefaultIngestedAccess(t, database, integrationAccess("access-cursor-late", from.Add(15*time.Minute), time.Time{}, accessCursorTenant, siteA, nodeA, "/late", "2001:db8::1f"))
	accessCursorSecond, err := client.ListAccess(context.Background(), scope{tenantID: accessCursorTenant}, filter, 2, accessCursorFirst.NextCursor)
	if err != nil || strings.Join(integrationAccessItemIDs(accessCursorSecond.Items), ",") != "access-cursor-a" || accessCursorSecond.NextCursor != "" || !accessCursorSecond.SnapshotAt.Equal(accessCursorFirst.SnapshotAt) {
		t.Fatalf("access default-ingested second page=%#v error=%v", accessCursorSecond, err)
	}

	// fix-waflogdetail2: a host filter narrows the access query itself, so
	// another domain's requests in the window no longer fail the page.
	accessHostTenant := "10000000-0000-4000-8000-000000000022"
	accessHostOther := integrationAccess("access-host-other", from.Add(30*time.Minute), ingested.Add(8*time.Second), accessHostTenant, siteA, nodeA, "/o", "2001:db8::22")
	accessHostOther.Host = "Other.example.test"
	accessHostThird := integrationAccess("access-host-third", from.Add(25*time.Minute), ingested.Add(8*time.Second), accessHostTenant, siteA, nodeA, "/t", "2001:db8::22")
	accessHostThird.Host = "third.example.test"
	insertIntegrationRows(t, database, "access_events", []integrationAccessRow{
		accessHostOther, accessHostThird,
		integrationAccess("access-host-main", from.Add(20*time.Minute), ingested.Add(8*time.Second), accessHostTenant, siteA, nodeA, "/m", "2001:db8::22"),
	})
	for host, want := range map[string]string{
		"":             "access-host-other,access-host-third,access-host-main",
		"example.test": "access-host-main",
		"other.example.test missing.example.test": "access-host-other",
		"example.test third.example.test":         "access-host-third,access-host-main",
	} {
		hostFilter := filter
		hostFilter.Host = host
		page, err := client.ListAccess(context.Background(), scope{tenantID: accessHostTenant}, hostFilter, 10, "")
		if err != nil || strings.Join(integrationAccessItemIDs(page.Items), ",") != want {
			t.Fatalf("access host %q page=%v error=%v", host, integrationAccessItemIDs(page.Items), err)
		}
	}

	securityCursorTenant := "10000000-0000-4000-8000-000000000020"
	securityCursorRows := []integrationSecurityRow{
		integrationSecurity("security-cursor-c", from.Add(30*time.Minute), ingested.Add(8*time.Second), securityCursorTenant, "block", "/c"),
		integrationSecurity("security-cursor-b", from.Add(20*time.Minute), ingested.Add(8*time.Second), securityCursorTenant, "block", "/b"),
		integrationSecurity("security-cursor-a", from.Add(10*time.Minute), ingested.Add(8*time.Second), securityCursorTenant, "block", "/a"),
	}
	// sec-log-agg: an aggregated CC 429 line stands for its event_count
	securityCursorRows[0].EventType, securityCursorRows[0].EventCount = "cc", 10
	insertIntegrationRows(t, database, "security_events", securityCursorRows)
	securityCursorFirst, err := client.ListBlockEvents(context.Background(), scope{tenantID: securityCursorTenant}, filter, 2, "")
	if err != nil || strings.Join(integrationBlockEventItemIDs(securityCursorFirst.Items), ",") != "security-cursor-c,security-cursor-b" || securityCursorFirst.NextCursor == "" {
		t.Fatalf("security default-ingested first page=%#v error=%v", securityCursorFirst, err)
	}
	if securityCursorFirst.Items[0].Count != 10 || securityCursorFirst.Items[1].Count != 1 {
		t.Fatalf("security event counts = %d, %d", securityCursorFirst.Items[0].Count, securityCursorFirst.Items[1].Count)
	}
	// sec-log-agg: challenge events (an aggregated CC challenge line) are
	// listed with block events; a temporary ban is not; action narrows.
	actionTenant := "10000000-0000-4000-8000-000000000021"
	challengeRow := integrationSecurity("security-action-challenge", from.Add(40*time.Minute), ingested.Add(8*time.Second), actionTenant, "challenge", "/c")
	challengeRow.EventType, challengeRow.EventCount = "cc", 25
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{challengeRow,
		integrationSecurity("security-action-block", from.Add(39*time.Minute), ingested.Add(8*time.Second), actionTenant, "block", "/b"),
		integrationSecurity("security-action-ban", from.Add(38*time.Minute), ingested.Add(8*time.Second), actionTenant, "temporary_ban", "/t"),
		// fix-waflogdetail: observed hits (log) are listed; allow is not a hit.
		func() integrationSecurityRow {
			row := integrationSecurity("security-action-log", from.Add(37*time.Minute), ingested.Add(8*time.Second), actionTenant, "log", "/l")
			row.Host = "Other.example.test"
			return row
		}(),
		integrationSecurity("security-action-allow", from.Add(36*time.Minute), ingested.Add(8*time.Second), actionTenant, "allow", "/a"),
	})
	for action, want := range map[string]string{"": "security-action-challenge,security-action-block,security-action-ban,security-action-log",
		"challenge": "security-action-challenge", "block": "security-action-block",
		"temporary_ban": "security-action-ban", "log": "security-action-log"} {
		actionFilter := filter
		actionFilter.Action = action
		page, err := client.ListBlockEvents(context.Background(), scope{tenantID: actionTenant}, actionFilter, 10, "")
		if err != nil || strings.Join(integrationBlockEventItemIDs(page.Items), ",") != want {
			t.Fatalf("action %q page=%v error=%v", action, integrationBlockEventItemIDs(page.Items), err)
		}
		if action == "challenge" && page.Items[0].Count != 25 {
			t.Fatalf("challenge count = %d", page.Items[0].Count)
		}
	}
	for name, item := range map[string]struct {
		filter Filter
		want   string
	}{
		"event type":  {Filter{EventType: "waf"}, "security-action-block,security-action-ban,security-action-log"},
		"host list":   {Filter{Host: "other.example.test missing.example.test"}, "security-action-log"},
		"single host": {Filter{Host: "example.test", Action: "block"}, "security-action-block"},
	} {
		narrowed := filter
		narrowed.EventType, narrowed.Host, narrowed.Action = item.filter.EventType, item.filter.Host, item.filter.Action
		page, err := client.ListBlockEvents(context.Background(), scope{tenantID: actionTenant}, narrowed, 10, "")
		if err != nil || strings.Join(integrationBlockEventItemIDs(page.Items), ",") != item.want {
			t.Fatalf("%s page=%v error=%v", name, integrationBlockEventItemIDs(page.Items), err)
		}
	}
	insertDefaultIngestedSecurity(t, database, integrationSecurity("security-cursor-late", from.Add(15*time.Minute), time.Time{}, securityCursorTenant, "block", "/late"))
	securityCursorSecond, err := client.ListBlockEvents(context.Background(), scope{tenantID: securityCursorTenant}, filter, 2, securityCursorFirst.NextCursor)
	if err != nil || strings.Join(integrationBlockEventItemIDs(securityCursorSecond.Items), ",") != "security-cursor-a" || securityCursorSecond.NextCursor != "" || !securityCursorSecond.SnapshotAt.Equal(securityCursorFirst.SnapshotAt) {
		t.Fatalf("security default-ingested second page=%#v error=%v", securityCursorSecond, err)
	}

	if _, err := database.execute(context.Background(), "SYSTEM START MERGES security_events", true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := database.execute(context.Background(), "OPTIMIZE TABLE security_events FINAL", true, nil); err != nil {
		t.Fatal(err)
	}
	securityMergedCountBody, err := database.execute(context.Background(), `SELECT toUInt32(count()) AS row_count
FROM security_events
WHERE tenant_id = toUUID({tenant_id:String}) AND event_id = {event_id:String}
FORMAT JSONEachRow`, true, url.Values{
		"param_tenant_id": {ambiguousTenant}, "param_event_id": {securityAmbiguousA.EventID},
	})
	if err != nil {
		t.Fatal(err)
	}
	var securityMergedCount struct {
		RowCount uint32 `json:"row_count"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(securityMergedCountBody), &securityMergedCount); err != nil || securityMergedCount.RowCount != 1 {
		t.Fatalf("merged security equal-version physical rows=%d decode=%v", securityMergedCount.RowCount, err)
	}
	if _, err := client.ListBlockEvents(context.Background(), scope{tenantID: ambiguousTenant}, filter, 10, ""); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("merged security equal-ingested ambiguity error=%v", err)
	}
}

func newIntegrationDatabase(t *testing.T) *integrationDatabase {
	t.Helper()
	endpoint, skip, err := clickHouseRuntimeEndpoint(
		os.Getenv("TEST_CLICKHOUSE_URL"),
		os.Getenv("TEST_CLICKHOUSE_REQUIRED"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if skip {
		t.Skip("set TEST_CLICKHOUSE_URL to run the ClickHouse analytics log integration test")
	}
	name := "task_analyticslog_" + strconv.Itoa(os.Getpid()) + "_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	username := os.Getenv("TEST_CLICKHOUSE_USERNAME")
	password := os.Getenv("TEST_CLICKHOUSE_PASSWORD")
	httpClient := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if _, err := NewClient(ClientConfig{Endpoint: endpoint, Database: name, Username: username, Password: password,
		CursorKeyring: testLogCursorKeyring()}, httpClient); err != nil {
		t.Fatalf("invalid TEST_CLICKHOUSE configuration: %v", err)
	}
	return &integrationDatabase{endpoint: endpoint, name: name, username: username, password: password, http: httpClient}
}

func clickHouseRuntimeEndpoint(endpoint, required string) (string, bool, error) {
	endpoint = strings.TrimSpace(endpoint)
	required = strings.TrimSpace(required)
	if required != "" && required != "0" && required != "1" {
		return "", false, errors.New("TEST_CLICKHOUSE_REQUIRED must be 0 or 1")
	}
	if endpoint == "" && required == "1" {
		return "", false, errors.New("TEST_CLICKHOUSE_URL is required when TEST_CLICKHOUSE_REQUIRED=1")
	}
	return endpoint, endpoint == "", nil
}

func TestClickHouseMigrationStatementsSkipCommentOnlySegments(t *testing.T) {
	migration := "-- predecessor note; still a comment\nCREATE TABLE first (id UInt8);\n-- between statements; still a comment\nALTER TABLE first ADD COLUMN value UInt8;\n"
	statements := clickHouseMigrationStatements(migration)
	if len(statements) != 2 || !strings.HasPrefix(statements[0], "CREATE TABLE first") ||
		!strings.HasPrefix(statements[1], "ALTER TABLE first") {
		t.Fatalf("migration statements=%q", statements)
	}
}

func clickHouseMigrationStatements(migration string) []string {
	linesWithoutComments := make([]string, 0)
	for _, line := range strings.Split(migration, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		linesWithoutComments = append(linesWithoutComments, line)
	}

	statements := make([]string, 0)
	for _, raw := range strings.Split(strings.Join(linesWithoutComments, "\n"), ";") {
		if statement := strings.TrimSpace(raw); statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}

func (database *integrationDatabase) create(t *testing.T) {
	t.Helper()
	if !strings.HasPrefix(database.name, "task_analyticslog_") || !validDatabase(database.name) {
		t.Fatal("refusing non-task-owned ClickHouse database")
	}
	parameters := url.Values{"param_database": {database.name}}
	if _, err := database.execute(context.Background(), "CREATE DATABASE {database:Identifier}", false, parameters); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := database.execute(ctx, "DROP DATABASE IF EXISTS {database:Identifier} SYNC", false, parameters); err != nil {
			t.Errorf("drop task-owned ClickHouse database: %v", err)
		}
	})
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate analytics log integration test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", ".."))
	for _, name := range []string{
		"001_analytics.up.sql", "002_analytics_authority_capture.up.sql",
		"003_analytics_hourly_rollup.up.sql", "004_analytics_version_evidence.up.sql",
		"005_package_monitor_metrics.up.sql", "006_access_event_state.up.sql",
		"007_connections_ingest_receipts.up.sql", "008_security_event_state.up.sql",
		"009_site_realtime_monitoring.up.sql",
		"012_analytics_log_query_projection.up.sql",
		"014_analytics_access_listen_port_projection.up.sql",
		"015_site_realtime_coverage_authority.up.sql",
		"022_security_event_evidence.up.sql",
		"025_security_event_count.up.sql",
		"028_access_upstream_addr.up.sql",
	} {
		migration, err := os.ReadFile(filepath.Join(root, "infra", "clickhouse", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range clickHouseMigrationStatements(string(migration)) {
			if _, err := database.execute(context.Background(), statement, true, nil); err != nil {
				t.Fatalf("apply analytics schema %s: %v", name, err)
			}
		}
	}
}

func assertClickHouseVersion(t *testing.T, database *integrationDatabase) {
	t.Helper()
	body, err := database.execute(context.Background(), "SELECT version() AS version FORMAT JSONEachRow", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &row); err != nil {
		t.Fatal(err)
	}
	if row.Version != requiredClickHouseVersion {
		t.Fatalf("ClickHouse version=%q, want %s", row.Version, requiredClickHouseVersion)
	}
}

func seedIntegrationRows(t *testing.T, database *integrationDatabase, from, ingested time.Time) {
	t.Helper()
	old := integrationAccess("replace-me", from.Add(40*time.Minute), ingested, tenantA, siteA, nodeA,
		"/old?token=old-secret", "2001:db8::30")
	old.StatusCode = 200
	old.Method = "GET"
	old.Protocol = "HTTP/2"
	old.CacheStatus = "HIT"
	old.Carrier = "old-carrier"
	rows := []integrationAccessRow{
		integrationAccess("tie-z", from.Add(50*time.Minute), ingested.Add(time.Second), tenantA, siteA, nodeA, "/z", "2001:db8::1"),
		integrationAccess("tie-y", from.Add(50*time.Minute), ingested.Add(2*time.Second), tenantA, siteA, nodeA, "/y", "2001:db8::2"),
		old,
		integrationAccess("event-b", from.Add(30*time.Minute), ingested.Add(3*time.Second), tenantA, siteA, nodeA,
			"/b?cookie=cookie-secret", "2001:db8::4"),
		integrationAccess("event-a", from.Add(20*time.Minute), ingested.Add(4*time.Second), tenantA, siteA, nodeA,
			"/a?authorization=authorization-secret", "2001:db8::5"),
		integrationAccess("tenant-b", from.Add(55*time.Minute), ingested.Add(5*time.Second), tenantB,
			"20000000-0000-4000-8000-00000000000b", "30000000-0000-4000-8000-00000000000b", "/foreign", "2001:db8::b"),
	}
	replacement := integrationAccess("replace-me", from.Add(40*time.Minute), ingested.Add(6*time.Second), tenantA, siteA, nodeA,
		"/new?token=query-secret", "2001:db8::3")
	replacement.StatusCode = 503
	replacement.Method = "POST"
	replacement.Protocol = "HTTP/3"
	replacement.CacheStatus = "MISS"
	replacement.Carrier = "carrier-match"
	replacement.UpstreamAddr = "10.0.0.1:80, 10.0.0.2:80"
	rows = append(rows, replacement)
	for index := 0; index < 101; index++ {
		rows = append(rows, integrationAccess(
			fmt.Sprintf("capacity-%03d", index), from.Add(10*time.Minute+time.Duration(index)*time.Millisecond),
			ingested.Add(time.Duration(10+index)*time.Millisecond), "10000000-0000-4000-8000-00000000000c",
			"20000000-0000-4000-8000-00000000000c", "30000000-0000-4000-8000-00000000000c",
			"/capacity", "2001:db8::c"))
	}
	insertIntegrationRows(t, database, "access_events", rows)

	security := []integrationSecurityRow{
		integrationSecurity("block-a", from.Add(45*time.Minute), ingested.Add(7*time.Second), tenantA, "block", "/blocked?token=block-secret"),
		integrationSecurity("challenge-a", from.Add(44*time.Minute), ingested.Add(8*time.Second), tenantA, "challenge", "/challenge"),
		integrationSecurity("block-b", from.Add(43*time.Minute), ingested.Add(9*time.Second), tenantB, "block", "/foreign-block"),
	}
	insertIntegrationRows(t, database, "security_events", security)
}

func integrationAccess(eventID string, occurredAt, ingestedAt time.Time, tenantID, siteID, nodeID, path, clientIP string) integrationAccessRow {
	return integrationAccessRow{
		MetricVersion: 1, EventID: eventID, OccurredAt: occurredAt, IngestedAt: ingestedAt, TenantID: tenantID,
		SiteID: siteID, NodeID: nodeID, RequestID: eventID + "-request", TraceID: eventID + "-trace",
		ConfigVersion: configA, Host: "example.test", ListenPort: 443, Path: path, ClientIP: clientIP, CountryCode: "CN",
		Carrier: "carrier-a", Method: "GET", Protocol: "HTTP/2", CacheStatus: "HIT", UpstreamResult: "ok",
		StatusCode: 200, RequestBytes: 100, ResponseBytes: 1000, DurationUS: 1000,
	}
}

func integrationSecurity(eventID string, occurredAt, ingestedAt time.Time, tenantID, action, path string) integrationSecurityRow {
	return integrationSecurityRow{
		MetricVersion: 1, EventID: eventID, OccurredAt: occurredAt, IngestedAt: ingestedAt, TenantID: tenantID,
		SiteID: siteA, NodeID: nodeA, RequestID: eventID + "-request", TraceID: eventID + "-trace",
		ConfigVersion: configA, Host: "example.test", Path: path, ClientIP: "2001:db8::20",
		CountryCode: "CN", Carrier: "carrier-security", EventType: "waf", Action: action, Severity: "high",
		RuleID: "rule-a", StatusCode: 0, RequestBytes: 10, ResponseBytes: 20,
	}
}

func insertDefaultIngestedAccess(t *testing.T, database *integrationDatabase, row integrationAccessRow) {
	t.Helper()
	query := `INSERT INTO access_events
(metric_version, event_id, occurred_at, tenant_id, site_id, node_id, request_id, trace_id, config_version_id,
	 host, listen_port, path, client_ip, country_code, carrier, method, protocol, cache_status, upstream_result,
 status_code, request_bytes, response_bytes, duration_us)
VALUES
({metric_version:UInt16}, {event_id:String}, fromUnixTimestamp64Milli({occurred_at_ms:Int64}, 'UTC'),
 toUUID({tenant_id:String}), toUUID({site_id:String}), toUUID({node_id:String}), {request_id:String}, {trace_id:String},
	 {config_version_id:String}, {host:String}, {listen_port:UInt16}, {path:String}, toIPv6({client_ip:String}), {country_code:String},
 {carrier:String}, {method:String}, {protocol:String}, {cache_status:String}, {upstream_result:String},
 {status_code:UInt16}, {request_bytes:UInt64}, {response_bytes:UInt64}, {duration_us:UInt64})`
	parameters := url.Values{
		"param_metric_version":    {strconv.FormatUint(uint64(row.MetricVersion), 10)},
		"param_event_id":          {row.EventID},
		"param_occurred_at_ms":    {strconv.FormatInt(row.OccurredAt.UnixMilli(), 10)},
		"param_tenant_id":         {row.TenantID},
		"param_site_id":           {row.SiteID},
		"param_node_id":           {row.NodeID},
		"param_request_id":        {row.RequestID},
		"param_trace_id":          {row.TraceID},
		"param_config_version_id": {row.ConfigVersion},
		"param_host":              {row.Host},
		"param_listen_port":       {strconv.FormatUint(uint64(row.ListenPort), 10)},
		"param_path":              {row.Path},
		"param_client_ip":         {row.ClientIP},
		"param_country_code":      {row.CountryCode},
		"param_carrier":           {row.Carrier},
		"param_method":            {row.Method},
		"param_protocol":          {row.Protocol},
		"param_cache_status":      {row.CacheStatus},
		"param_upstream_result":   {row.UpstreamResult},
		"param_status_code":       {strconv.FormatUint(uint64(row.StatusCode), 10)},
		"param_request_bytes":     {strconv.FormatUint(row.RequestBytes, 10)},
		"param_response_bytes":    {strconv.FormatUint(row.ResponseBytes, 10)},
		"param_duration_us":       {strconv.FormatUint(row.DurationUS, 10)},
	}
	if _, err := database.execute(context.Background(), query, true, parameters); err != nil {
		t.Fatal(err)
	}
}

func insertDefaultIngestedSecurity(t *testing.T, database *integrationDatabase, row integrationSecurityRow) {
	t.Helper()
	query := `INSERT INTO security_events
(metric_version, event_id, occurred_at, tenant_id, site_id, node_id, request_id, trace_id, config_version_id,
 host, path, client_ip, country_code, carrier, event_type, action, severity, rule_id,
 status_code, request_bytes, response_bytes)
VALUES
({metric_version:UInt16}, {event_id:String}, fromUnixTimestamp64Milli({occurred_at_ms:Int64}, 'UTC'),
 toUUID({tenant_id:String}), toUUID({site_id:String}), toUUID({node_id:String}), {request_id:String}, {trace_id:String},
 {config_version_id:String}, {host:String}, {path:String}, toIPv6({client_ip:String}), {country_code:String},
 {carrier:String}, {event_type:String}, {action:String}, {severity:String}, {rule_id:String},
 {status_code:UInt16}, {request_bytes:UInt64}, {response_bytes:UInt64})`
	parameters := url.Values{
		"param_metric_version":    {strconv.FormatUint(uint64(row.MetricVersion), 10)},
		"param_event_id":          {row.EventID},
		"param_occurred_at_ms":    {strconv.FormatInt(row.OccurredAt.UnixMilli(), 10)},
		"param_tenant_id":         {row.TenantID},
		"param_site_id":           {row.SiteID},
		"param_node_id":           {row.NodeID},
		"param_request_id":        {row.RequestID},
		"param_trace_id":          {row.TraceID},
		"param_config_version_id": {row.ConfigVersion},
		"param_host":              {row.Host},
		"param_path":              {row.Path},
		"param_client_ip":         {row.ClientIP},
		"param_country_code":      {row.CountryCode},
		"param_carrier":           {row.Carrier},
		"param_event_type":        {row.EventType},
		"param_action":            {row.Action},
		"param_severity":          {row.Severity},
		"param_rule_id":           {row.RuleID},
		"param_status_code":       {strconv.FormatUint(uint64(row.StatusCode), 10)},
		"param_request_bytes":     {strconv.FormatUint(row.RequestBytes, 10)},
		"param_response_bytes":    {strconv.FormatUint(row.ResponseBytes, 10)},
	}
	if _, err := database.execute(context.Background(), query, true, parameters); err != nil {
		t.Fatal(err)
	}
}

func insertIntegrationRows[T any](t *testing.T, database *integrationDatabase, table string, rows []T) {
	t.Helper()
	insertIntegrationRowsWithSettings(t, database, table, rows, nil)
}

func insertIntegrationRowsWithSettings[T any](
	t *testing.T,
	database *integrationDatabase,
	table string,
	rows []T,
	settings url.Values,
) {
	t.Helper()
	if table != "access_events" && table != "security_events" {
		t.Fatal("invalid integration table")
	}
	var body bytes.Buffer
	body.WriteString("INSERT INTO " + table + " FORMAT JSONEachRow\n")
	encoder := json.NewEncoder(&body)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.execute(context.Background(), body.String(), true, settings); err != nil {
		t.Fatal(err)
	}
}

func (database *integrationDatabase) execute(
	ctx context.Context,
	query string,
	useDatabase bool,
	parameters url.Values,
) ([]byte, error) {
	target, err := url.Parse(database.endpoint)
	if err != nil {
		return nil, errors.New("parse ClickHouse endpoint")
	}
	values := target.Query()
	if useDatabase {
		values.Set("database", database.name)
	}
	values.Set("max_execution_time", "30")
	values.Set("date_time_input_format", "best_effort")
	for key, entries := range parameters {
		for _, entry := range entries {
			values.Add(key, entry)
		}
	}
	target.RawQuery = values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(query))
	if err != nil {
		return nil, errors.New("build ClickHouse request")
	}
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("Accept-Encoding", "identity")
	if database.username != "" {
		request.SetBasicAuth(database.username, database.password)
	}
	response, err := database.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("execute ClickHouse request")
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 8192))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("ClickHouse returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func newIntegrationHandler(t *testing.T, service *Service, actor Actor) *Handler {
	t.Helper()
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) { return actor, nil }, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func decodeIntegrationAccessPage(t *testing.T, response *httptest.ResponseRecorder) accessResponse {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var page accessResponse
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func decodeIntegrationBlockEventPage(t *testing.T, response *httptest.ResponseRecorder) blockEventResponse {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var page blockEventResponse
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func integrationAccessIDs(items []accessResponseItem) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = item.EventID
	}
	return ids
}

func integrationAccessItemIDs(items []AccessLog) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = item.EventID
	}
	return ids
}

func integrationBlockEventIDs(items []blockEventResponseItem) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = item.EventID
	}
	return ids
}

func integrationBlockEventItemIDs(items []BlockEvent) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = item.EventID
	}
	return ids
}

func uniqueStrings(values []string) map[string]struct{} {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	return unique
}
