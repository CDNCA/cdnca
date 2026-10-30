package l4analytics

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The session log table keeps addresses out of the facts table.
func TestL4SessionLogMigrationIsSeparateFromFacts(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../"))
	up, err := os.ReadFile(filepath.Join(root, "infra/clickhouse/migrations/018_l4_session_logs.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CREATE TABLE IF NOT EXISTS l4_session_logs_v1", "client_ip String", "upstream_addr String",
		"end_reason LowCardinality(String)", "TYPE bloom_filter", "ENGINE = ReplacingMergeTree(source_watermark)",
		"TTL toDateTime(finalized_at, 'UTC') + INTERVAL 30 DAY DELETE"} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("session log migration omitted %q", want)
		}
	}
}

type fakeClickHouse struct {
	mu      sync.Mutex
	inserts map[string][]map[string]any
	queries []string
	params  []map[string]string
	exists  bool
	rows    []sessionLogRow
}

func (fake *fakeClickHouse) handler(t *testing.T) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		body, _ := io.ReadAll(request.Body)
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if query := request.URL.Query().Get("query"); strings.HasPrefix(query, "INSERT INTO ") {
			if fake.inserts == nil {
				fake.inserts = map[string][]map[string]any{}
			}
			table := strings.Fields(query)[2]
			scanner := bufio.NewScanner(bytes.NewReader(body))
			for scanner.Scan() {
				var row map[string]any
				if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
					t.Error(err)
				}
				fake.inserts[table] = append(fake.inserts[table], row)
			}
			writer.WriteHeader(http.StatusOK)
			return
		}
		text := string(body)
		fake.queries = append(fake.queries, text)
		params := map[string]string{}
		for key, values := range request.URL.Query() {
			if strings.HasPrefix(key, "param_") {
				params[strings.TrimPrefix(key, "param_")] = values[0]
			}
		}
		fake.params = append(fake.params, params)
		if strings.HasPrefix(text, "EXISTS TABLE") {
			if fake.exists {
				_, _ = writer.Write([]byte("{\"result\":1}\n"))
			} else {
				_, _ = writer.Write([]byte("{\"result\":0}\n"))
			}
			return
		}
		for _, row := range fake.rows {
			payload, _ := json.Marshal(row)
			_, _ = writer.Write(append(payload, '\n'))
		}
	}
}

func sessionEvent(id string, log *agentv1.L4SessionLogV1) *agentv1.L4SessionEventV1 {
	started := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	return &agentv1.L4SessionEventV1{
		Event: &commonv1.EventMetadata{EventId: id}, TenantId: testTenant, NodeId: testNode, SiteId: testSite,
		StreamId: testStream, ListenerId: testStream, ConfigVersionId: testStream, ConfigRevision: 1, Protocol: "tcp",
		ListenPort: 18080, SessionId: "1", StartedAt: timestamppb.New(started), FinalizedAt: timestamppb.New(started.Add(time.Second)),
		BytesUp: 3, BytesDown: 4, StatusCode: 200, SessionLog: log,
	}
}

// Every event is a fact; only events with a session log are log rows, and
// only when the table exists. The facts never carry an address.
func TestFactWriterSplitsSessionLogs(t *testing.T) {
	connect := uint32(7)
	for _, exists := range []bool{true, false} {
		fake := &fakeClickHouse{exists: exists}
		server := httptest.NewServer(fake.handler(t))
		source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		writer, err := NewClickHouseFactWriterWithSessionLogs(t.Context(), source)
		if err != nil {
			t.Fatal(err)
		}
		err = writer.Write(t.Context(), []*agentv1.L4SessionEventV1{
			sessionEvent("plain", nil),
			sessionEvent("logged", &agentv1.L4SessionLogV1{ClientIp: "203.0.113.10", ClientPort: 61000, PeerIp: "192.0.2.9",
				UpstreamAddr: "10.0.0.9:443", UpstreamConnectMs: &connect, EndReason: "killed"}),
		}, 9)
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		facts, logs := fake.inserts["l4_session_facts_v1"], fake.inserts["l4_session_logs_v1"]
		if len(facts) != 2 {
			t.Fatalf("facts = %v", facts)
		}
		for _, fact := range facts {
			for key := range fact {
				// Raw addresses stay out of the facts (package_subscription_id is not one).
				if (strings.Contains(key, "ip") && key != "package_subscription_id") || strings.Contains(key, "addr") {
					t.Fatalf("fact carries %s", key)
				}
			}
		}
		if !exists {
			if len(logs) != 0 {
				t.Fatalf("logs written without the table: %v", logs)
			}
			continue
		}
		if len(logs) != 1 || logs[0]["client_ip"] != "203.0.113.10" || logs[0]["peer_ip"] != "192.0.2.9" ||
			logs[0]["upstream_connect_ms"] != float64(7) || logs[0]["end_reason"] != "killed" || logs[0]["event_id"] != "logged" ||
			logs[0]["source_watermark"] != float64(9) || logs[0]["finalized_at"] != "2026-08-09 12:00:01.000" {
			t.Fatalf("logs = %v", logs)
		}
	}
}

// Session logs are tenant-scoped, filtered by stream, client, port and
// reason, and paged by (finalized_at, event_id).
func TestSessionLogQueryScopesFiltersAndPages(t *testing.T) {
	now := time.Date(2026, 8, 9, 13, 0, 0, 0, time.UTC)
	finalized := now.Add(-time.Minute)
	fake := &fakeClickHouse{exists: true, rows: []sessionLogRow{
		{FinalizedMS: finalized.UnixMilli(), StartedMS: finalized.Add(-time.Second).UnixMilli(), EventID: "a", NodeID: testNode, SiteID: testSite,
			StreamID: testStream, ListenerID: testStream, Protocol: "tcp", ListenPort: 18080, ClientIP: "203.0.113.10", EndReason: "closed"},
		{FinalizedMS: finalized.UnixMilli(), StartedMS: finalized.UnixMilli(), EventID: "b", NodeID: testNode, SiteID: testSite,
			StreamID: testStream, ListenerID: testStream, Protocol: "tcp", ListenPort: 18080, ClientIP: "203.0.113.10", EndReason: "rate_limited"},
	}}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	tenant := Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}
	query := SessionLogQuery{Query: Query{Audience: AudienceTenant, Range: "1h", Timezone: "UTC", StreamID: testStream, ListenPort: 18080, Limit: 1},
		ClientIP: "203.0.113.0/24", EndReason: "closed"}
	page, err := service.ReadSessionLogs(t.Context(), tenant, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 1 || page.Rows[0].EventID != "a" || page.NextCursor == "" || page.Rows[0].ClientIP != "203.0.113.10" {
		t.Fatalf("page = %+v", page)
	}
	sql, params := fake.queries[len(fake.queries)-1], fake.params[len(fake.params)-1]
	for _, want := range []string{"FROM l4_session_logs_v1 FINAL", "tenant_id = {tenant_id:UUID}", "stream_id = {stream_id:UUID}",
		"isIPAddressInRange(client_ip, {client_cidr:String})", "end_reason = {end_reason:String}", "listen_port = {listen_port:UInt16}",
		"ORDER BY finalized_at DESC, event_id DESC"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("query omits %q:\n%s", want, sql)
		}
	}
	// fix-ipdisplay: rows from a dual-stack listener are stored as ::ffff:a.b.c.d,
	// so an IPv4 filter also matches the mapped range.
	if !strings.Contains(sql, "isIPAddressInRange(client_ip, {client_cidr_mapped:String})") ||
		params["client_cidr_mapped"] != "::ffff:203.0.113.0/120" {
		t.Fatalf("IPv4 filter omits the mapped range: %v\n%s", params, sql)
	}
	if params["tenant_id"] != testTenant || params["client_cidr"] != "203.0.113.0/24" || params["limit"] != "2" {
		t.Fatalf("params = %v", params)
	}
	query.Cursor = page.NextCursor
	if _, err := service.ReadSessionLogs(t.Context(), tenant, query); err != nil {
		t.Fatal(err)
	}
	if sql, params := fake.queries[len(fake.queries)-1], fake.params[len(fake.params)-1]; !strings.Contains(sql, "(finalized_at, event_id) < ({after_finalized:DateTime64(3)}, {after_event:String})") ||
		params["after_event"] != "a" {
		t.Fatalf("second page query %s %v", sql, params)
	}
	for name, bad := range map[string]SessionLogQuery{
		"bad client": {Query: query.Query, ClientIP: "nope"},
		"bad reason": {Query: query.Query, EndReason: "drop table"},
	} {
		bad.Cursor = ""
		if _, err := service.ReadSessionLogs(t.Context(), tenant, bad); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A cursor is bound to the filter it was issued for.
	other := query
	other.ClientIP = "198.51.100.0/24"
	if _, err := service.ReadSessionLogs(t.Context(), tenant, other); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cursor reused under another filter: %v", err)
	}
	fake.exists = false
	query.Cursor = ""
	if _, err := service.ReadSessionLogs(t.Context(), tenant, query); !errors.Is(err, ErrSessionLogUnavailable) {
		t.Fatalf("missing table: %v", err)
	}
}

// The platform 四层访问日志 opens with no filter: every tenant's rows, newest
// first, within the default window and page limit; tenant_id and node_id are
// optional narrowing. A tenant session can never widen to the platform.
func TestSessionLogPlatformScopeNeedsNoFilter(t *testing.T) {
	now := time.Date(2026, 8, 9, 13, 0, 0, 0, time.UTC)
	fake := &fakeClickHouse{exists: true}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	if _, err := service.ReadSessionLogs(t.Context(), platform, SessionLogQuery{Query: Query{Audience: AudiencePlatform, Range: "1h", Timezone: "UTC", Limit: 50}}); err != nil {
		t.Fatal(err)
	}
	sql, params := fake.queries[len(fake.queries)-1], fake.params[len(fake.params)-1]
	if strings.Contains(sql, "tenant_id") || strings.Contains(sql, "node_id =") || !strings.Contains(sql, "ORDER BY finalized_at DESC, event_id DESC") ||
		params["limit"] != "51" || params["from"] != "2026-08-09 12:00:00.000" || params["to"] != "2026-08-09 13:00:00.000" {
		t.Fatalf("platform query %s %v", sql, params)
	}
	if _, err := service.ReadSessionLogs(t.Context(), platform, SessionLogQuery{Query: Query{Audience: AudiencePlatform, TenantID: testTenant, NodeID: testNode,
		Range: "1h", Timezone: "UTC", Limit: 50}}); err != nil {
		t.Fatal(err)
	}
	sql, params = fake.queries[len(fake.queries)-1], fake.params[len(fake.params)-1]
	if !strings.Contains(sql, "tenant_id = {tenant_id:UUID}") || !strings.Contains(sql, "node_id = {node_id:UUID}") ||
		params["tenant_id"] != testTenant || params["node_id"] != testNode {
		t.Fatalf("narrowed query %s %v", sql, params)
	}
	tenant := Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}
	for _, query := range []Query{
		{Audience: AudiencePlatform, Range: "1h", Timezone: "UTC", Limit: 50},
		{Audience: AudienceTenant, TenantID: testNode, Range: "1h", Timezone: "UTC", Limit: 50},
	} {
		if _, err := service.ReadSessionLogs(t.Context(), tenant, SessionLogQuery{Query: query}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant widened with %+v: %v", query, err)
		}
	}
}

// fix-ipdisplay: a dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d;
// the session log returns dotted IPv4 and leaves real IPv6 as is.
func TestSessionLogReturnsIPv4MappedClientsAsIPv4(t *testing.T) {
	now := time.Date(2026, 8, 9, 13, 0, 0, 0, time.UTC)
	finalized := now.Add(-time.Minute)
	fake := &fakeClickHouse{exists: true, rows: []sessionLogRow{
		{FinalizedMS: finalized.UnixMilli(), StartedMS: finalized.UnixMilli(), EventID: "b", NodeID: testNode, SiteID: testSite,
			StreamID: testStream, ListenerID: testStream, Protocol: "tcp", ListenPort: 18080, ClientIP: "::ffff:203.0.113.10", EndReason: "closed"},
		{FinalizedMS: finalized.UnixMilli(), StartedMS: finalized.UnixMilli(), EventID: "a", NodeID: testNode, SiteID: testSite,
			StreamID: testStream, ListenerID: testStream, Protocol: "tcp", ListenPort: 18080, ClientIP: "2001:db8::10", EndReason: "closed"},
	}}
	server := httptest.NewServer(fake.handler(t))
	defer server.Close()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	tenant := Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}
	page, err := service.ReadSessionLogs(t.Context(), tenant, SessionLogQuery{Query: Query{Audience: AudienceTenant, Range: "1h",
		Timezone: "UTC", StreamID: testStream, Limit: 10}})
	if err != nil || len(page.Rows) != 2 || page.Rows[0].ClientIP != "203.0.113.10" || page.Rows[1].ClientIP != "2001:db8::10" {
		t.Fatalf("page = %+v, %v", page, err)
	}
}
