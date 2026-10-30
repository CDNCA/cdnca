package l4analytics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClickHouseReadAggregatesPaginatesByAggregateBucket(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 1, 0, 0, time.UTC)
	bucket := now.Add(-time.Minute)
	row := aggregateRow{
		BucketMS: bucket.UnixMilli(), NodeID: testNode, SiteID: testSite, StreamID: testStream, ListenerID: testStream,
		Protocol: "tcp", ListenPort: 18080, Sessions: 1,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if got := request.URL.Query().Get("output_format_json_quote_64bit_integers"); got != "0" {
			t.Errorf("64-bit JSON setting = %q, want 0", got)
		}
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		if strings.Contains(query, "max(source_watermark)") {
			writeClickHouseJSONLine(t, writer, snapshotRow{
				AtMilliseconds: now.UnixMilli(), SourceWatermark: 7,
				FinalizedThroughMilliseconds: now.Add(-time.Second).UnixMilli(),
			})
			return
		}
		if request.URL.Query().Get("param_after_bucket") == "" {
			writeClickHouseJSONLine(t, writer, row)
			return
		}
		// A second raw fact in the same minute must remain in the first aggregate bucket.
		// The pre-fix raw-timestamp cursor incorrectly admits this duplicate aggregate.
		if strings.Contains(query, "(finalized_at, node_id") {
			writeClickHouseJSONLine(t, writer, row)
		}
	}))
	defer server.Close()

	source, err := NewClickHouseSource(ClickHouseConfig{
		Endpoint: server.URL, Database: "default", QueryTimeout: time.Second, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: now.Add(-time.Hour), To: now, Limit: 1}
	first, err := source.Read(t.Context(), Scope{TenantID: testTenant}, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Rows) != 1 || !first.HasMore {
		t.Fatalf("first page = %#v", first)
	}

	filter.Snapshot = first.Snapshot
	filter.After = &After{
		Bucket: first.Rows[0].Bucket, NodeID: first.Rows[0].NodeID, SiteID: first.Rows[0].SiteID,
		StreamID: first.Rows[0].StreamID, ListenerID: first.Rows[0].ListenerID,
	}
	second, err := source.Read(t.Context(), Scope{TenantID: testTenant}, filter)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Rows) != 0 || second.HasMore {
		t.Fatalf("same-minute continuation repeated aggregate: %#v", second)
	}
}

func TestClickHousePlatformReadOmitsTenantPredicateAndAcceptsEmptySnapshot(t *testing.T) {
	now := time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		body, _ := io.ReadAll(request.Body)
		queries = append(queries, string(body))
		if strings.Contains(string(body), "max(source_watermark)") {
			writeClickHouseJSONLine(t, writer, snapshotRow{AtMilliseconds: now.UnixMilli(), FinalizedThroughMilliseconds: now.UnixMilli()})
		}
	}))
	defer server.Close()

	source, err := NewClickHouseSource(ClickHouseConfig{
		Endpoint: server.URL, Database: "default", QueryTimeout: time.Second, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := source.Read(t.Context(), Scope{}, Filter{From: now.Add(-time.Hour), To: now, Limit: 100})
	if err != nil || len(page.Rows) != 0 || page.Snapshot.SourceWatermark != 0 {
		t.Fatalf("global empty page=%#v error=%v", page, err)
	}
	if len(queries) != 2 {
		t.Fatalf("queries=%d want=2", len(queries))
	}
	for _, query := range queries {
		if strings.Contains(query, "tenant_id =") {
			t.Fatalf("global query retained tenant predicate: %s", query)
		}
	}
}

func TestClickHouseInsertFactsUsesEndpointQueryParameters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		if got := request.URL.Query().Get("database"); got != "facts" {
			t.Errorf("database query parameter = %q, want facts", got)
		}
		if got := request.URL.Query().Get("query"); got != "INSERT INTO l4_session_facts_v1 FORMAT JSONEachRow" {
			t.Errorf("insert query parameter = %q", got)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	source, err := NewClickHouseSource(ClickHouseConfig{
		Endpoint: server.URL, Database: "facts", QueryTimeout: time.Second, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.insertRows(t.Context(), "l4_session_facts_v1", []byte("{\"event_id\":\"e1\"}\n")); err != nil {
		t.Fatalf("insertFacts() error = %v", err)
	}
}

func writeClickHouseJSONLine(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Error(err)
	}
}
