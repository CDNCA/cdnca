package analytics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
)

func TestRealtimeV2SnapshotUsesFinalizedConnectionDimensions(t *testing.T) {
	filter := realtimeV2Filter()
	filter.NodeID = realtimeV2NodeID
	filter.Domain = "cdn.example.test"
	filter.ListenPort = 443
	snapshot := realtimeV2Snapshot(filter)
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		_, _ = io.WriteString(w, realtimeV2SnapshotRow(snapshot))
	}))
	defer server.Close()
	source := newRealtimeV2TestSource(t, Config{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if _, err := source.ResolveSnapshot(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter); err != nil {
		t.Fatalf("ResolveSnapshot: %v", err)
	}
	for _, token := range []string{
		"connections_ingest_receipts_v1 FINAL", "state_rank >= 2", "node_id = {node_id:UUID}",
		"domain = {domain:String}", "listen_port = {listen_port:UInt16}", "finalized_through",
		"FROM snapshot_facts",
	} {
		if !strings.Contains(query, token) {
			t.Fatalf("snapshot query missing %q: %s", token, query)
		}
	}
}

func TestRealtimeV2BasicSupportsFinalizedConnectionFilters(t *testing.T) {
	filter := realtimeV2Filter()
	filter.Snapshot = realtimeV2Snapshot(filter)
	filter.NodeID = realtimeV2NodeID
	filter.Domain = "cdn.example.test"
	filter.ListenPort = 443
	requests := 0
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		_, _ = io.WriteString(w, realtimeV2BasicSummaryRow(filter.Snapshot, 1, 1)+realtimeV2BasicPointRow(filter.Snapshot, filter.From, 1))
	}))
	defer server.Close()
	source := newRealtimeV2TestSource(t, Config{Endpoint: server.URL, Database: "analytics"}, server.Client())
	result, err := source.LoadBasic(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter)
	if err != nil {
		t.Fatalf("LoadBasic with finalized filters: %v", err)
	}
	if result.FactCount != 1 || requests != 1 {
		t.Fatalf("result=%#v requests=%d", result, requests)
	}
	for _, token := range []string{
		"connections_ingest_receipts_v1 FINAL", "node_id = {node_id:UUID}",
		"domain = {domain:String}", "listen_port = {listen_port:UInt16}",
	} {
		if !strings.Contains(query, token) {
			t.Fatalf("basic query missing %q: %s", token, query)
		}
	}
}

func TestRealtimeV2ConnectionQueryKeepsTenantAndCursorDimensionsBound(t *testing.T) {
	filter := realtimeV2Filter()
	filter.Snapshot = realtimeV2Snapshot(filter)
	filter.NodeID = realtimeV2NodeID
	filter.Domain = "cdn.example.test"
	filter.ListenPort = 443
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		query = string(body)
		_, _ = io.WriteString(w, realtimeV2BasicSummaryRow(filter.Snapshot, 1, 1)+realtimeV2BasicPointRow(filter.Snapshot, filter.From, 1))
	}))
	defer server.Close()
	source := newRealtimeV2TestSource(t, Config{Endpoint: server.URL, Database: "analytics"}, server.Client())
	if _, err := source.LoadBasic(t.Context(), analyticsrealtime.Scope{TenantID: realtimeV2TenantID}, filter); err != nil {
		t.Fatalf("LoadBasic: %v", err)
	}
	for _, token := range []string{
		"tenant_id = {tenant_id:UUID}", "site_id = {site_id:UUID}",
		"node_id = {node_id:UUID}", "domain = {domain:String}", "listen_port = {listen_port:UInt16}",
		"snapshot_ms:UInt64", "finalized_through",
	} {
		if !strings.Contains(query, token) {
			t.Fatalf("connection query lost tenant/snapshot binding %q: %s", token, query)
		}
	}
}
