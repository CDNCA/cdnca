package analytics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPackageResourceNodesUsesBoundedNodeFactsAndPreservesUnknownTelemetry(t *testing.T) {
	at := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	nodeID := "44444444-4444-4444-8444-444444444444"
	unknownNodeID := "55555555-5555-4555-8555-555555555555"
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		for _, token := range []string{
			"access_events FINAL", "connections_ingest_receipts_v1 FINAL", "node_id",
			"package_subscription_id={subscription_id:UUID}", "occurred_at>={from:DateTime64(3,'UTC')}",
			"argMax", "toStartOfSecond", "FORMAT JSONEachRow",
		} {
			if !strings.Contains(query, token) {
				t.Errorf("query missing %q", token)
			}
		}
		parameters := request.URL.Query()
		if parameters.Get("param_tenant_id") != testTenantID ||
			parameters.Get("param_subscription_id") != testPackageSubscriptionID ||
			parameters.Get("param_at") != at.Format("2006-01-02 15:04:05.000") ||
			parameters.Get("param_from") != at.Add(-2*time.Minute).Format("2006-01-02 15:04:05.000") {
			t.Errorf("parameters=%v", parameters)
		}
		_, _ = io.WriteString(writer,
			`{"node_id":"`+nodeID+`","bandwidth_bps":8000000,"bandwidth_observed_at_ms":1789545599000,"connections":15,"connections_observed_at_ms":1789545598000}`+"\n"+
				`{"node_id":"`+unknownNodeID+`","bandwidth_bps":null,"bandwidth_observed_at_ms":null,"connections":15,"connections_observed_at_ms":1789545598000}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())

	items, err := client.PackageResourceNodes(context.Background(), PackageResourceNodesRequest{
		TenantScopeID: testTenantID, SubscriptionID: testPackageSubscriptionID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(items) != 2 || items[0].NodeID != nodeID || items[0].BandwidthBPS == nil ||
		*items[0].BandwidthBPS != 8000000 || items[0].Connections == nil || *items[0].Connections != 15 ||
		items[0].ObservedAt.IsZero() || items[1].NodeID != unknownNodeID ||
		items[1].BandwidthBPS != nil || items[1].Connections != nil || !items[1].ObservedAt.IsZero() {
		t.Fatalf("items=%#v calls=%d", items, calls)
	}
}

func TestPackageResourceNodesRejectsInvalidScopeAndFutureRows(t *testing.T) {
	at := time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC)
	client := mustClient(t, Config{Endpoint: "https://localhost", Database: "analytics_test"}, &http.Client{})
	if _, err := client.PackageResourceNodes(context.Background(), PackageResourceNodesRequest{
		TenantScopeID: "bad", SubscriptionID: testPackageSubscriptionID, At: at,
	}); err == nil {
		t.Fatal("invalid scope was accepted")
	}
}
