package analytics

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

type packageResourceAccessIntegrationRow struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	OccurredAt            time.Time `json:"occurred_at"`
	IngestedAt            time.Time `json:"ingested_at"`
	TenantID              string    `json:"tenant_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	Host                  string    `json:"host"`
	Path                  string    `json:"path"`
	ClientIP              string    `json:"client_ip"`
	Method                string    `json:"method"`
	Protocol              string    `json:"protocol"`
	CacheStatus           string    `json:"cache_status"`
	StatusCode            uint16    `json:"status_code"`
	RequestBytes          uint64    `json:"request_bytes"`
	ResponseBytes         uint64    `json:"response_bytes"`
	DurationUS            uint64    `json:"duration_us"`
}

func TestPackageResourceNodesClickHouseIntegration(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyRealtimeFinalizerClickHouseMigrations(t, database)

	at := time.Now().UTC().Truncate(time.Second)
	tenantID := "10000000-0000-4000-8000-000000000001"
	subscriptionID := "20000000-0000-4000-8000-000000000001"
	siteID := "30000000-0000-4000-8000-000000000001"
	nodeID := "40000000-0000-4000-8000-000000000001"
	unknownNodeID := "40000000-0000-4000-8000-000000000002"
	foreignTenantID := "10000000-0000-4000-8000-000000000002"
	accessRows := []packageResourceAccessIntegrationRow{
		packageResourceAccessRow("old-second", at.Add(-2*time.Second), tenantID, subscriptionID, siteID, nodeID, 250_000),
		packageResourceAccessRow("latest-a", at.Add(-500*time.Millisecond), tenantID, subscriptionID, siteID, nodeID, 500_000),
		packageResourceAccessRow("latest-b", at.Add(-200*time.Millisecond), tenantID, subscriptionID, siteID, nodeID, 500_000),
		packageResourceAccessRow("unknown-node", at.Add(-time.Second), tenantID, subscriptionID, siteID, unknownNodeID, 125_000),
		packageResourceAccessRow("foreign-tenant", at.Add(-time.Second), foreignTenantID, subscriptionID, siteID, nodeID, 9_000_000),
	}
	insertRankRows(t, database, `INSERT INTO access_events
		(metric_version,event_id,occurred_at,ingested_at,tenant_id,package_subscription_id,site_id,node_id,
		 host,path,client_ip,method,protocol,cache_status,status_code,request_bytes,response_bytes,duration_us)
		FORMAT JSONEachRow`, accessRows)

	receipt := realtimeConnectionReceiptIntegrationRow{
		SchemaVersion: 1, ReceiptID: "package-resource-receipt", BatchID: "package-resource-batch",
		EventID: "package-resource-connection", TenantID: tenantID, NodeID: nodeID,
		Domain: "resource.example.test", ListenPort: 443, InstallationID: "package-resource-installation",
		SiteID: siteID, PackageSubscriptionID: subscriptionID, OccurredAt: at.Add(-300 * time.Millisecond), Connections: 15,
		PayloadSHA256: strings.Repeat("a", 64), CanonicalEventSHA256: strings.Repeat("b", 64),
		EvidenceSHA256: strings.Repeat("c", 64), SourceWatermark: 1, FinalizedThrough: at,
		NATSStream: "ANALYTICS", NATSDurable: "package-resource", NATSStreamSequence: 1, NATSConsumerSequence: 1,
		PubackStream: "ANALYTICS", PubackSequence: 1, ClickHouseInsertToken: strings.Repeat("d", 64),
		State: "ch_prepared", StateRank: 2, ReceivedAt: at, UpdatedAt: at,
	}
	insertRankRows(t, database, "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow", []realtimeConnectionReceiptIntegrationRow{receipt})

	client, err := NewClient(Config{
		Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password,
		QueryTimeout: 3 * time.Second,
	}, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.WithTenantResolver(sameTenant{})
	items, err := client.PackageResourceNodes(t.Context(), PackageResourceNodesRequest{
		TenantScopeID: tenantID, SubscriptionID: subscriptionID, At: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].NodeID != nodeID || items[0].BandwidthBPS == nil || *items[0].BandwidthBPS != 8_000_000 ||
		items[0].Connections == nil || *items[0].Connections != 15 || !items[0].ObservedAt.Equal(at.Add(-300*time.Millisecond)) ||
		items[1].NodeID != unknownNodeID || items[1].BandwidthBPS != nil || items[1].Connections != nil || !items[1].ObservedAt.IsZero() {
		t.Fatalf("package resource nodes=%#v", items)
	}
}

func packageResourceAccessRow(
	eventID string,
	occurredAt time.Time,
	tenantID, subscriptionID, siteID, nodeID string,
	responseBytes uint64,
) packageResourceAccessIntegrationRow {
	return packageResourceAccessIntegrationRow{
		MetricVersion: 1, EventID: eventID, OccurredAt: occurredAt, IngestedAt: occurredAt.Add(time.Millisecond),
		TenantID: tenantID, PackageSubscriptionID: subscriptionID, SiteID: siteID, NodeID: nodeID,
		Host: "resource.example.test", Path: "/asset", ClientIP: "2001:db8::1", Method: "GET",
		Protocol: "HTTP/2", CacheStatus: "HIT", StatusCode: http.StatusOK, ResponseBytes: responseBytes, DurationUS: 10,
	}
}
