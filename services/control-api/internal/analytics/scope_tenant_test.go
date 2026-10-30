package analytics

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The scope and its tenant are distinct UUIDs (identity/users.go generates
// them independently). Facts carry the tenant: the node telemetry manifest
// and the gateway authorization take access_scopes.tenant_id.
const (
	scopeTenantTestScopeID  = "a0000000-0000-4000-8000-00000000000a"
	scopeTenantTestTenantID = "b0000000-0000-4000-8000-00000000000b"
)

type mapTenants map[string]string

func (tenants mapTenants) TenantOfScope(_ context.Context, scopeID string) (string, error) {
	tenant, ok := tenants[scopeID]
	if !ok {
		return "", ErrInvalidInput
	}
	return tenant, nil
}

// tenantRecorder answers every scope-keyed package read with a minimal valid
// row and records the tenant_id parameter of each ClickHouse query.
func tenantRecorder(t *testing.T) (*Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var tenants []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		mu.Lock()
		tenants = append(tenants, request.URL.Query().Get("param_tenant_id"))
		mu.Unlock()
		digest := strings.Repeat("ab", 32)
		switch {
		case strings.Contains(query, "peak_1s_spread_v1"):
			_, _ = io.WriteString(writer, `{"value":4096,"observed_at_ms":1785600000000,"finalized_through_ms":1785603600000,"source_evidence_digest":"`+digest+`"}`+"\n")
		case strings.Contains(query, "max(ingested_at) AS last_ingested_at"):
			_, _ = io.WriteString(writer, `{"access_snapshot_ms":1785600000000,"connection_snapshot_ms":1785600000000}`+"\n")
		case strings.Contains(query, "source_watermark") && strings.Contains(query, "peak_bandwidth_bps"):
			_, _ = io.WriteString(writer, `{"traffic_bytes":4096,"peak_bandwidth_bps":0,"bandwidth_95th_bps":0,"connections":0,"source_watermark":1,"finalized_through_ms":1785603600000}`+"\n")
		case strings.Contains(query, "bucket_ms"):
		case strings.Contains(query, "access_metering_facts_v1") && strings.Contains(query, "site_id={site_id:UUID}"):
			_, _ = io.WriteString(writer, `{"traffic_bytes":4096}`+"\n")
		case strings.Contains(query, "INTERVAL 5 MINUTE"):
			_, _ = io.WriteString(writer, `{"bucket_start":1785600000,"bytes_out":4096,"requests":1}`+"\n")
		case strings.Contains(query, "package_metric_access_facts_v1") || strings.Contains(query, "package_metric_connection_facts_v1"):
			_, _ = io.WriteString(writer, `{"value":4096,"observed_at_ms":1785600000000,"finalized_through_ms":1785603600000,"source_evidence_digest":"`+digest+`"}`+"\n")
		}
	}))
	t.Cleanup(server.Close)
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	return client, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), tenants...)
	}
}

// TestScopeKeyedPackageReadsQueryTheFactsTenant: every package read keyed by
// the access scope (overage enforcement, package monitor, package usage page,
// resource monitor, site traffic caps, market metering) queries ClickHouse
// with the tenant the production write path stamps on the facts. Before the
// fix they sent the scope ID, matched no row and read 0: never over quota.
func TestScopeKeyedPackageReadsQueryTheFactsTenant(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 8, 1, 16, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	reads := map[string]func(*Client) error{
		"PackageMetric traffic_bytes": func(client *Client) error {
			result, err := client.PackageMetric(ctx, PackageMetricRequest{TenantScopeID: scopeTenantTestScopeID,
				SubscriptionID: testPackageSubscriptionID, Metric: "traffic_bytes", PeriodStart: start, PeriodEnd: end})
			if err == nil && result.Value != 4096 {
				t.Errorf("PackageMetric value = %d", result.Value)
			}
			return err
		},
		"PackageMetric connections": func(client *Client) error {
			_, err := client.PackageMetric(ctx, PackageMetricRequest{TenantScopeID: scopeTenantTestScopeID,
				SubscriptionID: testPackageSubscriptionID, Metric: "connections", PeriodStart: start, PeriodEnd: end})
			return err
		},
		"PackageBandwidthFinalized": func(client *Client) error {
			_, err := client.PackageBandwidthFinalized(ctx, PackageMetricRequest{TenantScopeID: scopeTenantTestScopeID,
				SubscriptionID: testPackageSubscriptionID, Metric: "bandwidth_bps", PeriodStart: start, PeriodEnd: end})
			return err
		},
		"PackageUsage": func(client *Client) error {
			result, err := client.PackageUsage(ctx, PackageUsageRequest{TenantScopeID: scopeTenantTestScopeID,
				SubscriptionID: testPackageSubscriptionID, From: start, To: end, Timezone: "UTC",
				Bucket: PackageUsageBucketHour, Limit: 24})
			if err == nil && result.TrafficBytes != 4096 {
				t.Errorf("PackageUsage traffic = %d", result.TrafficBytes)
			}
			return err
		},
		"PackageResourceNodes": func(client *Client) error {
			_, err := client.PackageResourceNodes(ctx, PackageResourceNodesRequest{TenantScopeID: scopeTenantTestScopeID,
				SubscriptionID: testPackageSubscriptionID, At: end})
			return err
		},
		"SiteTraffic": func(client *Client) error {
			value, err := client.SiteTraffic(ctx, SiteTrafficRequest{TenantScopeID: scopeTenantTestScopeID,
				SiteID: testSiteID, From: start, To: end})
			if err == nil && value != 4096 {
				t.Errorf("SiteTraffic = %d", value)
			}
			return err
		},
		"PackageTrafficBucketsFiltered": func(client *Client) error {
			_, err := client.PackageTrafficBucketsFiltered(ctx, scopeTenantTestScopeID, testPackageSubscriptionID, start, end, false)
			return err
		},
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			client, tenants := tenantRecorder(t)
			client.WithTenantResolver(mapTenants{scopeTenantTestScopeID: scopeTenantTestTenantID})
			if err := read(client); err != nil {
				t.Fatalf("read: %v", err)
			}
			sent := tenants()
			if len(sent) == 0 {
				t.Fatal("no ClickHouse query")
			}
			for _, tenant := range sent {
				if tenant != scopeTenantTestTenantID {
					t.Fatalf("ClickHouse tenant_id = %q, want the facts' tenant %q (scope %q)", tenant, scopeTenantTestTenantID, scopeTenantTestScopeID)
				}
			}
		})
	}
}

// TestScopeKeyedPackageReadsFailClosedWithoutResolver: without the resolver
// (or with an unknown scope) the read fails rather than querying with the
// scope ID and reporting zero usage.
func TestScopeKeyedPackageReadsFailClosedWithoutResolver(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 8, 1, 16, 0, 0, 0, time.UTC)
	request := PackageMetricRequest{TenantScopeID: scopeTenantTestScopeID, SubscriptionID: testPackageSubscriptionID,
		Metric: "traffic_bytes", PeriodStart: start, PeriodEnd: start.Add(time.Hour)}

	client, tenants := tenantRecorder(t)
	client.WithTenantResolver(nil)
	if _, err := client.PackageMetric(ctx, request); !errors.Is(err, ErrTenantUnresolved) {
		t.Fatalf("no resolver: err = %v, want ErrTenantUnresolved", err)
	}
	client.WithTenantResolver(mapTenants{})
	if _, err := client.PackageMetric(ctx, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown scope: err = %v, want ErrInvalidInput", err)
	}
	client.WithTenantResolver(mapTenants{scopeTenantTestScopeID: "not-a-uuid"})
	if _, err := client.PackageMetric(ctx, request); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("invalid tenant: err = %v, want ErrInvalidResponse", err)
	}
	if sent := tenants(); len(sent) != 0 {
		t.Fatalf("ClickHouse queried with %v", sent)
	}
}
