//go:build integration

package analytics

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestScopeKeyedPackageReadsSeeProductionFacts (待出包前全量跑; needs
// TEST_DATABASE_URL and TEST_CLICKHOUSE_URL/TEST_CLICKHOUSE_DATABASE):
// facts are stamped the way production stamps them — the tenant the node
// telemetry manifest carries is `SELECT tenant_id FROM access_scopes`
// (edgepublish/site_runtime_v2.go), never the scope ID — written through
// WriteAccessEvents into access_events, projected by the CH materialized
// views, and read back through the scope-keyed package reads with the
// production PostgresTenants resolver. Before the fix every read was 0.
func TestScopeKeyedPackageReadsSeeProductionFacts(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	chDatabase := newRankTestDatabase(t)
	chDatabase.reset(t)
	applyAllClickHouseMigrations(t, chDatabase)
	pool := scopeTenantIntegrationPool(t)
	ctx := t.Context()

	// identity/users.go: the tenant and its scope are independent UUIDs.
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'pkg-tenantid')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	var stamped uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind='tenant'`, scopeID).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if stamped != tenantID || stamped == scopeID {
		t.Fatalf("stamped tenant %s, tenant %s, scope %s", stamped, tenantID, scopeID)
	}

	client, err := NewClient(Config{Endpoint: chDatabase.endpoint, Database: chDatabase.name,
		Username: chDatabase.username, Password: chDatabase.password, QueryTimeout: 5 * time.Second},
		&http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.WithTenantResolver(PostgresTenants{Query: pool})

	subscriptionID, siteID := uuid.NewString(), uuid.NewString()
	periodStart := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	periodEnd := periodStart.Add(time.Hour)
	events := make([]AccessEvent, 0, 3)
	for index, offset := range []time.Duration{5 * time.Minute, 20 * time.Minute, 40 * time.Minute} {
		event := validAccessEvent("pkg-tenantid-" + string(rune('a'+index)))
		event.OccurredAt = periodStart.Add(offset)
		event.TenantID, event.PackageSubscriptionID, event.SiteID = stamped.String(), subscriptionID, siteID
		event.RequestBytes, event.ResponseBytes = 100, 900
		events = append(events, event)
	}
	if err := client.WriteAccessEvents(ctx, "pkg-tenantid-batch", events); err != nil {
		t.Fatal(err)
	}
	const want = 3 * 1000

	// Overage enforcement and the package monitor.
	metric, err := client.PackageMetric(ctx, PackageMetricRequest{TenantScopeID: scopeID.String(), SubscriptionID: subscriptionID,
		Metric: "traffic_bytes", PeriodStart: periodStart, PeriodEnd: periodEnd})
	if err != nil || metric.Value != want {
		t.Fatalf("PackageMetric = %d, %v; want %d", metric.Value, err, want)
	}
	// The usage page (tenant and admin both pass the scope).
	usage, err := client.PackageUsage(ctx, PackageUsageRequest{TenantScopeID: scopeID.String(), SubscriptionID: subscriptionID,
		From: periodStart, To: periodEnd, Timezone: "UTC", Bucket: PackageUsageBucketHour, Limit: 24})
	if err != nil || usage.TrafficBytes != want {
		t.Fatalf("PackageUsage = %d, %v; want %d", usage.TrafficBytes, err, want)
	}
	// Site traffic caps.
	site, err := client.SiteTraffic(ctx, SiteTrafficRequest{TenantScopeID: scopeID.String(), SiteID: siteID,
		From: periodStart, To: periodEnd})
	if err != nil || site != want {
		t.Fatalf("SiteTraffic = %d, %v; want %d", site, err, want)
	}
	// Market metering.
	buckets, err := client.PackageTrafficBucketsFiltered(ctx, scopeID.String(), subscriptionID, periodStart, periodEnd, false)
	var bytesOut int64
	for _, bucket := range buckets {
		bytesOut += bucket.BytesOut
	}
	if err != nil || bytesOut != 3*900 {
		t.Fatalf("PackageTrafficBuckets out = %d, %v; want %d", bytesOut, err, 3*900)
	}
	// The usage search filters by tenants.id directly.
	search, err := client.SearchPackageUsage(ctx, UsageSearchRequest{From: periodStart, To: periodEnd, Timezone: "UTC",
		Bucket: PackageUsageBucketHour, ServiceType: "site", TenantID: stamped.String()})
	if err != nil || search.TrafficBytes != want {
		t.Fatalf("SearchPackageUsage = %d, %v; want %d", search.TrafficBytes, err, want)
	}

	// The scope ID itself matches no fact: this is the zero the bug read.
	unmapped := mustClient(t, Config{Endpoint: chDatabase.endpoint, Database: chDatabase.name,
		Username: chDatabase.username, Password: chDatabase.password}, &http.Client{Timeout: 10 * time.Second})
	if zero, err := unmapped.PackageMetric(ctx, PackageMetricRequest{TenantScopeID: scopeID.String(), SubscriptionID: subscriptionID,
		Metric: "traffic_bytes", PeriodStart: periodStart, PeriodEnd: periodEnd}); err != nil || zero.Value != 0 {
		t.Fatalf("scope ID as tenant_id = %d, %v; want 0 (no fact carries the scope ID)", zero.Value, err)
	}
	// An unknown scope fails instead of reading zero.
	if _, err := client.PackageMetric(ctx, PackageMetricRequest{TenantScopeID: uuid.NewString(), SubscriptionID: subscriptionID,
		Metric: "traffic_bytes", PeriodStart: periodStart, PeriodEnd: periodEnd}); err == nil {
		t.Fatal("unknown scope read succeeded")
	}
}

func scopeTenantIntegrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"pkg_tenantid_" + strings.ReplaceAll(uuid.NewString(), "-", "")}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := databasetest.CleanupContext()
		defer stop()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+schema.Sanitize()+" CASCADE")
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema[0]
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}
