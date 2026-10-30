//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSiteOriginRouteControl109PredecessorFailsClosedWithoutResources(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("109_site_origin_route_control.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("109_site_origin_route_control.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(up), "migration 109 requires the exact verified 108 release head") ||
		!strings.Contains(string(up), "ERRCODE='P1090'") ||
		strings.Index(string(up), "P1090") > strings.Index(string(up), "CREATE TABLE") {
		t.Fatal("109 up must fail closed before creating resources")
	}
	if !strings.Contains(string(down), "migration 109 rollback requires the exact verified 109 head") ||
		!strings.Contains(string(down), "ERRCODE='P1090'") {
		t.Fatal("109 down must require the exact verified 109 head")
	}

	pool := packageCommerceRBAC079Pool(t, 106)
	_, err = pool.Exec(t.Context(), string(up))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P1090" {
		t.Fatalf("109 up error = %v, want P1090", err)
	}
	var resources int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_class
		WHERE relnamespace=current_schema()::regnamespace
		  AND relname LIKE 'site_origin_route_%'`).Scan(&resources); err != nil {
		t.Fatal(err)
	}
	if resources != 0 {
		t.Fatalf("109 resources after fail-closed migration = %d, want 0", resources)
	}
}

func TestSiteOriginRouteControl109Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("109_site_origin_route_control.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("109_site_origin_route_control.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, required := range []string{
		"migration 109 requires the exact verified 108 release head",
		"migration_id='108_notification_provider_settlement'",
		"checksum_sha256='8f56c7f03a30c90547edbca9f50da785ed5cf05ddf2395e431c95cb791409ce9'",
		"down_checksum_sha256='63590fa028e8dc35df49171ef6d790b3cb50e136b0fd44f2f0522d405df3a1f9'",
		"REQUIRED_MIGRATION_108_INTEGRATION_SHA256=67dc5ddfa5ee3ab8c346c203f4deb1df6af36d7f697830c0b327fb24f3050cd9",
		"(SELECT count(*) FROM schema_migrations) <> 108",
		"(SELECT min(version) FROM schema_migrations) <> 1",
		"(SELECT max(version) FROM schema_migrations) <> 108",
		"migration_id IS NULL OR checksum_sha256 IS NULL",
		"checksum_sha256 !~ '^[0-9a-f]{64}$'",
		"down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'",
		"integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL",
		"integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL",
		"CREATE TABLE site_origin_route_configs",
		"CREATE TABLE site_origin_route_pools",
		"CREATE TABLE site_origin_route_endpoints",
		"CREATE TABLE site_origin_routes",
		"CREATE TABLE site_origin_route_write_requests",
		"cdnca.edge.origin-route/v1", "GET", "HEAD",
		"site.origin_route.update", "request_digest", "audit_event_id",
		"REVOKE ALL ON site_origin_route_configs FROM PUBLIC",
	} {
		if !strings.Contains(upSQL, required) {
			t.Errorf("109 up missing %q", required)
		}
	}
	upGuard := strings.Index(upSQL, "USING ERRCODE='P1090'")
	firstCreate := strings.Index(upSQL, "CREATE TABLE")
	if upGuard < 0 || firstCreate < 0 || upGuard > firstCreate {
		t.Fatal("109 up predecessor guard must run before the first CREATE TABLE")
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 109",
		"(SELECT min(version) FROM schema_migrations) <> 1",
		"(SELECT max(version) FROM schema_migrations) <> 109",
		"version=109 AND migration_id='109_site_origin_route_control'",
		"checksum_sha256='d6b3a67fa2504b048f969317c7605868ebe3ad4edf122286d546edfb023310c2'",
		"version=108 AND migration_id='108_notification_provider_settlement'",
		"checksum_sha256='8f56c7f03a30c90547edbca9f50da785ed5cf05ddf2395e431c95cb791409ce9'",
		"down_checksum_sha256='63590fa028e8dc35df49171ef6d790b3cb50e136b0fd44f2f0522d405df3a1f9'",
		"migration 109 rollback requires the exact verified 109 head",
		"migration 109 rollback would discard site origin route facts",
		"USING ERRCODE='P1090'", "USING ERRCODE='P1091'",
		"EXISTS (SELECT 1 FROM site_origin_route_configs)",
		"EXISTS (SELECT 1 FROM site_origin_route_pools)",
		"EXISTS (SELECT 1 FROM site_origin_route_endpoints)",
		"EXISTS (SELECT 1 FROM site_origin_routes)",
		"EXISTS (SELECT 1 FROM site_origin_route_write_requests)",
		"DROP CONSTRAINT site_origin_route_configs_default_pool_fk",
		"DROP CONSTRAINT site_origin_route_configs_default_fallback_pool_fk",
	} {
		if !strings.Contains(downSQL, required) {
			t.Errorf("109 down missing %q", required)
		}
	}
	downGuard := strings.Index(downSQL, "USING ERRCODE='P1090'")
	firstDrop := strings.Index(downSQL, "DROP TABLE")
	if downGuard < 0 || firstDrop < 0 || downGuard > firstDrop {
		t.Fatal("109 down release guard must run before the first DROP")
	}
	data, err := os.ReadFile("notification_provider_settlement_108_integration_test.go")
	if err != nil {
		t.Fatal(err)
	}
	actual108IntegrationSHA := fmt.Sprintf("%x", sha256.Sum256(data))
	if actual108IntegrationSHA != "67dc5ddfa5ee3ab8c346c203f4deb1df6af36d7f697830c0b327fb24f3050cd9" {
		t.Fatalf("108 integration SHA=%s, authoritative SHA drifted", actual108IntegrationSHA)
	}
	if !strings.Contains(upSQL, "REQUIRED_MIGRATION_108_INTEGRATION_SHA256="+actual108IntegrationSHA) {
		t.Fatalf("109 up does not bind computed 108 integration SHA %s", actual108IntegrationSHA)
	}
}

func TestSiteOriginRouteControl109DownRejectsWrongHeadAndFacts(t *testing.T) {
	down, err := controlmigrations.FS.ReadFile("109_site_origin_route_control.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong checksum", func(t *testing.T) {
		pool := siteOriginRoute109Pool(t)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET checksum_sha256=repeat('a',64) WHERE version=109`); err != nil {
			t.Fatal(err)
		}
		assertSiteOriginRoute109Code(t, executeSiteOriginRoute109Down(t, pool, down), "P1090")
		assertSiteOriginRoute109Resources(t, pool, true)
	})

	t.Run("future head", func(t *testing.T) {
		pool := siteOriginRoute109Pool(t)
		if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at
		) VALUES(110,'110_test_future',repeat('a',64),repeat('b',64),'verified',statement_timestamp())`); err != nil {
			t.Fatal(err)
		}
		assertSiteOriginRoute109Code(t, executeSiteOriginRoute109Down(t, pool, down), "P1090")
		assertSiteOriginRoute109Resources(t, pool, true)
	})

	t.Run("route facts", func(t *testing.T) {
		pool := siteOriginRoute109Pool(t)
		identity := seedCertificateIdentity085(t, pool)
		siteID := insertCertificateSite085(t, pool, identity, "origin-route-109.example.test")
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_route_configs(
				site_id,schema,default_pool_id,retry_methods,max_attempts,connect_timeout_ms,
				read_timeout_ms,total_budget_ms,updated_by_user_id,updated_at
			) VALUES($1,'cdnca.edge.origin-route/v1','primary',ARRAY['GET'],1,1000,1000,2000,$2,statement_timestamp())`,
				siteID, identity.tenantUser); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO site_origin_route_pools(
				site_id,pool_id,position,balance_method
			) VALUES($1,'primary',0,'round_robin')`, siteID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		assertSiteOriginRoute109Code(t, executeSiteOriginRoute109Down(t, pool, down), "P1091")
		assertSiteOriginRoute109Resources(t, pool, true)
	})
}

func siteOriginRoute109Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := packageCommerceRBAC079Pool(t, 108)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 109); err != nil {
		t.Fatalf("apply 109: %v", err)
	}
	return pool
}

func executeSiteOriginRoute109Down(t *testing.T, pool *pgxpool.Pool, down []byte) error {
	t.Helper()
	_, err := pool.Exec(t.Context(), string(down))
	return err
}

func assertSiteOriginRoute109Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("109 PostgreSQL error = %v, want %s", err, want)
	}
}

func assertSiteOriginRoute109Resources(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	for _, name := range []string{
		"site_origin_route_configs", "site_origin_route_pools", "site_origin_route_endpoints",
		"site_origin_routes", "site_origin_route_write_requests",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), "SELECT to_regclass($1) IS NOT NULL", name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != want {
			t.Fatalf("109 resource %s exists=%t, want %t", name, exists, want)
		}
	}
}
