package systemsettings

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FX61/NF26：公开子集只读平台作用域那一行，租户作用域不参与；没有记录时返回空值。
func TestPublicSettingsReadsPlatformScopeOnly(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "system_settings_public_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	for _, statement := range []string{
		`CREATE TABLE access_scopes(id uuid PRIMARY KEY, kind text NOT NULL, tenant_id uuid, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE platform_system_settings(platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id),
			revision bigint NOT NULL, settings jsonb NOT NULL, updated_by_user_id uuid, updated_at timestamptz NOT NULL)`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if value, err := service.Public(ctx); err != nil || value != (PublicSettings{}) {
		t.Fatalf("empty Public() = %#v, %v", value, err)
	}
	if hosts, err := service.CSPReportHosts(ctx); err != nil || hosts != "" {
		t.Fatalf("empty CSPReportHosts() = %q, %v", hosts, err)
	}

	platformID, tenantScopeID, tenantID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL),($2,'tenant',$3)`,
		platformID, tenantScopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	insert := func(scope uuid.UUID, value Settings) {
		raw, _ := json.Marshal(value)
		if _, err := pool.Exec(ctx, `INSERT INTO platform_system_settings(platform_scope_id,revision,settings,updated_at)
			VALUES($1,1,$2,now())`, scope, raw); err != nil {
			t.Fatal(err)
		}
	}
	tenantValue := DefaultSettings()
	tenantValue.PurchaseNotice = "<p>forged</p>"
	insert(tenantScopeID, tenantValue)
	if value, err := service.Public(ctx); err != nil || value != (PublicSettings{}) {
		t.Fatalf("tenant-scoped row leaked into Public() = %#v, %v", value, err)
	}
	platformValue := DefaultSettings()
	platformValue.PurchaseNotice = "<p>购买前请确认</p>"
	platformValue.GlobalJS = "window.__cdnca_global_js = 1"
	platformValue.BoundDomains = "admin.example.test"
	platformValue.GlobalJSReportHosts = []string{"hm.baidu.com", "stats.example.com"}
	insert(platformID, platformValue)
	if hosts, err := service.CSPReportHosts(ctx); err != nil || hosts != "https://hm.baidu.com https://stats.example.com" {
		t.Fatalf("CSPReportHosts() = %q, %v", hosts, err)
	}
	value, err := service.Public(ctx)
	if err != nil || value.PurchaseNotice != platformValue.PurchaseNotice || value.GlobalJS != platformValue.GlobalJS ||
		value.SystemName != platformValue.SystemName || value.UserTitle != platformValue.UserTitle || value.AdminTitle != platformValue.AdminTitle {
		t.Fatalf("Public() = %#v, %v", value, err)
	}
}
