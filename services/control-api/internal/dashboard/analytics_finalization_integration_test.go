package dashboard

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAnalyticsFinalizationReaderScopesActiveSources(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	schema := "dashboard_analytics_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	}()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	_, err = pool.Exec(ctx, `
		CREATE TABLE tenants (id uuid PRIMARY KEY, status text NOT NULL);
		CREATE TABLE access_scopes (id uuid PRIMARY KEY, tenant_id uuid);
		CREATE TABLE sites (
			id uuid PRIMARY KEY, scope_id uuid NOT NULL, enabled boolean NOT NULL,
			status text NOT NULL, deleted_at timestamptz
		);
		CREATE TABLE analytics_history_streams (history_epoch uuid PRIMARY KEY, retired_at timestamptz);
		CREATE TABLE analytics_ingest_watermarks_107 (
			tenant_id uuid NOT NULL, kind text NOT NULL, history_epoch uuid NOT NULL,
			dependency_state text NOT NULL, finalized_through timestamptz NOT NULL
		);`, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatal(err)
	}

	tenantA, tenantB, tenantInactive := uuid.New(), uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	epochA, epochB, retiredEpoch := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	_, err = pool.Exec(ctx, `
		INSERT INTO tenants(id,status) VALUES($1,'active'),($2,'active'),($3,'disabled');
		INSERT INTO access_scopes(id,tenant_id) VALUES($4,$1),($5,$2);
		INSERT INTO sites(id,scope_id,enabled,status,deleted_at)
		VALUES($6,$4,true,'active',NULL),($7,$5,false,'disabled',NULL);
		INSERT INTO analytics_history_streams(history_epoch,retired_at)
		VALUES($8,NULL),($9,NULL),($10,$11);
		INSERT INTO analytics_ingest_watermarks_107(tenant_id,kind,history_epoch,dependency_state,finalized_through)
		VALUES($1,'access.v1',$8,'ready',$11),($1,'security.v1',$8,'ready',$11),
		      ($2,'access.v1',$9,'ready',$11),($2,'security.v1',$9,'ready',$11);`,
		pgx.QueryExecModeSimpleProtocol, tenantA, tenantB, tenantInactive, scopeA, scopeB,
		uuid.New(), uuid.New(), epochA, epochB, retiredEpoch, now)
	if err != nil {
		t.Fatal(err)
	}

	reader := postgresAnalyticsFinalizationReader{}
	read := func(audience Audience, tenantID uuid.UUID) analyticsFinalizationSnapshot {
		t.Helper()
		var snapshot analyticsFinalizationSnapshot
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			snapshot, err = reader.Read(ctx, tx, audience, tenantID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}

	adminSnapshot := read(AudienceAdmin, uuid.Nil)
	if adminSnapshot.ExpectedTenants != 2 || adminSnapshot.AccessTenants != 2 ||
		adminSnapshot.SecurityTenants != 2 || adminSnapshot.Rows != 4 || adminSnapshot.ReadyRows != 4 {
		t.Fatalf("admin finalization snapshot = %#v", adminSnapshot)
	}
	tenantASnapshot := read(AudienceTenant, tenantA)
	if tenantASnapshot.ExpectedTenants != 1 || tenantASnapshot.AccessTenants != 1 ||
		tenantASnapshot.SecurityTenants != 1 || tenantASnapshot.Rows != 2 {
		t.Fatalf("tenant A finalization snapshot = %#v", tenantASnapshot)
	}
	tenantBSnapshot := read(AudienceTenant, tenantB)
	if tenantBSnapshot.ExpectedTenants != 1 || tenantBSnapshot.AccessTenants != 1 ||
		tenantBSnapshot.SecurityTenants != 1 || tenantBSnapshot.Rows != 2 {
		t.Fatalf("tenant B finalization snapshot = %#v", tenantBSnapshot)
	}
}
