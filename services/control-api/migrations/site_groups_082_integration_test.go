//go:build integration

package migrations_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var siteGroup082Now = time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)

func TestSiteGroups082BackfillConstraintsAndRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 81)
	fixture := seedSiteGroup082Identity(t, pool, "roundtrip")
	secondFixture := seedSiteGroup082Identity(t, pool, "roundtrip-second-scope")
	groupID := uuid.New()
	insertSiteGroup082Site(t, pool, fixture, uuid.New(), groupID, "默认分组", "one")
	insertSiteGroup082Site(t, pool, fixture, uuid.New(), groupID, "默认分组", "two")
	insertSiteGroup082Site(t, pool, secondFixture, uuid.New(), groupID, "另一租户分组", "other-scope")

	if err := migrateVersionIsolated(t.Context(), pool, "up", 82); err != nil {
		t.Fatalf("apply 082: %v", err)
	}
	assertSiteGroup082Head(t, pool, 82)

	var name string
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT name,revision FROM site_groups
		WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL`, fixture.scopeID, groupID).Scan(&name, &revision); err != nil {
		t.Fatal(err)
	}
	if name != "默认分组" || revision != 1 {
		t.Fatalf("backfilled group = name:%q revision:%d", name, revision)
	}
	var sameIDCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM site_groups WHERE id=$1`, groupID).
		Scan(&sameIDCount); err != nil {
		t.Fatal(err)
	}
	if sameIDCount != 2 {
		t.Fatalf("cross-scope same-ID groups = %d, want 2", sameIDCount)
	}

	if _, err := pool.Exec(t.Context(), `UPDATE site_groups
		SET name='重命名分组',revision=2,updated_at=$3
		WHERE scope_id=$1 AND id=$2`, fixture.scopeID, groupID, siteGroup082Now.Add(time.Minute)); err != nil {
		t.Fatalf("rename backfilled group: %v", err)
	}
	var names []string
	if err := pool.QueryRow(t.Context(), `SELECT array_agg(group_name ORDER BY domain)
		FROM sites WHERE scope_id=$1 AND group_id=$2`, fixture.scopeID, groupID).Scan(&names); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(names) != "[重命名分组 重命名分组]" {
		t.Fatalf("cascaded site names = %v", names)
	}

	_, err := pool.Exec(t.Context(), `UPDATE sites SET group_id=$2,group_name='伪造分组'
		WHERE scope_id=$1 AND id=(
			SELECT id FROM sites WHERE scope_id=$1 ORDER BY id LIMIT 1
		)`, fixture.scopeID, uuid.New())
	assertSiteGroup082Code(t, err, "P8206")
	_, err = pool.Exec(t.Context(), `UPDATE site_groups
		SET active=false,deleted_at=$3,revision=3,updated_at=$3 WHERE scope_id=$1 AND id=$2`,
		fixture.scopeID, groupID, siteGroup082Now.Add(2*time.Minute))
	assertSiteGroup082Code(t, err, "P8207")
	_, err = pool.Exec(t.Context(), `INSERT INTO site_groups(
		id,scope_id,name,revision,created_at,updated_at
	) VALUES($1,$2,'重命名分组',1,$3,$3)`, uuid.New(), fixture.scopeID, siteGroup082Now)
	assertSiteGroup082Code(t, err, "23505")
	_, err = pool.Exec(t.Context(), `INSERT INTO site_groups(
		id,scope_id,name,revision,created_at,updated_at
	) VALUES($1,$2,E'bad\nname',1,$3,$3)`, uuid.New(), fixture.scopeID, siteGroup082Now)
	assertSiteGroup082Code(t, err, "23514")
	platformScopeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
		platformScopeID); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `INSERT INTO site_groups(
		id,scope_id,name,revision,created_at,updated_at
	) VALUES($1,$2,'platform group',1,$3,$3)`, uuid.New(), platformScopeID, siteGroup082Now)
	assertSiteGroup082Code(t, err, "P8204")

	if err := migrateVersionIsolated(t.Context(), pool, "down", 82); err != nil {
		t.Fatalf("rollback 082: %v", err)
	}
	assertSiteGroup082Head(t, pool, 81)
	var relation *string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('site_groups')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != nil {
		t.Fatalf("site_groups remains after down: %q", *relation)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 82); err != nil {
		t.Fatalf("reapply 082: %v", err)
	}
	assertSiteGroup082Head(t, pool, 82)
	if err := pool.QueryRow(t.Context(), `SELECT name FROM site_groups
		WHERE scope_id=$1 AND id=$2`, fixture.scopeID, groupID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "重命名分组" {
		t.Fatalf("rebackfilled group name = %q", name)
	}
}

func TestSiteGroups082LegacyValidationFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		code string
		seed func(*testing.T, *pgxpool.Pool, siteGroup082Identity)
	}{
		{
			name: "unpaired fields", code: "P8201",
			seed: func(t *testing.T, pool *pgxpool.Pool, fixture siteGroup082Identity) {
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), uuid.New(), "valid", "unpaired")
				if _, err := pool.Exec(t.Context(), `UPDATE sites SET group_name=NULL WHERE scope_id=$1`, fixture.scopeID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "inconsistent name", code: "P8202",
			seed: func(t *testing.T, pool *pgxpool.Pool, fixture siteGroup082Identity) {
				groupID := uuid.New()
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), groupID, "alpha", "alpha")
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), groupID, "beta", "beta")
			},
		},
		{
			name: "duplicate active name", code: "P8203",
			seed: func(t *testing.T, pool *pgxpool.Pool, fixture siteGroup082Identity) {
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), uuid.New(), "same", "one")
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), uuid.New(), "same", "two")
			},
		},
		{
			name: "platform legacy scope", code: "P8204",
			seed: func(t *testing.T, pool *pgxpool.Pool, fixture siteGroup082Identity) {
				platformScopeID := uuid.New()
				if _, err := pool.Exec(t.Context(), `
					INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
					INSERT INTO memberships(scope_id,user_id,status,created_at)
					VALUES($1,$2,'active',$3)`, pgx.QueryExecModeSimpleProtocol,
					platformScopeID, fixture.userID, siteGroup082Now); err != nil {
					t.Fatal(err)
				}
				fixture.scopeID = platformScopeID
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), uuid.New(), "platform", "platform")
			},
		},
		{
			name: "invalid formal name", code: "P8201",
			seed: func(t *testing.T, pool *pgxpool.Pool, fixture siteGroup082Identity) {
				insertSiteGroup082Site(t, pool, fixture, uuid.New(), uuid.New(), " bad ", "invalid")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 81)
			fixture := seedSiteGroup082Identity(t, pool, strings.ReplaceAll(test.name, " ", "-"))
			test.seed(t, pool, fixture)
			err := migrateVersionIsolated(t.Context(), pool, "up", 82)
			assertSiteGroup082Code(t, err, test.code)
			assertSiteGroup082Head(t, pool, 81)
			var relation *string
			if queryErr := pool.QueryRow(t.Context(), `SELECT to_regclass('site_groups')::text`).Scan(&relation); queryErr != nil {
				t.Fatal(queryErr)
			}
			if relation != nil {
				t.Fatalf("failed migration left relation %q", *relation)
			}
		})
	}
}

func TestSiteGroups082DownRejectsUnrepresentableFacts(t *testing.T) {
	t.Run("write receipt", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 81)
		fixture := seedSiteGroup082Identity(t, pool, "receipt")
		groupID := uuid.New()
		insertSiteGroup082Site(t, pool, fixture, uuid.New(), groupID, "receipt", "receipt")
		if err := migrateVersionIsolated(t.Context(), pool, "up", 82); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(
			id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,
			request_digest,resource_id,created_at
		) VALUES($1,$2,$3,$3,'site_group.rename','receipt',$4,$5,$6)`, uuid.New(), fixture.userID,
			fixture.scopeID, make([]byte, 32), groupID, siteGroup082Now); err != nil {
			t.Fatal(err)
		}
		assertSiteGroup082Code(t, migrateVersionIsolated(t.Context(), pool, "down", 82), "P8210")
		assertSiteGroup082Head(t, pool, 82)
	})

	t.Run("unreferenced group", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 81)
		fixture := seedSiteGroup082Identity(t, pool, "unreferenced")
		if err := migrateVersionIsolated(t.Context(), pool, "up", 82); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO site_groups(
			id,scope_id,name,revision,created_at,updated_at
		) VALUES($1,$2,'unreferenced',1,$3,$3)`, uuid.New(), fixture.scopeID, siteGroup082Now); err != nil {
			t.Fatal(err)
		}
		assertSiteGroup082Code(t, migrateVersionIsolated(t.Context(), pool, "down", 82), "P8211")
		assertSiteGroup082Head(t, pool, 82)
	})
}

func TestSiteGroups082WriteReceiptsRejectTruncate(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 81)
	fixture := seedSiteGroup082Identity(t, pool, "receipt-truncate")
	groupID := uuid.New()
	insertSiteGroup082Site(t, pool, fixture, uuid.New(), groupID, "receipt truncate", "receipt-truncate")
	if err := migrateVersionIsolated(t.Context(), pool, "up", 82); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO site_group_write_requests(
		id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,
		request_digest,resource_id,created_at
	) VALUES($1,$2,$3,$3,'site_group.rename','receipt-truncate',$4,$5,$6)`, uuid.New(), fixture.userID,
		fixture.scopeID, make([]byte, 32), groupID, siteGroup082Now); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `TRUNCATE site_group_write_requests`)
	assertSiteGroup082Code(t, err, "P8212")
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM site_group_write_requests`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("write receipts after rejected truncate = %d, want 1", count)
	}
}

type siteGroup082Identity struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
}

func seedSiteGroup082Identity(t *testing.T, pool *pgxpool.Pool, slug string) siteGroup082Identity {
	t.Helper()
	fixture := siteGroup082Identity{tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New()}
	username := "site-group-082-" + strings.ReplaceAll(fixture.userID.String(), "-", "")
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name,status) VALUES($1,$2,'active');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($4,$5,$2,'unused','active',$6,$6);
		INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($3,$4,'active',$6)`,
		pgx.QueryExecModeSimpleProtocol, fixture.tenantID, "Site Group 082 "+slug,
		fixture.scopeID, fixture.userID, username, siteGroup082Now); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertSiteGroup082Site(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture siteGroup082Identity,
	siteID, groupID uuid.UUID,
	groupName, slug string,
) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			group_id,group_name,https_enabled,enabled,status,created_by_user_id,updated_by_user_id,
			created_at,updated_at
		) VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1'],
			ARRAY['192.0.2.1'],$5,$6,false,true,'active',$3,$3,$7,$7)`, siteID, fixture.scopeID,
			fixture.userID, slug+".example.test", groupID, groupName, siteGroup082Now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(
			site_id,position,host,port,weight,enabled
		) VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertSiteGroup082Code(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want SQLSTATE %s", want)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("error = %v, want SQLSTATE %s", err, want)
	}
}

func assertSiteGroup082Head(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var head int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if head != want {
		t.Fatalf("migration head=%d want=%d", head, want)
	}
}
