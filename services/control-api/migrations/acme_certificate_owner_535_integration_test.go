//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 535: ACME certificates issued before
// the fix have no owner ("历史归属未记录"). The backfill gives each one the
// owner resolve_certificate_order_owner_535 picks — the tenant member who
// ordered it, the tenant's owner when a platform admin ordered it, the parent
// certificate's owner for a renewal — and leaves uploaded / unresolvable
// assets alone. Afterwards the owner is immutable again (276).
func TestACMECertificateOwnerBackfill535(t *testing.T) {
	pool := databasetest.FreshSchemaPool(t, "mig535", nil, func(ctx context.Context, pool *pgxpool.Pool) error {
		return databasetest.MigrateThrough(ctx, pool, "up", 534)
	})
	ctx := t.Context()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		must(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	user := func(label string) uuid.UUID {
		id := uuid.New()
		must(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'x')`,
			id, "o535-"+label+"-"+strings.ReplaceAll(id.String(), "-", "")[:8], label)
		return id
	}
	grant := func(scope, u uuid.UUID, roleName string, permissions ...string) {
		roleID := uuid.New()
		must(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'535',true)`,
			roleID, scope, roleName)
		for _, permission := range permissions {
			must(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		}
		must(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, u)
		must(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scope, u, roleID)
	}
	tenantID, tenantScope := uuid.New(), uuid.New()
	must(`INSERT INTO tenants(id,display_name) VALUES($1,'535 tenant')`, tenantID)
	must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenantScope, tenantID)
	owner, admin := user("owner"), user("admin")
	grant(tenantScope, owner, "tenant_owner", "certificates.read", "certificates.manage")
	grant(platformScope, admin, "o535_admin", "platform.admin")
	// A non-owner member: its order and that order's renewal belong to it,
	// not to the tenant owner (rules ② and ① before ③).
	staff := user("staff")
	grant(tenantScope, staff, "o535_staff", "certificates.manage")

	// Seed issued orders and assets directly, as 1.0.35 before the fix left
	// them: source='acme', owner NULL. Runtime triggers are bypassed for
	// fixture rows only (session_replication_role), never for the migration.
	seedACME := func(orderBy uuid.UUID, renewalOf *uuid.UUID, name string) (orderID, assetID uuid.UUID) {
		t.Helper()
		orderID, assetID = uuid.New(), uuid.New()
		versionID := uuid.New()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role=replica`, nil},
			{`ALTER TABLE certificate_orders DISABLE TRIGGER certificate_orders_runtime_048`, nil},
			{`ALTER TABLE certificate_orders DISABLE TRIGGER certificate_orders_metadata_immutable_517`, nil},
			{`INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,status,not_after,renewal_of_order_id,
				created_by_user_id,updated_by_user_id,issued_asset_id,issued_asset_version_id,issued_at,
				leaf_fingerprint_sha256,leaf_spki_sha256,acme_directory_url,acme_account_key_ref,certificate_key_ref,
				external_order_url,authorization_urls_sha256,certificate_url)
				VALUES($1,$2,ARRAY[$3::text],'http-01','active',now()+interval '60 days',$4,$5,$5,$6,$7,now(),
				sha256('f'::bytea),sha256('s'::bytea),'https://ca.example/dir','account','certificate',
				'https://ca.example/order',sha256('a'::bytea),'https://ca.example/cert')`,
				[]any{orderID, tenantScope, name + ".example.com", renewalOf, orderBy, assetID, versionID}},
			{`INSERT INTO certificate_assets(tenant_scope_id,id,name,source,created_by_scope_id,created_by_user_id,
				updated_by_scope_id,updated_by_user_id,created_at,updated_at,display_id) VALUES($1,$2,$3,'acme',$1,$4,$1,$4,
				clock_timestamp(),clock_timestamp(),
				(SELECT COALESCE(max(display_id),0)+1 FROM certificate_assets))`,
				[]any{tenantScope, assetID, name, orderBy}},
			{`INSERT INTO certificate_asset_versions(tenant_scope_id,id,asset_id,version,initial_status,
				fingerprint_sha256,certificate_pem,public_key_sha256,private_key_reference,private_key_aad_sha256,
				sans,leaf_subject,serial_number,public_key_algorithm,public_key_bits,signature_algorithm,
				not_before,not_after,acme_order_id,renewal_due_at,imported_by_user_id,imported_at,actor_scope_id)
				VALUES($1,$2,$3,1,'default',sha256($4::bytea),'pem'::bytea,sha256($4::bytea),'ref',sha256($4::bytea),
				ARRAY[$5::text],'CN=x','01','ecdsa',256,'ecdsa-with-SHA256',
				now()-interval '1 day',now()+interval '60 days',$6,now()+interval '30 days',$7,now(),$1)`,
				[]any{tenantScope, versionID, assetID, []byte(name), name + ".example.com", orderID, orderBy}},
			{`ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_runtime_048`, nil},
			{`ALTER TABLE certificate_orders ENABLE ALWAYS TRIGGER certificate_orders_metadata_immutable_517`, nil},
		} {
			if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("seed %s: %v", name, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return orderID, assetID
	}
	memberOrder, memberAsset := seedACME(staff, nil, "member")
	_, adminAsset := seedACME(admin, nil, "admin")
	_, renewalAsset := seedACME(admin, &memberOrder, "renewal")

	// A second tenant with two members and no tenant_owner: nobody to pick.
	otherID, otherScope := uuid.New(), uuid.New()
	must(`INSERT INTO tenants(id,display_name) VALUES($1,'535 other')`, otherID)
	must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, otherScope, otherID)
	grant(otherScope, user("m1"), "o535_m1", "sites.read")
	grant(otherScope, user("m2"), "o535_m2", "sites.read")
	savedScope := tenantScope
	tenantScope = otherScope
	_, unresolvedAsset := seedACME(admin, nil, "unresolved")
	tenantScope = savedScope

	if err := databasetest.MigrateThrough(ctx, pool, "up", 535); err != nil {
		t.Fatalf("migrate 535: %v", err)
	}
	ownerOf := func(asset uuid.UUID) *uuid.UUID {
		t.Helper()
		var value *uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT owner_user_id FROM certificate_assets WHERE id=$1`, asset).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	for name, test := range map[string]struct {
		asset uuid.UUID
		want  *uuid.UUID
	}{
		"tenant member order":  {memberAsset, &staff},
		"platform admin order": {adminAsset, &owner},
		"renewal":              {renewalAsset, &staff},
		"no single owner":      {unresolvedAsset, nil},
	} {
		got := ownerOf(test.asset)
		if (got == nil) != (test.want == nil) || got != nil && *got != *test.want {
			t.Errorf("%s: owner = %v, want %v", name, got, test.want)
		}
	}
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM certificate_assets WHERE id=$1`, memberAsset).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("backfill revision = %d err=%v, want unchanged 1", revision, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE certificate_assets SET owner_user_id=$2 WHERE id=$1`, memberAsset, admin); err == nil ||
		!strings.Contains(err.Error(), "certificate asset owner is immutable") {
		t.Fatalf("owner update after 535 error = %v, want immutable", err)
	}

	if err := databasetest.MigrateThrough(ctx, pool, "down", 535); err != nil {
		t.Fatalf("down 535: %v", err)
	}
	if got := ownerOf(memberAsset); got == nil || *got != staff {
		t.Fatalf("down dropped backfilled owner: %v", got)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 535); err != nil {
		t.Fatalf("re-up 535: %v", err)
	}
}
