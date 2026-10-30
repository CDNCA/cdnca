//go:build integration

package migrations_test

import (
	"errors"
	"io/fs"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSiteL4AutomaticPublication086RoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 85)
	assertSiteL4AutomaticHead085(t, pool)
	assertSiteL4AutomaticTables086(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 86); err != nil {
		t.Fatalf("apply 086: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 86)
	assertSiteL4AutomaticTables086(t, pool, true)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 86); err != nil {
		t.Fatalf("empty 086 down: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 85)
	assertSiteL4AutomaticTables086(t, pool, false)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 86); err != nil {
		t.Fatalf("reapply 086: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 86)
}

func TestSiteL4AutomaticPublication086RequiresFrozen085Head(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 84)
	script, err := fs.ReadFile(controlmigrations.FS, "086_site_l4_automatic_publication.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), string(script))
	assertSiteL4AutomaticCode086(t, err, "P8600")
	assertPackageCommerceRBAC079Ledger(t, pool, 84)
	assertSiteL4AutomaticTables086(t, pool, false)
}

func TestSiteL4AutomaticPublication086DownGuards(t *testing.T) {
	tests := []struct {
		name string
		seed func(*testing.T, *pgxpool.Pool, automaticIdentity086)
	}{
		{name: "policy change", seed: seedAutomaticPolicy086},
		{name: "platform actor fact", seed: seedPlatformRequest086},
		{name: "nonterminal request", seed: seedPendingRequest086},
		{name: "worker fact", seed: seedWorkerFact086},
		{name: "error head", seed: seedErrorHead086},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 86)
			identity := seedAutomaticIdentity086(t, pool)
			test.seed(t, pool, identity)
			err := migrateVersionIsolated(t.Context(), pool, "down", 86)
			assertSiteL4AutomaticCode086(t, err, "P8601")
			assertPackageCommerceRBAC079Ledger(t, pool, 86)
		})
	}
}

type automaticIdentity086 struct {
	tenantScope, tenantUser, platformScope, platformUser uuid.UUID
}

func seedAutomaticIdentity086(t *testing.T, pool *pgxpool.Pool) automaticIdentity086 {
	t.Helper()
	identity := automaticIdentity086{tenantScope: uuid.New(), tenantUser: uuid.New(), platformScope: uuid.New(), platformUser: uuid.New()}
	tenantID, tenantRole, platformRole := uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'automatic publication 086')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'platform',NULL)`, []any{identity.tenantScope, tenantID, identity.platformScope}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES
				($1,$2,'tenant actor','hash'),($3,$4,'platform actor','hash')`, []any{
				identity.tenantUser, "auto-tenant-" + identity.tenantUser.String(),
				identity.platformUser, "auto-platform-" + identity.platformUser.String(),
			}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`, []any{identity.tenantScope, identity.tenantUser, identity.platformScope, identity.platformUser}},
			{`INSERT INTO roles(id,scope_id,name,system_role) VALUES
				($1,$2,'tenant_owner',true),($3,$4,'platform_owner',true)`, []any{tenantRole, identity.tenantScope, platformRole, identity.platformScope}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES
				($1,'sites.manage'),($1,'streams.manage'),($2,'platform.admin') ON CONFLICT DO NOTHING`, []any{tenantRole, platformRole}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($4,$5,$6)`, []any{identity.tenantScope, identity.tenantUser, tenantRole, identity.platformScope, identity.platformUser, platformRole}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func seedAutomaticPolicy086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086) {
	t.Helper()
	insertAutomaticPolicy086(t, pool, identity, 1)
}

func seedPendingRequest086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086) {
	t.Helper()
	insertAutomaticPolicy086(t, pool, identity, 1)
	insertAutomaticRequest086(t, pool, identity, identity.tenantScope, identity.tenantUser, "pending", false)
}

func seedPlatformRequest086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086) {
	t.Helper()
	insertAutomaticPolicy086(t, pool, identity, 1)
	insertAutomaticRequest086(t, pool, identity, identity.platformScope, identity.platformUser, "superseded", false)
}

func seedWorkerFact086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086) {
	t.Helper()
	insertAutomaticPolicy086(t, pool, identity, 1)
	requestID := insertAutomaticRequest086(t, pool, identity, identity.tenantScope, identity.tenantUser, "pending", false)
	_, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts(
		request_id,sequence,state,attempt,lease_owner,lease_token,lease_expires_at,occurred_at
	) VALUES($1,2,'leased',1,'worker-086',$2,clock_timestamp()+interval '1 minute',clock_timestamp())`, requestID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
}

func seedErrorHead086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086) {
	t.Helper()
	insertAutomaticPolicy086(t, pool, identity, 1)
	requestID := insertAutomaticRequest086(t, pool, identity, identity.tenantScope, identity.tenantUser, "pending", false)
	_, err := pool.Exec(t.Context(), `ALTER TABLE edge_automatic_publication_request_state_facts DISABLE TRIGGER USER`)
	if err == nil {
		_, err = pool.Exec(t.Context(), `DELETE FROM edge_automatic_publication_request_state_facts WHERE request_id=$1`, requestID)
	}
	if _, enableErr := pool.Exec(t.Context(), `ALTER TABLE edge_automatic_publication_request_state_facts ENABLE TRIGGER USER`); err == nil {
		err = enableErr
	}
	if err != nil {
		t.Fatal(err)
	}
}

func insertAutomaticPolicy086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086, revision int64) {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	if nodes[0].String() > nodes[1].String() {
		nodes[0], nodes[1] = nodes[1], nodes[0]
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at
	) VALUES($1,$2,'automatic',$3,30000,15000,2,3,600,$1,$4,'test_policy',clock_timestamp())`,
		identity.tenantScope, revision, nodes, identity.tenantUser)
	if err != nil {
		t.Fatal(err)
	}
}

func insertAutomaticRequest086(t *testing.T, pool *pgxpool.Pool, identity automaticIdentity086,
	actorScope, actorUser uuid.UUID, initialState string, workerFact bool,
) uuid.UUID {
	t.Helper()
	requestID, correlationID := uuid.New(), uuid.New()
	resourceID := uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO edge_automatic_publication_requests(
			id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,source_kind,
			source_resource_id,source_revision,operation,reason,permission_name,source_request_id,
			idempotency_key,correlation_id,request_digest,policy_revision,created_at
		) VALUES($1,$2::uuid,$3::uuid,$4,CASE WHEN $3::uuid=$2::uuid THEN 'tenant' ELSE 'platform' END,'site',$5,1,
			'site.create','resource_mutation','sites.manage','request-086',$6,$7,$8,1,clock_timestamp())`,
			requestID, identity.tenantScope, actorScope, actorUser, resourceID,
			"edgeauto."+requestID.String(), correlationID, make([]byte, 32)); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts(
			request_id,sequence,state,attempt,terminal_code,occurred_at
		) VALUES($1,1,$2::text,0,CASE WHEN $2::text='superseded' THEN 'superseded_by_newer_revision' ELSE NULL END,clock_timestamp())`,
			requestID, initialState)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = workerFact
	return requestID
}

func assertSiteL4AutomaticHead085(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var identifier, up, down, integrity string
	if err := pool.QueryRow(t.Context(), `SELECT migration_id,checksum_sha256,down_checksum_sha256,integrity_state
		FROM schema_migrations WHERE version=85`).Scan(&identifier, &up, &down, &integrity); err != nil {
		t.Fatal(err)
	}
	if identifier != "085_certificate_asset_actor_scope" ||
		up != "1e2554228e01bcc8d79fa78e55dd51eb65e52ce45afcd754a2e6cd9a9a540937" ||
		down != "116890b0368609b973415f1a25c599c145bd42fdfec0d1a25639160cc736f046" || integrity != "verified" {
		t.Fatalf("085 head = %q %q %q %q", identifier, up, down, integrity)
	}
}

func assertSiteL4AutomaticTables086(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	for _, table := range []string{
		"edge_automatic_publication_policy_facts", "edge_automatic_publication_requests",
		"edge_automatic_publication_request_state_facts",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass(current_schema()||'.'||$1) IS NOT NULL`, table).Scan(&exists); err != nil || exists != want {
			t.Fatalf("table %s exists=%t want=%t err=%v", table, exists, want, err)
		}
	}
}

func assertSiteL4AutomaticCode086(t *testing.T, err error, want string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != want {
		t.Fatalf("PostgreSQL error=%v code=%q want=%q", err, func() string {
			if postgresError == nil {
				return ""
			}
			return postgresError.Code
		}(), want)
	}
}

var _ = time.Second
