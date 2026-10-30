//go:build integration

package migrations_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestTenantDNSHub599: hub rows only cover tenant-entered DNS accounts (the
// platform copy is refused), idempotency keys are unique per member, and
// down refuses while an unconfirmed operation exists.
func TestTenantDNSHub599(t *testing.T) {
	// Keep equal to the 599 contract's version.
	const version = 599
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	tenantProvider, platformCopy := uuid.New(), uuid.New()
	provider := `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
		created_by_user_id,updated_by_user_id,managed_by)
		VALUES($1,$2,$3,'cloudflare','credential-key',decode(repeat('ab',32),'hex'),'verified',$4,$4,$5)`
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'hub599')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Hub owner','test-hash')`,
			[]any{userID, "hub599-" + strings.ReplaceAll(userID.String(), "-", "")[:12]}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{provider, []any{tenantProvider, scopeID, "Own DNS", userID, "tenant"}},
		{provider, []any{platformCopy, scopeID, "Platform copy", userID, "platform"}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	listing := `INSERT INTO tenant_dns_provider_listings(scope_id,provider_id,last_listed_at,updated_at) VALUES($1,$2,now(),now())`
	if _, err := pool.Exec(ctx, listing, scopeID, tenantProvider); err != nil {
		t.Fatal(err)
	}
	var pgErr *pgconn.PgError
	if _, err := pool.Exec(ctx, listing, scopeID, platformCopy); !errors.As(err, &pgErr) || pgErr.Code != "P5993" {
		t.Fatalf("platform copy listing: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_dns_domains(scope_id,provider_id,apex,last_listed_at)
		VALUES($1,$2,'example.com',now())`, scopeID, tenantProvider); err != nil {
		t.Fatal(err)
	}
	op := `INSERT INTO tenant_dns_record_ops(id,scope_id,provider_id,apex,actor_user_id,idempotency_key,request_sha256,
		action,record_type,record_name,after,state,response_status,response,request_id,created_at,updated_at)
		VALUES($1,$2,$3,'example.com',$4,'key-1',repeat('a',64),'create','TXT','www.example.com',
		'{"value":"v=spf1 -all"}','uncertain',202,'{}','req-1',now(),now())`
	if _, err := pool.Exec(ctx, op, uuid.New(), scopeID, tenantProvider, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, op, uuid.New(), scopeID, tenantProvider, userID); !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate idempotency key: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil || !strings.Contains(err.Error(), "unconfirmed") {
		t.Fatalf("down with an uncertain op: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_dns_record_ops SET state='applied'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
}
