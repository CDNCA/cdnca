//go:build integration

// Package tenantaccesstest seeds a tenant, a platform administrator
// (platform.admin) and a platform member without it, each with a live
// session, for fix-adminall integration cases. Integration builds only.
package tenantaccesstest

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Principal struct{ UserID, SessionID uuid.UUID }

type Fixture struct {
	PlatformScope, TenantScope, TenantID uuid.UUID
	Admin, Viewer                        Principal
}

func Seed(t *testing.T, pool *pgxpool.Pool) Fixture {
	t.Helper()
	ctx := t.Context()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", strings.Fields(q)[2], err)
		}
	}
	f := Fixture{TenantScope: uuid.New(), TenantID: uuid.New()}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.PlatformScope); err != nil {
		f.PlatformScope = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, f.PlatformScope)
	}
	exec(`INSERT INTO tenants(id,display_name) VALUES($1,'adminall tenant')`, f.TenantID)
	exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, f.TenantScope, f.TenantID)
	platform := func(permission string) Principal {
		p := Principal{UserID: uuid.New(), SessionID: uuid.New()}
		roleID := uuid.New()
		suffix := strings.ReplaceAll(p.UserID.String(), "-", "")[:12]
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'adminall','x')`, p.UserID, "aa"+suffix)
		exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'adminall',true)`,
			roleID, f.PlatformScope, "aa_"+suffix)
		exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission)
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, f.PlatformScope, p.UserID)
		exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, f.PlatformScope, p.UserID, roleID)
		digest := sha256.Sum256(p.SessionID[:])
		exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,now()-interval '1 minute',now()+interval '1 hour')`, p.SessionID, p.UserID, f.PlatformScope, digest[:])
		return p
	}
	f.Admin, f.Viewer = platform("platform.admin"), platform("sites.read")
	return f
}

// Check runs call in its own rolled-back transaction for the admin (must
// pass) and the viewer (must be refused).
func Check(t *testing.T, pool *pgxpool.Pool, f Fixture, call func(ctx context.Context, tx pgx.Tx, p Principal) error) {
	t.Helper()
	run := func(p Principal) error {
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		return call(t.Context(), tx, p)
	}
	if err := run(f.Admin); err != nil {
		t.Fatalf("platform admin acting for the tenant refused: %v", err)
	}
	if err := run(f.Viewer); err == nil {
		t.Fatal("platform member without platform.admin allowed")
	}
}
