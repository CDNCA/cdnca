//go:build integration

package sitecapture

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// A16: an active site that never saved a capture policy must read as
// unconfigured (not 404), the first save with expected_revision 0 must create
// revision 1, and a missing or foreign site must still answer ErrNotFound.
func TestPostgresStoreUnconfiguredSiteCreatesFirstRevision(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Fatal("TEST_DATABASE_TEMPLATE is required (build it with TestBuildMigrationTemplate)")
	}
	ctx := context.Background()
	scopeID, tenantID, userID, sessionID, roleID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sessionHash := sha256.Sum256(sessionID[:])
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'capture-a16')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'capture-a16','owner','hash')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
		{`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$1,$2,$3,$4,$5,$6)`, []any{sessionID, userID, scopeID, sessionHash[:],
			time.Now().UTC().Add(-time.Hour), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'capture-a16','a16',true)`, []any{roleID, scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'site_capture.read'),($1,'site_capture.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{scopeID, userID, roleID}},
		// A site needs its origin pool and a primary origin in the same
		// transaction (deferred validate_site_origin_pool check).
		{`WITH site AS (INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,1,$2,$3,'capture-a16.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3) RETURNING id),
			origin_pool AS (INSERT INTO site_origin_pools(site_id) SELECT id FROM site)
			INSERT INTO site_origins(site_id,position,host,port) SELECT id,1,'192.0.2.10',80 FROM site`, []any{siteID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %q: %v", statement.sql, err)
		}
	}
	store, err := NewPostgresStore(pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant", SessionID: sessionID,
		Permissions: []string{PermissionRead, PermissionManage}}

	if _, err := service.Get(ctx, actor, scopeID, siteID); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("Get never-configured site err=%v, want ErrUnconfigured", err)
	}
	if _, err := service.Get(ctx, actor, scopeID, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing site err=%v, want ErrNotFound", err)
	}

	document := DefaultDocument()
	document.Enabled, document.Methods, document.RequestHeaderAllowlist = true, []string{"GET"}, []string{"User-Agent"}
	written, err := service.Update(ctx, actor, UpdateRequest{ScopeID: scopeID, SiteID: siteID, ExpectedRevision: 0,
		IdempotencyKey: "a16-create", RequestID: "a16-request", TraceID: "a16-trace", Document: document})
	if err != nil || written.Policy.Revision != 1 {
		t.Fatalf("first create result=%+v err=%v", written, err)
	}
	read, err := service.Get(ctx, actor, scopeID, siteID)
	if err != nil || read.Revision != 1 || !read.Document.Enabled {
		t.Fatalf("read after create=%+v err=%v", read, err)
	}
}
