//go:build integration

package observabilitylog

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestOperationLogUserAgentAndObjectNamesPostgreSQL (tp-b6b) on the real
// schema: audit.Append stores the request's User-Agent (control characters
// removed, cut to 512 bytes) and the operation log returns it, rows written
// without one return ""; the 对象 column gets the object's name in one query
// per page (site domain, node name), a soft-deleted site or a purged node is
// marked deleted, and an object of another tenant is never named.
func TestOperationLogUserAgentAndObjectNamesPostgreSQL(t *testing.T) {
	pool := anonymousNotificationPool(t)
	ctx := t.Context()
	scopeA, scopeB, userA, userB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	liveSite, deletedSite, otherSite, liveNode, goneNode := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants(id,display_name) VALUES($1,'Name A'),($2,'Name B');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash) VALUES
			($5,'name-a','Name A','unused'),($6,'name-b','Name B','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($4,$6)`, pgx.QueryExecModeSimpleProtocol,
		uuid.New(), uuid.New(), scopeA, scopeB, userA, userB); err != nil {
		t.Fatal(err)
	}
	for index, site := range []struct {
		id, scope, owner uuid.UUID
		domain           string
	}{{liveSite, scopeA, userA, "live.example.test"}, {deletedSite, scopeA, userA, "gone.example.test"},
		{otherSite, scopeB, userB, "secret-b.example.test"}} {
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id,display_id) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],
				ARRAY['origin.example.test'],$3,$3,$5)`, site.id, site.scope, site.owner, site.domain, index+1); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site.id); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, site.id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE sites SET deleted_at=now() WHERE id=$1`, deletedSite); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		VALUES($1,$2,'edge-a-01','active',$3,1)`, liveNode, scopeA, userA); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	longUA := "Mozilla/5.0\r\n\x00(X11) " + strings.Repeat("é", 400) // 2 x 400 bytes: cut on a rune boundary
	appendEvent := func(reqCtx context.Context, scope, actor uuid.UUID, action, resourceType, resourceID string, at time.Time) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := audit.AppendTx(reqCtx, tx, audit.Event{ScopeID: scope, ActorUserID: &actor, Action: action,
				ResourceType: resourceType, ResourceID: resourceID, RequestID: "req-" + uuid.NewString()[:8],
				Result: "success", OccurredAt: at, Payload: map[string]any{}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	browser := audit.WithUserAgent(ctx, "Mozilla/5.0 (Macintosh) Chrome/141.0\t")
	appendEvent(browser, scopeA, userA, "site.update", "site", liveSite.String(), now.Add(-6*time.Minute))
	appendEvent(audit.WithUserAgent(ctx, longUA), scopeA, userA, "site.delete", "site", deletedSite.String(), now.Add(-5*time.Minute))
	appendEvent(ctx, scopeA, userA, "node.update", "node", liveNode.String(), now.Add(-4*time.Minute)) // no UA (job / old row)
	appendEvent(browser, scopeA, userA, "node.delete", "node", goneNode.String(), now.Add(-3*time.Minute))
	// A's audit row pointing at B's site id must not reveal B's domain.
	appendEvent(browser, scopeA, userA, "site.update", "site", otherSite.String(), now.Add(-2*time.Minute))
	appendEvent(browser, scopeA, userA, "site.update", "site", "not-a-uuid", now.Add(-time.Minute))
	appendEvent(browser, scopeB, userB, "site.update", "site", otherSite.String(), now.Add(-time.Minute))

	var storedUA []string
	rows, err := pool.Query(ctx, `SELECT user_agent FROM audit_events WHERE scope_id=$1 ORDER BY stream_position`, scopeA)
	if err != nil {
		t.Fatal(err)
	}
	if storedUA, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		t.Fatal(err)
	}
	if len(storedUA) != 6 || storedUA[0] != "Mozilla/5.0 (Macintosh) Chrome/141.0" || storedUA[2] != "" ||
		len(storedUA[1]) > 512 || strings.ContainsAny(storedUA[1], "\r\n\x00") || !strings.HasPrefix(storedUA[1], "Mozilla/5.0(X11) é") ||
		!strings.HasSuffix(storedUA[1], "é") {
		t.Fatalf("stored user agents = %q", storedUA)
	}
	// The chain (user_agent hashed when present) still verifies.
	if err := audit.New(pool).VerifyScope(ctx, scopeA); err != nil {
		t.Fatalf("verify chain with user agents: %v", err)
	}

	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenantA := Actor{UserID: userA, ScopeID: scopeA, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	page, err := service.List(ctx, tenantA, Query{Kinds: []Kind{KindOperation}, From: now.Add(-time.Hour), To: now.Add(time.Second), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 6 || page.TotalCount != 6 {
		t.Fatalf("tenant A page = %d items, total %d: %+v", len(page.Items), page.TotalCount, page.Items)
	}
	type want struct {
		resourceID, name, userAgent string
		deleted                     bool
	}
	expected := []want{ // newest first
		{"not-a-uuid", "", "Mozilla/5.0 (Macintosh) Chrome/141.0", false},
		{otherSite.String(), "", "Mozilla/5.0 (Macintosh) Chrome/141.0", true},
		{goneNode.String(), "", "Mozilla/5.0 (Macintosh) Chrome/141.0", true},
		{liveNode.String(), "edge-a-01", "", false},
		{deletedSite.String(), "", storedUA[1], true},
		{liveSite.String(), "live.example.test", "Mozilla/5.0 (Macintosh) Chrome/141.0", false},
	}
	for index, item := range page.Items {
		w := expected[index]
		if item.ResourceID != w.resourceID || item.ResourceName != w.name || item.ResourceDeleted != w.deleted || item.UserAgent != w.userAgent {
			t.Errorf("row %d = id %q name %q deleted %v ua %q, want %+v", index, item.ResourceID, item.ResourceName,
				item.ResourceDeleted, item.UserAgent, w)
		}
		if strings.Contains(item.ResourceName, "secret-b") {
			t.Fatalf("tenant A saw tenant B's object name: %+v", item)
		}
	}

	// Tenant B sees its own site by name and none of A's rows.
	tenantB := Actor{UserID: userB, ScopeID: scopeB, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	page, err = service.List(ctx, tenantB, Query{Kinds: []Kind{KindOperation}, From: now.Add(-time.Hour), To: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ResourceName != "secret-b.example.test" || page.Items[0].ResourceDeleted {
		t.Fatalf("tenant B page = %+v", page.Items)
	}
}
