//go:build integration

package observabilitylog

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestOperationLogRegionsAndTenantScopePostgreSQL (B6) on the real schema:
// operation rows carry the 361 source_ip column and the audit category; the
// region comes from the stored ipintel/base library by source IP at query
// time (unloaded -> unknown, miss -> unknown, hit -> 国家-省-市); a tenant
// user sees only their own scope's rows they acted on.
func TestOperationLogRegionsAndTenantScopePostgreSQL(t *testing.T) {
	pool := anonymousNotificationPool(t)
	ctx := t.Context()
	scopeA, scopeB, userA, userB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants(id,display_name) VALUES($1,'Region A'),($2,'Region B');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash) VALUES
			($5,'region-a','Region A','unused'),($6,'region-b','Region B','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($3,$6),($4,$6)`, pgx.QueryExecModeSimpleProtocol,
		uuid.New(), uuid.New(), scopeA, scopeB, userA, userB); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	appendEvent := func(scope, actor uuid.UUID, action, resourceType, resourceID, sourceIP string, at time.Time) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := audit.AppendTx(ctx, tx, audit.Event{ScopeID: scope, ActorUserID: &actor, Action: action,
				ResourceType: resourceType, ResourceID: resourceID, RequestID: "req-" + uuid.NewString()[:8], Result: "success",
				SourceIP: sourceIP, OccurredAt: at, Payload: map[string]any{}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(scopeA, userA, "site.update", "site", "11", "1.0.0.7", now.Add(-3*time.Minute))
	appendEvent(scopeA, userA, "site.update", "site", "12", "9.9.9.9", now.Add(-2*time.Minute))
	appendEvent(scopeA, userB, "site.update", "site", "13", "1.0.0.8", now.Add(-time.Minute)) // same scope, other user
	appendEvent(scopeB, userB, "site.update", "site", "14", "1.0.0.9", now.Add(-time.Minute)) // other scope

	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.SetIPIntelLookup(analyticslog.NewPostgresIPIntelLookup(pool, nil))
	tenantA := Actor{UserID: userA, ScopeID: scopeA, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	query := Query{Kinds: []Kind{KindOperation}, Category: string(audit.CategorySite), From: now.Add(-time.Hour), To: now.Add(time.Second)}
	list := func() []Fact {
		t.Helper()
		page, err := service.List(ctx, tenantA, query)
		if err != nil {
			t.Fatal(err)
		}
		return page.Items
	}

	// Library not loaded: rows still list, region unknown, no error.
	rows := list()
	if len(rows) != 2 || rows[0].ResourceID != "12" || rows[1].ResourceID != "11" {
		t.Fatalf("tenant A rows = %+v, want only A's own two operations", rows)
	}
	for _, row := range rows {
		if row.GeoCode != "unknown" || row.Category != "site" || row.SourceIP == "unknown" {
			t.Fatalf("row without library = %+v", row)
		}
	}

	generated := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	artifact, err := ipintel.Build(ipintel.BuildInput{Revision: 1, BuildID: "ipintel-test-0001", GeneratedAt: generated,
		DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(30 * 24 * time.Hour),
		Sources: []ipintel.Source{{ID: "fixture", Name: "fixture", URL: "https://example.test", License: "CC0-1.0", Ref: "1", Role: "test"}},
		Facts: []ipintel.Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Tags: ipintel.TagCNTelecom, Country: "CN",
			Province: 370000, City: 370700}},
		Regions: map[uint32]string{370000: "山东省", 370700: "潍坊市"}})
	if err != nil {
		t.Fatal(err)
	}
	artifactsynctest.SeedDownloaded(t, pool, artifactsynctest.IPIntelBase(1, "ipintel-test-0001", artifact.SHA256, 2), artifact.Bytes)
	// A fresh lookup sees the library at once (the shared one rechecks every 30s).
	service.SetIPIntelLookup(analyticslog.NewPostgresIPIntelLookup(pool, nil))
	rows = list()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	miss, hit := rows[0], rows[1]
	if hit.SourceIP != "1.0.0.7" || hit.GeoCode != "CN" || hit.GeoRegion != "山东省" || hit.GeoCity != "潍坊市" || hit.GeoResolution != "matched" {
		t.Fatalf("hit row = %+v", hit)
	}
	if miss.SourceIP != "9.9.9.9" || miss.GeoCode != "unknown" || miss.GeoRegion != "" {
		t.Fatalf("miss row = %+v", miss)
	}

	// The tenant cannot widen the scope or read another member's history.
	if _, err := service.List(ctx, tenantA, Query{TargetScopeID: &scopeB, Kinds: []Kind{KindOperation}}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant cross-scope read=%v, want permission denied", err)
	}
	if _, err := service.List(ctx, tenantA, Query{AuditActorUserID: &userB, Kinds: []Kind{KindOperation}}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant actor filter=%v, want permission denied", err)
	}
	// A category with none of A's rows is empty, not an error.
	query.Category = string(audit.CategoryCert)
	if rows := list(); len(rows) != 0 {
		t.Fatalf("cert category rows = %+v", rows)
	}
}
