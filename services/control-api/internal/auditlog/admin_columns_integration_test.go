//go:build integration

package auditlog

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type fixedIPIntel map[string]*analyticslog.IPInfo

func (lookup fixedIPIntel) Lookup(_ context.Context, addresses []string) map[string]*analyticslog.IPInfo {
	out := map[string]*analyticslog.IPInfo{}
	for _, address := range addresses {
		if info := lookup[address]; info != nil {
			out[address] = info
		}
	}
	return out
}

// log-merge: the admin log center rows carry the tenant name, the actor's
// username, the UA (login rows from the session), 国家-省-市 from the IP
// library, and object names looked up inside the row's own scope (B6b), and
// the operation tab can exclude the auth category.
func TestStoreAdminColumnsReuseB6Facts(t *testing.T) {
	pool := migratedPool(t)
	ctx := context.Background()
	tenantA, tenantB, scopeA, scopeB := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	userA, userB, sessionID := uuid.New(), uuid.New(), uuid.New()
	siteA, siteB := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants(id,display_name) VALUES($1,'Tenant Alpha'),($2,'Tenant Beta');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($5,'alice','Alice','unused'),($6,'bob','Bob','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($4,$6)`, pgx.QueryExecModeSimpleProtocol,
		tenantA, tenantB, scopeA, scopeB, userA, userB); err != nil {
		t.Fatal(err)
	}
	for index, site := range []struct {
		id, scope, owner uuid.UUID
		domain           string
	}{{siteA, scopeA, userA, "alpha.example.test"}, {siteB, scopeB, userB, "secret-beta.example.test"}} {
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
	base := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,user_agent,source_ip,created_at,expires_at)
		VALUES($1,$1,$2,$3,decode(repeat('ab',32),'hex'),'Mozilla/5.0 (Session)','198.51.100.9',$4,$4::timestamptz + interval '1 day')`,
		sessionID, userA, scopeA, base); err != nil {
		t.Fatal(err)
	}
	request := audit.WithUserAgent(audit.WithSourceIP(ctx, netip.MustParseAddr("203.0.113.7")), "Mozilla/5.0 (Operation)")
	events := []audit.Event{
		{ScopeID: scopeA, ActorUserID: &userA, Action: "site.update", ResourceType: "site", ResourceID: siteA.String(),
			RequestID: "m1", Result: "success", OccurredAt: base},
		// Tenant A's row pointing at tenant B's site must not reveal B's domain.
		{ScopeID: scopeA, ActorUserID: &userA, Action: "site.update", ResourceType: "site", ResourceID: siteB.String(),
			RequestID: "m2", Result: "success", OccurredAt: base.Add(time.Minute)},
		{ScopeID: scopeA, ActorUserID: &userA, Action: "auth.login", ResourceType: "session_family", ResourceID: sessionID.String(),
			RequestID: "m3", Result: "success", OccurredAt: base.Add(2 * time.Minute), Payload: map[string]any{"session_id": sessionID.String()}},
	}
	log := audit.New(pool)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, event := range events {
			if err := log.Append(request, tx, event); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	store.SetIPIntelLookup(fixedIPIntel{
		"203.0.113.7":  {Country: "CN", ProvinceName: "山东省", CityName: "潍坊市"},
		"198.51.100.9": {Country: "US", ProvinceName: "California"},
	})

	page, err := store.List(ctx, Filter{}, audit.LocaleZH, time.UTC)
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("list: %+v %v", page, err)
	}
	login, foreign, own := page.Items[0], page.Items[1], page.Items[2]
	if login.Action != "auth.login" || login.SourceIP != "198.51.100.9" || login.UserAgent != "Mozilla/5.0 (Session)" ||
		login.GeoCode != "US" || login.GeoRegion != "California" || login.GeoCity != "" {
		t.Fatalf("login row = %+v", login)
	}
	if own.TenantName != "Tenant Alpha" || own.ActorUsername != "alice" || own.UserAgent != "Mozilla/5.0 (Operation)" ||
		own.SourceIP != "203.0.113.7" || own.GeoCode != "CN" || own.GeoRegion != "山东省" || own.GeoCity != "潍坊市" ||
		own.Resource != "alpha.example.test" || own.ResourceDeleted {
		t.Fatalf("operation row = %+v", own)
	}
	if foreign.Resource != siteB.String() || !foreign.ResourceDeleted || foreign.TenantName != "Tenant Alpha" {
		t.Fatalf("cross-tenant row leaked or not marked deleted: %+v", foreign)
	}

	operations, err := store.List(ctx, Filter{ExcludeCategory: "auth"}, audit.LocaleZH, time.UTC)
	if err != nil || len(operations.Items) != 2 {
		t.Fatalf("exclude auth: %+v %v", operations, err)
	}
	for _, item := range operations.Items {
		if item.Category == "auth" {
			t.Fatalf("exclude auth kept %+v", item)
		}
	}
	if err := (&Filter{ExcludeCategory: "misc"}).Validate(); err == nil {
		t.Fatal("unknown exclude_category accepted")
	}

	// No IP library: the stored payload geo (empty here) stays, nothing fails.
	plain, err := NewStore(pool).List(ctx, Filter{ScopeIDs: []uuid.UUID{scopeA}, Category: "site"}, audit.LocaleZH, time.UTC)
	if err != nil || len(plain.Items) != 2 || plain.Items[0].GeoCode != "" {
		t.Fatalf("without IP library: %+v %v", plain, err)
	}
}
