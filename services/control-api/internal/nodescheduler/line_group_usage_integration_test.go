//go:build integration

package nodescheduler

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A platform line
// group counts the sites and forwards of every scope that route to it, by the
// CNAME allocation resolution order (own group > package > platform default).
func TestLineGroupUsageCountsPlatformGroupAcrossTenants(t *testing.T) {
	fixture := newIntegrationFixture(t)
	tenantA := fixture.actor
	tenantB := seedTenantActor(t, fixture.pool, "usage-b")
	platform := uuid.New()
	lineGroupFixtureExec(t, fixture, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	hk, other, fallback := uuid.New(), uuid.New(), uuid.New()
	for _, group := range []struct {
		id        uuid.UUID
		isDefault bool
	}{{hk, false}, {other, false}, {fallback, true}} {
		seedUsageLineGroup(t, fixture, platform, group.id, group.isDefault)
	}

	// Explicit own group (tenant A).
	seedUsageSite(t, fixture, tenantA, &hk, nil, false)
	// Package inheritance (tenant B, the #2/#3 case).
	inherited := seedUsageSite(t, fixture, tenantB, nil, seedUsageSubscription(t, fixture, tenantB, hk.String(), ""), false)
	// Explicit group wins over the package's.
	seedUsageSite(t, fixture, tenantA, &other, seedUsageSubscription(t, fixture, tenantA, hk.String(), ""), false)
	// Package backup group counts like before.
	seedUsageSite(t, fixture, tenantA, nil, seedUsageSubscription(t, fixture, tenantA, other.String(), hk.String()), false)
	// No group, no package: the platform default.
	seedUsageSite(t, fixture, tenantB, nil, nil, false)
	// A package without a line group does not fall back to the platform default.
	seedUsageSite(t, fixture, tenantA, nil, seedUsageSubscription(t, fixture, tenantA, "", ""), false)
	// Deleted sites never count.
	seedUsageSite(t, fixture, tenantA, &hk, nil, true)

	// Forwards: own group without a package (migration 597), package
	// inheritance, own backup group, deleted.
	seedUsageForward(t, fixture, tenantA, &hk, nil, nil, false)
	seedUsageForward(t, fixture, tenantB, nil, nil, seedUsageSubscription(t, fixture, tenantB, hk.String(), ""), false)
	seedUsageForward(t, fixture, tenantB, &other, &hk, seedUsageSubscription(t, fixture, tenantB, other.String(), ""), false)
	seedUsageForward(t, fixture, tenantA, &hk, nil, nil, true)

	assertLineGroupUsage(t, fixture, platform, map[uuid.UUID]LineGroupStatistics{
		hk:       {SiteCount: 3, ForwardCount: 3},
		other:    {SiteCount: 2, ForwardCount: 1},
		fallback: {SiteCount: 1},
	})

	// Deleting the inherited site removes it from the count.
	lineGroupFixtureExec(t, fixture, `UPDATE sites SET deleted_at=now() WHERE id=$1`, inherited)
	assertLineGroupUsage(t, fixture, platform, map[uuid.UUID]LineGroupStatistics{
		hk:       {SiteCount: 2, ForwardCount: 3},
		other:    {SiteCount: 2, ForwardCount: 1},
		fallback: {SiteCount: 1},
	})
}

// A tenant's line group list only counts the tenant's own sites and forwards;
// another tenant's rows pointing at the same group ID do not resolve to it.
func TestListStatisticsTenantCountsOnlyOwnScope(t *testing.T) {
	fixture := newIntegrationFixture(t)
	tenantB := seedTenantActor(t, fixture.pool, "usage-isolated")
	groupID := uuid.New()
	created, err := fixture.service.PutGroup(t.Context(), fixture.actor,
		fixture.putRequest(groupID, 0, "租户线路", "usage-tenant-create"))
	if err != nil {
		t.Fatal(err)
	}
	seedUsageSite(t, fixture, fixture.actor, &groupID, nil, false)
	seedUsageSite(t, fixture, fixture.actor, nil, seedUsageSubscription(t, fixture, fixture.actor, groupID.String(), ""), false)
	seedUsageForward(t, fixture, fixture.actor, nil, &groupID, seedUsageSubscription(t, fixture, fixture.actor, "", ""), false)
	seedUsageSite(t, fixture, tenantB, &groupID, nil, false)
	seedUsageSite(t, fixture, tenantB, nil, seedUsageSubscription(t, fixture, tenantB, groupID.String(), ""), false)
	seedUsageForward(t, fixture, tenantB, &groupID, nil, nil, false)

	statistics, err := fixture.service.ListStatistics(t.Context(), fixture.actor, []LineGroupRevision{created.Group})
	if err != nil {
		t.Fatal(err)
	}
	if got := statistics[groupID]; got.SiteCount != 2 || got.ForwardCount != 1 {
		t.Fatalf("tenant statistics = %+v, want 2 sites and 1 forward of its own scope", got)
	}
}

func assertLineGroupUsage(t *testing.T, fixture *integrationFixture, scopeID uuid.UUID, want map[uuid.UUID]LineGroupStatistics) {
	t.Helper()
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id.String())
	}
	var got map[uuid.UUID]LineGroupStatistics
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var err error
		got, err = lineGroupUsage(t.Context(), tx, scopeID, ids)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for id, expected := range want {
		if got[id] != expected {
			t.Fatalf("usage of %s = %+v, want %+v (all %+v)", id, got[id], expected, got)
		}
	}
}

func seedUsageLineGroup(t *testing.T, fixture *integrationFixture, scopeID, groupID uuid.UUID, isDefault bool) {
	t.Helper()
	lineGroupFixtureExec(t, fixture, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at,display_id,resolved_value,ipv4_resolved_value,
			is_platform_default)
		VALUES($1::uuid,$2,'usage-'||left($1::uuid::text,8),1,$3,$3,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),
			'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''),$4)`,
		groupID, scopeID, fixture.actor.UserID, isDefault)
}

// seedUsageSubscription returns a subscription of the actor's scope whose
// snapshot names primary/backup line groups ("" leaves the key out).
func seedUsageSubscription(t *testing.T, fixture *integrationFixture, owner Actor, primary, backup string) *uuid.UUID {
	t.Helper()
	id := uuid.New()
	lineGroupFixtureExec(t, fixture, `INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
			domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
			tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,1,jsonb_build_object('revision',1,'name','snapshot','spec',jsonb_strip_nulls(jsonb_build_object(
			'node_group_id',NULLIF($4,''),'backup_node_group_id',NULLIF($5,'')))),
			10,10,10,0,now()-interval '1 hour',now()+interval '30 days','UTC','monthly',1,1,$6,$6,now(),now())`,
		id, owner.ScopeID, uuid.New(), primary, backup, owner.UserID)
	return &id
}

func seedUsageSite(t *testing.T, fixture *integrationFixture, owner Actor, groupID, subscriptionID *uuid.UUID, deleted bool) uuid.UUID {
	t.Helper()
	site := uuid.New()
	lineGroupFixtureExec(t, fixture, `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,
			updated_by_user_id,display_id,node_group_id,package_subscription_id,package_id,deleted_at)
		VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites),$5,$6,CASE WHEN $6::uuid IS NOT NULL THEN gen_random_uuid() END,
			CASE WHEN $7 THEN now() END)`,
		site, owner.ScopeID, owner.UserID, "s"+site.String()[:8]+".usage.example", groupID, subscriptionID, deleted)
	return site
}

func seedUsageForward(t *testing.T, fixture *integrationFixture, owner Actor, groupID, backupID, subscriptionID *uuid.UUID, deleted bool) {
	t.Helper()
	lineGroupFixtureExec(t, fixture, `INSERT INTO l4_forwards(
			id,scope_id,owner_user_id,name,protocol,listen_port,upstream_address,upstream_port,
			connect_timeout_ms,response_timeout_ms,package_subscription_id,max_connections_per_client,
			created_by_user_id,updated_by_user_id,created_at,updated_at,node_group_id,backup_node_group_id,deleted_at,display_id
		) VALUES($1,$2,$3,'usage forward '||left($1::uuid::text,8),'tcp',(SELECT COALESCE(max(listen_port),20000)+1 FROM l4_forwards),'192.0.2.20',443,
			3000,30000,$4,100,$3,$3,now(),now(),$5,$6,CASE WHEN $7 THEN now() END,
			(SELECT COALESCE(max(display_id),0)+1 FROM l4_forwards))`,
		uuid.New(), owner.ScopeID, owner.UserID, subscriptionID, groupID, backupID, deleted)
}
