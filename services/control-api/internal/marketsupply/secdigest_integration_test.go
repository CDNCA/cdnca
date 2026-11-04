//go:build integration

package marketsupply

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type digestReaders struct {
	enforced []analyticslog.AttackSiteSummary
	logged   []analyticslog.LoggedSiteSummary
	logs     map[uuid.UUID][]secdigest.Log
}

func (r digestReaders) ListAttackSummaries(context.Context, time.Time, time.Time, uint64, uint16) ([]analyticslog.AttackSiteSummary, error) {
	return r.enforced, nil
}

func (r digestReaders) ListLoggedSummaries(context.Context, time.Time, time.Time, uint16) ([]analyticslog.LoggedSiteSummary, error) {
	return r.logged, nil
}

func (r digestReaders) SiteSecurityWindow(_ context.Context, _, site uuid.UUID, _, _ time.Time, _ int,
) ([]secdigest.Log, int64, []secdigest.Action, error) {
	return r.logs[site], int64(len(r.logs[site])), nil, nil
}

// a market site with observe-only WAF / CC decisions alone gets a
// digest too; Summary keeps the enforced counts, Extension the logged one,
// and a site of another tenant is skipped.
func TestSecurityDigestsCarryLoggedDecisions(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, time.Now)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New(), uuid.New()}, NodePoolRef: insertLineGroup(t, pool, platform, actor.userID).String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 5, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	out := mustSync(t, svc, g)
	sub, scope := out[0].SubscriptionID, out[0].TenantScopeID
	var owner, tenant uuid.UUID
	// ClickHouse rows carry access_scopes.tenant_id, not the scope ID.
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, scope).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, tenantPrefix+out[0].Key).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	insert := func(domain string) uuid.UUID {
		site := uuid.New()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id,package_subscription_id,package_id) VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites),
				$2,$3,$5,ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3,$4,
				(SELECT product_id FROM package_subscriptions WHERE id=$4))`, site, scope, owner, sub, domain)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,level) VALUES($1,1,'192.0.2.10',80,0)`, site)
			return err
		}); err != nil {
			t.Fatalf("insert site: %v", err)
		}
		return site
	}
	mixed, logOnly := insert("mixed.logev.example.test"), insert("logonly.logev.example.test")
	subscriber := uuid.New()
	svc.RememberSubscriber(out[0].Key, subscriber)

	start := now.Truncate(5 * time.Minute).Add(-5 * time.Minute)
	line := func(at time.Duration, action, host string) secdigest.Log {
		return secdigest.Log{AtMS: start.Add(at).UnixMilli(), ClientIP: "203.0.113.9", Host: host, Path: "/q", Action: action, Detector: "xss"}
	}
	foreignTenant, foreignSite := uuid.New(), uuid.New()
	readers := digestReaders{
		enforced: []analyticslog.AttackSiteSummary{{TenantID: tenant.String(), SiteID: mixed.String(), Events: 3, Blocked: 3, Clients: 1,
			TopClientIP: "203.0.113.9", FirstEventAt: start.Add(time.Second), LastEventAt: start.Add(2 * time.Second)}},
		logged: []analyticslog.LoggedSiteSummary{{TenantID: tenant.String(), SiteID: mixed.String(), Logged: 5},
			{TenantID: tenant.String(), SiteID: logOnly.String(), Logged: 2},
			{TenantID: foreignTenant.String(), SiteID: foreignSite.String(), Logged: 9}},
		logs: map[uuid.UUID][]secdigest.Log{
			mixed:   {line(time.Second, "block", "mixed.logev.example.test"), line(3*time.Second, "log", "mixed.logev.example.test")},
			logOnly: {line(4*time.Second, "log", "logonly.logev.example.test")},
		},
	}
	svc.WithSecurityReaders(readers, readers)
	leaf := uuid.New()
	targets, err := svc.SecurityDigests(ctx, leaf, start)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets %+v", targets)
	}
	bySite := map[uuid.UUID]DigestTarget{}
	for _, target := range targets {
		bySite[target.Digest.LeafSiteID] = target
	}
	m, l := bySite[mixed], bySite[logOnly]
	if m.Digest.Summary.Events != 3 || m.Digest.Summary.Blocked != 3 || m.Extension.Logged != 5 || len(m.Digest.Logs) != 2 ||
		m.Digest.Logs[0].Action != "log" || m.Digest.Summary.FirstMS != start.Add(time.Second).UnixMilli() || m.Subscriber != subscriber {
		t.Fatalf("mixed site digest %+v", m)
	}
	if l.Digest.Summary != (secdigest.Summary{}) || l.Extension.Logged != 2 || len(l.Digest.Logs) != 1 ||
		l.Digest.Logs[0].Action != "log" || len(l.Domains) != 1 || l.Domains[0] != "logonly.logev.example.test" {
		t.Fatalf("log-only site digest %+v", l)
	}
	public, private, _ := ed25519.GenerateKey(nil)
	for _, target := range targets {
		signed, err := secdigest.SignExtended(target.Digest, target.Extension, private)
		if err != nil {
			t.Fatalf("sign %s: %v", target.Digest.LeafSiteID, err)
		}
		// A subscriber built before the extension still accepts it.
		if _, _, err := secdigest.Verify(public, secdigest.Signed{Payload: signed.Payload, Signature: signed.Signature}); err != nil {
			t.Fatalf("old subscriber rejects %s: %v", target.Digest.LeafSiteID, err)
		}
	}
}
