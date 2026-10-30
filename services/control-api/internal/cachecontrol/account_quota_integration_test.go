//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// addFixtureSite adds a second site to the fixture's account.
func addFixtureSite(t *testing.T, pool *pgxpool.Pool, fixture cacheFixture, domain string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sites (
				id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,created_by_user_id,updated_by_user_id,display_id
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,true,'active',$3,$3,
			          (SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`,
			siteID, fixture.actor.ScopeID, fixture.actor.UserID, domain,
			[]string{"80"}, []string{"443"}, []string{"192.0.2.1"}, []string{"192.0.2.1"}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools (site_id) VALUES ($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
			VALUES ($1,1,'192.0.2.1',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return siteID
}

// addTenantMember adds a second user of the fixture's tenant holding the
// same roles (a member, not the owner).
func addTenantMember(t *testing.T, pool *pgxpool.Pool, fixture cacheFixture, username string) Actor {
	t.Helper()
	member := Actor{UserID: uuid.New(), ScopeID: fixture.actor.ScopeID, ActorScopeID: fixture.actor.ScopeID}
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash,status)
		VALUES ($1,$2,$2,'test-hash','active')`, member.UserID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id,user_id,status) VALUES ($1,$2,'active')`,
		member.ScopeID, member.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (scope_id,user_id,role_id)
		VALUES ($1,$2,$3),($1,$2,$4)`, member.ScopeID, member.UserID, fixture.roleID, fixture.readRoleID); err != nil {
		t.Fatal(err)
	}
	return member
}

// fix-cachequota: the daily quota is the account's, shared by all its sites;
// the account's own limit overrides the default (null follows it again), is
// revision-checked and audited; the count resets at the next UTC+8 midnight;
// an over-quota create says which quota and how much was used.
func TestAccountDailyQuotaSharedAcrossSitesAndOverridable(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "accountquota", 1)
	secondSite := addFixtureSite(t, pool, fixture, "second.accountquota.example")
	ctx := context.Background()
	urls := func(domain, prefix string, count int) []string {
		result := make([]string, count)
		for index := range result {
			result[index] = fmt.Sprintf("http://%s/%s-%d", domain, prefix, index)
		}
		return result
	}
	create := func(siteID uuid.UUID, domain, key string, count int) error {
		_, err := store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
			SiteID: siteID, Action: ActionPurge, TargetType: TargetExactURL, Targets: urls(domain, key, count),
			NodeIDs: fixture.nodeIDs, IdempotencyKey: key, RequestID: key + "-request",
		})
		return err
	}
	// Bootstrap default 2000 URL purges per account: 1500 on one site and
	// 500 on the other use it up together.
	for batch := 0; batch < 3; batch++ {
		if err := create(fixture.siteID, fixture.domain, fmt.Sprint("aq-a-", batch), 500); err != nil {
			t.Fatalf("site A batch %d: %v", batch, err)
		}
	}
	if err := create(secondSite, "second.accountquota.example", "aq-b-0", 500); err != nil {
		t.Fatalf("site B: %v", err)
	}
	err := create(secondSite, "second.accountquota.example", "aq-b-over", 1)
	var limitErr *DailyLimitError
	if !errors.As(err, &limitErr) || !errors.Is(err, ErrDailyLimitExceeded) || limitErr.Quota != QuotaURLPurge ||
		limitErr.Limit != 2000 || limitErr.Used != 2000 || limitErr.Requested != 1 {
		t.Fatalf("2001st URL of the account: %v (%+v)", err, limitErr)
	}
	// fix-cachequota2: a member of the tenant shares the owner's quota.
	member := addTenantMember(t, pool, fixture, "accountquota-member")
	if _, err := store.CreateOperation(ctx, member, CreateOperationRequest{
		SiteID: secondSite, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: urls("second.accountquota.example", "aq-member", 1), NodeIDs: fixture.nodeIDs,
		IdempotencyKey: "aq-member", RequestID: "aq-member-request",
	}); !errors.As(err, &limitErr) || limitErr.Used != 2000 {
		t.Fatalf("member over the tenant's shared quota: %v", err)
	}
	usage, err := store.DailyUsage(ctx, fixture.actor)
	if err != nil || usage.ScopeID != fixture.actor.ScopeID || usage.URLPurge.Used != 2000 || usage.URLPurge.Remaining != 0 ||
		usage.URLPurge.DefaultLimit != 2000 || usage.URLPurge.Override != nil || usage.Revision != 0 {
		t.Fatalf("usage = %+v, %v", usage, err)
	}

	// A tenant cannot set its own limits (only the platform route writes them;
	// the write path is covered with a formal platform session in
	// cachecontrolhttp TestCacheControlProductionHandlerAuthenticatesFormalSessions).
	raised := 2500
	if _, err := store.SetAccountLimits(ctx, fixture.actor, SetAccountLimitsRequest{
		Limits: AccountLimits{URLPurge: &raised}, RequestID: "aq-tenant-set",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("tenant sets its own limits: %v", err)
	}
	// The account's own limits: URL purges raised, prewarms stopped.
	if _, err := pool.Exec(ctx, `INSERT INTO cache_operation_account_quotas
		(scope_id,url_purge_limit,prewarm_limit,revision,updated_by_user_id,updated_at) VALUES ($1,2500,0,1,$2,$3)`,
		fixture.actor.ScopeID, fixture.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	set, err := store.DailyUsage(ctx, fixture.actor)
	if err != nil || set.Revision != 1 || set.URLPurge.Limit != 2500 || set.URLPurge.Remaining != 500 ||
		set.URLPurge.DefaultLimit != 2000 || set.Prewarm.Limit != 0 || set.DirectoryPurge.Override != nil {
		t.Fatalf("overridden = %+v, %v", set, err)
	}
	// Revisions advance by one (P5882).
	if _, err := pool.Exec(ctx, `UPDATE cache_operation_account_quotas SET revision=5 WHERE scope_id=$1`,
		fixture.actor.ScopeID); err == nil {
		t.Fatal("revision jump accepted")
	}
	if err := create(secondSite, "second.accountquota.example", "aq-b-raised", 500); err != nil {
		t.Fatalf("within the raised limit: %v", err)
	}
	if _, err := store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPrewarm, TargetType: TargetExactURL, Targets: urls(fixture.domain, "warm", 1),
		NodeIDs: fixture.nodeIDs, IdempotencyKey: "aq-warm", RequestID: "aq-warm-request",
	}); !errors.As(err, &limitErr) || limitErr.Quota != QuotaPrewarm || limitErr.Limit != 0 {
		t.Fatalf("prewarm with a zero limit: %v", err)
	}
	// Back to the defaults (null).
	if _, err := pool.Exec(ctx, `UPDATE cache_operation_account_quotas SET url_purge_limit=NULL,prewarm_limit=NULL,
		revision=2 WHERE scope_id=$1`, fixture.actor.ScopeID); err != nil {
		t.Fatal(err)
	}
	reset, err := store.DailyUsage(ctx, fixture.actor)
	if err != nil || reset.Revision != 2 || reset.URLPurge.Limit != 2000 || reset.URLPurge.Override != nil || reset.Prewarm.Limit == 0 {
		t.Fatalf("reset = %+v, %v", reset, err)
	}
	// The next UTC+8 day starts from zero.
	clock.Add(24 * time.Hour)
	next, err := store.DailyUsage(ctx, fixture.actor)
	if err != nil || next.URLPurge.Used != 0 || !next.ResetsAt.After(usage.ResetsAt) {
		t.Fatalf("next day = %+v, %v", next, err)
	}
}
