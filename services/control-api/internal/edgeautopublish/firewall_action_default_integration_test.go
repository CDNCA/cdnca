//go:build integration

package edgeautopublish_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fw-default (605, was 607): sites without their own firewall action follow the
// tenant default (else the undelivered system default); DELETE restores
// inheritance; a default change republishes only when a site inherits.

type firewallDefaultFixture struct {
	pool     *pgxpool.Pool
	identity automaticIntegrationIdentity
	service  *firewallactioncontrol.Service
	actor    firewallcontrol.Actor
	// trust 是首个站点安装的权益信任库；keyset LKG 是单例，第二个站点必须复用它。
	trust *entitlementguard.TrustStore
}

func newFirewallDefaultFixture(t *testing.T) (firewallDefaultFixture, uuid.UUID) {
	t.Helper()
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	siteID := settledAutomaticSiteWithTrust(t, pool, identity, trust, "fw-default-a.example.test")
	store := firewallactioncontrol.NewStore(pool, allowFirewallAuthorizer{}, func() time.Time { return automaticIntegrationNow }).
		WithSiteRevisionPublisher(edgeautopublish.UnrequestedRevisionPublisher{})
	return firewallDefaultFixture{pool: pool, identity: identity, service: firewallactioncontrol.NewService(store),
		actor: firewallcontrol.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant",
			Permissions: []string{firewallcontrol.PermissionRead, firewallcontrol.PermissionManage}}, trust: trust}, siteID
}

func (fixture firewallDefaultFixture) secondSite(t *testing.T) uuid.UUID {
	t.Helper()
	service := site.NewService(site.NewStoreWithClock(fixture.pool, func() time.Time { return automaticIntegrationNow }, fixture.trust))
	created, err := service.Create(t.Context(), site.Actor{UserID: fixture.identity.tenantUser, ScopeID: fixture.identity.tenantScope, ScopeKind: "tenant"},
		newSiteRequest("fw-default-b.example.test", "fw-default-b.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	return created.Site.ID
}

func (fixture firewallDefaultFixture) settle(t *testing.T) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts(
		request_id,sequence,state,attempt,terminal_code,occurred_at)
		SELECT request_row.id,state.sequence+1,'superseded',0,'test_settled',clock_timestamp()
		FROM edge_automatic_publication_requests request_row
		JOIN LATERAL (SELECT sequence,state FROM edge_automatic_publication_request_state_facts
			WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON state.state='pending'
		WHERE request_row.target_scope_id=$1`, fixture.identity.tenantScope); err != nil {
		t.Fatal(err)
	}
}

func fwPolicy(engage uint64) firewallactioncontrol.PolicyInput {
	return firewallactioncontrol.PolicyInput{
		NormalAction: firewallactioncontrol.ActionDisconnect, EscalatedAction: firewallactioncontrol.ActionNFTables,
		EngageThreshold: engage, RecoverThreshold: 10, RecoveryWindows: 5,
		BlockNetworks: []string{"203.0.113.0/24"}, TrustedProxies: []string{}, TrustedCrawlers: []firewallactioncontrol.TrustedCrawler{},
		ReturnPage: firewallactioncontrol.ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "limited"},
	}
}

func (fixture firewallDefaultFixture) get(t *testing.T, siteID uuid.UUID) firewallactioncontrol.Policy {
	t.Helper()
	policy, err := fixture.service.Get(t.Context(), firewallactioncontrol.ReadRequest{Actor: fixture.actor,
		TargetScopeID: fixture.identity.tenantScope, SiteID: siteID})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func (fixture firewallDefaultFixture) putDefault(t *testing.T, expected int64, engage uint64) (firewallactioncontrol.DefaultWriteResult, error) {
	t.Helper()
	return fixture.service.PutDefault(t.Context(), firewallactioncontrol.DefaultPutRequest{Actor: fixture.actor,
		TargetScopeID: fixture.identity.tenantScope, ExpectedRevision: expected, IdempotencyKey: uuid.NewString(),
		RequestID: uuid.NewString(), Policy: fwPolicy(engage)})
}

func (fixture firewallDefaultFixture) putSite(t *testing.T, siteID uuid.UUID, expected int64, engage uint64) (firewallactioncontrol.WriteResult, error) {
	t.Helper()
	return fixture.service.Put(t.Context(), firewallactioncontrol.PutRequest{Actor: fixture.actor,
		TargetScopeID: fixture.identity.tenantScope, SiteID: siteID, ExpectedRevision: expected, IdempotencyKey: uuid.NewString(),
		RequestID: uuid.NewString(), Policy: fwPolicy(engage)})
}

func (fixture firewallDefaultFixture) inherit(t *testing.T, siteID uuid.UUID, expected int64) (firewallactioncontrol.WriteResult, error) {
	t.Helper()
	return fixture.service.Inherit(t.Context(), firewallactioncontrol.InheritRequest{Actor: fixture.actor,
		TargetScopeID: fixture.identity.tenantScope, SiteID: siteID, ExpectedRevision: expected, IdempotencyKey: uuid.NewString(),
		RequestID: uuid.NewString()})
}

func (fixture firewallDefaultFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2`,
		fixture.identity.tenantScope, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestFirewallActionSiteInheritsSystemThenTenantDefault(t *testing.T) {
	fixture, siteID := newFirewallDefaultFixture(t)
	view := fixture.get(t, siteID)
	if !view.Inherited || view.Source != firewallactioncontrol.SourceSystemDefault || view.Delivered || view.Revision != 0 ||
		view.DeploymentState != firewallactioncontrol.StateInherited || view.EngageThreshold != 100 || view.UpdatedAt != nil {
		t.Fatalf("system default view = %+v", view)
	}
	defaults, err := fixture.service.GetDefault(t.Context(), firewallactioncontrol.DefaultReadRequest{Actor: fixture.actor, TargetScopeID: fixture.identity.tenantScope})
	if err != nil || defaults.Source != firewallactioncontrol.SourceSystemDefault || defaults.Revision != 0 || defaults.InheritingSiteCount != 1 {
		t.Fatalf("GetDefault() = (%+v, %v)", defaults, err)
	}
	before := scopeRevision(t, fixture.pool, fixture.identity.tenantScope)
	saved, err := fixture.putDefault(t, 0, 300)
	if err != nil || saved.Policy.Revision != 1 || saved.Policy.Source != firewallactioncontrol.SourceTenantDefault || saved.Policy.InheritingSiteCount != 1 {
		t.Fatalf("PutDefault() = (%+v, %v)", saved, err)
	}
	if kind, operation := requireRequestAtCurrentRevision(t, fixture.pool, fixture.identity.tenantScope, before); kind != "site" || operation != "site.update" {
		t.Fatalf("default request=%s/%s", kind, operation)
	}
	view = fixture.get(t, siteID)
	if !view.Inherited || view.Source != firewallactioncontrol.SourceTenantDefault || !view.Delivered || view.EngageThreshold != 300 ||
		view.ID != firewallactioncontrol.InheritedPolicyID(fixture.identity.tenantScope, siteID) {
		t.Fatalf("tenant default view = %+v", view)
	}
	if _, err := fixture.putDefault(t, 0, 400); !errors.Is(err, firewallactioncontrol.ErrRevisionConflict) {
		t.Fatalf("stale default error = %v", err)
	}
	if fixture.auditCount(t, "firewall.action.default_put") != 1 {
		t.Fatal("default_put audit event missing")
	}
}

func TestFirewallActionOverrideThenRestoreInheritance(t *testing.T) {
	fixture, siteID := newFirewallDefaultFixture(t)
	if _, err := fixture.putDefault(t, 0, 300); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.putSite(t, siteID, 0, 500)
	if err != nil || first.Policy.Revision != 1 || first.Policy.Inherited || first.Policy.Source != firewallactioncontrol.SourceSite {
		t.Fatalf("override = (%+v, %v)", first, err)
	}
	// A pending candidate no longer blocks the next save (no outcome path).
	second, err := fixture.putSite(t, siteID, 1, 600)
	if err != nil || second.Policy.Revision != 2 || second.Policy.EngageThreshold != 600 {
		t.Fatalf("second save = (%+v, %v)", second, err)
	}
	if _, err := fixture.inherit(t, siteID, 1); !errors.Is(err, firewallactioncontrol.ErrRevisionConflict) {
		t.Fatalf("stale inherit error = %v", err)
	}
	fixture.settle(t)
	before := scopeRevision(t, fixture.pool, fixture.identity.tenantScope)
	restored, err := fixture.inherit(t, siteID, 2)
	if err != nil || !restored.Policy.Inherited || restored.Policy.Revision != 3 || restored.Policy.EngageThreshold != 300 {
		t.Fatalf("inherit = (%+v, %v)", restored, err)
	}
	requireRequestAtCurrentRevision(t, fixture.pool, fixture.identity.tenantScope, before)
	if fixture.auditCount(t, "firewall.action.inherit") != 1 {
		t.Fatal("inherit audit event missing")
	}
	if _, err := fixture.inherit(t, siteID, 3); !errors.Is(err, firewallactioncontrol.ErrNotFound) {
		t.Fatalf("inherit twice error = %v", err)
	}
	if _, err := fixture.service.Recover(t.Context(), firewallactioncontrol.RecoverRequest{Actor: fixture.actor,
		TargetScopeID: fixture.identity.tenantScope, SiteID: siteID, ExpectedRevision: 3, IdempotencyKey: uuid.NewString(),
		RequestID: uuid.NewString()}); !errors.Is(err, firewallactioncontrol.ErrNotFound) {
		t.Fatalf("recover inherited error = %v", err)
	}
	var outbox int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM firewall_action_publication_outbox WHERE site_id=$1 AND revision=3`, siteID).Scan(&outbox); err != nil || outbox != 0 {
		t.Fatalf("inherited revision entered the outbox: %d %v", outbox, err)
	}
	// Overriding again continues the same revision counter.
	again, err := fixture.putSite(t, siteID, 3, 700)
	if err != nil || again.Policy.Revision != 4 || again.Policy.Inherited {
		t.Fatalf("override after inherit = (%+v, %v)", again, err)
	}
	if view := fixture.get(t, siteID); view.Inherited || view.EngageThreshold != 700 {
		t.Fatalf("view after override = %+v", view)
	}
}

func TestFirewallActionDefaultChangeRepublishesOnlyWithInheritingSites(t *testing.T) {
	fixture, siteA := newFirewallDefaultFixture(t)
	siteB := fixture.secondSite(t)
	if _, err := fixture.putSite(t, siteA, 0, 500); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.putSite(t, siteB, 0, 500); err != nil {
		t.Fatal(err)
	}
	fixture.settle(t)
	before := scopeRevision(t, fixture.pool, fixture.identity.tenantScope)
	saved, err := fixture.putDefault(t, 0, 300)
	if err != nil || saved.Policy.InheritingSiteCount != 0 {
		t.Fatalf("PutDefault() = (%+v, %v)", saved, err)
	}
	if after := scopeRevision(t, fixture.pool, fixture.identity.tenantScope); after != before {
		t.Fatalf("default without inheriting sites advanced the scope: %d -> %d", before, after)
	}
	var requests int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_revision>$2`, fixture.identity.tenantScope, before).Scan(&requests); err != nil || requests != 0 {
		t.Fatalf("default without inheriting sites enqueued %d requests (%v)", requests, err)
	}
	if view := fixture.get(t, siteA); view.Inherited || view.EngageThreshold != 500 {
		t.Fatalf("override changed by default: %+v", view)
	}
	if _, err := fixture.inherit(t, siteB, 1); err != nil {
		t.Fatal(err)
	}
	fixture.settle(t)
	before = scopeRevision(t, fixture.pool, fixture.identity.tenantScope)
	saved, err = fixture.putDefault(t, 1, 350)
	if err != nil || saved.Policy.InheritingSiteCount != 1 {
		t.Fatalf("PutDefault() = (%+v, %v)", saved, err)
	}
	requireRequestAtCurrentRevision(t, fixture.pool, fixture.identity.tenantScope, before)
	if view := fixture.get(t, siteB); !view.Inherited || view.EngageThreshold != 350 {
		t.Fatalf("inheriting site view = %+v", view)
	}
	if view := fixture.get(t, siteA); view.Inherited || view.EngageThreshold != 500 {
		t.Fatalf("override view = %+v", view)
	}
}

func TestFirewallActionDefaultConcurrentWritesShareOneRevision(t *testing.T) {
	fixture, _ := newFirewallDefaultFixture(t)
	var wait sync.WaitGroup
	results := make(chan error, 4)
	for index := range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := fixture.putDefault(t, 0, uint64(200+index))
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case !errors.Is(err, firewallactioncontrol.ErrRevisionConflict):
			t.Fatalf("concurrent default error = %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent defaults succeeded %d times", succeeded)
	}
	replayKey, requestID := uuid.NewString(), uuid.NewString()
	request := firewallactioncontrol.DefaultPutRequest{Actor: fixture.actor, TargetScopeID: fixture.identity.tenantScope,
		ExpectedRevision: 1, IdempotencyKey: replayKey, RequestID: requestID, Policy: fwPolicy(250)}
	first, err := fixture.service.PutDefault(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := fixture.service.PutDefault(t.Context(), request)
	if err != nil || !replay.Replayed || replay.Policy.Revision != first.Policy.Revision {
		t.Fatalf("replay = (%+v, %v)", replay, err)
	}
	request.Policy = fwPolicy(260)
	if _, err := fixture.service.PutDefault(t.Context(), request); !errors.Is(err, firewallactioncontrol.ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
}
