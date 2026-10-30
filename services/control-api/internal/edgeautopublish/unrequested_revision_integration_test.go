//go:build integration

package edgeautopublish_test

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-finalgaps2 (保存即生效): writes that advance an automatic scope's
// source revision outside any site request must enqueue a publication when
// the scope's last request has already settled; otherwise the nodes keep the
// old configuration until some unrelated save.

type allowFirewallAuthorizer struct{}

func (allowFirewallAuthorizer) Authorize(context.Context, pgx.Tx, firewallcontrol.Actor, uuid.UUID, string) error {
	return nil
}

// settledAutomaticSite creates a site on an automatic scope and settles the
// create's request, as a published save leaves it.
func settledAutomaticSite(t *testing.T, pool *pgxpool.Pool, identity automaticIntegrationIdentity, domain string) uuid.UUID {
	t.Helper()
	trust := installAutomaticSiteEntitlement(t, pool)
	service := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	insertPolicy(t, pool, identity, 1, edgeautopublish.ModeAutomatic)
	created, err := service.Create(t.Context(), site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"},
		newSiteRequest(domain, domain))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts(
		request_id,sequence,state,attempt,terminal_code,occurred_at)
		SELECT id,2,'superseded',0,'test_settled',clock_timestamp() FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1`, identity.tenantScope); err != nil {
		t.Fatal(err)
	}
	return created.Site.ID
}

// requireRequestAtCurrentRevision fails unless an automatic request covers
// the scope's current revision, and returns its source kind and operation.
func requireRequestAtCurrentRevision(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, before int64) (string, string) {
	t.Helper()
	current := scopeRevision(t, pool, scopeID)
	if current <= before {
		t.Fatalf("write did not advance the scope revision: %d -> %d", before, current)
	}
	var kind, operation string
	if err := pool.QueryRow(t.Context(), `SELECT source_kind,operation FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_revision=$2`, scopeID, current).Scan(&kind, &operation); err != nil {
		t.Fatalf("no automatic request at revision %d (was %d): %v", current, before, err)
	}
	return kind, operation
}

func TestFirewallActionPutAfterSettledRequestEnqueuesCurrentRevision(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	siteID := settledAutomaticSite(t, pool, identity, "firewall-action.example.test")
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'firewall.manage') ON CONFLICT DO NOTHING`,
		identity.tenantRole); err != nil {
		t.Fatal(err)
	}
	store := firewallactioncontrol.NewStore(pool, allowFirewallAuthorizer{}, func() time.Time { return automaticIntegrationNow }).
		WithSiteRevisionPublisher(edgeautopublish.UnrequestedRevisionPublisher{})
	before := scopeRevision(t, pool, identity.tenantScope)
	if _, err := firewallactioncontrol.NewService(store).Put(t.Context(), firewallactioncontrol.PutRequest{
		Actor: firewallcontrol.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant",
			Permissions: []string{firewallcontrol.PermissionManage}},
		TargetScopeID: identity.tenantScope, SiteID: siteID, IdempotencyKey: "firewall-action-put", RequestID: uuid.NewString(),
		Policy: firewallactioncontrol.PolicyInput{
			NormalAction: firewallactioncontrol.ActionReturnPage, EscalatedAction: firewallactioncontrol.ActionNFTables,
			EngageThreshold: 100, RecoverThreshold: 20, RecoveryWindows: 3,
			BlockNetworks: []string{"198.51.100.0/24"}, TrustedProxies: []string{}, TrustedCrawlers: []firewallactioncontrol.TrustedCrawler{},
			ReturnPage: firewallactioncontrol.ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "limited"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if kind, operation := requireRequestAtCurrentRevision(t, pool, identity.tenantScope, before); kind != "site" || operation != "site.update" {
		t.Fatalf("firewall action request=%s/%s", kind, operation)
	}
}

func TestL2TopologyWritesAfterSettledRequestEnqueueCurrentRevision(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	settledAutomaticSite(t, pool, identity, "l2-topology.example.test")
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'node_scheduling.manage') ON CONFLICT DO NOTHING`,
		identity.tenantRole); err != nil {
		t.Fatal(err)
	}
	scheduler := nodescheduler.NewService(pool, func() time.Time { return automaticIntegrationNow })
	scheduler.SetPublicationTrigger(edgeautopublish.LineGroupPublisher{})
	actor := nodescheduler.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}

	before := scopeRevision(t, pool, identity.tenantScope)
	created, err := scheduler.PutL2Config(t.Context(), actor, nodescheduler.L2ConfigWriteRequest{
		Name: "l2", Mode: nodescheduler.L2ModeCache, LoadMethod: nodescheduler.L2LoadRoundRobin,
		IdempotencyKey: "l2-create", RequestID: "l2-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	if kind, operation := requireRequestAtCurrentRevision(t, pool, identity.tenantScope, before); kind != "line_group" ||
		operation != edgeautopublish.OperationLineGroupNodesChanged {
		t.Fatalf("L2 create request=%s/%s", kind, operation)
	}
	// The create's request settles; an update, then a delete, still publish.
	settle := func() {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_request_state_facts(
			request_id,sequence,state,attempt,terminal_code,occurred_at)
			SELECT request_row.id,state.sequence+1,'superseded',0,'test_settled',clock_timestamp()
			FROM edge_automatic_publication_requests request_row
			JOIN LATERAL (SELECT sequence,state FROM edge_automatic_publication_request_state_facts
				WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1) state ON state.state='pending'
			WHERE request_row.target_scope_id=$1`, identity.tenantScope); err != nil {
			t.Fatal(err)
		}
	}
	settle()
	before = scopeRevision(t, pool, identity.tenantScope)
	updated, err := scheduler.PutL2Config(t.Context(), actor, nodescheduler.L2ConfigWriteRequest{
		ConfigID: created.Config.ID, ExpectedRevision: created.Config.Revision, Name: "l2-renamed",
		Mode: nodescheduler.L2ModeCache, LoadMethod: nodescheduler.L2LoadRoundRobin,
		IdempotencyKey: "l2-update", RequestID: "l2-update",
	})
	if err != nil {
		t.Fatal(err)
	}
	requireRequestAtCurrentRevision(t, pool, identity.tenantScope, before)
	settle()
	before = scopeRevision(t, pool, identity.tenantScope)
	if _, err := scheduler.DeleteL2Config(t.Context(), actor, updated.Config.ID, updated.Config.Revision, "l2-delete", "l2-delete"); err != nil {
		t.Fatal(err)
	}
	requireRequestAtCurrentRevision(t, pool, identity.tenantScope, before)
}
