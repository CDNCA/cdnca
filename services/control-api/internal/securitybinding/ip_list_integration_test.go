package securitybinding

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Named IP lists (migration 451) — the store (scopes,
// platform lists, revisions, idempotency, in-use refusal), the sites whose
// active WAF version references a list (IPListSitesTx, jsonb_path) and the
// republication of their scope when a list changes (system trigger ip_list).
func TestSecurityIPListStoreAndRepublication(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantB
	ctx := t.Context()
	store := securityiplist.NewStore(pool, func() time.Time { return bindingTestNow })
	tenantActor := securityiplist.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	platformActor := securityiplist.Actor{UserID: fixture.platform.UserID, ScopeID: fixture.platform.ScopeID, ScopeKind: "platform"}
	write := func(id uuid.UUID, revision int64, key, name string, entries ...string) securityiplist.WriteRequest {
		return securityiplist.WriteRequest{ListID: id, ExpectedRevision: revision, IdempotencyKey: key, RequestID: key,
			Input: securityiplist.Input{Name: name, Entries: entries}}
	}

	platformList, err := store.Create(ctx, platformActor, write(uuid.Nil, 0, "ipl-platform", "scanners", "198.51.100.7", "198.51.100.0/24", "198.51.100.7"))
	// Canonical: masked, deduplicated, ordered (a contained address is kept).
	if err != nil || !platformList.Platform || !slices.Equal(platformList.Entries, []string{"198.51.100.0/24", "198.51.100.7/32"}) {
		t.Fatalf("platform create = %+v %v", platformList, err)
	}
	own, err := store.Create(ctx, tenantActor, write(uuid.Nil, 0, "ipl-own", "office", "192.0.2.9", "2001:db8::/32"))
	if err != nil || own.Platform || own.Revision != 1 {
		t.Fatalf("tenant create = %+v %v", own, err)
	}
	replay, err := store.Create(ctx, tenantActor, write(uuid.Nil, 0, "ipl-own", "office", "192.0.2.9", "2001:db8::/32"))
	if err != nil || replay.ID != own.ID {
		t.Fatalf("replay = %+v %v", replay, err)
	}
	if _, err := store.Create(ctx, tenantActor, write(uuid.Nil, 0, "ipl-own", "office", "192.0.2.10")); !errors.Is(err, securityiplist.ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay: %v", err)
	}
	if _, err := store.Create(ctx, tenantActor, write(uuid.Nil, 0, "ipl-dup", "Office ", "192.0.2.10")); !errors.Is(err, securityiplist.ErrNameConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	lists, err := store.ListAll(ctx, tenantActor)
	if err != nil || len(lists) != 2 || lists[0].ID != own.ID || lists[1].ID != platformList.ID {
		t.Fatalf("tenant lists = %+v %v", lists, err)
	}
	if lists, err := store.ListAll(ctx, securityiplist.Actor{UserID: fixture.tenantA.userID, ScopeID: fixture.tenantA.scopeID,
		ScopeKind: "tenant"}); err != nil || len(lists) != 1 || lists[0].ID != platformList.ID {
		t.Fatalf("other tenant lists = %+v %v", lists, err)
	}
	if _, err := store.Update(ctx, tenantActor, write(platformList.ID, 1, "ipl-steal", "x", "10.0.0.0/8")); !errors.Is(err, securityiplist.ErrNotFound) {
		t.Fatalf("tenant updated a platform list: %v", err)
	}

	// The tenant's WAF policy version 2 references its own list and is the
	// site's active version; a second site is bound with nothing published.
	policy := policyDocument(tenant.policyID, tenant.scopeID, securitypolicy.KindWAF, "policy-b", 2)
	policy.Rules[0].Conditions = []securitypolicy.Condition{{Field: "ip_list", Operator: "in_ip_list", Values: []string{own.ID.String()}}}
	document, _ := json.Marshal(policy)
	if _, err := pool.Exec(ctx, `INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
		VALUES($1,2,$2,$3,$4)`, tenant.policyID, document, tenant.userID, bindingTestNow); err != nil {
		t.Fatal(err)
	}
	other := insertSite(t, pool, tenant, "b2.example.test")
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO security_policy_site_bindings
			(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,last_claimed_policy_version,last_bundle_id,
			 revision,created_at,updated_at) VALUES($1,$2,$3,$4,'waf',2,2,$5,1,now(),now())`,
			uuid.New(), tenant.scopeID, tenant.siteID, tenant.policyID, uuid.New())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,
		created_at,updated_at) VALUES($1,$2,$3,$4,'waf',now(),now())`, uuid.New(), tenant.scopeID, other, tenant.policyID); err != nil {
		t.Fatal(err)
	}
	sitesOf := func(id uuid.UUID) []edgepublish.IPListSite {
		t.Helper()
		var sites []edgepublish.IPListSite
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) (err error) {
			sites, err = edgepublish.IPListSitesTx(ctx, tx, id)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return sites
	}
	if sites := sitesOf(own.ID); len(sites) != 1 || sites[0] != (edgepublish.IPListSite{ScopeID: tenant.scopeID, SiteID: tenant.siteID}) {
		t.Fatalf("referencing sites = %+v", sites)
	}
	if sites := sitesOf(platformList.ID); len(sites) != 0 {
		t.Fatalf("unreferenced list sites = %+v", sites)
	}

	// The fixture's scope has a configuration (source revision base): every
	// change advances it once and a manual scope queues a system
	// republication with trigger ip_list.
	var base int64
	if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		tenant.scopeID).Scan(&base); err != nil {
		t.Fatal(err)
	}
	updated, err := store.Update(ctx, tenantActor, write(own.ID, 1, "ipl-update-1", "office", "192.0.2.0/28"))
	if err != nil || updated.Revision != 2 {
		t.Fatalf("update = %+v %v", updated, err)
	}
	if _, err := store.Update(ctx, tenantActor, write(own.ID, 1, "ipl-stale", "office", "192.0.2.1")); !errors.Is(err, securityiplist.ErrRevisionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	var source int64
	var triggers []string
	if err := pool.QueryRow(ctx, `SELECT scope.source_revision,head.triggers FROM edge_configuration_scopes scope
		JOIN edge_system_republication_heads head ON head.scope_id=scope.scope_id WHERE scope.scope_id=$1`,
		tenant.scopeID).Scan(&source, &triggers); err != nil {
		t.Fatal(err)
	}
	if source != base+1 || !slices.Equal(triggers, []string{edgepublish.SystemTriggerIPList}) {
		t.Fatalf("source revision %d -> %d triggers %v, want +1 [ip_list]", base, source, triggers)
	}
	// A second change merges into the pending head (debounced) and advances once more.
	if _, err := store.Update(ctx, tenantActor, write(own.ID, 2, "ipl-update-2", "office", "192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, pool, `SELECT source_revision::int FROM edge_configuration_scopes WHERE scope_id=$1`, tenant.scopeID); int64(got) != base+2 {
		t.Fatalf("source revision after second change %d, want %d", got, base+2)
	}
	var scopes []uuid.UUID
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) (err error) {
		scopes, err = edgeautopublish.RepublishIPListChangeTx(ctx, tx, platformList.ID, 2)
		return err
	}); err != nil || len(scopes) != 0 {
		t.Fatalf("unreferenced republication = %v %v", scopes, err)
	}

	// An automatic scope (small-1035j J2) publishes each referencing site as
	// its policy's actor (site.update, EnqueueSiteSettingTx), not through the
	// system channel: the source revision still advances once, the pending
	// system head gains nothing, the bound site without a published version
	// gets no request.
	if _, err := pool.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		VALUES($1,1,'automatic',ARRAY[$2::uuid],30000,15000,2,3,600,$1,$3,'ip_list_test',clock_timestamp())`,
		tenant.scopeID, tenant.nodeID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	head := `SELECT generation::int FROM edge_system_republication_heads WHERE scope_id=$1`
	generation := countRows(t, pool, head, tenant.scopeID)
	if _, err := store.Update(ctx, tenantActor, write(own.ID, 3, "ipl-update-auto", "office", "192.0.2.2")); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, pool, `SELECT source_revision::int FROM edge_configuration_scopes WHERE scope_id=$1`, tenant.scopeID); int64(got) != base+3 {
		t.Fatalf("source revision after automatic change %d, want %d", got, base+3)
	}
	type request struct {
		site                 uuid.UUID
		actor                uuid.UUID
		operation, requestID string
	}
	rows, err := pool.Query(ctx, `SELECT source_resource_id,actor_user_id,operation,source_request_id FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_request_id LIKE 'ip-list.%' ORDER BY created_at`, tenant.scopeID)
	if err != nil {
		t.Fatal(err)
	}
	requests, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (request, error) {
		var value request
		return value, row.Scan(&value.site, &value.actor, &value.operation, &value.requestID)
	})
	want := request{site: tenant.siteID, actor: tenant.userID, operation: "site.update", requestID: "ip-list." + own.ID.String() + ".4"}
	if err != nil || len(requests) != 1 || requests[0] != want {
		t.Fatalf("automatic requests = %+v %v, want [%+v]", requests, err, want)
	}
	if got := countRows(t, pool, head, tenant.scopeID); got != generation {
		t.Fatalf("system republication generation %d -> %d on an automatic scope", generation, got)
	}

	// A referenced list cannot be deleted; an unreferenced one can.
	if err := store.Delete(ctx, tenantActor, write(own.ID, 4, "ipl-del-used", "")); !errors.Is(err, securityiplist.ErrInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	if err := store.Delete(ctx, platformActor, write(platformList.ID, 1, "ipl-del", "")); err != nil {
		t.Fatal(err)
	}
	if lists, err := store.ListAll(ctx, tenantActor); err != nil || len(lists) != 1 || lists[0].ID != own.ID {
		t.Fatalf("after delete = %+v %v", lists, err)
	}
	if count := countRows(t, pool, `SELECT count(*) FROM audit_events WHERE action LIKE 'security.ip_list.%'`); count < 6 {
		t.Fatalf("audit events %d", count)
	}
}

func countRows(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, query string, args ...any) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
