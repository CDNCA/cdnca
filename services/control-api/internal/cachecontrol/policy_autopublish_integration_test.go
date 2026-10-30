//go:build integration

package cachecontrol

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
)

// N7: saving a cache policy on an automatic scope enqueues the
// scope's automatic publication (site.update at the advanced source
// revision), as every other site setting does; a manual scope enqueues none.
func TestPublishPolicyEnqueuesAutomaticPublication(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow }).
		WithSiteSettingEnqueuer(edgeautopublish.SiteSettingPublisher{})
	ctx := context.Background()

	manual := seedCacheFixture(t, pool, "policy-autopub-manual", 1)
	if _, err := store.PublishPolicy(ctx, manual.actor, PublishPolicyRequest{
		SiteID: manual.siteID, Document: validPolicyDocument(60),
		IdempotencyKey: "policy-autopub-manual", RequestID: "policy-autopub-manual-request",
	}); err != nil {
		t.Fatal(err)
	}
	var manualRequests int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1`, manual.actor.ScopeID).Scan(&manualRequests); err != nil {
		t.Fatal(err)
	}
	if manualRequests != 0 {
		t.Fatalf("manual scope automatic requests=%d, want 0", manualRequests)
	}

	fixture := seedCacheFixture(t, pool, "policy-autopub", 1)
	if _, err := pool.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		VALUES($1,1,'automatic',ARRAY[$2::uuid],30000,15000,2,3,600,$1,$3,'cache_policy_test',clock_timestamp())`,
		fixture.actor.ScopeID, fixture.nodeIDs[0], fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	result, err := store.PublishPolicy(ctx, fixture.actor, PublishPolicyRequest{
		SiteID: fixture.siteID, Document: validPolicyDocument(60),
		IdempotencyKey: "policy-autopub", RequestID: "policy-autopub-request",
	})
	if err != nil || result.Policy.Revision != 1 {
		t.Fatalf("publish policy=(%+v,%v)", result, err)
	}
	var count int
	var sourceKind, operation, resourceID string
	var requestRevision, scopeRevision int64
	if err := pool.QueryRow(ctx, `SELECT count(*) OVER (),request.source_kind,request.operation,
		request.source_resource_id::text,request.source_revision,scope.source_revision
		FROM edge_automatic_publication_requests request
		JOIN edge_configuration_scopes scope ON scope.scope_id=request.target_scope_id
		WHERE request.target_scope_id=$1`, fixture.actor.ScopeID).Scan(
		&count, &sourceKind, &operation, &resourceID, &requestRevision, &scopeRevision); err != nil {
		t.Fatal(err)
	}
	if count != 1 || sourceKind != "site" || operation != "site.update" || resourceID != fixture.siteID.String() ||
		requestRevision != scopeRevision {
		t.Fatalf("automatic request count/kind/operation/resource/revision=%d/%s/%s/%s/%d (scope %d)",
			count, sourceKind, operation, resourceID, requestRevision, scopeRevision)
	}
	replay, err := store.PublishPolicy(ctx, fixture.actor, PublishPolicyRequest{
		SiteID: fixture.siteID, Document: validPolicyDocument(60),
		IdempotencyKey: "policy-autopub", RequestID: "policy-autopub-request",
	})
	if err != nil || !replay.Replayed {
		t.Fatalf("replay=(%+v,%v)", replay, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1`, fixture.actor.ScopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("requests after replay=%d err=%v, want 1", count, err)
	}
}
