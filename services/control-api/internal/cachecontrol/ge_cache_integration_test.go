//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// carryNode makes the node carry the fixture scope's configuration (a
// current config version), as a published node does.
func carryNode(t *testing.T, pool *pgxpool.Pool, fixture cacheFixture, nodeID uuid.UUID, slug string) {
	t.Helper()
	configID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,
		created_at,published_at
	) VALUES($1,$2,$3,$4,'cache-test','1','releasable',$5,$4,$6,$6)`, configID,
		fixture.actor.ScopeID, []byte("active-"+slug), make([]byte, 32), "ge-cache-"+slug, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,revision,updated_at
	) VALUES($1,$2,$3,7,$4)`, nodeID, fixture.actor.ScopeID, configID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
}

// ge-cache I: without node IDs an operation goes to every carrying node, and
// a node that starts carrying the site later gets a follow-up.
func TestOperationWithoutNodesUsesCarryingNodesAndFollowsNewOnes(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "carrying", 3)
	request := CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/a.css"}, IdempotencyKey: "carrying", RequestID: "carrying-request",
	}
	if _, err := store.CreateOperation(context.Background(), fixture.actor, request); !errors.Is(err, ErrNoCarryingNode) {
		t.Fatalf("no carrying node: %v", err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[0], "first")
	carryNode(t, pool, fixture, fixture.nodeIDs[1], "second")
	created, err := store.CreateOperation(context.Background(), fixture.actor, request)
	if err != nil || len(created.Operation.Nodes) != 2 {
		t.Fatalf("automatic operation = %+v, %v", created.Operation.Nodes, err)
	}
	replayed, err := store.CreateOperation(context.Background(), fixture.actor, request)
	if err != nil || !replayed.Replayed || replayed.Operation.ID != created.Operation.ID {
		t.Fatalf("replay = %+v, %v", replayed, err)
	}
	if count, err := store.SyncCarryingNodes(context.Background(), fixture.actor.ScopeID, "sync-1"); err != nil || count != 0 {
		t.Fatalf("sync with no new node = %d, %v", count, err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[2], "third")
	if count, err := store.SyncCarryingNodes(context.Background(), fixture.actor.ScopeID, "sync-2"); err != nil || count != 1 {
		t.Fatalf("sync with a new node = %d, %v", count, err)
	}
	if count, err := store.SyncCarryingNodes(context.Background(), fixture.actor.ScopeID, "sync-3"); err != nil || count != 0 {
		t.Fatalf("sync again = %d, %v", count, err)
	}
	var followUps int
	var nodes []uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT count(*),
		(SELECT array_agg(node_id) FROM cache_operation_nodes node JOIN cache_operations child ON child.id=node.operation_id
		 WHERE child.parent_operation_id=$1)
		FROM cache_operations WHERE parent_operation_id=$1`, created.Operation.ID).Scan(&followUps, &nodes); err != nil {
		t.Fatal(err)
	}
	if followUps != 1 || len(nodes) != 1 || nodes[0] != fixture.nodeIDs[2] {
		t.Fatalf("follow-ups = %d nodes %v", followUps, nodes)
	}
	// CACHE-ADD-09b: the follow-up's read model names its parent; the
	// user's operation names none.
	var childID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM cache_operations WHERE parent_operation_id=$1`,
		created.Operation.ID).Scan(&childID); err != nil {
		t.Fatal(err)
	}
	child, err := store.GetOperation(context.Background(), fixture.actor, childID)
	if err != nil || child.ParentOperationID == nil || *child.ParentOperationID != created.Operation.ID {
		t.Fatalf("follow-up parent = %v, %v", child.ParentOperationID, err)
	}
	parent, err := store.GetOperation(context.Background(), fixture.actor, created.Operation.ID)
	if err != nil || parent.ParentOperationID != nil {
		t.Fatalf("user operation parent = %v, %v", parent.ParentOperationID, err)
	}
	// An explicit-node operation never follows new nodes.
	explicit := createSimpleOperation(t, store, fixture, "explicit", 0, fixture.nodeIDs[:1])
	var auto bool
	if err := pool.QueryRow(context.Background(), `SELECT auto_nodes FROM cache_operations WHERE id=$1`, explicit.ID).Scan(&auto); err != nil || auto {
		t.Fatalf("explicit operation auto=%v %v", auto, err)
	}
}

// ge-cache F: the platform's daily URL purge limit (bootstrap 2000) counts
// the site's targets of the day; a whole-site purge counts as a directory
// purge (bootstrap 500).
func TestOperationDailyLimitIsEnforced(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "daily", 1)
	targets := func(prefix string, count int) []string {
		result := make([]string, count)
		for index := range result {
			result[index] = fmt.Sprintf("http://%s/%s-%d", fixture.domain, prefix, index)
		}
		return result
	}
	for batch := 0; batch < 4; batch++ {
		if _, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
			SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
			Targets: targets(fmt.Sprint(batch), 500), NodeIDs: fixture.nodeIDs,
			IdempotencyKey: fmt.Sprint("daily-", batch), RequestID: fmt.Sprint("daily-request-", batch),
		}); err != nil {
			t.Fatalf("batch %d: %v", batch, err)
		}
	}
	over := CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: targets("over", 1), NodeIDs: fixture.nodeIDs, IdempotencyKey: "daily-over", RequestID: "daily-over-request",
	}
	if _, err := store.CreateOperation(context.Background(), fixture.actor, over); !errors.Is(err, ErrDailyLimitExceeded) {
		t.Fatalf("2001st URL: %v", err)
	}
	// Prewarms have their own limit.
	if _, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPrewarm, TargetType: TargetExactURL,
		Targets: targets("warm", 1), NodeIDs: fixture.nodeIDs, IdempotencyKey: "daily-warm", RequestID: "daily-warm-request",
	}); err != nil {
		t.Fatalf("prewarm under its own limit: %v", err)
	}
	// The next day the URL limit resets.
	clock.Add(24 * time.Hour)
	if _, err := store.CreateOperation(context.Background(), fixture.actor, over); err != nil {
		t.Fatalf("next day: %v", err)
	}
}

// Policy extensions round-trip through the definition and the binding.
func TestPolicyExtensionsRoundTrip(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "extensions", 1)
	document := validPolicyV2Document(3600, 60)
	document.Extensions = PolicyExtensions{StaleIfError: true, BackgroundUpdate: true, MaxObjectBytes: 1 << 30, SliceBytes: 1 << 20}
	published, err := store.PublishPolicy(context.Background(), fixture.actor, PublishPolicyRequest{
		SiteID: fixture.siteID, Document: document, IdempotencyKey: "extensions", RequestID: "extensions-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	read, err := store.GetPolicy(context.Background(), fixture.actor, fixture.siteID, 0)
	if err != nil || read.Document.Extensions != document.Extensions || published.Policy.Document.Extensions != document.Extensions {
		t.Fatalf("extensions = %+v / %+v, %v", read.Document.Extensions, published.Policy.Document.Extensions, err)
	}
	invalid := validPolicyV2Document(3600, 60)
	invalid.Extensions = PolicyExtensions{BackgroundUpdate: true}
	if _, err := store.PublishPolicy(context.Background(), fixture.actor, PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 1, Document: invalid, IdempotencyKey: "extensions-invalid",
		RequestID: "extensions-invalid-request",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("background update without stale: %v", err)
	}
}
