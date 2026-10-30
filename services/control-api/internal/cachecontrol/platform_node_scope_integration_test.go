//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 迁移 287 之后：租户能在承载自己站点的 platform 节点上清缓存；不承载它的节点（别的租户的、从未发布过的）拒绝。
func TestTenantPurgeOnPlatformNodesCarryingTheSite(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	tenant := seedCacheFixture(t, pool, "platform-topology-a", 0)
	other := seedCacheFixture(t, pool, "platform-topology-b", 0)
	ctx := context.Background()

	platformScopeID, platformUserID := seedPlatformOperator(t, pool)
	carrying := seedPlatformNode(t, pool, platformScopeID, platformUserID, "platform-carrying")
	foreign := seedPlatformNode(t, pool, platformScopeID, platformUserID, "platform-foreign")
	unpublished := seedPlatformNode(t, pool, platformScopeID, platformUserID, "platform-unpublished")
	publishScopeToNode(t, pool, tenant.actor.ScopeID, carrying)
	publishScopeToNode(t, pool, other.actor.ScopeID, foreign)

	request := CreateOperationRequest{
		SiteID: tenant.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + tenant.domain + "/assets/app.js"},
		NodeIDs: []uuid.UUID{carrying}, IdempotencyKey: "platform-topology-purge",
		RequestID: "platform-topology-purge-request",
	}
	created, err := store.CreateOperation(ctx, tenant.actor, request)
	if err != nil {
		t.Fatalf("tenant purge on platform node carrying its site: %v", err)
	}
	if len(created.Operation.Nodes) != 1 || created.Operation.Nodes[0].NodeID != carrying ||
		created.Operation.Nodes[0].NodeDisplayID == "" {
		t.Fatalf("created operation nodes=%+v", created.Operation.Nodes)
	}

	for name, nodeID := range map[string]uuid.UUID{
		"node carrying another tenant": foreign,
		"node never published":         unpublished,
	} {
		denied := request
		denied.NodeIDs = []uuid.UUID{nodeID}
		denied.IdempotencyKey = "platform-topology-" + nodeID.String()
		denied.RequestID = denied.IdempotencyKey + "-request"
		// fix-cacheflow2 P2-11: one node-selection refusal for both cases.
		if _, err := store.CreateOperation(ctx, tenant.actor, denied); !errors.Is(err, ErrTargetNodeUnavailable) {
			t.Fatalf("%s: err=%v, want ErrTargetNodeUnavailable", name, err)
		}
	}

	claims, err := store.Claim(ctx, ClaimRequest{
		ScopeID: tenant.actor.ScopeID, WorkerID: "platform-topology-worker",
		OnlineNodeIDs: []uuid.UUID{carrying}, Limit: 1, LeaseDuration: time.Minute,
		RequestID: "platform-topology-claim", RequireActiveConfig: true,
	})
	if err != nil || len(claims) != 1 || claims[0].NodeID != carrying || claims[0].ConfigRevision == 0 {
		t.Fatalf("claim on platform node: claims=%+v err=%v", claims, err)
	}
	reported, err := store.Report(ctx, reportRequest(claims[0], "platform-topology-worker", 1,
		"platform-topology-report", []ItemState{ItemSucceeded}))
	if err != nil || reported.Operation.State != StateSucceeded {
		t.Fatalf("report on platform node: result=%+v err=%v", reported, err)
	}
	loaded, err := store.GetOperation(ctx, tenant.actor, created.Operation.ID)
	if err != nil || loaded.State != StateSucceeded || len(loaded.Nodes) != 1 || loaded.Nodes[0].NodeID != carrying {
		t.Fatalf("load operation on platform node: operation=%+v err=%v", loaded, err)
	}
}

func seedPlatformOperator(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	scopeID, userID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status)
		VALUES($1,$2,'platform operator','test-hash','active')`, userID,
		"platform-topology-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func seedPlatformNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, name string) uuid.UUID {
	t.Helper()
	nodeID := uuid.New()
	insertCacheNode(t, pool, nodeID, scopeID, userID, name)
	return nodeID
}

// publishScopeToNode 复刻 edgepublish.claimEligibleNodes 的认领写法与发布成功后的 current 版本。
func publishScopeToNode(t *testing.T, pool *pgxpool.Pool, scopeID, nodeID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	configID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at
	) VALUES($1,$2,$3,$4,'cache-test','1','releasable',$5,$4,$6,$6)`, configID, scopeID,
		[]byte("platform-topology"), make([]byte, 32), "platform-topology-"+configID.String(), cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_config_state (node_id,configuration_scope_id,updated_at)
		VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, nodeID, scopeID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_config_state
		SET current_config_version_id=$2,revision=revision+1,updated_at=$3
		WHERE node_id=$1 AND configuration_scope_id=$4`, nodeID, configID, cacheTestNow, scopeID); err != nil {
		t.Fatal(err)
	}
}
