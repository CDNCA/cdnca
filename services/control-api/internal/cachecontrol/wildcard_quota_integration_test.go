//go:build integration

package cachecontrol

// Q4 通配刷新能力门控、Q6 系统跟进不扣今日额度；fp-site3 CACHE-01 额度读取同口径。待出包前全量跑。

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// declareNodeCapabilities records a Connect session for the node whose
// capabilities include the given ones.
func declareNodeCapabilities(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, epoch int64, features ...agentv1.CapabilityName) {
	t.Helper()
	capabilities := &agentv1.AgentCapabilities{AgentVersion: "1.0.35"}
	for _, feature := range features {
		capabilities.Features = append(capabilities.Features, &agentv1.Capability{Name: feature, ApiVersion: 1})
	}
	snapshot, err := proto.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(snapshot)
	if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
			certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
			capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
			VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',now())`,
			nodeID, epoch, uuid.New(), digest[:], snapshot)
		return err
	}); err != nil {
		t.Fatalf("declare capabilities: %v", err)
	}
}

// Q4：通配刷新只发给声明 CACHE_WILDCARD_PURGE 的节点；新节点未声明就不建跟进。
func TestWildcardPurgeNeedsNodeCapability(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "wildcard", 3)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,
			actor_scope_id,actor_user_id,request_id,occurred_at
		) VALUES ($1,$2,1,'activate',$3,$1,$4,'wildcard',$5),($1,$2,1,'activate','*.wq.example',$1,$4,'wildcard',$5)`,
		fixture.actor.ScopeID, fixture.siteID, fixture.domain, fixture.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[0], "w-first")
	request := CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://*.wq.example/a.css"}, IdempotencyKey: "wildcard", RequestID: "wildcard-request",
	}
	if _, err := store.CreateOperation(context.Background(), fixture.actor, request); !errors.Is(err, ErrWildcardPurgeUnsupported) {
		t.Fatalf("node without capability: %v", err)
	}
	declareNodeCapabilities(t, pool, fixture.nodeIDs[0], 1, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_WILDCARD_PURGE)
	created, err := store.CreateOperation(context.Background(), fixture.actor, request)
	if err != nil || len(created.Operation.Nodes) != 1 {
		t.Fatalf("capable node: %+v %v", created.Operation.Nodes, err)
	}
	prewarm := request
	prewarm.Action, prewarm.IdempotencyKey = ActionPrewarm, "wildcard-prewarm"
	if _, err := store.CreateOperation(context.Background(), fixture.actor, prewarm); !errors.Is(err, ErrWildcardTargetHost) {
		t.Fatalf("wildcard prewarm: %v", err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[1], "w-old")
	if count, err := store.SyncCarryingNodes(context.Background(), fixture.actor.ScopeID, "w-sync-1"); err != nil || count != 0 {
		t.Fatalf("follow-up to a node without capability = %d, %v", count, err)
	}
	carryNode(t, pool, fixture, fixture.nodeIDs[2], "w-new")
	declareNodeCapabilities(t, pool, fixture.nodeIDs[2], 1, agentv1.CapabilityName_CAPABILITY_NAME_CACHE_WILDCARD_PURGE)
	if count, err := store.SyncCarryingNodes(context.Background(), fixture.actor.ScopeID, "w-sync-2"); err != nil || count != 1 {
		t.Fatalf("follow-up to a capable node = %d, %v", count, err)
	}
}

// Q6：系统给新承载节点建的跟进子任务不计入今日额度，只算用户首次提交。
func TestCarryingFollowUpsDoNotCountTowardsDailyLimit(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "followquota", 2)
	carryNode(t, pool, fixture, fixture.nodeIDs[0], "q-first")
	targets := func(prefix string, count int) []string {
		result := make([]string, count)
		for index := range result {
			result[index] = fmt.Sprintf("http://%s/%s-%d", fixture.domain, prefix, index)
		}
		return result
	}
	for batch := 0; batch < 3; batch++ {
		if _, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
			SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL, Targets: targets(fmt.Sprint(batch), 500),
			IdempotencyKey: fmt.Sprint("fq-", batch), RequestID: fmt.Sprint("fq-request-", batch),
		}); err != nil {
			t.Fatalf("batch %d: %v", batch, err)
		}
	}
	// 新节点加入：三个父任务各建一个跟进（共 1500 个目标），不应计入。
	carryNode(t, pool, fixture, fixture.nodeIDs[1], "q-second")
	if count, err := store.SyncCarryingNodes(context.Background(), fixture.actor.ScopeID, "fq-sync"); err != nil || count != 3 {
		t.Fatalf("follow-ups = %d, %v", count, err)
	}
	// 用户已用 1500，再提交 500 恰好到 2000，应受理。
	if _, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL, Targets: targets("last", 500),
		IdempotencyKey: "fq-last", RequestID: "fq-last-request",
	}); err != nil {
		t.Fatalf("user's 2000th URL with follow-ups present: %v", err)
	}
	if _, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL, Targets: targets("over", 1),
		IdempotencyKey: "fq-over", RequestID: "fq-over-request",
	}); !errors.Is(err, ErrDailyLimitExceeded) {
		t.Fatalf("2001st URL: %v", err)
	}
	// CACHE-01（fp-site3）：额度读取接口与提交检查同一口径——跟进不计，已用 2000、剩余 0。
	usage, err := store.DailyUsage(context.Background(), fixture.actor)
	if err != nil || usage.URLPurge.Used != 2000 || usage.URLPurge.Remaining != 0 || usage.URLPurge.Limit != 2000 ||
		usage.DirectoryPurge.Used != 0 || usage.Prewarm.Used != 0 || !usage.ResetsAt.After(cacheTestNow) {
		t.Fatalf("daily usage = %+v, %v", usage, err)
	}
}
