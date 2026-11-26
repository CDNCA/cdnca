//go:build integration

package edgeautopublish_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/cdnca/cdnca/services/control-api/internal/packageautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// 社区版没有套餐：全新安装后租户范围没有任何自动发布策略，建站返回 201 却不入队，节点永远收不到。
// 作用域第一次改动网站或四层转发时按自动发布处理（参数同开通套餐，由该操作者发布），之后照常入队；
// 手动策略照旧不入队（TestSiteAndL4MutationsEnqueueAtomically）。
func TestCommunityScopeWithoutPolicyPublishesAutomatically(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	trust := installAutomaticSiteEntitlement(t, pool)
	siteService := site.NewService(site.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }, trust))
	l4Service := l4forward.NewService(l4forward.NewStoreWithClock(pool, func() time.Time { return automaticIntegrationNow }))
	l4Binding := insertAutomaticL4Binding(t, pool, identity)

	// 平台管理员替用户建站（README 第 7 步）：策略的操作者是管理员（分配 CNAME 要管理员的有效会话）。
	sessionID := uuid.New()
	digest := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,
		created_at,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
		sessionID, uuid.New(), identity.platformUser, identity.platformScope, digest[:]); err != nil {
		t.Fatal(err)
	}
	platformActor := site.Actor{UserID: identity.platformUser, ScopeID: identity.platformScope, ScopeKind: "platform",
		SessionID: sessionID}
	request := newSiteRequest("community.example.test", "community-site")
	request.TargetScopeID, request.OwnerUserID = identity.tenantScope, identity.tenantUser
	if _, err := siteService.Create(t.Context(), platformActor, request); err != nil {
		t.Fatalf("site create: %v", err)
	}
	assertRequestCount(t, pool, 1)
	assertLatestOperation(t, pool, "site.create")

	type policyRow struct {
		revision                            int64
		mode, reason                        string
		nodes                               int
		actorScope, actorUser               uuid.UUID
		activationMS, observationMS         int64
		successes, maxAttempts, deadlineSec int
	}
	policies := func() []policyRow {
		t.Helper()
		rows, err := pool.Query(t.Context(), `SELECT revision,mode,reason,cardinality(node_ids),actor_scope_id,actor_user_id,
			activation_timeout_ms,observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds
			FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1 ORDER BY revision`, identity.tenantScope)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var result []policyRow
		for rows.Next() {
			var row policyRow
			if err := rows.Scan(&row.revision, &row.mode, &row.reason, &row.nodes, &row.actorScope, &row.actorUser,
				&row.activationMS, &row.observationMS, &row.successes, &row.maxAttempts, &row.deadlineSec); err != nil {
				t.Fatal(err)
			}
			result = append(result, row)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return result
	}
	want := policyRow{revision: 1, mode: edgeautopublish.ModeAutomatic, reason: packageautopublish.ReasonCommunityDefault,
		actorScope: identity.platformScope, actorUser: identity.platformUser,
		activationMS: 60_000, observationMS: 30_000, successes: 3, maxAttempts: 3, deadlineSec: 1800}
	if got := policies(); len(got) != 1 || got[0] != want {
		t.Fatalf("policies after the first site=%+v, want only %+v", got, want)
	}

	// 之后的改动（用户自己建站、四层转发）沿用这条策略入队，不再追加策略。
	tenantActor := site.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	if _, err := siteService.Create(t.Context(), tenantActor, newSiteRequest("community-two.example.test", "community-two")); err != nil {
		t.Fatalf("second site create: %v", err)
	}
	tenantL4Actor := l4forward.Actor{UserID: identity.tenantUser, ScopeID: identity.tenantScope, ScopeKind: "tenant"}
	if _, err := l4Service.Create(t.Context(), tenantL4Actor, newL4Request(l4Binding, "community-stream", 18088, "community-stream")); err != nil {
		t.Fatalf("l4 create: %v", err)
	}
	assertRequestCount(t, pool, 3)
	assertLatestOperation(t, pool, "stream.create")
	if got := policies(); len(got) != 1 || got[0] != want {
		t.Fatalf("policies after later changes=%+v, want only %+v", got, want)
	}
}
