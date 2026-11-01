//go:build integration

package apikey

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AA-KEY-01：撤权先提交、排队中的签发必须在锁内按实时授权重核，不得按锁前会话权限签出旧权限密钥。

// narrowAlice 走与正式角色变更相同的授权锁协议，收回 alice 的若干权限：系统角色 tenant_owner 的权限不可改
// （guard_system_role_permission_mutation），自定义角色只能经 custom RBAC 建，所以像夹具 live RBAC 用例那样
// 建一个只含夹具三项权限减去被收回者的系统角色，再把 alice 的角色分配换过去。
func narrowAlice(t *testing.T, fixture *apiKeyIntegrationFixture, permissions ...string) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(context.Background(), tx, protocol.OperationUserUpdate,
			[]uuid.UUID{fixture.alice.ScopeID}); err != nil {
			return err
		}
		narrowed := uuid.New()
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO roles (id,scope_id,name,description,system_role,created_at)
			VALUES ($1,$2,$3,'API key scope recheck probe',true,now())`,
			narrowed, fixture.alice.ScopeID, "apikey_narrowed_"+strings.ReplaceAll(narrowed.String(), "-", "")); err != nil {
			return err
		}
		if _, err := tx.Exec(context.Background(), `
			INSERT INTO role_permissions (role_id,permission_name)
			SELECT $1::uuid, p FROM unnest(ARRAY['api_keys.self.manage','sites.read','sites.manage']) p
			WHERE NOT p=ANY($2) ON CONFLICT DO NOTHING`,
			narrowed, permissions); err != nil {
			return err
		}
		return reassignAlice(tx, fixture, narrowed)
	}); err != nil {
		t.Fatalf("narrow alice permissions %v: %v", permissions, err)
	}
}

// restoreAlice 把 alice 换回夹具建的 tenant_owner 角色。
func restoreAlice(t *testing.T, fixture *apiKeyIntegrationFixture) {
	t.Helper()
	if err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(context.Background(), tx, protocol.OperationUserUpdate,
			[]uuid.UUID{fixture.alice.ScopeID}); err != nil {
			return err
		}
		var owner uuid.UUID
		if err := tx.QueryRow(context.Background(), `SELECT id FROM roles WHERE scope_id=$1 AND name='tenant_owner'`,
			fixture.alice.ScopeID).Scan(&owner); err != nil {
			return err
		}
		return reassignAlice(tx, fixture, owner)
	}); err != nil {
		t.Fatalf("restore alice role: %v", err)
	}
}

func reassignAlice(tx pgx.Tx, fixture *apiKeyIntegrationFixture, roleID uuid.UUID) error {
	if _, err := tx.Exec(context.Background(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		fixture.alice.ScopeID, fixture.alice.UserID); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		INSERT INTO role_assignments (scope_id,user_id,role_id,assigned_at) VALUES ($1,$2,$3,now())`,
		fixture.alice.ScopeID, fixture.alice.UserID, roleID)
	return err
}

func waitAdvisoryWaiters(t *testing.T, fixture *apiKeyIntegrationFixture, count int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var actual int
		if err := fixture.pool.QueryRow(t.Context(), `
			SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
			WHERE l.locktype='advisory' AND NOT l.granted AND a.datname=current_database()`).Scan(&actual); err != nil {
			t.Fatalf("observe lock queue: %v", err)
		}
		if actual >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d lock waiters; no product verdict", count)
}

func expectScopesUnavailable(t *testing.T, err error, want ...string) {
	t.Helper()
	var refusal *ScopesUnavailableError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error = %v, want ScopesUnavailableError%v", err, want)
	}
	if strings.Join(refusal.Scopes, ",") != strings.Join(want, ",") {
		t.Fatalf("unavailable scopes = %v, want %v", refusal.Scopes, want)
	}
}

func expectNoKeyWrite(t *testing.T, fixture *apiKeyIntegrationFixture, idempotencyKey string) {
	t.Helper()
	var keys, writes, audits int
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT (SELECT count(*) FROM api_keys WHERE name=$1),
		       (SELECT count(*) FROM api_key_write_requests WHERE idempotency_key=$1),
		       (SELECT count(*) FROM audit_events WHERE request_id=$1)`, idempotencyKey).
		Scan(&keys, &writes, &audits); err != nil {
		t.Fatalf("count refused write facts: %v", err)
	}
	if keys != 0 || writes != 0 || audits != 0 {
		t.Fatalf("refused write left keys=%d writes=%d audits=%d", keys, writes, audits)
	}
}

func TestAPIKeyCreateQueuedBehindRoleNarrowingIsRefused(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	holder, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
		t.Fatal(err)
	}
	narrowed := make(chan struct{})
	go func() {
		defer close(narrowed)
		narrowAlice(t, fixture, "sites.manage")
	}()
	waitAdvisoryWaiters(t, fixture, 1)
	created := make(chan error, 1)
	go func() {
		// fixture.alice 是锁前的会话权限快照，仍含 sites.manage。
		_, err := fixture.service.CreateSelf(context.Background(), fixture.alice, CreateInput{
			Name: "race-stale-grant", Scopes: []string{"sites.manage", "sites.read"},
			IdempotencyKey: "race-stale-grant", RequestID: "race-stale-grant",
		})
		created <- err
	}()
	waitAdvisoryWaiters(t, fixture, 2)
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-narrowed
	expectScopesUnavailable(t, <-created, "sites.manage")
	expectNoKeyWrite(t, fixture, "race-stale-grant")

	// 拒绝不留半成品：权限恢复后同一幂等键按新请求重新评估并成功。
	restoreAlice(t, fixture)
	issued, err := fixture.service.CreateSelf(t.Context(), fixture.alice, CreateInput{
		Name: "race-stale-grant", Scopes: []string{"sites.manage", "sites.read"},
		IdempotencyKey: "race-stale-grant", RequestID: "race-stale-grant",
	})
	if err != nil || strings.Join(issued.Key.Scopes, ",") != "sites.manage,sites.read" {
		t.Fatalf("retry after restore = scopes %v err %v", issued.Key.Scopes, err)
	}
}

func TestAPIKeyWritesRecheckLiveAuthorityInsideLock(t *testing.T) {
	fixture := newAPIKeyIntegrationFixture(t)
	ctx := t.Context()
	readKey := mustCreateSelfKey(t, fixture, "recheck-read")
	manageKey, err := fixture.service.CreateSelf(ctx, fixture.alice, CreateInput{
		Name: "recheck-manage", Scopes: []string{"sites.manage"},
		IdempotencyKey: "recheck-manage", RequestID: "recheck-manage",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "recheck-pending", Scopes: []string{"sites.manage"}, PendingTTL: time.Hour,
		IdempotencyKey: "recheck-pending", RequestID: "recheck-pending",
	})
	if err != nil {
		t.Fatal(err)
	}
	narrowAlice(t, fixture, "sites.manage")
	stale := fixture.alice // 仍含 sites.manage 的旧会话快照

	_, err = fixture.service.UpdateSelf(ctx, stale, UpdateInput{
		ID: readKey.Key.ID, ExpectedRevision: readKey.Key.Revision, Name: readKey.Key.Name,
		Scopes: []string{"sites.manage", "sites.read"}, ExpiresAt: readKey.Key.ExpiresAt,
		IdempotencyKey: "recheck-update", RequestID: "recheck-update",
	})
	expectScopesUnavailable(t, err, "sites.manage")

	_, err = fixture.service.RotateSelf(ctx, stale, MutationInput{
		ID: manageKey.Key.ID, ExpectedRevision: manageKey.Key.Revision,
		IdempotencyKey: "recheck-rotate", RequestID: "recheck-rotate",
	})
	expectScopesUnavailable(t, err, "sites.manage")

	_, err = fixture.service.ActivateSelf(ctx, stale, MutationInput{
		ID: pending.ID, ExpectedRevision: pending.Revision,
		IdempotencyKey: "recheck-activate", RequestID: "recheck-activate",
	})
	expectScopesUnavailable(t, err, "sites.manage")

	// 简单版"重置密钥"刷新为实时可授予的全部，不再带回已收回的权限。
	refreshed, err := fixture.service.RotateSelf(ctx, stale, MutationInput{
		ID: readKey.Key.ID, ExpectedRevision: readKey.Key.Revision, GrantAllScopes: true,
		IdempotencyKey: "recheck-grant-all", RequestID: "recheck-grant-all",
	})
	if err != nil || strings.Join(refreshed.Key.Scopes, ",") != "sites.read" {
		t.Fatalf("grant-all after narrowing = scopes %v err %v", refreshed.Key.Scopes, err)
	}

	_, err = fixture.service.AdminCreatePending(ctx, fixture.admin, AdminCreateInput{
		TargetScopeID: fixture.alice.ScopeID, TargetUserID: fixture.alice.UserID,
		Name: "recheck-admin", Scopes: []string{"sites.manage"}, PendingTTL: time.Hour,
		IdempotencyKey: "recheck-admin", RequestID: "recheck-admin",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		// 管理端的目标权限在锁前加载（targetPrincipal），这里已能直接拒绝；锁内重核覆盖排队竞态。
		t.Fatalf("admin pending after narrowing error = %v", err)
	}

	// 已签出但权限已缩小的密钥：列表/详情按实时权限标出不再生效的权限，调用时被拒。
	page, err := fixture.service.ListSelfPage(ctx, stale, APIKeyListInput{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		want := []string(nil)
		if slices.Contains(item.Scopes, "sites.manage") {
			want = []string{"sites.manage"}
		}
		if strings.Join(item.UnavailableScopes, ",") != strings.Join(want, ",") {
			t.Fatalf("key %s unavailable scopes = %v, want %v", item.Name, item.UnavailableScopes, want)
		}
	}
	detail, err := fixture.service.GetSelf(ctx, stale, manageKey.Key.ID)
	if err != nil || strings.Join(detail.UnavailableScopes, ",") != "sites.manage" {
		t.Fatalf("detail unavailable scopes = %v err %v", detail.UnavailableScopes, err)
	}
	if _, err := fixture.service.Authenticate(ctx, manageKey.Key.KeyID+"."+manageKey.Secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("narrowed-out key authentication error = %v", err)
	}
}

func TestAPIKeyCreateRefusedWhenSelfManageOrMembershipLost(t *testing.T) {
	for _, probe := range []struct {
		name  string
		apply func(*testing.T, *apiKeyIntegrationFixture)
	}{
		{"self manage revoked", func(t *testing.T, f *apiKeyIntegrationFixture) { narrowAlice(t, f, "api_keys.self.manage") }},
		{"membership suspended", func(t *testing.T, f *apiKeyIntegrationFixture) {
			if err := pgx.BeginFunc(context.Background(), f.pool, func(tx pgx.Tx) error {
				if _, err := protocol.BeginAuthorityMutation(context.Background(), tx, protocol.OperationMembershipSuspend,
					[]uuid.UUID{f.alice.ScopeID}); err != nil {
					return err
				}
				_, err := tx.Exec(context.Background(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
					f.alice.ScopeID, f.alice.UserID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			fixture := newAPIKeyIntegrationFixture(t)
			probe.apply(t, fixture)
			_, err := fixture.service.CreateSelf(t.Context(), fixture.alice, CreateInput{
				Name: "lost-authority", Scopes: []string{"sites.read"},
				IdempotencyKey: "lost-authority", RequestID: "lost-authority",
			})
			var refusal *ScopesUnavailableError
			if !errors.Is(err, ErrPermissionDenied) || errors.As(err, &refusal) {
				t.Fatalf("%s create error = %v, want plain permission denied", probe.name, err)
			}
			expectNoKeyWrite(t, fixture, "lost-authority")
		})
	}
}
