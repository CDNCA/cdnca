//go:build integration

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

// fix-regen2 (73, 10-26): 平台管理员 admin 对租户站点 ikvm.asia 点"重新生成"，
// 分配任务的操作人不是该租户成员，AuthorizeDNSReconcile 只认租户成员而拒绝，
// 被包成权益拒绝、CNAME 记成 dns_reconcile_unavailable（"DNS 服务商调用失败"）。
// 真实 gate + 真实租约 guard + 真实 PostgresStore：
//   - 平台管理员（platform scope 的 platform.admin）对租户站点 Apply 成功，审计记平台代租户；
//   - 非成员非平台用户被拒，错误是 ErrPermissionDenied，worker 记 dns_permission_denied；
//   - 租户成员路径不变。
func TestDNSReconcileGateAuthorizesPlatformAdministratorForTenantSite(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := marketLimitsInstallLease(t, pool, marketLimitsLicense{id: "regen2-license-key", key: signing}, uuid.New())

	platformScope, platformAdmin, platformDNS, platformReader, stranger := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	adminRole, dnsRole, readRole := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES
			($1,$5,'platform admin','hash'),($2,$6,'platform dns','hash'),
			($3,$7,'platform reader','hash'),($4,$8,'stranger','hash')`,
			[]any{platformAdmin, platformDNS, platformReader, stranger, regen2Name("admin"), regen2Name("dns"),
				regen2Name("reader"), regen2Name("stranger")}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3),($1,$4)`,
			[]any{platformScope, platformAdmin, platformDNS, platformReader}},
		{`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$4,'regen2-admin',true),
			($2,$4,'regen2-dns',true),($3,$4,'regen2-read',true)`,
			[]any{adminRole, dnsRole, readRole, platformScope}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'platform.admin'),
			($2,'dns.manage'),($2,'sites.manage'),($3,'dns.read')`, []any{adminRole, dnsRole, readRole}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$5),($1,$3,$6),($1,$4,$7)`,
			[]any{platformScope, platformAdmin, platformDNS, platformReader, adminRole, dnsRole, readRole}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	gate := &dnsReconcileEntitlementGate{pool: pool, guard: entitlementguard.NewGuard(pool, time.Now, trust)}
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	store, err := dnsreconcile.NewPostgresStore(pool, jobs, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := dnsreconcile.NewRuntime(dnsreconcile.RuntimeConfig{
		ProviderAttempts: 3, ProviderTimeout: 5 * time.Second, PollAttempts: 20, RequiredConsecutive: 3,
		InitialBackoff: time.Second, MaximumBackoff: 30 * time.Second, OverallTimeout: 15 * time.Minute,
		ApplyLeaseDuration: 16 * time.Minute, CommitLeaseDuration: 16 * time.Minute, Now: time.Now,
	}, dnsreconcile.RuntimeDependencies{
		Store: store, CheckerResolver: dnsReconcileCheckerResolver{checker: &dnscheck.Checker{}},
		ProviderResolver: unusedDNSRecoveryProviderResolver{}, Entitlement: gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	apply := func(actor uuid.UUID, key string) (dnsreconcile.Task, error) {
		check := dnscheck.CheckRequest{
			TenantID: fixture.tenantID, SiteID: fixture.siteID, Name: "label.example.test",
			Expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordCNAME, Values: []string{"lg.example.test"}}},
			TTL:      300, PropagationWindow: 5 * time.Minute,
			Provider: dnscheck.ProviderSnapshot{TenantID: fixture.tenantID, SiteID: fixture.siteID,
				ZoneID: fixture.zoneID, Revision: 3},
		}
		return runtime.Apply(t.Context(), dnsreconcile.ApplyRequest{
			TenantID: fixture.tenantID, SiteID: fixture.siteID, ActorUserID: actor, IdempotencyKey: key,
			RequestID: "regen2/" + key, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ExpectedRevision: 3, RequiredConsecutive: 3, Check: check,
		})
	}
	auditPayload := func(task dnsreconcile.Task) (uuid.UUID, string) {
		t.Helper()
		var actor uuid.UUID
		var scopeKind string
		if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,COALESCE(payload->>'actor_scope_kind','')
			FROM audit_events WHERE action='dns.reconcile.apply' AND resource_id=$1`, task.ID.String()).
			Scan(&actor, &scopeKind); err != nil {
			t.Fatal(err)
		}
		return actor, scopeKind
	}

	t.Run("platform_admin_succeeds", func(t *testing.T) {
		for _, actor := range []uuid.UUID{platformAdmin, platformDNS} {
			task, err := apply(actor, "regen2-platform-"+actor.String()[:8])
			if err != nil || task.ID == uuid.Nil {
				t.Fatalf("platform actor %s Apply = (%+v, %v), want queued task", actor, task, err)
			}
			if auditActor, kind := auditPayload(task); auditActor != actor || kind != "platform" {
				t.Fatalf("platform actor audit = (%s, %q), want (%s, platform)", auditActor, kind, actor)
			}
		}
	})

	t.Run("non_member_denied_as_dns_permission_denied", func(t *testing.T) {
		for _, actor := range []uuid.UUID{stranger, platformReader} {
			_, err := apply(actor, "regen2-denied-"+actor.String()[:8])
			if !errors.Is(err, dnsreconcile.ErrPermissionDenied) {
				t.Fatalf("actor %s Apply error = %v, want ErrPermissionDenied", actor, err)
			}
			if code := cnameallocation.ApplyFailureCode(err); code != cnameallocation.FailureDNSPermissionDenied {
				t.Fatalf("worker failure code = %q, want dns_permission_denied", code)
			}
		}
		var tasks int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_reconcile_tasks
			WHERE tenant_id=$1 AND idempotency_key LIKE 'regen2-denied-%'`, fixture.tenantID).Scan(&tasks); err != nil || tasks != 0 {
			t.Fatalf("denied actors created %d tasks (%v)", tasks, err)
		}
	})

	t.Run("tenant_member_unchanged", func(t *testing.T) {
		task, err := apply(fixture.userID, "regen2-member")
		if err != nil || task.ID == uuid.Nil {
			t.Fatalf("tenant member Apply = (%+v, %v)", task, err)
		}
		if auditActor, kind := auditPayload(task); auditActor != fixture.userID || kind != "" {
			t.Fatalf("tenant member audit = (%s, %q), want (%s, \"\")", auditActor, kind, fixture.userID)
		}
	})

	t.Run("platform_admin_propagation_context", func(t *testing.T) {
		resolver := &dnsReconcilePropagationContextResolver{pool: pool}
		for _, actor := range []uuid.UUID{platformAdmin, fixture.userID} {
			if got, err := resolver.ResolvePropagationContext(t.Context(), fixture.tenantID, fixture.siteID,
				fixture.zoneID, actor); err != nil || got.ZoneID != fixture.zoneID {
				t.Fatalf("actor %s propagation context = (%+v, %v)", actor, got, err)
			}
		}
		if _, err := resolver.ResolvePropagationContext(t.Context(), fixture.tenantID, fixture.siteID,
			fixture.zoneID, stranger); err == nil {
			t.Fatal("non-member propagation context resolved")
		}
	})
}

func regen2Name(role string) string {
	return "regen2" + role + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
}
