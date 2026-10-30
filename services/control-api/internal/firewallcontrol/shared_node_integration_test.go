//go:build integration

package firewallcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixedSigner struct{}

func (fixedSigner) KeyID() string                                { return "p0a-test" }
func (fixedSigner) Sign(context.Context, []byte) ([]byte, error) { return make([]byte, 64), nil }

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error { return nil }

// sharedNodeFixture: tenants A and B each have a site on one platform line
// group, so one platform node carries both (tenant_carries_node_287); with
// ownedNode, A also owns a node of its own.
type sharedNodeFixture struct {
	pool                             *pgxpool.Pool
	platform, tenantA, tenantB, user uuid.UUID
	sharedNode, ownedNodeA           uuid.UUID
	siteA, siteB                     uuid.UUID
}

func newSharedNodeFixture(t *testing.T, ownedNode bool) sharedNodeFixture {
	t.Helper()
	ctx := t.Context()
	pool := databasetest.MigratedPool(t, nil)
	f := sharedNodeFixture{pool: pool, tenantA: uuid.New(), tenantB: uuid.New(), user: uuid.New(),
		sharedNode: uuid.New(), ownedNodeA: uuid.New(), siteA: uuid.New(), siteB: uuid.New()}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.platform); errors.Is(err, pgx.ErrNoRows) {
		f.platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, err := tx.Exec(ctx, sql, args...); err != nil {
				t.Fatalf("%.90s: %v", sql, err)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO control_installation_entitlement(installation_id) SELECT 'p0a-install'
			WHERE NOT EXISTS (SELECT 1 FROM control_installation_entitlement)`)
		exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, f.platform)
		for _, scope := range []uuid.UUID{f.tenantA, f.tenantB} {
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'p0a')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
		}
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'p0a','x')`, f.user, "p0a-"+f.user.String()[:8])
		for _, scope := range []uuid.UUID{f.tenantA, f.tenantB} {
			exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scope, f.user)
		}
		display := 0
		node := func(id, scope uuid.UUID) {
			display++
			exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,$4,'active',$5)`,
				id, 97000+display, scope, "p0a-"+id.String()[:8], f.user)
		}
		node(f.sharedNode, f.platform)
		if ownedNode {
			node(f.ownedNodeA, f.tenantA)
		}
		// One platform line group serving the shared node carries both tenants' sites.
		group := uuid.New()
		exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
			created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
			VALUES($1::uuid,$2,$3,2,$4::uuid,$4::uuid,$5,$5,$6,'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''))`,
			group, f.platform, "p0a-"+group.String()[:8], f.user, now, 97900)
		exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,priority,weight,enabled) VALUES($1,$2,$3,$4,2,'198.51.100.7',4,80,0,1,true)`, uuid.New(), f.sharedNode, f.platform, group)
		site := func(id, scope uuid.UUID) {
			display++
			exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id,node_group_id) VALUES($1,$2,$3,$4,'{203.0.113.20}','{203.0.113.20}',$3,$3,$5,$6)`,
				id, scope, f.user, "p0a-"+uuid.NewString()[:8]+".example", 97000+display, group)
		}
		site(f.siteA, f.tenantA)
		site(f.siteB, f.tenantB)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []uuid.UUID{f.tenantA, f.tenantB} {
		var carried bool
		if err := pool.QueryRow(ctx, `SELECT tenant_carries_node_287($1,$2)`, scope, f.sharedNode).Scan(&carried); err != nil || !carried {
			t.Fatalf("fixture: shared node carries %s = %t (%v), want true", scope, carried, err)
		}
	}
	return f
}

// putDenyPolicy stores tenant's enabled policy (one ANY deny) straight
// through the store's SQL path (Put).
func (f sharedNodeFixture) putDenyPolicy(t *testing.T, tenant uuid.UUID) error {
	t.Helper()
	policy := PolicyInput{Enabled: true, DefaultAction: ActionAllow, Rules: []RuleInput{{ID: uuid.New(), Priority: 1,
		Action: ActionDeny, CIDRs: []string{"192.0.2.0/24"}, Protocol: ProtocolAny}}}
	document, _ := json.Marshal(policy)
	store := NewStore(f.pool, allowAuthorizer{}, nil, time.Now)
	_, err := store.Put(t.Context(), PutRequest{
		Actor:         Actor{UserID: f.user, ScopeID: tenant, ScopeKind: ScopeTenant, Permissions: []string{PermissionManage}},
		TargetScopeID: tenant, ExpectedRevision: 0, Policy: policy, DocumentSHA256: sha256.Sum256(document),
		IdempotencyKey: "p0a-" + uuid.NewString()[:8], RequestSHA256: sha256.Sum256([]byte(uuid.NewString())),
		RequestID: uuid.NewString(),
	})
	return err
}

func (f sharedNodeFixture) project(t *testing.T) {
	t.Helper()
	projector, err := NewProjector(f.pool, fixedSigner{}, ProjectorConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projector.ProjectBatch(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// hostCommandsOn counts global (host) firewall commands queued for node, by tenant.
func (f sharedNodeFixture) hostCommandsOn(t *testing.T, node uuid.UUID) map[uuid.UUID]int {
	t.Helper()
	rows, err := f.pool.Query(t.Context(), `SELECT tenant_scope_id,count(*) FROM firewall_command_outbox
		WHERE policy_kind='global' AND node_id=$1 AND state IN ('pending','retryable','published') GROUP BY 1`, node)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := map[uuid.UUID]int{}
	for rows.Next() {
		var tenant uuid.UUID
		var count int
		if err := rows.Scan(&tenant, &count); err != nil {
			t.Fatal(err)
		}
		counts[tenant] = count
	}
	return counts
}

// A08: tenants A and B share a platform node; A's host rule must not reach
// that node, so B's traffic there is never filtered by it. Red on the old
// projector (tenant_carries_node_287 targets) and on the old Put.
func TestSharedPlatformNodeTakesNoTenantHostRule(t *testing.T) {
	f := newSharedNodeFixture(t, false)
	err := f.putDenyPolicy(t, f.tenantA)
	if !errors.Is(err, ErrSharedNodeOnly) {
		t.Fatalf("put on a tenant with only shared nodes: err=%v, want ErrSharedNodeOnly", err)
	}
	f.project(t)
	if got := f.hostCommandsOn(t, f.sharedNode); len(got) != 0 {
		t.Fatalf("shared node received tenant host commands: %v", got)
	}
}

// A owns a node and shares a platform node with B: A's host rule goes to its
// own node only.
func TestOwnedNodeStillTakesTenantHostRule(t *testing.T) {
	f := newSharedNodeFixture(t, true)
	if err := f.putDenyPolicy(t, f.tenantA); err != nil {
		t.Fatal(err)
	}
	f.project(t)
	if got := f.hostCommandsOn(t, f.sharedNode); len(got) != 0 {
		t.Fatalf("shared node received tenant host commands: %v (B is filtered by A's rule)", got)
	}
	if got := f.hostCommandsOn(t, f.ownedNodeA); got[f.tenantA] != 1 {
		t.Fatalf("owned node commands = %v, want one for tenant A", got)
	}
	var state string
	if err := f.pool.QueryRow(t.Context(), `SELECT state FROM global_firewall_publication_outbox WHERE tenant_scope_id=$1`, f.tenantA).Scan(&state); err != nil || state != "projected" {
		t.Fatalf("publication state=%q err=%v, want projected", state, err)
	}
}

// P0-a 遗留（待出包前全量跑）：A 有自有节点但没有启用的站点（平台 scope、首个站点
// 前的租户同理）。命令按 (站点, 节点) 寻址，无处可投；原来每 30 秒 retryable 永不
// 终止，现在一次终结为 failed / no_enabled_sites，策略 deployment_state=failed。
func TestHostRuleWithoutEnabledSitesSettles(t *testing.T) {
	f := newSharedNodeFixture(t, true)
	if _, err := f.pool.Exec(t.Context(), `UPDATE sites SET enabled=false,status='disabled' WHERE id=$1`, f.siteA); err != nil {
		t.Fatal(err)
	}
	if err := f.putDenyPolicy(t, f.tenantA); err != nil {
		t.Fatal(err)
	}
	f.project(t)
	var state, reason, deployment string
	if err := f.pool.QueryRow(t.Context(), `SELECT outbox.state,COALESCE(outbox.last_error,''),policy.deployment_state
		FROM global_firewall_publication_outbox outbox JOIN global_firewall_policies policy ON policy.id=outbox.policy_id
		WHERE outbox.tenant_scope_id=$1`, f.tenantA).Scan(&state, &reason, &deployment); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || reason != "no_enabled_sites" || deployment != "failed" {
		t.Fatalf("publication state=%s reason=%s deployment=%s, want failed/no_enabled_sites/failed", state, reason, deployment)
	}
	if got := f.hostCommandsOn(t, f.ownedNodeA); len(got) != 0 {
		t.Fatalf("commands without a site: %v", got)
	}
}
