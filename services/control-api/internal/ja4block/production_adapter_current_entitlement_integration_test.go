//go:build integration

package ja4block

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
)

// JA4 封禁发布目标（LoadPublicationTarget）对跟随套餐的站点按
// 当前生效权益的套餐主线取目标快照。线路 A 的快照只含甲、B 的只含乙；初购 A 目标为甲，改到 B 后为乙，
// 回切 A 又是甲。
func TestLoadPublicationTargetFollowsCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user})
	site := lines.Site("ja4-current.example.test")
	exec := func(query string, args ...any) { t.Helper(); packagelinefixture.Exec(t, pool, query, args...) }
	// Not expected in a publication (package disabled) and none exists: the site counts as synced.
	exec(`UPDATE package_subscriptions SET admin_enabled=false WHERE id=$1`, lines.Subscription)
	for _, line := range []uuid.UUID{lines.LineA, lines.LineB} {
		node, snapshot := lines.Node(line), uuid.New()
		digest := nodescheduler.CanonicalNodeSetDigest([]uuid.UUID{node})
		exec(`INSERT INTO edge_target_snapshots(id,tenant_scope_id,revision,source_line_group_id,source_revision,
			source_configuration_digest,node_set_digest,node_count,created_at) VALUES($1,$2,1,$3,1,$4,$5,1,now())`,
			snapshot, scope, line, make([]byte, 32), digest[:])
		exec(`INSERT INTO edge_target_snapshot_nodes(tenant_scope_id,snapshot_id,snapshot_revision,node_id) VALUES($1,$2,1,$3)`,
			scope, snapshot, node)
		exec(`INSERT INTO node_presence(node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,
			occurred_at,projected_at,online_since,openresty_state,firewall_state,confirmed_session_epoch,
			confirmed_heartbeat_sequence,confirmed_event_id,confirmed_request_id,confirmed_payload_digest,last_seen_at,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,active_deployments,revision,updated_at)
			VALUES($1,'online',1,1,$2,$2,$3,now(),now(),now(),'running','running',1,1,$2,$2,$3,now(),1,1,0,'[]',1,now())`,
			node, uuid.New(), make([]byte, 32))
		exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,revision,updated_at) VALUES($1,$2,1,now())`, node, scope)
	}
	resolver, err := newPostgresPublicationTargetResolver(pool, time.Now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	expect := func(step string, line uuid.UUID) {
		t.Helper()
		target, err := resolver.LoadPublicationTarget(t.Context(), scope, site)
		if err != nil || !slices.Equal(target.TargetNodeIDs, []uuid.UUID{lines.Node(line)}) {
			t.Fatalf("%s: target nodes=%v err=%v, want [%s]", step, target.TargetNodeIDs, err, lines.Node(line))
		}
	}
	expect("package A", lines.LineA)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB)
	lines.Change(lines.LineA)
	expect("back to package A", lines.LineA)
}
