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

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担：JA4 封禁发布目标
// 取平台默认线路组的目标快照；跟随套餐的网站仍取套餐主线的快照。
func TestLoadPublicationTargetPlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("ja4-community.example.test", lines.LineA)
	lines.Change(lines.LineB)
	packaged := lines.Site("ja4-packaged.example.test")
	exec := func(query string, args ...any) { t.Helper(); packagelinefixture.Exec(t, pool, query, args...) }
	// Not expected in a publication (package disabled) and none exists: the packaged site counts as synced.
	exec(`UPDATE package_subscriptions SET admin_enabled=false WHERE id=$1`, lines.Subscription)
	// The community site has no package to disable: an open domain claim
	// suspension likewise leaves it out of publications (synced).
	exec(`INSERT INTO domain_claim_suspensions(id,scope_id,site_id,canonical_domain,claimant_scope_id,claimant_user_id,
		ownership_id,request_id,created_at) VALUES($1,$2,$3,'ja4-community.example.test',$4,$5,$6,'ja4-community',now())`,
		uuid.New(), scope, community, platform, user, uuid.New())
	for _, line := range []uuid.UUID{lines.LineA, lines.LineB} {
		node, snapshot := lines.Node(line), uuid.New()
		digest := nodescheduler.CanonicalNodeSetDigest([]uuid.UUID{node})
		exec(`INSERT INTO edge_target_snapshots(id,tenant_scope_id,revision,source_line_group_id,source_revision,
			source_configuration_digest,node_set_digest,node_count,created_at) VALUES($1,$2,1,$3,1,$4,$5,1,now())`,
			snapshot, platform, line, make([]byte, 32), digest[:])
		exec(`INSERT INTO edge_target_snapshot_nodes(tenant_scope_id,snapshot_id,snapshot_revision,node_id) VALUES($1,$2,1,$3)`,
			platform, snapshot, node)
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
	for site, want := range map[uuid.UUID]uuid.UUID{community: lines.NodeJia, packaged: lines.NodeYi} {
		target, err := resolver.LoadPublicationTarget(t.Context(), scope, site)
		if err != nil || !slices.Equal(target.TargetNodeIDs, []uuid.UUID{want}) {
			t.Fatalf("site %s target nodes=%v err=%v, want [%s]", site, target.TargetNodeIDs, err, want)
		}
	}
}
