//go:build integration

package edgepublish

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

// a market site (a leaf tenant site on the seller's
// hidden supply group) following the package's L2 goes through the L2
// configuration the seller names on that supply group: the publication to
// the seller's L1 node carries the L2 pool of the seller's L2 node. Without
// a configuration, or with the site's L2 off, the site goes straight to the
// origin.
func TestMarketSupplyGroupL2ReachesTheSellersNodes(t *testing.T) {
	fixture := newPublishFixture(t)
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := fixture.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	l1, l2 := uuid.New(), uuid.New()
	features := append(v2DefaultNodeFeatures(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L2_ROUTING, ApiVersion: edgeconfig.L2RoutingAPIVersion})
	keys := map[uuid.UUID][]byte{}
	for index, node := range []uuid.UUID{l1, l2} {
		insertPublishNode(t, fixture.pool, fixture.platformScopeID, fixture.platformUserID, node, "supply-l2-"+node.String()[:8])
		exec(`UPDATE nodes SET ipv4=$2::inet WHERE id=$1`, node, []string{"203.0.113.71", "203.0.113.72"}[index])
		keys[node] = capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.platformScopeID, fixture.platformUserID,
			node, &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "supply-l2", OperatingSystem: "linux", Architecture: "amd64",
				Features: features}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey
		fixture.nodeKeys[node] = keys[node]
	}
	// The seller's own L2 configuration, with a region (a supply group has
	// none: migration 629 lets it name any of the scope's configurations).
	config := uuid.New()
	exec(`INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,
		created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'卖家 L2','华南','global','rr',$3,$3,$4,$4)`,
		config, fixture.platformScopeID, fixture.platformUserID, publishTestClock.Add(-time.Hour))
	exec(`INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$5,$6,$6)`, uuid.New(), fixture.platformScopeID, config, l2, fixture.platformUserID, publishTestClock.Add(-time.Hour))
	// The seller (platform.admin) writes the hidden supply group with the L1 node.
	exec(`INSERT INTO role_permissions(role_id,permission_name)
		SELECT assignment.role_id,'platform.admin' FROM role_assignments assignment
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 ON CONFLICT DO NOTHING`, fixture.platformScopeID, fixture.platformUserID)
	scheduler := nodescheduler.NewService(fixture.pool, time.Now)
	actor := nodescheduler.Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: "platform"}
	group := uuid.New()
	put := func(revision int64, configID *uuid.UUID, key string) {
		t.Helper()
		if _, err := scheduler.PutMarketSupplyGroup(ctx, actor, nodescheduler.PutGroupRequest{GroupID: group, ExpectedRevision: revision,
			Name: "市场供给 supply-l2", Endpoints: []nodescheduler.Endpoint{{ID: uuid.NewSHA1(group, l1[:]), NodeID: l1, Address: "203.0.113.71",
				Port: 443, Weight: 100, Enabled: true}}, L2ConfigID: configID, IdempotencyKey: key, RequestID: key}); err != nil {
			t.Fatalf("supply group %s: %v", key, err)
		}
	}
	put(0, &config, "supply-l2-group-1")
	site := fixture.createSite(t, "supply-l2-market.example.com", 80, false).Site
	exec(`UPDATE sites SET node_group_id=$2 WHERE id=$1`, site.ID, group)

	publishSite := func(key string) *edgesite.Site {
		t.Helper()
		request := fixture.publishRequest(key, l1)
		request.NodeIDs = []uuid.UUID{l1, l2}
		result, err := fixture.service.Publish(ctx, request)
		if err != nil {
			t.Fatalf("publish %s: %v", key, err)
		}
		release := receivedV2Release(t, fixture, result, l1, keys[l1])
		for index := range release.Sites {
			if release.Sites[index].SiteID == site.ID.String() {
				return &release.Sites[index]
			}
		}
		t.Fatalf("%s: L1 release has no site %s", key, site.ID)
		return nil
	}
	got := publishSite("supply-l2-with-l2").Origin
	if got.L2 == nil {
		t.Fatalf("market site origin %+v, want the seller's L2", got)
	}
	pool := slices.IndexFunc(got.Pools, func(p edgesite.Pool) bool { return p.Kind == edgesite.PoolL2 })
	if pool < 0 || got.DefaultPoolID != got.Pools[pool].ID || len(got.Pools[pool].Endpoints) != 1 ||
		got.Pools[pool].Endpoints[0].NodeID != l2.String() {
		t.Fatalf("origin pools %+v default %q, want the seller's L2 node %s", got.Pools, got.DefaultPoolID, l2)
	}

	// The buyer turned L2 off (siteconf l2_off), or the seller cleared the
	// supply's L2: the publication's topology has no L2 for the site.
	siteL2 := func() *L2TopologySnapshot {
		t.Helper()
		tx, err := fixture.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		facts, err := loadSiteFacts(ctx, tx, fixture.scopeID)
		if err != nil {
			t.Fatal(err)
		}
		topology, _, err := siteL2PublicationTopology(ctx, tx, fixture.scopeID, fixture.sourceRevision(), facts,
			[]uuid.UUID{l1, l2}, publishTestClock)
		if err != nil {
			t.Fatal(err)
		}
		if topology == nil {
			return nil
		}
		return topology.Sites[site.ID]
	}
	if got := siteL2(); got == nil || len(got.Endpoints) != 1 || got.Endpoints[0].NodeID != l2 || got.SourceLineGroupID != group {
		t.Fatalf("package mode topology %+v", got)
	}
	exec(`UPDATE site_origin_pools SET l2_mode='off' WHERE site_id=$1`, site.ID)
	if got := siteL2(); got != nil {
		t.Fatalf("L2 off: site L2 %+v", got)
	}
	exec(`UPDATE site_origin_pools SET l2_mode='package' WHERE site_id=$1`, site.ID)
	put(1, nil, "supply-l2-group-2")
	if got := siteL2(); got != nil {
		t.Fatalf("supply without L2: site L2 %+v", got)
	}
}
