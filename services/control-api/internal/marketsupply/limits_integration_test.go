//go:build integration

package marketsupply

import (
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type limitsRow struct {
	nodes                                            int
	requests, bandwidth, connections, newPerSec, qps int64
	stopped                                          bool
	holdAction                                       *string
}

func loadLimits(t *testing.T, svc *Service, subscription uuid.UUID) limitsRow {
	t.Helper()
	var row limitsRow
	if err := svc.pool.QueryRow(t.Context(), `SELECT serving_nodes,node_requests,node_bandwidth_bps,node_connections,
		node_new_per_second,node_qps,node_stopped,hold_action FROM market_supply_limits WHERE package_subscription_id=$1`,
		subscription).Scan(&row.nodes, &row.requests, &row.bandwidth, &row.connections, &row.newPerSec, &row.qps,
		&row.stopped, &row.holdAction); err != nil {
		t.Fatal(err)
	}
	return row
}

// threeNodeLineGroup is insertLineGroup with three endpoint nodes, the last
// two held out of serving (availability monitor): one serving node.
func threeNodeLineGroup(t *testing.T, svc *Service, scope, user uuid.UUID) (uuid.UUID, []uuid.UUID) {
	t.Helper()
	group := uuid.New()
	name := "market-pool3-" + group.String()[:8]
	nodes := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	err := pgx.BeginFunc(t.Context(), svc.pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			  VALUES($1,$2,$3,1,$4,$4,now(),now())`, []any{group, scope, name, user}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			  failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			  VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,3,$4,$5,now())`, []any{group, scope, name, make([]byte, 32), user}},
		}
		for index, node := range nodes {
			endpoint := uuid.New()
			statements = append(statements,
				struct {
					query string
					args  []any
				}{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
				  VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`, []any{node, scope, "n-" + node.String()[:8], user}},
				struct {
					query string
					args  []any
				}{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				  VALUES($1,$2,$3,$4,1,$5,4,443,'','',0,1,true)`, []any{endpoint, node, scope, group, fmt.Sprintf("192.0.2.%d", 81+index)}},
				struct {
					query string
					args  []any
				}{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
				  consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
				  VALUES($1,$2,1,$3,'unknown',0,0,0,now(),1,now(),now())`, []any{scope, group, endpoint}})
			if index > 0 {
				statements = append(statements, struct {
					query string
					args  []any
				}{`INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
				  VALUES($1,'availability_monitor',true,'test_down',1,now(),now(),now())`, []any{node}})
			}
		}
		statements = append(statements, struct {
			query string
			args  []any
		}{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2`, []any{scope, group}})
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return group, nodes[1:]
}

// ADR 0012 ML-08 acceptance: grant v2 limits land as per node shares
// ceil(total / serving nodes); a node count change re-splits and republishes
// once; a stop hold stops the nodes and its release restores them; an
// unreachable market (nil holds) keeps the last hold; nothing changes, no
// republication.
func TestMarketLimitsShareHoldAndRepublish(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, time.Now)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID, held := threeNodeLineGroup(t, svc, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New(), uuid.New()}, NodePoolRef: poolID.String(),
		Limits: spec.LimitSet{
			{Metric: spec.MetricDomains, Cap: 5, Action: spec.ActionRejectNew},
			{Metric: spec.MetricBandwidthPeakBPS, Cap: 100_000_001, Action: spec.ActionThrottle, SustainBuckets: 2},
			{Metric: spec.MetricMonthlyTrafficBytes, Cap: 1 << 40, Action: spec.ActionThrottle, ThrottleBPS: 8_000_000},
			{Metric: spec.MetricConcurrentConnections, Cap: 10, Action: spec.ActionThrottle, SustainBuckets: 2},
			{Metric: spec.MetricConcurrentRequests, Cap: 7, Action: spec.ActionThrottle, SustainBuckets: 2},
			{Metric: spec.MetricNewConnectionsPerSecond, Cap: 5, Action: spec.ActionPause, SustainBuckets: 2},
			{Metric: spec.MetricQPS, Cap: 101, Action: spec.ActionStop, SustainBuckets: 2},
		},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	out := mustSync(t, svc, g)
	if out[0].Action != "opened" {
		t.Fatalf("sync %+v", out[0])
	}
	sub, tenant := out[0].SubscriptionID, out[0].TenantScopeID
	// One node: the totals; the product's connections are the request budget.
	if got := loadLimits(t, svc, sub); got.nodes != 1 || got.requests != 7 || got.bandwidth != 100_000_001 ||
		got.connections != 10 || got.newPerSec != 5 || got.qps != 101 || got.stopped || got.holdAction != nil {
		t.Fatalf("one node %+v", got)
	}
	var connections int64
	if err := pool.QueryRow(ctx, `SELECT (product_snapshot#>>'{spec,limits,connections}')::bigint FROM package_subscriptions
		WHERE id=$1`, sub).Scan(&connections); err != nil || connections != 7 {
		t.Fatalf("product connections %d %v (no -1 hardcode)", connections, err)
	}

	// A site of the subscription, so changes republish it.
	var owner uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, tenantPrefix+out[0].Key).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	site := uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,package_subscription_id,package_id) VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM sites),
			$2,$3,'limits.market.example.test',ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3,$4,
			(SELECT product_id FROM package_subscriptions WHERE id=$4))`, site, tenant, owner, sub)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,level) VALUES($1,1,'192.0.2.10',80,0)`, site)
		return err
	}); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	// The market tenant publishes automatically (ensureDelivery): one
	// automatic site.update request per change; a manual scope would get a
	// market_limits system republication instead.
	heads := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM edge_system_republication_heads
				WHERE scope_id=$1 AND 'market_limits'=ANY(triggers)) +
			(SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1 AND operation='site.update'
				AND source_request_id LIKE 'market-limits:%')`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	siteRevision := func() int64 {
		t.Helper()
		var r int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM sites WHERE id=$1`, site).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := siteRevision()
	// Nothing changed: no republication.
	if n, err := svc.RefreshLimits(ctx, map[string]Hold{}); err != nil || n != 0 || heads() != 0 || siteRevision() != before {
		t.Fatalf("unchanged refresh republished: %d %v", n, err)
	}

	// Three serving nodes: ceil shares, one republication.
	exec(t, pool, `UPDATE node_serving_holds SET held=false, held_since=NULL, revision=2 WHERE node_id = ANY($1)`, held)
	if n, err := svc.RefreshLimits(ctx, map[string]Hold{}); err != nil || n != 1 {
		t.Fatalf("node change %d %v", n, err)
	}
	if got := loadLimits(t, svc, sub); got.nodes != 3 || got.requests != 3 || got.bandwidth != 33_333_334 ||
		got.connections != 4 || got.newPerSec != 2 || got.qps != 34 || got.stopped {
		t.Fatalf("three nodes %+v", got)
	}
	if heads() != 1 || siteRevision() != before+1 {
		t.Fatalf("republish heads %d site revision %d->%d", heads(), before, siteRevision())
	}

	// Stop hold: nodes stop; an unreachable market keeps it; release restores.
	key := Key(g)
	if n, err := svc.RefreshLimits(ctx, map[string]Hold{key: {Action: "stop", Revision: 5}}); err != nil || n != 1 {
		t.Fatalf("stop %d %v", n, err)
	}
	if got := loadLimits(t, svc, sub); !got.stopped || got.holdAction == nil || *got.holdAction != "stop" || got.qps != 34 {
		t.Fatalf("stopped %+v", got)
	}
	if n, err := svc.RefreshLimits(ctx, nil); err != nil || n != 0 || !loadLimits(t, svc, sub).stopped {
		t.Fatalf("market unreachable must keep the stop: %d %v", n, err)
	}
	// A grant resync keeps the hold too.
	mustSync(t, svc, g)
	if !loadLimits(t, svc, sub).stopped {
		t.Fatal("grant sync dropped the hold")
	}
	// Pause: nodes serve (DNS only); throttle: bandwidth throttle_bps / nodes.
	if _, err := svc.RefreshLimits(ctx, map[string]Hold{key: {Action: "pause", Revision: 6}}); err != nil {
		t.Fatal(err)
	}
	if got := loadLimits(t, svc, sub); got.stopped || got.bandwidth != 33_333_334 {
		t.Fatalf("pause %+v", got)
	}
	if _, err := svc.RefreshLimits(ctx, map[string]Hold{key: {Action: "throttle", ThrottleBPS: 8_000_000, Revision: 7}}); err != nil {
		t.Fatal(err)
	}
	if got := loadLimits(t, svc, sub); got.bandwidth != 2_666_667 || got.stopped {
		t.Fatalf("throttle %+v", got)
	}
	if _, err := svc.RefreshLimits(ctx, map[string]Hold{}); err != nil {
		t.Fatal(err)
	}
	if got := loadLimits(t, svc, sub); got.stopped || got.holdAction != nil || got.bandwidth != 33_333_334 {
		t.Fatalf("released %+v", got)
	}
}
