package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FX02: adding a node to a line group a site uses must publish the scope to
// the new node without anyone publishing by hand.
func TestLineGroupNodeAdditionRepublishesAutomaticScope(t *testing.T) {
	fixture := newLineGroupPublicationFixture(t)
	ctx, pool, scheduler, schedulerActor := fixture.ctx, fixture.pool, fixture.scheduler, fixture.actor
	group, oldEndpoint, oldNode, newNode, otherNode := fixture.group, fixture.oldEndpoint, fixture.oldNode, fixture.newNode, fixture.otherNode
	sourceRevision := fixture.sourceRevision
	lineRequests := func() int {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM edge_automatic_publication_requests
			WHERE target_scope_id=$1 AND source_kind='line_group' AND source_resource_id=$2`, fixture.scopeID, group.Group.GroupID).
			Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	// A weight-only edit changes no node: nothing is republished.
	before := sourceRevision()
	weighted := oldEndpoint
	weighted.Weight = 5
	group, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{
		GroupID: group.Group.GroupID, ExpectedRevision: group.Group.Revision, Name: "line",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{weighted},
		IdempotencyKey: "line-group-2", RequestID: "line-group-2",
	})
	if err != nil || sourceRevision() != before || lineRequests() != 0 {
		t.Fatalf("weight edit republished: %v revision %d->%d requests=%d", err, before, sourceRevision(), lineRequests())
	}

	// Adding a node advances the revision and queues one automatic request.
	added := []nodescheduler.Endpoint{weighted,
		{ID: uuid.New(), NodeID: newNode, Address: "192.0.2.42", Port: 80, Weight: 1, Enabled: true}}
	addRequest := nodescheduler.PutGroupRequest{
		GroupID: group.Group.GroupID, ExpectedRevision: group.Group.Revision, Name: "line",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: added,
		IdempotencyKey: "line-group-3", RequestID: "line-group-3",
	}
	group, err = scheduler.PutGroup(ctx, schedulerActor, addRequest)
	if err != nil || sourceRevision() != before+1 || lineRequests() != 1 {
		t.Fatalf("node addition: %v revision %d->%d requests=%d", err, before, sourceRevision(), lineRequests())
	}
	// Replaying the write neither advances nor queues again.
	if replay, err := scheduler.PutGroup(ctx, schedulerActor, addRequest); err != nil || !replay.Replayed ||
		sourceRevision() != before+1 || lineRequests() != 1 {
		t.Fatalf("replay republished: %v replayed=%v requests=%d", err, replay.Replayed, lineRequests())
	}
	var payload map[string]any
	if err := pool.QueryRow(ctx, `SELECT payload FROM audit_events WHERE action='node_scheduling.group.update'
		AND request_id='line-group-3'`).Scan(&payload); err != nil || payload["automatic_publications"] != float64(1) {
		t.Fatalf("audit payload = %v (%v)", payload, err)
	}

	// The worker publishes to the group's current nodes, not the policy's frozen list.
	autoStore := edgeautopublish.NewStore(pool)
	claim, found, err := autoStore.Claim(ctx, "line-worker", time.Minute)
	if err != nil || !found || claim.Request.SourceKind != edgeautopublish.SourceLineGroup {
		t.Fatalf("claim = %+v found=%v err=%v", claim.Request, found, err)
	}
	var nodes []uuid.UUID
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		prepared, err := autoStore.PrepareAutomaticPublication(ctx, tx, edgepublish.AutomaticClaimReference{
			RequestID: claim.Request.ID, LeaseToken: claim.LeaseToken, StateSequence: claim.StateSequence})
		nodes = prepared.Request.NodeIDs
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || !containsNode(nodes, oldNode) || !containsNode(nodes, newNode) || containsNode(nodes, otherNode) {
		t.Fatalf("publication nodes = %v, want old %s and new %s", nodes, oldNode, newNode)
	}
}

func containsNode(nodes []uuid.UUID, want uuid.UUID) bool {
	for _, node := range nodes {
		if node == want {
			return true
		}
	}
	return false
}

// NF04: a node held for failed sync gets its scope republished, at most once
// per retry window.
func TestNodeSyncRetrierQueuesOneRetryPerWindow(t *testing.T) {
	fixture := newLineGroupPublicationFixture(t)
	retrier := edgeautopublish.NewNodeSyncRetrier(fixture.pool)
	window := time.Now().Add(-30 * time.Minute)
	before := fixture.sourceRevision()
	queued, err := retrier.RetryNodeSync(fixture.ctx, fixture.oldNode, fixture.scopeID, window)
	if err != nil || !queued || fixture.sourceRevision() != before+1 {
		t.Fatalf("first retry: queued=%v err=%v revision %d->%d", queued, err, before, fixture.sourceRevision())
	}
	if queued, err := retrier.RetryNodeSync(fixture.ctx, fixture.oldNode, fixture.scopeID, window); err != nil || queued ||
		fixture.sourceRevision() != before+1 {
		t.Fatalf("second retry inside the window: queued=%v err=%v", queued, err)
	}
	var kind, operation string
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT source_kind,operation FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_resource_id=$2`, fixture.scopeID, fixture.oldNode).Scan(&kind, &operation); err != nil ||
		kind != edgeautopublish.SourceNodeSync || operation != edgeautopublish.OperationNodeSyncRetry {
		t.Fatalf("retry request = %s %s (%v)", kind, operation, err)
	}
}

// A scope without an automatic policy gets the same republication
// through the system channel, with the advance attributed to the trigger.
func TestLineGroupNodeAdditionAndSyncRetryQueueManualScope(t *testing.T) {
	fixture := newLineGroupPublicationFixtureMode(t, false)
	ctx, pool := fixture.ctx, fixture.pool
	count := func(query string, args ...any) int {
		t.Helper()
		var value int
		if err := pool.QueryRow(ctx, query, append([]any{fixture.scopeID}, args...)...).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := fixture.sourceRevision()
	added := []nodescheduler.Endpoint{fixture.oldEndpoint,
		{ID: uuid.New(), NodeID: fixture.newNode, Address: "192.0.2.42", Port: 80, Weight: 1, Enabled: true}}
	if _, err := fixture.scheduler.PutGroup(ctx, fixture.actor, nodescheduler.PutGroupRequest{
		GroupID: fixture.group.Group.GroupID, ExpectedRevision: fixture.group.Group.Revision, Name: "line",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: added, IdempotencyKey: "manual-line", RequestID: "manual-line",
	}); err != nil {
		t.Fatal(err)
	}
	if fixture.sourceRevision() != before+1 ||
		count(`SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1 AND state='pending'
			AND triggers=ARRAY['line_group']`) != 1 ||
		count(`SELECT count(*) FROM edge_system_revision_segments WHERE scope_id=$1 AND source='line_group'
			AND from_revision=$2 AND to_revision=$3`, before, before+1) != 1 ||
		count(`SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1`) != 0 {
		t.Fatal("line group node addition did not queue the manual scope's system republication")
	}
	retrier := edgeautopublish.NewNodeSyncRetrier(pool)
	window := time.Now().Add(-30 * time.Minute)
	if queued, err := retrier.RetryNodeSync(ctx, fixture.oldNode, fixture.scopeID, window); err != nil || !queued {
		t.Fatalf("manual sync retry: queued=%v err=%v", queued, err)
	}
	if queued, err := retrier.RetryNodeSync(ctx, fixture.oldNode, fixture.scopeID, window); err != nil || queued {
		t.Fatalf("second manual sync retry inside the window: queued=%v err=%v", queued, err)
	}
	if count(`SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
			AND triggers=ARRAY['line_group','node_sync'] AND generation=2`) != 1 ||
		count(`SELECT count(*) FROM edge_system_revision_segments WHERE scope_id=$1 AND source='node_sync'`) != 1 {
		t.Fatal("sync retry was not merged into the manual scope's system republication")
	}
}

type lineGroupPublicationFixture struct {
	t                           *testing.T
	ctx                         context.Context
	pool                        *pgxpool.Pool
	scopeID                     uuid.UUID
	scheduler                   *nodescheduler.Service
	actor                       nodescheduler.Actor
	group                       nodescheduler.WriteResult
	oldEndpoint                 nodescheduler.Endpoint
	oldNode, newNode, otherNode uuid.UUID
}

// newLineGroupPublicationFixture: one automatic tenant scope with a site on a
// one-node line group, its policy naming only that node.
func newLineGroupPublicationFixture(t *testing.T) *lineGroupPublicationFixture {
	t.Helper()
	return newLineGroupPublicationFixtureMode(t, true)
}

func newLineGroupPublicationFixtureMode(t *testing.T, automatic bool) *lineGroupPublicationFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "line_group_publish_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") })
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "line-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "line-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Line tenant", "line-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "line-site-owner",
		"sites.manage", "dns.manage", "node_scheduling.manage")
	oldNode, newNode, otherNode := uuid.New(), uuid.New(), uuid.New()
	for index, id := range []uuid.UUID{oldNode, newNode, otherNode} {
		// A node-bound endpoint must use the node's own IP: .41, .42, .43.
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,$3,'active',$4,$5,$6)`,
			id, tenant.scopeID, id.String(), tenant.userID, index+1, "192.0.2.4"+string(rune('1'+index)))
	}
	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
	scheduler.SetPublicationTrigger(edgeautopublish.LineGroupPublisher{})
	schedulerActor := nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	oldEndpoint := nodescheduler.Endpoint{ID: uuid.New(), NodeID: oldNode, Address: "192.0.2.41", Port: 80, Weight: 1, Enabled: true}
	group, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{
		Name: "line", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{oldEndpoint},
		IdempotencyKey: "line-group-1", RequestID: "line-group-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	productID := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 100, 1000)
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(ctx, manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 3, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "line-subscription", RequestID: "line-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Opening the package turned on automatic publication (migration 457);
	// a manual scope switches it back before its site is created.
	if !automatic {
		exec(`INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,
		reason,created_at) SELECT $1,COALESCE(max(revision),0)+1,'manual','{}',30000,15000,2,3,600,$1,$2,'line_group_test',
		clock_timestamp() FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`, tenant.scopeID, tenant.userID)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	if _, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "line-site", RequestID: "line-site",
			Fields: SiteFields{Domains: []string{"line.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled,
				NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID}}); err != nil {
		t.Fatal(err)
	}
	// The scope publishes automatically; its policy names only the old node.
	if automatic {
		exec(`INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,
		reason,created_at) SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,30000,15000,2,3,600,$1,$3,'line_group_test',clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
			tenant.scopeID, []uuid.UUID{oldNode}, tenant.userID)
	}
	return &lineGroupPublicationFixture{t: t, ctx: ctx, pool: pool, scopeID: tenant.scopeID, scheduler: scheduler,
		actor: schedulerActor, group: group, oldEndpoint: oldEndpoint, oldNode: oldNode, newNode: newNode, otherNode: otherNode}
}

func (fixture *lineGroupPublicationFixture) sourceRevision() int64 {
	fixture.t.Helper()
	var revision int64
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		fixture.scopeID).Scan(&revision); err != nil {
		fixture.t.Fatal(err)
	}
	return revision
}

// The scope's automatic publication carries its line group's L2
// configuration, so (a) naming another configuration on the line group, and
// (b) writing the configuration (here: adding a member) republish the using
// scope, and (c) the configuration's members join the publication targets.
func TestLineGroupL2ConfigRepublishesAndTargetsItsMembers(t *testing.T) {
	fixture := newLineGroupPublicationFixture(t)
	ctx, pool, scheduler, actor := fixture.ctx, fixture.pool, fixture.scheduler, fixture.actor
	requests := func(kind string) int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM edge_automatic_publication_requests
			WHERE target_scope_id=$1 AND source_kind=$2`, fixture.scopeID, kind).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	config, err := scheduler.PutL2Config(ctx, actor, nodescheduler.L2ConfigWriteRequest{
		Name: "l2", Mode: nodescheduler.L2ModeGlobal, LoadMethod: nodescheduler.L2LoadRoundRobin,
		IdempotencyKey: "autol2-config", RequestID: "autol2-config",
	})
	if err != nil {
		t.Fatal(err)
	}
	// (a) the line group names the configuration: same nodes, still republished
	before, lineBefore := fixture.sourceRevision(), requests(edgeautopublish.SourceLineGroup)
	_, err = scheduler.PutGroup(ctx, actor, nodescheduler.PutGroupRequest{
		GroupID: fixture.group.Group.GroupID, ExpectedRevision: fixture.group.Group.Revision, Name: "line",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{fixture.oldEndpoint},
		L2ConfigID: &config.Config.ID, IdempotencyKey: "autol2-group", RequestID: "autol2-group",
	})
	if err != nil || fixture.sourceRevision() <= before || requests(edgeautopublish.SourceLineGroup) != lineBefore+1 {
		t.Fatalf("l2_config_id change: %v revision %d->%d line requests %d->%d", err, before, fixture.sourceRevision(),
			lineBefore, requests(edgeautopublish.SourceLineGroup))
	}
	// (b) adding a member republishes the scope using the line group
	before = fixture.sourceRevision()
	if _, err := scheduler.AddL2Nodes(ctx, actor, nodescheduler.L2NodeAddRequest{ConfigID: config.Config.ID,
		NodeIDs: []uuid.UUID{fixture.newNode}, IdempotencyKey: "autol2-member", RequestID: "autol2-member"}); err != nil {
		t.Fatal(err)
	}
	if fixture.sourceRevision() <= before {
		t.Fatalf("L2 member write did not advance the using scope: %d -> %d", before, fixture.sourceRevision())
	}
	// (c) the automatic publication targets the line group node and the L2 member
	var nodes []uuid.UUID
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		nodes, err = edgeautopublish.ScopeTargetNodeIDsTx(ctx, tx, fixture.scopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !containsNode(nodes, fixture.oldNode) || !containsNode(nodes, fixture.newNode) || containsNode(nodes, fixture.otherNode) {
		t.Fatalf("targets %v: want line node %s and L2 member %s", nodes, fixture.oldNode, fixture.newNode)
	}
}
