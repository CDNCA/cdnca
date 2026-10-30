//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/packageautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Opening a package puts the tenant on
// automatic publication with a policy that names no nodes (migration 457).
// A site edit then publishes on its own to the nodes of the package's
// primary line group as they are at publish time; a scope whose groups have
// no node fails with a stated reason; a manual publication of a later
// revision supersedes the queued automatic one; ending the package returns
// the tenant to manual.
func TestPackageOpenPublishesAutomaticallyToPackageLineGroup(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	store := edgeautopublish.NewStore(scope.Pool)
	worker, err := edgeautopublish.NewWorker(store, scope.AutomaticService(t, store), edgeautopublish.WorkerConfig{
		WorkerID: "autopub", LeaseDuration: time.Minute, RetryDelay: 0})
	if err != nil {
		t.Fatal(err)
	}
	ensure := func() bool {
		var changed bool
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			changed, err = packageautopublish.EnsureTx(t.Context(), tx, scope.ScopeID, scope.ScopeID, scope.UserID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if !ensure() || ensure() {
		t.Fatal("EnsureTx must write one automatic policy and keep it")
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1
		AND mode='automatic' AND cardinality(node_ids)=0 AND target_snapshot_id IS NULL AND reason='package_opened'`); got != 1 {
		t.Fatalf("package policies = %d", got)
	}

	// No line group serves the scope yet: the first automatic publication
	// ends with no_target_nodes instead of retrying as an unknown outcome.
	scope.EditOrigin(t, "198.51.100.10")
	queueSiteUpdate(t, scope)
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("worker without nodes: worked=%v err=%v", worked, err)
	}
	if state, code := latestAutomaticState(t, scope); state != edgeautopublish.StateFailed ||
		code != edgeautopublish.FailureNoTargetNodes {
		t.Fatalf("automatic request without nodes = %s/%s", state, code)
	}

	// The package's primary line group gets two nodes; the next edit goes
	// to both of them.
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	groupID := addLineGroup(t, scope, nodeA, nodeB)
	// Fixture: the site belongs to the package and the sold package carries
	// the group as its primary line (immutable once sold: the fixture
	// bypasses the triggers).
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions
			SET product_snapshot=jsonb_set(product_snapshot,'{spec,node_group_id}',to_jsonb($2::text)) WHERE id=$1`,
			scope.SubscriptionID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE sites SET package_subscription_id=$2,
			package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`,
			scope.SiteID, scope.SubscriptionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	scope.EditOrigin(t, "198.51.100.11")
	queueSiteUpdate(t, scope)
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("worker with the line group: worked=%v err=%v", worked, err)
	}
	if state, code := latestAutomaticState(t, scope); state != edgeautopublish.StateReconciling {
		t.Fatalf("automatic request with nodes = %s/%s, want reconciling", state, code)
	}
	first := scope.LatestPublication(t)
	if want := sortedNodes(nodeA, nodeB); !slices.Equal(first.NodeIDs, want) {
		t.Fatalf("automatic publication went to %v, want the line group nodes %v", first.NodeIDs, want)
	}

	// Manual and automatic publications share the scope's source revision
	// CAS: a manual publication of a newer revision supersedes the queued
	// automatic request for the older one, which never publishes.
	scope.SettleDeployments(t)
	scope.EditOrigin(t, "198.51.100.12")
	queueSiteUpdate(t, scope)
	queued := latestAutomaticRequest(t, scope)
	scope.EditOrigin(t, "198.51.100.13")
	advanceScope(t, scope)
	if err := scope.PublishManually(t, "autopub-manual", nodeA); err != nil {
		t.Fatalf("manual publication beside automatic: %v", err)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil {
		t.Fatalf("worker after manual publication: worked=%v err=%v", worked, err)
	}
	if state := automaticRequestState(t, scope, queued); state != edgeautopublish.StateSuperseded {
		t.Fatalf("queued automatic request after a newer manual publication = %s, want superseded", state)
	}
	if latest := scope.LatestPublication(t); !slices.Equal(latest.NodeIDs, []uuid.UUID{nodeA}) ||
		latest.SourceRevision <= first.SourceRevision {
		t.Fatalf("latest publication = %+v, want the manual one to node A", latest)
	}

	// The package ends: the tenant is manual again and edits wait.
	stop := func(at time.Time) bool {
		var changed bool
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			changed, err = packageautopublish.StopTx(t.Context(), tx, scope.ScopeID, scope.ScopeID, scope.UserID, at)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return changed
	}
	var endsAt time.Time
	if err := scope.Pool.QueryRow(t.Context(), `SELECT ends_at FROM package_subscriptions WHERE id=$1`,
		scope.SubscriptionID).Scan(&endsAt); err != nil {
		t.Fatal(err)
	}
	if stop(endsAt.Add(-time.Second)) {
		t.Fatal("StopTx stopped a scope whose package is still live")
	}
	if !stop(endsAt) || stop(endsAt) {
		t.Fatal("StopTx must return the scope to manual once")
	}
	requests := scope.Count(t, `SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1`)
	scope.EditOrigin(t, "198.51.100.14")
	queueSiteUpdate(t, scope)
	if got := scope.Count(t, `SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1`); got != requests {
		t.Fatalf("an edit after the package ended queued %d automatic requests", got-requests)
	}
}

// queueSiteUpdate is the automatic half of a site edit: the scope's revision
// advances and a site.update request is queued through the scope's policy.
func queueSiteUpdate(t *testing.T, scope *edgepublish.SystemRepublishScope) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, scope.ScopeID); err != nil {
			return err
		}
		_, err := edgeautopublish.EnqueueSiteSettingTx(t.Context(), tx, scope.ScopeID, scope.SiteID, "autopub-"+uuid.NewString())
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func advanceScope(t *testing.T, scope *edgepublish.SystemRepublishScope) {
	t.Helper()
	scope.Exec(t, `SELECT advance_edge_configuration_scope_revision($1)`, scope.ScopeID)
}

func addLineGroup(t *testing.T, scope *edgepublish.SystemRepublishScope, nodes ...uuid.UUID) uuid.UUID {
	t.Helper()
	groupID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'autopub-group',1,$3,$3,now(),now())`,
			groupID, scope.ScopeID, scope.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,
			resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,
			recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			VALUES($1,$2,1,'autopub-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,$3,$4,$5,now())`,
			groupID, scope.ScopeID, len(nodes), make([]byte, 32), scope.UserID); err != nil {
			return err
		}
		for index, nodeID := range nodes {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,
				config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
				VALUES($1,$2,$3,$4,1,$5::inet,4,443,'','',0,1,true)`, uuid.New(), nodeID, scope.ScopeID, groupID,
				[]string{"192.0.2.71", "192.0.2.72", "192.0.2.73"}[index]); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,
			endpoint_id,status,consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now()
			FROM node_line_endpoints WHERE tenant_scope_id=$1 AND line_group_id=$2`, scope.ScopeID, groupID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=now()
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=1`, scope.ScopeID, groupID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return groupID
}

func latestAutomaticRequest(t *testing.T, scope *edgepublish.SystemRepublishScope) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := scope.Pool.QueryRow(t.Context(), `SELECT id FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 ORDER BY source_revision DESC,created_at DESC LIMIT 1`, scope.ScopeID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func automaticRequestState(t *testing.T, scope *edgepublish.SystemRepublishScope, requestID uuid.UUID) string {
	t.Helper()
	var state string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT state FROM edge_automatic_publication_request_state_facts
		WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1`, requestID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func latestAutomaticState(t *testing.T, scope *edgepublish.SystemRepublishScope) (string, string) {
	t.Helper()
	var state string
	var code *string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT state.state,state.terminal_code
		FROM edge_automatic_publication_request_state_facts state
		WHERE state.request_id=$1 ORDER BY state.sequence DESC LIMIT 1`, latestAutomaticRequest(t, scope)).
		Scan(&state, &code); err != nil {
		t.Fatal(err)
	}
	if code == nil {
		return state, ""
	}
	return state, *code
}
