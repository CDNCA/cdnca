//go:build integration

package edgepublish_test

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// After "重装此节点" the enrollment
// republishes the node's scopes; the new host has no service ticket yet and
// refuses the deployment (installation_frozen). Once its receipt says it
// serves, the scope must reach it again without anyone publishing.
func TestAutomaticScopeRefusedWhileFrozenAfterReinstallIsRedelivered(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := onlineNodes(t, scope, 1)[0]
	groupID := scope.AddStreamLineGroup(t, "198.51.100.95", nodeA)
	scope.Exec(t, `UPDATE sites SET node_group_id=$2 WHERE id=$1`, scope.SiteID, groupID)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)
	state, code := publishLineGroupChange(t, scope, worker)
	requireReconciling(t, "first publication", state, code)
	scope.SettleDeployments(t)

	// The reinstall: the node runs nothing of the scope; the enrollment
	// queues the node_sync republication (nodeidentity.resetHostDeliveryStateTx).
	scope.Exec(t, `UPDATE node_config_state SET current_config_version_id=NULL,previous_config_version_id=NULL,
		revision=revision+1,updated_at=clock_timestamp() WHERE node_id=$1`, nodeA)
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		return edgeautopublish.RepublishReinstalledNodeTx(t.Context(), tx, nodeA, []uuid.UUID{scope.ScopeID},
			"node-reinstall/"+uuid.NewString())
	}); err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("reinstall republication: worked=%v err=%v", worked, err)
	}
	reinstall := scope.LatestPublication(t)
	if reinstall.NodeIDs == nil || reinstall.NodeIDs[0] != nodeA {
		t.Fatalf("reinstall republication went to %v", reinstall.NodeIDs)
	}

	// The new host has no ticket: it refuses (edgestatus marks the refusal).
	var deploymentID uuid.UUID
	var attempt int
	if err := scope.Pool.QueryRow(t.Context(), `SELECT deployment.id,deployment.attempt FROM node_deployments deployment
		JOIN edge_config_publications publication ON publication.rollout_id=deployment.rollout_id
		WHERE publication.configuration_scope_id=$1 AND publication.source_revision=$2 AND deployment.node_id=$3`,
		scope.ScopeID, reinstall.SourceRevision, nodeA).Scan(&deploymentID, &attempt); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state='failed',updated_at=clock_timestamp()
			WHERE id=$1 AND attempt=$2`, deploymentID, attempt); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_frozen_refusals(deployment_id,attempt,node_id,
			configuration_scope_id,refused_at) VALUES($1,$2,$3,$4,clock_timestamp())`, deploymentID, attempt, nodeA, scope.ScopeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The ticket lands: the node's receipt says it serves.
	scope.Exec(t, `INSERT INTO installation_ban_node_state(node_id,revision,status,applied,updated_at,applied_revision)
		VALUES($1,1,'serving',true,clock_timestamp(),1)`, nodeA)
	store, err := nodeserving.NewStore(scope.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := nodeserving.NewFrozenRedeliveryEvaluator(store, edgeautopublish.FrozenRepublisher{}).Evaluate(t.Context()); err != nil {
		t.Fatalf("frozen redelivery: %v", err)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		state, code := latestAutomaticState(t, scope)
		t.Fatalf("redelivery: worked=%v err=%v (latest request %s/%s)", worked, err, state, code)
	}
	state, code = latestAutomaticState(t, scope)
	redelivered := scope.LatestPublication(t)
	if redelivered.SourceRevision <= reinstall.SourceRevision || redelivered.NodeIDs == nil || redelivered.NodeIDs[0] != nodeA {
		t.Fatalf("after the ticket: latest publication %d to %v (reinstall %d), request %s/%s",
			redelivered.SourceRevision, redelivered.NodeIDs, reinstall.SourceRevision, state, code)
	}
}
