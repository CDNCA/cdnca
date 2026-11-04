package nodeserving

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// After "重装此节点" a deployment of the previous host held
// the node (node already has an active deployment) until its deadline; an
// activated or reverting one would have held it forever (no timeout, only the
// node's report ends it). A reinstall ends every running deployment created
// before the node's newest enrollment as failed (host_replaced, migration
// 627), so the new host's deployment can be queued at once. A node enrolled
// once, and a deployment created after the newest enrollment, are left alone.
func TestReinstallEndsPreviousHostDeployments(t *testing.T) {
	harness := newServingHarness(t)
	started, activated, reverting, overdue, enrolledOnce := harness.addNode(), harness.addNode(), harness.addNode(),
		harness.addNode(), harness.addNode()
	for _, nodeID := range []uuid.UUID{started, activated, reverting, overdue, enrolledOnce} {
		seedServingNodeEnrollment(t, harness, nodeID)
	}
	deployments := map[string]timeoutDeployment{
		"started":       harness.deployV1(started, "started", "pending", -time.Hour),
		"activated":     harness.deployV1(activated, "activated", "published", -time.Hour),
		"reverting":     harness.deployV1(reverting, "reverting", "published", -time.Hour),
		"overdue":       harness.deployV1(overdue, "staged", "published", time.Hour),
		"enrolled once": harness.deployV1(enrolledOnce, "started", "published", -time.Hour),
	}
	for _, nodeID := range []uuid.UUID{started, activated} {
		if err := harness.insertNextDeployment(nodeID); !activeIndexConflict(err) {
			t.Fatalf("next deployment before the reinstall: %v, want the one-active-per-node-scope conflict", err)
		}
	}
	// No fact, no failure: the 627 state machine still refuses it.
	if _, err := harness.pool.Exec(harness.ctx, `UPDATE node_deployments SET state='failed' WHERE id=$1`,
		deployments["activated"].id); err == nil {
		t.Fatal("an activated deployment failed without a host replacement fact")
	}

	closed := map[uuid.UUID]int{}
	for _, nodeID := range []uuid.UUID{started, activated, reverting, overdue} {
		seedServingNodeEnrollment(t, harness, nodeID) // the reinstall
		closed[nodeID] = closeReplacedHost(t, harness, nodeID)
	}
	closed[enrolledOnce] = closeReplacedHost(t, harness, enrolledOnce)
	for name, test := range map[string]struct {
		nodeID        uuid.UUID
		state, outbox string
		closed        int
	}{
		"started":       {started, "failed", "cancelled", 1},
		"activated":     {activated, "failed", "published", 1},
		"reverting":     {reverting, "failed", "published", 1},
		"overdue":       {overdue, "failed", "published", 1},
		"enrolled once": {enrolledOnce, "started", "published", 0},
	} {
		state, outbox, timedOut := harness.deploymentState(deployments[name])
		var previous string
		err := harness.pool.QueryRow(harness.ctx, `SELECT previous_state FROM node_deployment_host_replacements
			WHERE deployment_id=$1 AND reason_code='host_replaced'`, deployments[name].id).Scan(&previous)
		replaced := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		if state != test.state || outbox != test.outbox || timedOut || replaced != (test.closed == 1) ||
			closed[test.nodeID] != test.closed {
			t.Errorf("%s: state=%s outbox=%s timed out=%v replaced=%v (%s) closed=%d, want %s %s replaced=%v closed=%d",
				name, state, outbox, timedOut, replaced, previous, closed[test.nodeID], test.state, test.outbox,
				test.closed == 1, test.closed)
		}
	}
	// The new host's deployment is queued at once.
	for _, nodeID := range []uuid.UUID{started, activated, reverting, overdue} {
		if err := harness.insertNextDeployment(nodeID); err != nil {
			t.Fatalf("next deployment after the reinstall: %v", err)
		}
	}
	// The new host's own running deployment is not a previous host's.
	if count := closeReplacedHost(t, harness, started); count != 0 {
		t.Fatalf("closing again ended %d deployments of the current host", count)
	}
	// A fact must name the node's newest enrollment.
	stale := harness.addNode()
	seedServingNodeEnrollment(t, harness, stale)
	seedServingNodeEnrollment(t, harness, stale)
	previousHost := harness.deployV1(stale, "activated", "published", -time.Hour)
	var oldest uuid.UUID
	if err := harness.pool.QueryRow(harness.ctx, `SELECT id FROM node_certificates WHERE node_id=$1
		ORDER BY issued_at LIMIT 1`, stale).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	_, err := harness.pool.Exec(harness.ctx, `INSERT INTO node_deployment_host_replacements(deployment_id,attempt,
		previous_state,reason_code,node_id,certificate_id,replaced_at) VALUES($1,1,'activated','host_replaced',$2,$3,clock_timestamp())`,
		previousHost.id, stale, oldest)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P6273" {
		t.Fatalf("host replacement naming an older enrollment = %v, want P6273", err)
	}
}

func closeReplacedHost(t *testing.T, harness *servingHarness, nodeID uuid.UUID) int {
	t.Helper()
	var closed int
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		var err error
		closed, err = edgedeployment.CloseReplacedHostDeploymentsTx(harness.ctx, tx, nodeID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return closed
}
