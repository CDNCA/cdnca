//go:build integration

package nodeserving

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordingRetrier records the node_sync republications asked for.
type recordingRetrier struct{ calls [][2]uuid.UUID }

func (retrier *recordingRetrier) RetryNodeSync(_ context.Context, nodeID, scopeID uuid.UUID, _ time.Time) (bool, error) {
	retrier.calls = append(retrier.calls, [2]uuid.UUID{nodeID, scopeID})
	return true, nil
}

// backdate moves all of the node's enrollments back by enrollmentAgo and sets its
// deployments' creation deploymentAgo before now (seeded as a
// replica: the fact triggers are not under test here).
func (harness *servingHarness) backdate(nodeID uuid.UUID, enrollmentAgo, deploymentAgo time.Duration) {
	harness.t.Helper()
	if err := pgx.BeginFunc(harness.ctx, harness.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(harness.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if enrollmentAgo > 0 {
			if _, err := tx.Exec(harness.ctx, `UPDATE node_certificates SET issued_at=issued_at-$2::interval WHERE node_id=$1`,
				nodeID, enrollmentAgo.String()); err != nil {
				return err
			}
		}
		_, err := tx.Exec(harness.ctx, `UPDATE node_deployments SET created_at=clock_timestamp()-$2::interval,
			updated_at=clock_timestamp()-$2::interval,deadline_at=GREATEST(deadline_at,clock_timestamp()-$2::interval+interval '1 second') WHERE node_id=$1`,
			nodeID, deploymentAgo.String())
		return err
	}); err != nil {
		harness.t.Fatal(err)
	}
}

// the enrollment of a reinstalled host resets
// its delivery state and republishes its scopes once, in the enrollment
// transaction. That republication reached the new host before it could take
// it (no service ticket yet: installation_frozen; the node artifact set not
// installed yet: "pack system/bot-ai-crawler object …: object not found") and
// failed; nothing retried it, the node stayed without its sites until an
// operator ran reset-node-host-delivery. A recently reinstalled node whose
// newest deployment of a scope failed on the new host is republished again.
func TestReinstalledNodeFailedDeploymentIsRetried(t *testing.T) {
	harness := newServingHarness(t)
	failedAfter, healthy, enrolledOnce, stale, oldHostOnly := harness.addNode(), harness.addNode(), harness.addNode(),
		harness.addNode(), harness.addNode()
	for _, nodeID := range []uuid.UUID{failedAfter, healthy, stale, oldHostOnly} {
		seedServingNodeEnrollment(t, harness, nodeID)
		seedServingNodeEnrollment(t, harness, nodeID) // the reinstall
	}
	seedServingNodeEnrollment(t, harness, enrolledOnce)
	harness.deployV1(failedAfter, "failed", "published", time.Hour)
	harness.deployV1(healthy, "healthy", "published", time.Hour)
	harness.deployV1(enrolledOnce, "failed", "published", time.Hour)
	harness.deployV1(stale, "failed", "published", time.Hour)
	harness.deployV1(oldHostOnly, "failed", "published", time.Hour)
	// deployV1 stamps created_at three hours ago: move them after the enrollment
	for _, nodeID := range []uuid.UUID{failedAfter, healthy, enrolledOnce} {
		harness.backdate(nodeID, 0, 0)
	}
	harness.backdate(stale, 7*time.Hour, 0) // reinstalled 7 hours ago: outside the window
	// the failure belongs to the previous host: deployed 5 minutes ago, the new host enrolled 1 minute ago
	harness.backdate(oldHostOnly, 0, 5*time.Minute)

	retrier := &recordingRetrier{}
	if err := NewReinstallRedeliveryEvaluator(harness.store, retrier).Evaluate(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if len(retrier.calls) != 1 || retrier.calls[0] != [2]uuid.UUID{failedAfter, harness.scopeID} {
		t.Fatalf("retried %v, want only node %s scope %s", retrier.calls, failedAfter, harness.scopeID)
	}

	// a deployment in flight on the new host is waited for
	harness.deployV1(failedAfter, "started", "published", -time.Hour)
	harness.backdate(failedAfter, 0, 0)
	retrier.calls = nil
	if err := NewReinstallRedeliveryEvaluator(harness.store, retrier).Evaluate(harness.ctx); err != nil {
		t.Fatal(err)
	}
	if len(retrier.calls) != 0 {
		t.Fatalf("retried while a deployment is in flight: %v", retrier.calls)
	}
}
