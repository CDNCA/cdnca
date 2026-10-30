//go:build integration

package edgedeployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fix-cfgflow2 §3 / fix-cfgflow3 (PG): queueing a newer deployment of a node
// and scope cancels the older deployment's command still waiting to be sent
// or retried (here: the deployment failed while its command was retrying),
// and leaves other nodes' commands and the new command alone.
func TestCreateRolloutCancelsReplacedCommandOfSameNodeAndScope(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scopeID, userID := seedEdgeScope(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configV1 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "replaced-v1", "replaced-key", publicKey, privateKey, []byte("config v1")))
	configV2 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "replaced-v2", "replaced-key", publicKey, privateKey, []byte("config v2")))
	node, otherNode := uuid.New(), uuid.New()
	for _, nodeID := range []uuid.UUID{node, otherNode} {
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
	}
	old, err := store.CreateRollout(ctx, testRolloutRequest(scopeID, configV1.ID, []uuid.UUID{node, otherNode}, "replaced-old"))
	if err != nil {
		t.Fatal(err)
	}
	var oldDeployment, otherDeployment uuid.UUID
	for _, deployment := range old.Rollout.Deployments {
		if deployment.NodeID == node {
			oldDeployment = deployment.ID
		} else {
			otherDeployment = deployment.ID
		}
	}
	// The old deployment failed while its command was retrying; the other
	// node's old command is still pending (its deployment runs on).
	// Same transitions as the edgeoutbox publisher (publishing, then a
	// retryable failure) and the status projection (delivered, then failed).
	for _, status := range []string{"publishing", "failed"} {
		if _, err := pool.Exec(ctx, `UPDATE edge_command_outbox SET status=$2,updated_at=$3 WHERE deployment_id=$1`,
			oldDeployment, status, integrationClock); err != nil {
			t.Fatal(err)
		}
	}
	for index, state := range []string{"delivered", "failed"} {
		if _, err := pool.Exec(ctx, `UPDATE node_deployments SET state=$2,updated_at=$3 WHERE id=$1 AND attempt=1`,
			oldDeployment, state, integrationClock.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	newer, err := store.CreateRollout(ctx, testRolloutRequest(scopeID, configV2.ID, []uuid.UUID{node}, "replaced-new"))
	if err != nil {
		t.Fatal(err)
	}
	outbox := func(deploymentID uuid.UUID) (string, string) {
		t.Helper()
		var status, lastError string
		if err := pool.QueryRow(ctx, `SELECT status,COALESCE(last_error,'') FROM edge_command_outbox
			WHERE deployment_id=$1`, deploymentID).Scan(&status, &lastError); err != nil {
			t.Fatal(err)
		}
		return status, lastError
	}
	if status, lastError := outbox(oldDeployment); status != "cancelled" || lastError != "superseded:newer_deployment" {
		t.Fatalf("replaced command = %s (%s), want cancelled (superseded:newer_deployment)", status, lastError)
	}
	if status, _ := outbox(otherDeployment); status != "pending" {
		t.Fatalf("other node's command = %s, want pending", status)
	}
	if status, _ := outbox(newer.Rollout.Deployments[0].ID); status != "pending" && status != "held" {
		t.Fatalf("new command = %s, want pending or held", status)
	}
}
