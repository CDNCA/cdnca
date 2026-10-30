//go:build integration

package edgedeployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func nodeArtifactConfig(t *testing.T, store *Store, scopeID uuid.UUID, key string, public ed25519.PublicKey,
	private ed25519.PrivateKey) ConfigVersion {
	t.Helper()
	set := validArtifactInput(t, uuid.New(), "edge-key", public, private, []byte(`{"set":"`+key+`"}`))
	set.MediaType = artifactset.MediaTypeSet
	return persistTestConfig(t, store, PersistConfigRequest{ConfigurationScopeID: scopeID,
		CanonicalSnapshot: []byte(`{"node_artifact_set":"` + key + `"}`), GeneratorName: "node-artifact-set", GeneratorVersion: "1.0.0",
		IdempotencyKey: key, Artifacts: []ArtifactInput{set}})
}

// A node-side artifact rollout (platform scope) must leave the node's running
// configuration alone and must not block, or be blocked by, the tenant
// scope's deployment on the same node.
func TestNodeArtifactRolloutDoesNotTouchNodeConfiguration(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	tenantScopeID, userID := seedEdgeScope(t, pool)
	platformScopeID, platformUserID := seedEdgePlatformIdentity(t, pool)
	nodeID := uuid.New()
	seedEdgeNode(t, pool, tenantScopeID, userID, nodeID)
	_ = platformUserID

	// Tenant deployment in flight on the node.
	siteConfig := persistTestConfig(t, store, testConfigRequest(t, tenantScopeID, "site-1", "edge-key", public, private, []byte("site")))
	site, err := store.CreateRollout(ctx, testRolloutRequest(tenantScopeID, siteConfig.ID, []uuid.UUID{nodeID}, "site-rollout-1"))
	if err != nil {
		t.Fatal(err)
	}

	library := nodeArtifactConfig(t, store, platformScopeID, "ip-intel-1", public, private)
	// The ordinary path refuses a platform-scope configuration on a tenant node.
	if _, err := store.CreateRollout(ctx, testRolloutRequest(platformScopeID, library.ID, []uuid.UUID{nodeID}, "ip-ordinary")); !errors.Is(err, ErrConfigurationScopeConflict) {
		t.Fatalf("ordinary rollout of node artifact = %v", err)
	}
	// The node-side path only takes the platform scope.
	if _, err := store.CreateNodeArtifactRolloutTx(ctx, mustBegin(t, pool), testRolloutRequest(tenantScopeID, siteConfig.ID,
		[]uuid.UUID{nodeID}, "ip-tenant")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("node artifact rollout in a tenant scope = %v", err)
	}
	tx := mustBegin(t, pool)
	delivery, err := store.CreateNodeArtifactRolloutTx(ctx, tx, testRolloutRequest(platformScopeID, library.ID, []uuid.UUID{nodeID}, "ip-1"))
	if err != nil {
		t.Fatalf("node artifact rollout while the site deploys: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	command := delivery.Rollout.Deployments[0].Command
	if command.GetPreviousConfigVersionId() != "" || len(command.Artifacts) != 1 ||
		command.GetConfigurationScopeId() != platformScopeID.String() {
		t.Fatalf("node artifact command = %+v", command)
	}
	var states, platformStates int
	var queued bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM node_config_state WHERE node_id=$1),
		(SELECT count(*) FROM node_config_state WHERE configuration_scope_id=$2),
		(SELECT queued_per_scope FROM node_deployments WHERE id=$3)`, nodeID, platformScopeID,
		delivery.Rollout.Deployments[0].ID).Scan(&states, &platformStates, &queued); err != nil {
		t.Fatal(err)
	}
	if states != 1 || platformStates != 0 || !queued {
		t.Fatalf("node config states=%d platform states=%d queued_per_scope=%v", states, platformStates, queued)
	}
	// A second in-flight delivery to the same node is refused (one per node).
	tx = mustBegin(t, pool)
	library2 := nodeArtifactConfig(t, store, platformScopeID, "ip-intel-2", public, private)
	if _, err := store.CreateNodeArtifactRolloutTx(ctx, tx, testRolloutRequest(platformScopeID, library2.ID, []uuid.UUID{nodeID}, "ip-2")); !errors.Is(err, ErrNodeDeploymentActive) {
		t.Fatalf("second in-flight node artifact = %v", err)
	}
	_ = tx.Rollback(ctx)
	// The tenant's next deployment is not blocked by the library delivery.
	for index, state := range []string{"delivered", "failed"} {
		if _, err := pool.Exec(ctx, `UPDATE node_deployments SET state=$2,updated_at=$3 WHERE id=$1`,
			site.Rollout.Deployments[0].ID, state, integrationClock.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	siteConfig2 := persistTestConfig(t, store, testConfigRequest(t, tenantScopeID, "site-2", "edge-key", public, private, []byte("site2")))
	if _, err := store.CreateRollout(ctx, testRolloutRequest(tenantScopeID, siteConfig2.ID, []uuid.UUID{nodeID}, "site-rollout-2")); err != nil {
		t.Fatalf("tenant deployment while the library is in flight: %v", err)
	}
	// Node-side media types cannot be mixed into a tenant configuration.
	mixed := testConfigRequest(t, tenantScopeID, "site-mixed", "edge-key", public, private, []byte("mixed"))
	part := validArtifactInput(t, uuid.New(), "edge-key", public, private, []byte("part"))
	part.MediaType = artifactset.MediaTypeSegment
	mixed.Artifacts = append(mixed.Artifacts, part)
	if _, err := store.PersistReleasableConfig(ctx, mixed); err == nil {
		t.Fatal("tenant configuration accepted a node-side artifact")
	}
}

func mustBegin(t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}
