//go:build integration

package edgepublish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// originAuthTestSource stands in for originauthcontrol.ProductionSource: the
// scope's latest publication with one credential (or err).
type originAuthTestSource struct {
	scope *edgepublish.SystemRepublishScope
	err   error
	calls int
}

func (source *originAuthTestSource) Build(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (originauthcontrol.ProductionMaterial, error) {
	source.calls++
	if source.err != nil {
		return originauthcontrol.ProductionMaterial{}, source.err
	}
	var material originauthcontrol.ProductionMaterial
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT id,tenant_id,revision,canonical_snapshot FROM origin_auth_publications
		WHERE tenant_scope_id=$1 ORDER BY revision DESC LIMIT 1`, scopeID).Scan(&material.PublicationID,
		&material.TenantID, &revision, &material.CanonicalSnapshot); err != nil {
		return originauthcontrol.ProductionMaterial{}, err
	}
	material.TenantScopeID, material.PublicationRevision = scopeID, uint64(revision)
	if err := json.Unmarshal(material.CanonicalSnapshot, &material.Snapshot); err != nil {
		return originauthcontrol.ProductionMaterial{}, err
	}
	material.Credentials = []originauthcontrol.ProductionCredentialMaterial{{
		RevisionRef: material.Snapshot.Rules[0].CurrentCredentialRevisionRef, Provider: originauthcontrol.ProviderS3,
		Secret: originauthcontrol.CredentialSecret{AccessKeyID: "AK-delivery", SecretAccessKey: "SK-delivery",
			NotBefore: time.Now().Add(-time.Hour).UTC(), ExpiresAt: time.Now().Add(24 * time.Hour).UTC()}}}
	return material, nil
}

type originAuthTestSigner struct{ private ed25519.PrivateKey }

func (originAuthTestSigner) ArtifactSigningKeyID() string { return "origin-auth-delivery-test" }
func (signer originAuthTestSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer originAuthTestSigner) SignArtifact(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, value), nil
}

// publishOriginAuth stores the scope's next origin auth publication with one
// rule on the scope's site (as SetSiteSystem's publish does) and returns it.
func publishOriginAuth(t *testing.T, scope *edgepublish.SystemRepublishScope, revision int64) []byte {
	t.Helper()
	snapshot := originauthcontrol.PublicationSnapshot{SchemaVersion: "cdnca.control.originauth-publication/v1",
		TenantScopeID: scope.ScopeID, PublicationRevision: revision,
		Rules: []originauthcontrol.PublicationRule{{RuleID: uuid.New(), SiteID: scope.SiteID, SourcePosition: 1,
			Provider: originauthcontrol.ProviderS3, Algorithm: originauthcontrol.AlgorithmS3,
			Endpoint: "https://s3.us-east-1.amazonaws.com", PathPrefix: "/", Region: "us-east-1", Service: "s3",
			SignatureTTLSeconds: 300, CurrentCredentialRevisionRef: uuid.New()}}}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	// The publication is seeded as a fact (055 validate_origin_auth_publication
	// wants the pending write and audit of the real create path, which this test
	// does not exercise): replica mode skips that trigger only for this insert.
	tx, err := scope.Pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO origin_auth_publications(id,tenant_scope_id,tenant_id,revision,schema_version,
		canonical_snapshot,snapshot_sha256,previous_sha256,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
		SELECT $1,$2,scope.tenant_id,$3,'cdnca.control.originauth-publication/v1',$4,$5,
		  (SELECT snapshot_sha256 FROM origin_auth_publications WHERE tenant_scope_id=$2 ORDER BY revision DESC LIMIT 1),
		  $2,$6,'msc6-publish','msc6-publish',clock_timestamp() FROM access_scopes scope WHERE scope.id=$2`,
		uuid.New(), scope.ScopeID, revision, canonical, digest[:], scope.UserID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return canonical
}

func newOriginAuthDeliverer(t *testing.T, scope *edgepublish.SystemRepublishScope, source *originAuthTestSource,
	retry time.Duration) *edgepublish.OriginAuthDeliverer {
	t.Helper()
	producer, err := edgepublish.NewOriginAuthArtifactProducer(originAuthTestSigner{
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	deliverer, err := edgepublish.NewOriginAuthDeliverer(scope.Pool, scope.DeploymentStore(t), source, producer,
		audit.New(scope.Pool), edgepublish.OriginAuthDelivererConfig{RetryDelay: retry,
			HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second,
				ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2}})
	if err != nil {
		t.Fatal(err)
	}
	return deliverer
}

func deliver(t *testing.T, deliverer *edgepublish.OriginAuthDeliverer, scope *edgepublish.SystemRepublishScope,
) edgepublish.OriginAuthDeliveryStatus {
	t.Helper()
	status, err := deliverer.Deliver(t.Context(), scope.ScopeID, scope.UserID)
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	return status
}

// fix-mktsiteconf6: a leaf's origin auth publication reaches the online target
// nodes by itself through one system secret rollout (encrypted per node,
// audited as the system); it is not started again while in flight or once
// delivered; an offline node waits and gets it when it comes back; a node that
// refused it is retried after the backoff; a new publication is delivered again.
func TestOriginAuthSystemDeliveryReachesTheNodesWithoutAManualPublish(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "msc6-baseline", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.SetPresence(t, nodeA, true, 1)
	source := &originAuthTestSource{scope: scope}
	deliverer := newOriginAuthDeliverer(t, scope, source, time.Millisecond)

	if status := deliver(t, deliverer, scope); status.State != edgepublish.OriginAuthDeliveryNone {
		t.Fatalf("before any publication: %+v", status)
	}
	snapshot := publishOriginAuth(t, scope, 1)
	status := deliver(t, deliverer, scope)
	if status.State != edgepublish.OriginAuthDeliveryDelivering || status.RolloutID == nil || status.Nodes != 2 ||
		status.Revision != 1 {
		t.Fatalf("first delivery: %+v", status)
	}
	first := *status.RolloutID
	var generator string
	var stored []byte
	var nodes []uuid.UUID
	var encrypted int
	if err := scope.Pool.QueryRow(t.Context(), `SELECT version.generator_name,version.canonical_snapshot,
		ARRAY(SELECT node_id FROM node_deployments WHERE rollout_id=rollout.id ORDER BY node_id),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=version.id AND kind='node_secret_bundle'
		   AND recipient_key_id IS NOT NULL)
		FROM rollouts rollout JOIN config_versions version ON version.id=rollout.config_version_id
		WHERE rollout.id=$1 AND rollout.configuration_scope_id=$2`, first, scope.ScopeID).
		Scan(&generator, &stored, &nodes, &encrypted); err != nil {
		t.Fatal(err)
	}
	// Only A is online; B (offline) waits. The snapshot is the publication's.
	if generator != edgepublish.OriginAuthSecretGeneratorName || !bytes.Equal(stored, snapshot) ||
		!slices.Equal(nodes, []uuid.UUID{nodeA}) || encrypted != 1 {
		t.Fatalf("rollout: generator=%q nodes=%v encrypted=%d same snapshot=%v", generator, nodes, encrypted,
			bytes.Equal(stored, snapshot))
	}
	if bytes.Contains(stored, []byte("SK-delivery")) {
		t.Fatal("credential in clear in the config snapshot")
	}
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE action='edge_secret_rollout.create'
		AND resource_id=$2::text AND actor_user_id IS NULL AND payload->>'actor_kind'='system'
		AND payload->>'reason'='market_origin_auth_delivery' AND payload->>'accountable_user_id'=$3::text
		AND scope_id=$1`, first.String(), scope.UserID.String()); got != 1 {
		t.Fatalf("system secret rollout audits = %d", got)
	}

	// In flight: nothing new.
	if status := deliver(t, deliverer, scope); status.State != edgepublish.OriginAuthDeliveryDelivering ||
		status.RolloutID != nil {
		t.Fatalf("while in flight: %+v", status)
	}
	scope.SetRolloutDeploymentState(t, first, nodeA, "healthy")
	if status := deliver(t, deliverer, scope); status.State != edgepublish.OriginAuthDeliveryWaitingNodes ||
		status.Delivered != 1 || status.RolloutID != nil {
		t.Fatalf("A delivered, B offline: %+v", status)
	}

	// B comes online: it alone gets it; its refusal is retried after the backoff.
	scope.SetPresence(t, nodeB, true, 1)
	status = deliver(t, deliverer, scope)
	if status.RolloutID == nil {
		t.Fatalf("B online: %+v", status)
	}
	second := *status.RolloutID
	scope.SetRolloutDeploymentState(t, second, nodeB, "failed")
	time.Sleep(5 * time.Millisecond) // > RetryDelay
	status = deliver(t, deliverer, scope)
	if status.RolloutID == nil || *status.RolloutID == second {
		t.Fatalf("B retry: %+v", status)
	}
	scope.SetRolloutDeploymentState(t, *status.RolloutID, nodeB, "healthy")
	if status := deliver(t, deliverer, scope); status.State != edgepublish.OriginAuthDeliveryDelivered ||
		status.Delivered != 2 {
		t.Fatalf("all delivered: %+v", status)
	}
	if source.calls != 3 {
		t.Fatalf("builds = %d, want 3 (one per started rollout)", source.calls)
	}

	// A new publication (the leaf synced a changed rule) goes out again.
	publishOriginAuth(t, scope, 2)
	if status := deliver(t, deliverer, scope); status.State != edgepublish.OriginAuthDeliveryDelivering ||
		status.Revision != 2 || status.RolloutID == nil {
		t.Fatalf("revision 2: %+v", status)
	}
}

// A rollout that cannot be built (the credential does not decrypt) starts
// nothing, is audited as a system failure with its reason and retried after
// the backoff; after SystemRepublicationMaxAttempts the delivery is failed.
func TestOriginAuthSystemDeliveryReportsAndBoundsBuildFailures(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "msc6-baseline", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.SetPresence(t, nodeA, true, 1)
	publishOriginAuth(t, scope, 1)
	source := &originAuthTestSource{scope: scope, err: originauthcontrol.ErrEncryptionUnavailable}
	deliverer := newOriginAuthDeliverer(t, scope, source, time.Hour)

	status := deliver(t, deliverer, scope)
	if status.State != edgepublish.OriginAuthDeliveryRetrying || status.Reason != edgepublish.OriginAuthDeliveryCredential ||
		status.RolloutID != nil {
		t.Fatalf("build failure: %+v", status)
	}
	if got := scope.Count(t, `SELECT count(*) FROM rollouts rollout JOIN config_versions version
		ON version.id=rollout.config_version_id WHERE rollout.configuration_scope_id=$1 AND version.generator_name=$2`,
		edgepublish.OriginAuthSecretGeneratorName); got != 0 {
		t.Fatalf("rollouts after a failed build = %d", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='edge_secret_rollout.create'
		AND result='failure' AND actor_kind='system' AND reason_code=$2`, edgepublish.OriginAuthDeliveryCredential); got != 1 {
		t.Fatalf("failure audits = %d", got)
	}
	// Not due yet (one hour backoff): no new build.
	if deliver(t, deliverer, scope); source.calls != 1 {
		t.Fatalf("builds before the backoff = %d", source.calls)
	}
	if _, err := deliverer.Status(t.Context(), scope.ScopeID); err != nil || source.calls != 1 {
		t.Fatalf("Status built or failed: calls=%d err=%v", source.calls, err)
	}

	// The count is stored (fix-mktsiteconf7 §2): a restarted controller (a
	// new deliverer) still waits out the backoff and keeps counting.
	restarted := newOriginAuthDeliverer(t, scope, source, time.Hour)
	if status := deliver(t, restarted, scope); source.calls != 1 || status.State != edgepublish.OriginAuthDeliveryRetrying {
		t.Fatalf("after a restart: calls=%d status=%+v", source.calls, status)
	}
	if got := scope.Count(t, `SELECT count(*) FROM origin_auth_delivery_build_failures
		WHERE tenant_scope_id=$1 AND revision=1 AND attempts=1 AND reason=$2`, edgepublish.OriginAuthDeliveryCredential); got != 1 {
		t.Fatalf("stored build failures = %d", got)
	}

	fast := newOriginAuthDeliverer(t, scope, source, time.Nanosecond)
	for range edgepublish.SystemRepublicationMaxAttempts {
		status = deliver(t, fast, scope)
	}
	if status.State != edgepublish.OriginAuthDeliveryFailed || status.Reason != edgepublish.OriginAuthDeliveryCredential {
		t.Fatalf("after the attempts: %+v", status)
	}
	calls := source.calls
	if deliver(t, fast, scope); source.calls != calls {
		t.Fatal("a failed delivery was attempted again before a new publication")
	}
	// The credential is fixed and the leaf republishes: it starts over.
	source.err = nil
	publishOriginAuth(t, scope, 2)
	if status := deliver(t, fast, scope); status.State != edgepublish.OriginAuthDeliveryDelivering || status.RolloutID == nil {
		t.Fatalf("after a new publication: %+v", status)
	}
	if got := scope.Count(t, `SELECT count(*) FROM origin_auth_delivery_build_failures WHERE tenant_scope_id=$1`); got != 0 {
		t.Fatalf("build failures kept after a successful start = %d", got)
	}
}
