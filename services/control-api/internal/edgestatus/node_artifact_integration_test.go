//go:build integration

package edgestatus

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nodeArtifactHarness struct {
	t             *testing.T
	pool          *pgxpool.Pool
	store         *Store
	validator     *Validator
	deployments   *edgedeployment.Store
	prefix        string
	platformScope uuid.UUID
	nodeID        uuid.UUID
	public        ed25519.PublicKey
	private       ed25519.PrivateKey
}

func newNodeArtifactHarness(t *testing.T) *nodeArtifactHarness {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, adminPool, schema := openStatusTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		adminPool.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	harness := &nodeArtifactHarness{t: t, pool: pool, prefix: "cdnca.integration.node-artifact.deployment-status"}
	validatorConfig := DefaultValidatorConfig()
	validatorConfig.SubjectPrefix = harness.prefix
	var err error
	if harness.validator, err = NewValidator(validatorConfig); err != nil {
		t.Fatal(err)
	}
	if harness.store, err = NewStore(pool); err != nil {
		t.Fatal(err)
	}
	if harness.deployments, err = edgedeployment.NewStore(pool); err != nil {
		t.Fatal(err)
	}
	tenantID, tenantScope, userID := uuid.New(), uuid.New(), uuid.New()
	harness.platformScope, harness.nodeID = uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants (id, display_name) VALUES ($1, 'node artifact tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, []any{tenantScope, tenantID}},
		{`INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')`, []any{harness.platformScope}},
		{`INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, 'node artifact', 'unused')`,
			[]any{userID, "node-artifact-" + strings.ReplaceAll(userID.String(), "-", "")[:12]}},
		{`INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id, display_id) VALUES ($1, $2, 'node-artifact', 'active', $3, 1)`,
			[]any{harness.nodeID, tenantScope, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	harness.public, harness.private, _ = ed25519.GenerateKey(rand.Reader)
	return harness
}

// deploy persists a platform-scope configuration holding one node artifact
// and rolls it out to the node.
func (harness *nodeArtifactHarness) deploy(mediaType string, wire []byte, key string) deploymentFixture {
	harness.t.Helper()
	ctx := context.Background()
	digest := sha256.Sum256(wire)
	config, err := harness.deployments.PersistReleasableConfig(ctx, edgedeployment.PersistConfigRequest{
		ConfigurationScopeID: harness.platformScope, CanonicalSnapshot: []byte(`{"node_artifact":"` + key + `"}`),
		GeneratorName: "node-artifact-set", GeneratorVersion: "1", IdempotencyKey: key,
		Artifacts: []edgedeployment.ArtifactInput{{ID: uuid.New(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
			WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: digest[:], Signature: ed25519.Sign(harness.private, wire),
			SigningKeyID: "edge-key", SigningPublicKey: harness.public,
			SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: mediaType,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE}}})
	if err != nil {
		harness.t.Fatal(err)
	}
	request := edgedeployment.CreateRolloutRequest{ConfigurationScopeID: harness.platformScope, ConfigVersionID: config.ConfigVersion.ID,
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: []uuid.UUID{harness.nodeID},
		RequiredCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET, ApiVersion: 1}},
		HealthCheck:          edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1},
		Deadline:             time.Now().UTC().Add(time.Hour), IdempotencyKey: key + "-rollout", RequestID: uuid.NewString(), CorrelationID: uuid.NewString()}
	var rollout edgedeployment.CreateRolloutResult
	if err := pgx.BeginFunc(ctx, harness.pool, func(tx pgx.Tx) error {
		var createErr error
		rollout, createErr = harness.deployments.CreateNodeArtifactRolloutTx(ctx, tx, request)
		return createErr
	}); err != nil {
		harness.t.Fatal(err)
	}
	deployment := rollout.Rollout.Deployments[0]
	return deploymentFixture{nodeID: harness.nodeID, scopeID: harness.platformScope, deploymentID: deployment.ID,
		rolloutID: rollout.Rollout.ID, configID: config.ConfigVersion.ID, action: "apply", command: deployment.Command}
}

func (harness *nodeArtifactHarness) project(status *agentv1.DeploymentStatus) error {
	envelope, err := harness.validator.Decode(harness.prefix+"."+harness.nodeID.String(), marshalStatus(harness.t, status))
	if err != nil {
		return err
	}
	_, err = harness.store.Project(context.Background(), envelope)
	return err
}

func (harness *nodeArtifactHarness) set(revision uint64, version string) ([]byte, artifactset.Set) {
	harness.t.Helper()
	content := []byte("ip intelligence library " + version)
	digest := artifactset.Digest(content)
	set := artifactset.Set{NodeID: harness.nodeID.String(), Revision: revision, IssuedAt: time.Now().UTC(),
		Items: []artifactset.Item{{ArtifactID: "ipintel/base", Version: version, Revision: revision, MediaType: artifactset.MediaTypeIPIntel,
			SHA256: digest, Size: int64(len(content)), Compression: artifactset.CompressionNone, CompressedSHA256: digest,
			CompressedSize: int64(len(content)), Segments: []artifactset.Segment{{SHA256: digest, Size: int64(len(content))}},
			Encryption: artifactset.EncryptionNone}}}
	wire, err := artifactset.Sign(set, "edge-key", harness.private)
	if err != nil {
		harness.t.Fatal(err)
	}
	decoded, err := artifactset.Decode(wire)
	if err != nil {
		harness.t.Fatal(err)
	}
	return wire, decoded
}

func receiptFor(t *testing.T, set artifactset.Set, wire []byte, result, reason string, activeRevision uint64, activeSHA string) []byte {
	t.Helper()
	receipt := artifactset.Receipt{NodeID: set.NodeID, Revision: set.Revision, SetSHA256: artifactset.Digest(wire),
		Result: result, ActiveRevision: activeRevision, ActiveSetSHA256: activeSHA, ReportedAt: time.Now()}
	for _, item := range set.Items {
		receipt.Items = append(receipt.Items, artifactset.ItemResult{ArtifactID: item.ArtifactID, Version: item.Version,
			SHA256: item.SHA256, Result: result, Reason: reason})
	}
	encoded, err := artifactset.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (harness *nodeArtifactHarness) appliedItems() map[string]string {
	harness.t.Helper()
	rows, err := harness.pool.Query(context.Background(), `SELECT artifact_id||'@'||version||'#'||item_revision, media_type
		FROM node_artifact_applied_items WHERE node_id=$1`, harness.nodeID)
	if err != nil {
		harness.t.Fatal(err)
	}
	items := map[string]string{}
	for rows.Next() {
		var key, media string
		if err := rows.Scan(&key, &media); err != nil {
			harness.t.Fatal(err)
		}
		items[key] = media
	}
	return items
}

func (harness *nodeArtifactHarness) latestReceipt() (revision int64, result string, active int64) {
	harness.t.Helper()
	if err := harness.pool.QueryRow(context.Background(), `SELECT revision,result,active_revision
		FROM node_artifact_set_receipts WHERE node_id=$1`, harness.nodeID).Scan(&revision, &result, &active); err != nil {
		harness.t.Fatal(err)
	}
	return revision, result, active
}

// A node artifact set deployment (PA-01) moves through the state machine
// without becoming the node's running configuration; its terminal status
// must carry the node's receipt bound to the deployed set, and the receipt
// is what the publication gate reads (node_artifact_applied_items). A
// rejected later set keeps the applied items of the last known good set.
func TestNodeArtifactSetReceiptRecordsTheAppliedSet(t *testing.T) {
	harness := newNodeArtifactHarness(t)
	ctx := context.Background()
	wire, set := harness.set(1, "7")
	fixture := harness.deploy(artifactset.MediaTypeSet, wire, "set-1")
	projectStatusPath(t, harness.store, harness.validator, harness.prefix, fixture,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
	)
	healthy := func(receipt []byte) *agentv1.DeploymentStatus {
		status := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
		status.RunningConfigUnchanged = true
		status.ArtifactSetReceipt = receipt
		return status
	}
	// A running-config identity on a node-side delivery is a forgery.
	forged := healthy(receiptFor(t, set, wire, artifactset.ResultApplied, "", 1, artifactset.Digest(wire)))
	forged.ActiveConfigIdentityCapability = statusIdentityCapability()
	forged.ActiveConfigIdentity = &agentv1.ActiveConfigIdentity{Schema: agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: fixture.configID.String(), ArtifactSha256: make([]byte, 32)}
	forged.Checks = []*agentv1.CheckResult{activeConfigProbeCheck()}
	other, otherSet := harness.set(1, "8")
	for name, status := range map[string]*agentv1.DeploymentStatus{
		"running-config identity": forged,
		"no receipt":              healthy(nil),
		"receipt of another set":  healthy(receiptFor(t, otherSet, other, artifactset.ResultApplied, "", 1, artifactset.Digest(other))),
		"rejected receipt on healthy": healthy(receiptFor(t, set, wire, artifactset.ResultRejected,
			artifactset.ReasonSegmentMismatch, 0, "")),
		"receipt that is not canonical": healthy(append(receiptFor(t, set, wire, artifactset.ResultApplied, "", 1,
			artifactset.Digest(wire)), ' ')),
	} {
		if err := harness.project(status); err == nil {
			t.Fatalf("%s: healthy set status accepted", name)
		}
	}
	if len(harness.appliedItems()) != 0 {
		t.Fatal("a refused status wrote applied items")
	}
	if err := harness.project(healthy(receiptFor(t, set, wire, artifactset.ResultApplied, "", 1, artifactset.Digest(wire)))); err != nil {
		t.Fatalf("healthy set status with its receipt: %v", err)
	}
	assertDeploymentState(t, harness.pool, fixture.deploymentID, "healthy", 5)
	if revision, result, active := harness.latestReceipt(); revision != 1 || result != artifactset.ResultApplied || active != 1 {
		t.Fatalf("receipt = (%d, %s, %d)", revision, result, active)
	}
	if items := harness.appliedItems(); len(items) != 1 || items["ipintel/base@7#1"] != artifactset.MediaTypeIPIntel {
		t.Fatalf("applied items = %v", items)
	}
	var states, events int
	if err := harness.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM node_config_state WHERE node_id=$1),
		(SELECT count(*) FROM domain_event_outbox_368 WHERE subject='deployment/'||$2::text)`,
		harness.nodeID, fixture.deploymentID).Scan(&states, &events); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	if states != 0 || events != 0 {
		t.Fatalf("node-side delivery wrote node_config_state=%d domain events=%d", states, events)
	}

	// Revision 2 is rejected (a segment was altered on the node): the receipt
	// is recorded, the node keeps revision 1 and so do the applied items.
	wire2, set2 := harness.set(2, "8")
	fixture2 := harness.deploy(artifactset.MediaTypeSet, wire2, "set-2")
	projectFixtureState(t, harness.store, harness.validator, harness.prefix, fixture2,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	failed := fixtureStatus(fixture2, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2)
	failed.RunningConfigUnchanged = true
	failed.Error = &commonv1.ProtocolError{Code: commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION,
		Message: "node artifact set rejected; the last known good set is kept"}
	failed.ArtifactSetReceipt = receiptFor(t, set2, wire2, artifactset.ResultApplied, "", 2, artifactset.Digest(wire2))
	if err := harness.project(failed); err == nil {
		t.Fatal("failed set status accepted an applied receipt")
	}
	failed.ArtifactSetReceipt = receiptFor(t, set2, wire2, artifactset.ResultRejected, artifactset.ReasonSegmentMismatch,
		1, artifactset.Digest(wire))
	if err := harness.project(failed); err != nil {
		t.Fatalf("failed set status with a rejected receipt: %v", err)
	}
	if revision, result, active := harness.latestReceipt(); revision != 2 || result != artifactset.ResultRejected || active != 1 {
		t.Fatalf("receipt after the rejected set = (%d, %s, %d)", revision, result, active)
	}
	if items := harness.appliedItems(); len(items) != 1 || items["ipintel/base@7#1"] == "" {
		t.Fatalf("applied items after the rejected set = %v", items)
	}
	// Each recorded receipt is audited with the node as actor.
	var applied, rejected int
	var reason string
	if err := harness.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE result='success'),
			count(*) FILTER (WHERE result='failure'),
			COALESCE(max(payload->>'reason_code') FILTER (WHERE result='failure'),'')
		FROM audit_events WHERE action=$1 AND resource_id=$2 AND payload->>'actor_kind'='node'`,
		ArtifactSetReceiptAuditAction, harness.nodeID.String()).Scan(&applied, &rejected, &reason); err != nil {
		t.Fatal(err)
	}
	if applied != 1 || rejected != 1 || reason != artifactset.ReasonSegmentMismatch {
		t.Fatalf("receipt audits: applied=%d rejected=%d reason=%q", applied, rejected, reason)
	}

	// A segment object deployment never carries a receipt.
	segment := []byte(fmt.Sprintf("segment-%s", uuid.NewString()))
	fixture3 := harness.deploy(artifactset.MediaTypeSegment, segment, "segment-1")
	projectStatusPath(t, harness.store, harness.validator, harness.prefix, fixture3,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
	)
	segmentHealthy := fixtureStatus(fixture3, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
	segmentHealthy.RunningConfigUnchanged = true
	segmentHealthy.ArtifactSetReceipt = receiptFor(t, set, wire, artifactset.ResultApplied, "", 1, artifactset.Digest(wire))
	if err := harness.project(segmentHealthy); err == nil {
		t.Fatal("segment status accepted a receipt")
	}
	segmentHealthy.ArtifactSetReceipt = nil
	if err := harness.project(segmentHealthy); err != nil {
		t.Fatalf("segment healthy: %v", err)
	}
}
