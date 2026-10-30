//go:build integration

package securityactivation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

const siteRuntimeV2SchemaForTest = "cdnca.edge.site-runtime/v2"

// v2 activation: docs/architecture/security-activation-v2.md.
type v2ActivationFixture struct {
	activationFixture
	privateKeys map[uuid.UUID][]byte
}

// newV2ActivationFixture is the activation fixture (both target nodes are
// enrolled 1.0.35 agents, buildActivationFixture) with their artifact keys.
func newV2ActivationFixture(t *testing.T) v2ActivationFixture {
	t.Helper()
	base := newActivationFixture(t)
	return v2ActivationFixture{activationFixture: base, privateKeys: base.nodeKeys}
}

// activationNodeFeatures is what a 1.0.35 agent declares.
func activationNodeFeatures() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV6, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CC, ApiVersion: 4},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
	}
}

// activationNodeFeaturesWithCC is a 1.0.35 agent's features with CC at
// version cc (sessions of nodes that run an older CC).
func activationNodeFeaturesWithCC(cc uint32) []*agentv1.Capability {
	features := activationNodeFeatures()
	for index, capability := range features {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CC {
			features[index] = &agentv1.Capability{Name: capability.GetName(), ApiVersion: cc}
		}
	}
	return features
}

// enrollActivationNodes gives both target nodes a real 1.0.35 identity
// (issued certificate, active artifact key) and returns their artifact keys.
func enrollActivationNodes(t *testing.T, fixture activationFixture) map[uuid.UUID][]byte {
	t.Helper()
	keys := map[uuid.UUID][]byte{}
	features := fixture.nodeFeatures
	if features == nil {
		features = activationNodeFeatures()
	}
	for _, nodeID := range []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID} {
		keys[nodeID] = capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool,
			fixture.scopeID, fixture.actor.UserID, nodeID, &agentv1.AgentCapabilities{
				AgentVersion: "1.0.35", BuildId: "activation", OperatingSystem: "linux", Architecture: "amd64",
				Features: features,
			}, fixture.now.Add(-10*time.Minute), true).ArtifactPrivateKey
	}
	return keys
}

type v2NodeArtifact struct {
	deploymentID, eventID, artifactID uuid.UUID
	digest                            [sha256.Size]byte
}

func loadV2NodeArtifacts(t *testing.T, fixture v2ActivationFixture, candidate Candidate) map[uuid.UUID]v2NodeArtifact {
	t.Helper()
	rows, err := fixture.pool.Query(t.Context(), `SELECT node_id,deployment_id,event_id,artifact_id,artifact_sha256
		FROM security_policy_activation_node_artifacts_333 WHERE tenant_scope_id=$1 AND config_version_id=$2`,
		candidate.TenantScopeID, candidate.CandidateConfigVersionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	result := map[uuid.UUID]v2NodeArtifact{}
	for rows.Next() {
		var nodeID uuid.UUID
		var item v2NodeArtifact
		var digest []byte
		if err := rows.Scan(&nodeID, &item.deploymentID, &item.eventID, &item.artifactID, &digest); err != nil {
			t.Fatal(err)
		}
		copy(item.digest[:], digest)
		result[nodeID] = item
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

// openV2PhaseBundle assembles, as the node does, what nodeID receives in the
// candidate's phase rollout (site runtime v8: the shared signed root and the
// node's own key envelope).
func openV2PhaseBundle(t *testing.T, fixture v2ActivationFixture, candidate Candidate, phase string,
	nodeID uuid.UUID) (edgeconfig.Bundle, edgedeployment.NodeArtifactBinding, int) {
	t.Helper()
	var binding edgedeployment.NodeArtifactBinding
	var maxAttempts int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT deployment.id,deployment.command_event_id,
		deployment.config_version_id,artifact.id,artifact.recipient_key_id,rollout.max_attempts
		FROM rollouts rollout
		JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
		JOIN node_deployment_artifacts link ON link.deployment_id=deployment.id AND link.deployment_attempt=deployment.attempt
		JOIN configuration_artifacts artifact ON artifact.id=link.artifact_id AND artifact.config_version_id=link.config_version_id
		WHERE rollout.idempotency_key=$1 AND deployment.node_id=$2 AND deployment.attempt=1
		  AND artifact.encryption_algorithm='hpke_x25519_hkdf_sha256_aes_256_gcm'`,
		derivedKey(phase, candidate.ID.String()), nodeID).Scan(&binding.DeploymentID, &binding.EventID,
		&binding.ConfigVersionID, &binding.ArtifactID, &binding.RecipientKeyID, &maxAttempts); err != nil {
		t.Fatalf("node %s has no %s key envelope: %v", nodeID, phase, err)
	}
	binding.NodeID, binding.Attempt = nodeID, 1
	release, err := edgepublish.OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, binding.DeploymentID,
		fixture.privateKeys[nodeID])
	if err != nil {
		t.Fatalf("node %s cannot assemble its %s release: %v", nodeID, phase, err)
	}
	if release.RootSHA256 != hex.EncodeToString(candidate.CandidateArtifactSHA256[:]) {
		t.Fatalf("node %s root digest is not the candidate identity digest", nodeID)
	}
	return release.Bundle, binding, maxAttempts
}

// markV2PhaseHealthy is markProductionPhaseHealthy with each node reporting
// its own artifact's digest.
func markV2PhaseHealthy(t *testing.T, fixture v2ActivationFixture, candidate Candidate, phase string) {
	t.Helper()
	artifacts := loadV2NodeArtifacts(t, fixture, candidate)
	if err := reportV2PhaseHealthy(t, fixture, candidate, phase, func(nodeID uuid.UUID) [sha256.Size]byte {
		return artifacts[nodeID].digest
	}); err != nil {
		t.Fatal(err)
	}
}

// reportV2PhaseHealthy records the phase's nodes healthy, each reporting
// digest(node) as its active artifact, in one transaction.
func reportV2PhaseHealthy(t *testing.T, fixture v2ActivationFixture, candidate Candidate, phase string,
	reported func(uuid.UUID) [sha256.Size]byte) error {
	t.Helper()
	rolloutID := productionPhaseRolloutID(t, fixture.pool, candidate.ID, phase)
	rows, err := fixture.pool.Query(t.Context(), `SELECT id,node_id FROM node_deployments
		WHERE rollout_id=$1 AND attempt=1 ORDER BY node_id`, rolloutID)
	if err != nil {
		t.Fatal(err)
	}
	type deployment struct{ id, nodeID uuid.UUID }
	var deployments []deployment
	for rows.Next() {
		var item deployment
		if err := rows.Scan(&item.id, &item.nodeID); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		deployments = append(deployments, item)
	}
	rows.Close()
	if len(deployments) == 0 {
		t.Fatalf("phase %s has no deployments", phase)
	}
	return pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		for _, item := range deployments {
			digest := reported(item.nodeID)
			for index, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
				payload := []byte(candidate.ID.String() + ":" + phase + ":" + state)
				payloadDigest := sha256.Sum256(payload)
				var apiVersion, schema, configID, artifact any
				if state == "healthy" {
					apiVersion, schema, configID, artifact = 1, 1, candidate.CandidateConfigVersionID, digest[:]
				}
				at := fixture.now.Add(time.Duration(index+1) * time.Second)
				if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(
					id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,
					occurred_at,received_at,active_config_identity_api_version,active_config_identity_schema,
					active_config_version_id,active_config_artifact_sha256)
					VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$8,$9,$10,$11,$12)`, uuid.New(), item.id,
					uuid.New(), index+1, state, payload, payloadDigest[:], at, apiVersion, schema, configID, artifact); err != nil {
					return err
				}
				if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
					WHERE id=$1 AND attempt=1`, item.id, state, at); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(t.Context(), `UPDATE node_config_state SET
				current_config_version_id=$2,current_config_identity_schema=1,
				current_config_artifact_sha256=$3,updated_at=$4 WHERE node_id=$1`, item.nodeID,
				candidate.CandidateConfigVersionID, digest[:], fixture.now); err != nil {
				return err
			}
		}
		return nil
	})
}

// v2SitePolicyVersion is the WAF policy version the site's listeners carry
// in the node's v2 document (0 when none).
func v2SitePolicyVersion(t *testing.T, bundle edgeconfig.Bundle, siteID, policyID uuid.UUID) int64 {
	t.Helper()
	var document struct {
		Schema string `json:"schema"`
		Sites  []struct {
			ID        string `json:"id"`
			Listeners []struct {
				Security *edgeconfig.ListenerSecurity `json:"security"`
			} `json:"listeners"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(bundle.Files["site-runtime.v2.json"], &document); err != nil ||
		document.Schema != siteRuntimeV2SchemaForTest {
		t.Fatalf("node bundle is not a site runtime v2 document: %v", err)
	}
	var version int64
	for _, site := range document.Sites {
		if site.ID != siteID.String() || len(site.Listeners) == 0 {
			continue
		}
		for _, listener := range site.Listeners {
			if listener.Security == nil {
				t.Fatal("site listener has no security in the candidate")
			}
			for _, policy := range listener.Security.Policies {
				if policy.PolicyID == policyID.String() {
					version = policy.PolicyVersion
				}
			}
		}
	}
	return version
}

func startV2Activation(t *testing.T, fixture v2ActivationFixture, store *Store, key string, canarySize int) (StartInput, Candidate) {
	t.Helper()
	input := prepareProductionStart(t, fixture.activationFixture, store, key,
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, canarySize)
	// Not chosen: the default site runtime, v2 since 1.0.35.
	input.SiteRuntimeSchema = ""
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatalf("v2 Start: %v", err)
	}
	return input, started.Candidate
}

// Start encrypts one artifact per target node (canary and expand); each node
// opens its own and gets the candidate policy in its v2 document. Canary
// healthy → expand → all healthy → promoted, the binding's policy active.
func TestSiteRuntimeV2ActivationCanaryExpandPromote(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	input, candidate := startV2Activation(t, fixture, store, "v2-activation-promote", 1)
	if candidate.Status != StatusClaimed || len(candidate.CanaryNodeIDs) != 1 || len(candidate.ExpandNodeIDs) != 1 {
		t.Fatalf("v2 candidate = %+v", candidate)
	}
	artifacts := loadV2NodeArtifacts(t, fixture, candidate)
	// Each node has its own key envelope; all run the shared root, whose
	// digest is the candidate's identity.
	if len(artifacts) != 2 || artifacts[fixture.canaryNodeID].artifactID == artifacts[fixture.expandNodeID].artifactID ||
		artifacts[fixture.canaryNodeID].digest != candidate.CandidateArtifactSHA256 ||
		artifacts[fixture.expandNodeID].digest != candidate.CandidateArtifactSHA256 {
		t.Fatalf("v2 node artifacts = %+v", artifacts)
	}
	for _, capability := range candidate.RequiredCapabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME && capability.ApiVersion < 2 {
			t.Fatalf("v2 candidate requires site runtime %d", capability.ApiVersion)
		}
	}
	canaryNode := candidate.CanaryNodeIDs[0]
	bundle, binding, maxAttempts := openV2PhaseBundle(t, fixture, candidate, "canary", canaryNode)
	if maxAttempts != 1 || binding.DeploymentID != artifacts[canaryNode].deploymentID ||
		binding.ArtifactID != artifacts[canaryNode].artifactID || binding.EventID != artifacts[canaryNode].eventID {
		t.Fatalf("canary deployment %+v (max attempts %d) is not the pre-assigned binding %+v",
			binding, maxAttempts, artifacts[canaryNode])
	}
	if got := v2SitePolicyVersion(t, bundle, fixture.siteID, fixture.policyID); got != input.PolicyVersion {
		t.Fatalf("canary document policy version = %d, want %d", got, input.PolicyVersion)
	}

	// A digest no artifact of the deployment has is not an active identity
	// (migration 087).
	for name, digest := range map[string][sha256.Size]byte{
		"unbound": sha256.Sum256([]byte("not an artifact of the deployment")),
	} {
		if err := reportV2PhaseHealthy(t, fixture, candidate, "canary", func(uuid.UUID) [sha256.Size]byte {
			return digest
		}); err == nil || !strings.Contains(err.Error(), "P8702") {
			t.Fatalf("canary reporting the %s digest: %v, want P8702", name, err)
		}
	}
	fixture2, store2, input2, candidate2 := fixture, store, input, candidate
	markV2PhaseHealthy(t, fixture2, candidate2, "canary")
	canary, err := store2.Reconcile(t.Context(), fixture2.actor, productionReconcileInput(candidate2, "v2-canary"))
	if err != nil || canary.Action != string(actionExpand) || canary.Candidate.Status != StatusCanary {
		t.Fatalf("v2 canary Reconcile = (%+v, %v)", canary, err)
	}
	expandNode := candidate2.ExpandNodeIDs[0]
	expandBundle, expandBinding, expandAttempts := openV2PhaseBundle(t, fixture2, candidate2, "expand", expandNode)
	expected := loadV2NodeArtifacts(t, fixture2, candidate2)[expandNode]
	if expandAttempts != 1 || expandBinding.DeploymentID != expected.deploymentID || expandBinding.ArtifactID != expected.artifactID {
		t.Fatalf("expand deployment %+v is not the pre-assigned binding %+v", expandBinding, expected)
	}
	if got := v2SitePolicyVersion(t, expandBundle, fixture2.siteID, fixture2.policyID); got != input2.PolicyVersion {
		t.Fatalf("expand document policy version = %d, want %d", got, input2.PolicyVersion)
	}
	markV2PhaseHealthy(t, fixture2, candidate2, "expand")
	final, err := store2.Reconcile(t.Context(), fixture2.actor, productionReconcileInput(candidate2, "v2-expand"))
	if err != nil || final.Action != string(actionPromote) || final.Candidate.Status != StatusPromoted {
		t.Fatalf("v2 expand Reconcile = (%+v, %v)", final, err)
	}
	assertBindingActiveAndSource(t, fixture2.activationFixture, input2.PolicyVersion, fixture2.sourceRevision+1)
}

// A canary that loaded its v2 artifact and then failed fails the candidate;
// the activation rolls that node back to the previous (v1) config without a
// site runtime requirement, and the reverted proof recovers the candidate.
// The expand node never got the candidate.
func TestSiteRuntimeV2ActivationCanaryFailureRecovers(t *testing.T) {
	fixture := newV2ActivationFixture(t)
	store := newProductionActivationStore(t, fixture.activationFixture)
	_, candidate := startV2Activation(t, fixture, store, "v2-activation-recover", 1)
	canaryNode := candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, fixture.activationFixture, candidate, canaryNode); err != nil {
		t.Fatal(err)
	}
	failed, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "v2-canary-failed"))
	if err != nil || failed.Action != string(actionFail) || failed.Candidate.Status != StatusFailed {
		t.Fatalf("v2 failed Reconcile = (%+v, %v)", failed, err)
	}
	var rollouts int
	var action string
	var configID, nodeID uuid.UUID
	var commandBytes []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) OVER (),rollout.action,rollout.config_version_id,
		deployment.node_id,deployment.command_bytes
		FROM security_policy_activation_recovery_rollouts recovery
		JOIN rollouts rollout ON rollout.id=recovery.rollout_id
		JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
		WHERE recovery.candidate_id=$1`, candidate.ID).Scan(&rollouts, &action, &configID, &nodeID, &commandBytes); err != nil {
		t.Fatal(err)
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil {
		t.Fatal(err)
	}
	if rollouts != 1 || action != "rollback" || configID != fixture.previousConfigID || nodeID != canaryNode ||
		len(command.Artifacts) != 0 {
		t.Fatalf("recovery rollouts=%d action=%s config=%s node=%s artifacts=%d", rollouts, action, configID,
			nodeID, len(command.Artifacts))
	}
	for _, capability := range command.RequiredCapabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			t.Fatalf("rollback to the v1 config requires %v", capability)
		}
	}
	assertRecoveryPendingFacts(t, fixture.pool, candidate.ID, 1, 0)
	if err := markProductionRecoveryReverted(t, fixture.activationFixture, candidate.ID, canaryNode); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "v2-recovered"))
	if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
		t.Fatalf("v2 recovery Reconcile = (%+v, %v)", recovered, err)
	}
	assertRecoveryPendingFacts(t, fixture.pool, candidate.ID, 1, 1)
	var expandDeployments int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM rollouts WHERE idempotency_key=$1`,
		derivedKey("expand", candidate.ID.String())).Scan(&expandDeployments); err != nil || expandDeployments != 0 {
		t.Fatalf("expand rollouts after canary failure = %d, %v", expandDeployments, err)
	}
}

// dynamicRoutingNodeFeatures is what a dynamic routing (site_runtime 9)
// agent declares.
func dynamicRoutingNodeFeatures() []*agentv1.Capability {
	features := activationNodeFeatures()
	for _, capability := range features {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			capability.ApiVersion = edgeconfig.DynamicRoutingSiteRuntimeVersion
		}
	}
	return features
}

// Both targets run dynamic routing: the candidate is delivered as the v2
// root (cdnca.edge.site-root/v2) with a key envelope per node. Migration 398:
// the node artifact rows naming the v2 root are accepted (354 refused them
// with P3332), and the activation runs canary → expand → promoted.
func TestSiteRuntimeV2ActivationOnDynamicRoutingNodes(t *testing.T) {
	base := buildActivationFixtureWithFeatures(t, false, dynamicRoutingNodeFeatures())
	fixture := v2ActivationFixture{activationFixture: base, privateKeys: base.nodeKeys}
	store := newProductionActivationStore(t, fixture.activationFixture)
	input, candidate := startV2Activation(t, fixture, store, "v9-activation-promote", 1)
	if candidate.Status != StatusClaimed || len(candidate.CanaryNodeIDs) != 1 || len(candidate.ExpandNodeIDs) != 1 {
		t.Fatalf("v9 candidate = %+v", candidate)
	}
	var rootDigest []byte
	var mediaType string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT sha256,media_type FROM configuration_artifacts
		WHERE config_version_id=$1 AND encryption_algorithm='none'`, candidate.CandidateConfigVersionID).
		Scan(&rootDigest, &mediaType); err != nil {
		t.Fatal(err)
	}
	if mediaType != "application/vnd.cdnca.edge-site-root+json;version=2" ||
		string(rootDigest) != string(candidate.CandidateArtifactSHA256[:]) {
		t.Fatalf("v9 candidate root %s %x, identity %x", mediaType, rootDigest, candidate.CandidateArtifactSHA256)
	}
	artifacts := loadV2NodeArtifacts(t, fixture, candidate)
	if len(artifacts) != 2 || artifacts[fixture.canaryNodeID].artifactID == artifacts[fixture.expandNodeID].artifactID ||
		artifacts[fixture.canaryNodeID].digest != candidate.CandidateArtifactSHA256 ||
		artifacts[fixture.expandNodeID].digest != candidate.CandidateArtifactSHA256 {
		t.Fatalf("v9 node artifacts = %+v", artifacts)
	}
	siteRuntime := uint32(0)
	for _, capability := range candidate.RequiredCapabilities {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
			siteRuntime = capability.ApiVersion
		}
	}
	if siteRuntime != edgeconfig.DynamicRoutingSiteRuntimeVersion {
		t.Fatalf("v9 candidate requires site runtime %d", siteRuntime)
	}
	markV2PhaseHealthy(t, fixture, candidate, "canary")
	canary, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "v9-canary"))
	if err != nil || canary.Action != string(actionExpand) || canary.Candidate.Status != StatusCanary {
		t.Fatalf("v9 canary Reconcile = (%+v, %v)", canary, err)
	}
	markV2PhaseHealthy(t, fixture, candidate, "expand")
	final, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "v9-expand"))
	if err != nil || final.Action != string(actionPromote) || final.Candidate.Status != StatusPromoted {
		t.Fatalf("v9 expand Reconcile = (%+v, %v)", final, err)
	}
	assertBindingActiveAndSource(t, fixture.activationFixture, input.PolicyVersion, fixture.sourceRevision+1)
}
