//go:build integration

package edgepublish

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSiteRuntimeV2PublicationUsesNodeBoundHPKEArtifacts(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSiteWithPortSets(t, "node-bound-hpke.example", []string{"80"}, []string{"443"}, true)
	seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
	// Every target is site runtime v2 capable; only the recipient key differs.
	seedV2Node := func(nodeID uuid.UUID) []byte {
		return capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
			nodeID, &agentv1.AgentCapabilities{
				AgentVersion: "1.0.0", BuildId: "node-bound-hpke", OperatingSystem: "linux", Architecture: "amd64",
				Features: siteRuntimeV2NodeFeatures(),
			}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey
	}
	seedV2Node(fixture.nodeID)
	unkeyedNode := uuid.New()
	insertPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, unkeyedNode, "node-bound-hpke-unkeyed")
	seedV2Node(unkeyedNode)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE node_artifact_encryption_keys
		SET status='revoked',deactivated_at=$2,deactivation_reason='node-bound HPKE test revocation'
		WHERE node_id=$1 AND status='active'`, unkeyedNode, publishTestClock); err != nil {
		t.Fatal(err)
	}
	// Publication capabilities are bound to the active artifact key (7816d106),
	// so a node without one is refused at the capability gate.
	unkeyedRequest := siteRuntimeV2PublishRequest(fixture, "site-runtime-v2-unkeyed", unkeyedNode, siteRuntimeV2Schema)
	if _, err := fixture.service.Publish(t.Context(), unkeyedRequest); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("unkeyed node publication = %v", err)
	}
	assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
	secondNode := uuid.New()
	insertPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, secondNode, "node-bound-hpke-second")
	secondPrivateKey := seedV2Node(secondNode)
	request := siteRuntimeV2PublishRequest(fixture, "site-runtime-v2-node-hpke", fixture.nodeID, siteRuntimeV2Schema)
	request.NodeIDs = []uuid.UUID{fixture.nodeID, secondNode}
	request.MaxAttempts = 3
	result, err := fixture.service.Publish(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	type nodeArtifact struct {
		nodeID, deploymentID, eventID, configID, artifactID uuid.UUID
		commandBytes, wireBytes                             []byte
		recipientKeyID                                      string
		maxAttempts                                         int
	}
	rows, err := fixture.pool.Query(t.Context(), `SELECT deployment.node_id,deployment.id,deployment.command_event_id,
		deployment.config_version_id,deployment.command_bytes,artifact.id,artifact.wire_bytes,
		artifact.recipient_key_id,rollout.max_attempts
		FROM node_deployments deployment
		JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		JOIN node_deployment_artifacts binding ON binding.deployment_id=deployment.id AND binding.deployment_attempt=deployment.attempt
		JOIN configuration_artifacts artifact ON artifact.id=binding.artifact_id AND artifact.config_version_id=binding.config_version_id
		WHERE deployment.rollout_id=$1 AND artifact.media_type=$2 ORDER BY deployment.node_id`, result.RolloutID,
		siteobject.KeyMediaType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var artifacts []nodeArtifact
	for rows.Next() {
		var value nodeArtifact
		if err := rows.Scan(&value.nodeID, &value.deploymentID, &value.eventID, &value.configID, &value.commandBytes,
			&value.artifactID, &value.wireBytes, &value.recipientKeyID, &value.maxAttempts); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 2 || artifacts[0].artifactID == artifacts[1].artifactID ||
		bytes.Equal(artifacts[0].wireBytes, artifacts[1].wireBytes) {
		t.Fatalf("node artifact set = %+v", artifacts)
	}

	var second nodeArtifact
	for _, artifact := range artifacts {
		if artifact.maxAttempts != 1 {
			t.Fatalf("encrypted rollout max attempts = %d", artifact.maxAttempts)
		}
		command := new(agentv1.DeploymentCommand)
		// Dynamic routing: [shared signed v2 root, this node's key envelope].
		if err := proto.Unmarshal(artifact.commandBytes, command); err != nil || len(command.Artifacts) != 2 ||
			command.Artifacts[0].MediaType != siteobject.RootMediaTypeV2 {
			t.Fatalf("decode node command = %+v, %v", command, err)
		}
		descriptor := command.Artifacts[1]
		if descriptor.ArtifactId != artifact.artifactID.String() || descriptor.GetRecipientKeyId() != artifact.recipientKeyID ||
			descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
			t.Fatalf("node descriptor = %+v", descriptor)
		}
		if artifact.nodeID == secondNode {
			second = artifact
		}
	}
	if second.nodeID == uuid.Nil {
		t.Fatal("second node artifact is missing")
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(second.commandBytes, command); err != nil {
		t.Fatal(err)
	}
	descriptor := command.Artifacts[1]
	binding := edgedeployment.NodeArtifactBinding{NodeID: second.nodeID, DeploymentID: second.deploymentID,
		EventID: second.eventID, Attempt: 1, ConfigVersionID: second.configID, ArtifactID: second.artifactID,
		RecipientKeyID: second.recipientKeyID}
	plaintext, err := openUnitConfigurationArtifact(secondPrivateKey, binding, edgedeployment.ArtifactInput{
		ID: second.artifactID, Kind: descriptor.Kind, WireBytes: second.wireBytes, SizeBytes: descriptor.SizeBytes,
		SHA256: descriptor.Sha256, Signature: descriptor.Signature, SigningKeyID: descriptor.SigningKeyId,
		SigningPublicKey: fixture.signer.PublicKey(), SignatureAlgorithm: descriptor.SignatureAlgorithm,
		Compression: descriptor.Compression, MediaType: descriptor.MediaType,
		EncryptionAlgorithm: descriptor.EncryptionAlgorithm, RecipientKeyID: descriptor.RecipientKeyId,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := siteobject.ParseKeyDocument(plaintext)
	if err != nil || key.ConfigVersionID != result.ConfigVersionID.String() ||
		key.RootSHA256 != hex.EncodeToString(command.Artifacts[0].Sha256) {
		t.Fatalf("decrypted key document = %+v, %v", key, err)
	}
	if release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, second.deploymentID, secondPrivateKey); err != nil ||
		len(release.Bundle.Files["site-runtime.v2.json"]) == 0 {
		t.Fatalf("second node release: %v", err)
	}

	artifactConfig := edgeartifact.DefaultConfig()
	artifactStore, err := edgeartifact.NewStoreWithClock(fixture.pool, artifactConfig, func() time.Time { return publishTestClock })
	if err != nil {
		t.Fatal(err)
	}
	fetch := &controlv1.FetchArtifactRequest{
		Request: &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.New(publishTestClock), CorrelationId: uuid.NewString()},
		EventId: second.eventID.String(), NodeId: second.nodeID.String(), DeploymentId: second.deploymentID.String(),
		Attempt: 1, ArtifactId: second.artifactID.String(), GatewayInstanceId: uuid.NewString(),
	}
	first, err := artifactStore.FetchChunk(t.Context(), fetch)
	if err != nil || first.Response == nil || !bytes.Equal(first.Response.Chunk.Data, second.wireBytes) {
		t.Fatalf("initial ciphertext fetch = %+v, %v", first, err)
	}
	replayed, err := artifactStore.FetchChunk(t.Context(), fetch)
	if err != nil || !replayed.Replayed || replayed.Response == nil || !bytes.Equal(replayed.Response.Chunk.Data, second.wireBytes) {
		t.Fatalf("ciphertext fetch replay = %+v, %v", replayed, err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE node_artifact_encryption_keys SET status='revoked',
		deactivated_at=$2,deactivation_reason='integration revocation' WHERE id=$1`, second.recipientKeyID, publishTestClock); err != nil {
		t.Fatal(err)
	}
	fresh := proto.Clone(fetch).(*controlv1.FetchArtifactRequest)
	fresh.Request.RequestId = uuid.NewString()
	if _, err := artifactStore.FetchChunk(context.Background(), fresh); !errors.Is(err, edgeartifact.ErrBindingConflict) {
		t.Fatalf("revoked recipient fetch = %v", err)
	}
}
