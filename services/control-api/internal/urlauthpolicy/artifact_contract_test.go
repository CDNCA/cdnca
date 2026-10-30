package urlauthpolicy

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestURLAuthProducerConsumerContract(t *testing.T) {
	if [3]string{artifactHPKEBindingDomain, artifactHPKEInfoDomain, artifactHPKEAADDomain} != [3]string{
		"cdnca-edge-artifact-hpke-binding-v1\x00", "cdnca-edge-artifact-hpke-info-v1\x00", "cdnca-edge-artifact-hpke-aad-v1\x00",
	} {
		t.Fatal("producer drifted from the published Agent HPKE protocol domains")
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := recipient.PublicKey().Bytes()
	private := recipient.Bytes()
	defer clear(private)
	digest := sha256.Sum256(public)
	recipientID := "x25519:" + hex.EncodeToString(digest[:])
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signingPrivate)
	request := ArtifactBuildRequest{EventID: uuid.New(), DeploymentID: uuid.New(), Attempt: 1,
		ConfigVersionID: uuid.New(), ArtifactID: uuid.New(), ConfigurationScopeID: uuid.New(),
		RecipientKeyID: recipientID, RecipientPublicKey: public}
	policyID, tenantID, siteID := uuid.New(), uuid.New(), uuid.New()
	keyFile := "/var/lib/cdnca-edge/urlauth/keys/" + policyID.String() + "/k-current.key"
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	material := ArtifactMaterial{PolicyID: policyID, TenantID: tenantID, SiteID: siteID, Revision: 7,
		Snapshot: EdgePolicy{SchemaVersion: SchemaVersion, PolicyVersion: 7, TenantID: tenantID.String(), SiteID: siteID.String(), Algorithm: AlgorithmHMACSHA256,
			SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid", MaxValiditySeconds: 300,
			ExcludedQueryParameters: []string{}, TrustedProxies: []string{}, CurrentKey: EdgeKey{KeyID: "k-current", KeyFile: keyFile}},
		Keys: []ArtifactSecret{{KeyID: "k-current", KeyFile: keyFile, Secret: secret}}}
	producer, err := NewArtifactProducer(artifactTestSigner{id: "url-auth-contract-key", private: signingPrivate})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := producer.Build(t.Context(), request, material)
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(signingPublic, artifact.WireBytes, artifact.Signature) {
		t.Fatal("production artifact signature is invalid")
	}
	// Only the Agent contract test supplies this private directory. This
	// exchange never prints generated test keys or decrypted secret material.
	output := os.Getenv("CDNCA_SECRET_ARTIFACT_CONTRACT_OUTPUT")
	if output == "" {
		return
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("cross-module output must be a private directory")
	}
	command := &agentv1.DeploymentCommand{
		Event:        &commonv1.EventMetadata{EventId: request.EventID.String(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString()},
		DeploymentId: request.DeploymentID.String(), Attempt: request.Attempt, RolloutId: uuid.NewString(),
		ConfigVersionId: request.ConfigVersionID.String(), Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		ConfigurationScopeId: proto.String(request.ConfigurationScopeID.String()),
		DeadlineTime:         timestamppb.New(time.Now().Add(time.Hour)),
		Artifacts: []*agentv1.ArtifactDescriptor{{ArtifactId: artifact.ID.String(), Kind: artifact.Kind, SizeBytes: artifact.SizeBytes,
			Sha256: artifact.SHA256, Signature: artifact.Signature, SigningKeyId: artifact.SigningKeyID,
			SignatureAlgorithm: artifact.SignatureAlgorithm, Compression: artifact.Compression, MediaType: artifact.MediaType,
			EncryptionAlgorithm: artifact.EncryptionAlgorithm, RecipientKeyId: artifact.RecipientKeyID}},
	}
	commandBytes, err := proto.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	fixture := map[string][]byte{"command": commandBytes, "wire": artifact.WireBytes, "recipient_private_key": private, "signing_public_key": signingPublic}
	encoded, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	file, err := os.OpenFile(filepath.Join(output, "url-auth.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(encoded)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("cross-module fixture write failed")
	}
}
