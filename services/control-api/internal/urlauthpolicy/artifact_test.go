package urlauthpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
)

type artifactTestSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer artifactTestSigner) ArtifactSigningKeyID() string { return signer.id }
func (signer artifactTestSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer artifactTestSigner) SignArtifact(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, value), nil
}

func TestArtifactProducerEncryptsSignsAndBindsURLAuthMaterial(t *testing.T) {
	receiverPublic, receiverPrivate, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := receiverPublic.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	recipientDigest := sha256.Sum256(publicBytes)
	request := ArtifactBuildRequest{
		EventID: uuid.MustParse("01990000-0000-7000-8000-000000000001"), DeploymentID: uuid.MustParse("01990000-0000-7000-8000-000000000002"),
		Attempt: 1, ConfigVersionID: uuid.MustParse("01990000-0000-7000-8000-000000000003"), ArtifactID: uuid.MustParse("01990000-0000-7000-8000-000000000004"),
		ConfigurationScopeID: uuid.MustParse("01990000-0000-7000-8000-000000000008"),
		RecipientKeyID:       "x25519:" + bytesToHex(recipientDigest[:]), RecipientPublicKey: publicBytes,
	}
	material := ArtifactMaterial{
		PolicyID: uuid.MustParse("01990000-0000-7000-8000-000000000005"), TenantID: uuid.MustParse("01990000-0000-7000-8000-000000000006"),
		SiteID: uuid.MustParse("01990000-0000-7000-8000-000000000007"), Revision: 7,
		Snapshot: EdgePolicy{SchemaVersion: SchemaVersion, PolicyVersion: 7, TenantID: "01990000-0000-7000-8000-000000000006", SiteID: "01990000-0000-7000-8000-000000000007", Algorithm: AlgorithmHMACSHA256,
			SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid", MaxValiditySeconds: 300,
			ExcludedQueryParameters: []string{}, TrustedProxies: []string{}, CurrentKey: EdgeKey{KeyID: "k-current", KeyFile: "/var/lib/cdnca-edge/urlauth/keys/01990000-0000-7000-8000-000000000005/k-current.key"}},
		Keys: []ArtifactSecret{{KeyID: "k-current", KeyFile: "/var/lib/cdnca-edge/urlauth/keys/01990000-0000-7000-8000-000000000005/k-current.key", Secret: []byte("secret-current-32-bytes-exactly!")}},
	}
	signer := artifactTestSigner{id: "url-auth-signing-v1", private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))}
	producer, err := newArtifactProducer(signer, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	withoutScope := request
	withoutScope.ConfigurationScopeID = uuid.Nil
	if _, err := producer.Build(t.Context(), withoutScope, material); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Build(without configuration scope) error = %v, want ErrInvalidInput", err)
	}
	artifact, err := producer.Build(t.Context(), request, material)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE || artifact.MediaType != ArtifactMediaType ||
		artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		artifact.RecipientKeyID == nil || *artifact.RecipientKeyID != request.RecipientKeyID ||
		!ed25519.Verify(artifact.SigningPublicKey, artifact.WireBytes, artifact.Signature) {
		t.Fatalf("artifact contract mismatch: %#v", artifact)
	}
	plaintext := decryptArtifactForTest(t, receiverPrivate, request, artifact)
	defer zeroBytes(plaintext)
	var document struct {
		SchemaVersion string `json:"schema_version"`
		Activation    struct {
			PolicyID             string `json:"policy_id"`
			PolicyVersion        uint64 `json:"policy_version"`
			TenantID             string `json:"tenant_id"`
			ConfigurationScopeID string `json:"configuration_scope_id"`
		} `json:"activation"`
		Keys []ArtifactSecret `json:"keys"`
	}
	if err := json.Unmarshal(plaintext, &document); err != nil {
		t.Fatal(err)
	}
	if document.Activation.ConfigurationScopeID != request.ConfigurationScopeID.String() ||
		document.Activation.TenantID != material.TenantID.String() {
		t.Fatalf("activation scope = %q tenant = %q, want scope %s tenant %s", document.Activation.ConfigurationScopeID,
			document.Activation.TenantID, request.ConfigurationScopeID, material.TenantID)
	}
	if document.SchemaVersion != ArtifactSchemaVersion || document.Activation.PolicyID != material.PolicyID.String() ||
		document.Activation.PolicyVersion != 7 || len(document.Keys) != 1 || !bytes.Equal(document.Keys[0].Secret, material.Keys[0].Secret) {
		t.Fatalf("plaintext contract mismatch: %+v", document)
	}
}

func TestArtifactPublicationServiceRequiresProductionDependencies(t *testing.T) {
	if _, err := NewArtifactPublicationService(nil, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("constructor error = %v", err)
	}
}

func decryptArtifactForTest(t *testing.T, privateKey kem.PrivateKey, request ArtifactBuildRequest, artifact edgedeployment.ArtifactInput) []byte {
	t.Helper()
	info, aad, err := artifactContext(artifactMetadataFrom(request, artifact))
	if err != nil {
		t.Fatal(err)
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	encapsulationSize := scheme.CiphertextSize()
	receiver, err := artifactSuite.NewReceiver(privateKey, info)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(artifact.WireBytes[:encapsulationSize])
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := opener.Open(artifact.WireBytes[encapsulationSize:], aad)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func bytesToHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&15]
	}
	return string(result)
}
