package challengepublication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
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

func TestArtifactProducerEncryptsSignsAndBindsChallengeMaterial(t *testing.T) {
	receiverPublic, receiverPrivate, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := receiverPublic.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	recipientDigest := sha256.Sum256(publicBytes)
	request := testArtifactBuildRequest(publicBytes, "x25519:"+hex.EncodeToString(recipientDigest[:]))
	material := testArtifactMaterial()
	signer := artifactTestSigner{id: "challenge-signing-v1", private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))}
	producer, err := newArtifactProducer(signer, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	if err != nil {
		t.Fatal(err)
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
	var document ArtifactDocument
	if err := json.Unmarshal(plaintext, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != ArtifactSchemaVersion || document.Activation.PolicyID != material.PolicyID.String() ||
		document.Activation.TenantID != material.TenantID.String() || document.Activation.PolicyVersion != material.Policy.PolicyVersion ||
		len(document.Policy.Rules) != 1 || len(document.Keys) != 2 ||
		!bytes.Equal(document.Keys[0].Secret, material.Keys[0].Secret) {
		t.Fatalf("plaintext contract mismatch: %+v", document)
	}
}

func TestArtifactProducerRejectsIncompleteRotationAndRecipientMismatch(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := newArtifactProducer(artifactTestSigner{id: "challenge-signing-v1", private: privateKey}, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	material := testArtifactMaterial()
	material.Keys = material.Keys[:1]
	request := testArtifactBuildRequest(publicBytes, "x25519:"+strings.Repeat("0", 64))
	if _, err := producer.Build(t.Context(), request, material); err == nil {
		t.Fatal("invalid recipient and incomplete rotation were accepted")
	}
}

func TestArtifactProducerCarriesExternalCredentialOnlyForExactRuleScope(t *testing.T) {
	public, private, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, _ := public.MarshalBinary()
	digest := sha256.Sum256(publicBytes)
	request := testArtifactBuildRequest(publicBytes, "x25519:"+hex.EncodeToString(digest[:]))
	material := testArtifactMaterial()
	material.Policy.Rules[0].Mode = "external"
	material.Policy.Rules[0].RuleID = material.PolicyID.String()
	material.Policy.Rules[0].ExternalProvider = &ExternalProvider{Provider: "tencent", AppID: "2060000000"}
	material.ExternalCredentials = []ExternalCredential{{
		TenantID: material.TenantID.String(), SiteID: material.Policy.Rules[0].SiteID,
		Provider: "tencent", AppID: "2060000000", Secret: []byte("tencent-controlled-secret-0001"), Environment: "production",
	}}
	producer, err := newArtifactProducer(artifactTestSigner{id: "challenge-signing-v1",
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))},
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := producer.Build(t.Context(), request, material)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := decryptArtifactForTest(t, private, request, artifact)
	defer zeroBytes(plaintext)
	var document ArtifactDocument
	if err := json.Unmarshal(plaintext, &document); err != nil || len(document.ExternalCredentials) != 1 ||
		document.ExternalCredentials[0].TenantID != material.TenantID.String() ||
		document.ExternalCredentials[0].SiteID != material.Policy.Rules[0].SiteID ||
		!bytes.Equal(document.ExternalCredentials[0].Secret, material.ExternalCredentials[0].Secret) {
		t.Fatalf("external artifact = %+v err=%v", document, err)
	}
	material.ExternalCredentials[0].SiteID = uuid.NewString()
	if _, err := producer.Build(t.Context(), request, material); err == nil {
		t.Fatal("cross-site external credential accepted")
	}
}

func testArtifactBuildRequest(publicKey []byte, recipientID string) ArtifactBuildRequest {
	return ArtifactBuildRequest{
		EventID: uuid.MustParse("01990000-0000-7000-8000-000000000001"), DeploymentID: uuid.MustParse("01990000-0000-7000-8000-000000000002"),
		Attempt: 1, ConfigVersionID: uuid.MustParse("01990000-0000-7000-8000-000000000003"), ArtifactID: uuid.MustParse("01990000-0000-7000-8000-000000000004"),
		RecipientKeyID: recipientID, RecipientPublicKey: publicKey,
	}
}

func testArtifactMaterial() ArtifactMaterial {
	return ArtifactMaterial{
		PolicyID: uuid.MustParse("01990000-0000-7000-8000-000000000005"),
		TenantID: uuid.MustParse("01990000-0000-7000-8000-000000000006"),
		Policy: Policy{
			SchemaVersion: PolicySchemaVersion, PolicyVersion: 7, Algorithm: "hmac-sha256", CookieName: "__Host-cdnca_challenge",
			TrustedProxies: []string{}, BypassRoutes: []BypassRoute{}, CurrentKey: KeyReference{KeyID: "key-current"},
			PreviousKey: &KeyReference{KeyID: "key-previous"},
			Rules: []Rule{{RuleID: "01990000-0000-7000-8000-000000000007", Priority: 10,
				TenantID: "01990000-0000-7000-8000-000000000006", SiteID: "01990000-0000-7000-8000-000000000008",
				Host: "edge.example.test", Mode: "click", ChallengeTTLSeconds: 60, PassTTLSeconds: 300,
				ClockSkewSeconds: 10, AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5,
				IPBinding: "exact", BindUserAgent: true}},
		},
		Keys: []ArtifactSecret{{KeyID: "key-current", Secret: []byte("current-challenge-secret-material-01")},
			{KeyID: "key-previous", Secret: []byte("previous-challenge-secret-material-1")}},
	}
}

func decryptArtifactForTest(t *testing.T, privateKey kem.PrivateKey, request ArtifactBuildRequest, artifact edgedeployment.ArtifactInput) []byte {
	t.Helper()
	info, aad, err := artifactContext(artifactMetadataFrom(request, artifact))
	if err != nil {
		t.Fatal(err)
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	receiver, err := artifactSuite.NewReceiver(privateKey, info)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(artifact.WireBytes[:scheme.CiphertextSize()])
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := opener.Open(artifact.WireBytes[scheme.CiphertextSize():], aad)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}
