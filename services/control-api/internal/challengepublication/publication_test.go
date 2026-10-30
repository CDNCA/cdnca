package challengepublication

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

func TestSecretArtifactBuilderFreezesRolloutBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := NewArtifactProducer(artifactTestSigner{id: "challenge-signing-v1", private: private})
	if err != nil {
		t.Fatal(err)
	}
	recipient, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	recipientBytes, err := recipient.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	recipientDigest := sha256.Sum256(recipientBytes)
	binding := testSecretBinding(recipientBytes, "x25519:"+hex.EncodeToString(recipientDigest[:]))
	builder, err := NewSecretArtifactBuilder(producer, testArtifactMaterial())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := builder(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ID != binding.ArtifactID || artifact.RecipientKeyID == nil || *artifact.RecipientKeyID != binding.RecipientKeyID ||
		!ed25519.Verify(public, artifact.WireBytes, artifact.Signature) {
		t.Fatal("secret rollout binding was not preserved")
	}
}

func testSecretBinding(publicKey []byte, recipientID string) edgedeployment.SecretArtifactBinding {
	return edgedeployment.SecretArtifactBinding{
		EventID: uuid.MustParse("01990000-0000-7000-8000-000000000001"), DeploymentID: uuid.MustParse("01990000-0000-7000-8000-000000000002"),
		RolloutID: uuid.MustParse("01990000-0000-7000-8000-000000000009"), Attempt: 1,
		ConfigVersionID: uuid.MustParse("01990000-0000-7000-8000-000000000003"), ArtifactID: uuid.MustParse("01990000-0000-7000-8000-000000000004"),
		NodeID: uuid.MustParse("01990000-0000-7000-8000-00000000000a"), RecipientKeyID: recipientID, RecipientPublicKey: publicKey,
	}
}
