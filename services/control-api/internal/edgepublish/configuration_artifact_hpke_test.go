package edgepublish

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

func TestConfigurationArtifactHPKEIsNodeUniqueAndAgentCompatible(t *testing.T) {
	signer := newUnitConfigurationArtifactSigner(t)
	producer, err := newConfigurationArtifactProducer(signer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("signed site runtime v3 bundle")
	configID := uuid.New()
	bindings := make([]edgedeployment.NodeArtifactBinding, 2)
	publicKeys := make([][]byte, len(bindings))
	privateKeys := make([][]byte, len(bindings))
	for index := range bindings {
		bindings[index], publicKeys[index], privateKeys[index] = newUnitConfigurationArtifactBinding(t, configID)
	}

	artifacts := make([]edgedeployment.ArtifactInput, len(bindings))
	for index := range bindings {
		artifacts[index], err = producer.Build(context.Background(), bindings[index], publicKeys[index], plaintext, siteobject.KeyMediaType)
		if err != nil {
			t.Fatalf("Build(%d) error = %v", index, err)
		}
		if artifacts[index].Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION ||
			artifacts[index].EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
			artifacts[index].RecipientKeyID == nil || *artifacts[index].RecipientKeyID != bindings[index].RecipientKeyID ||
			bytes.Equal(artifacts[index].WireBytes, plaintext) {
			t.Fatalf("artifact[%d] metadata = %+v", index, artifacts[index])
		}
		opened, openErr := openUnitConfigurationArtifact(privateKeys[index], bindings[index], artifacts[index])
		if openErr != nil || !bytes.Equal(opened, plaintext) {
			t.Fatalf("open artifact[%d] = (%q, %v)", index, opened, openErr)
		}
	}
	if bytes.Equal(artifacts[0].WireBytes, artifacts[1].WireBytes) || artifacts[0].ID == artifacts[1].ID ||
		*artifacts[0].RecipientKeyID == *artifacts[1].RecipientKeyID {
		t.Fatal("per-node artifacts reused wire, artifact ID, or recipient")
	}
	if _, err := openUnitConfigurationArtifact(privateKeys[1], bindings[0], artifacts[0]); err == nil {
		t.Fatal("wrong recipient key decrypted configuration artifact")
	}
}

func TestConfigurationArtifactHPKEBindsCompleteDeploymentContext(t *testing.T) {
	signer := newUnitConfigurationArtifactSigner(t)
	producer, err := newConfigurationArtifactProducer(signer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding, publicKey, privateKey := newUnitConfigurationArtifactBinding(t, uuid.New())
	artifact, err := producer.Build(context.Background(), binding, publicKey, []byte("configuration"), siteobject.KeyMediaType)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*edgedeployment.NodeArtifactBinding, *edgedeployment.ArtifactInput)
	}{
		{"event", func(value *edgedeployment.NodeArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.EventID = uuid.New()
		}},
		{"deployment", func(value *edgedeployment.NodeArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.DeploymentID = uuid.New()
		}},
		{"attempt", func(value *edgedeployment.NodeArtifactBinding, _ *edgedeployment.ArtifactInput) { value.Attempt++ }},
		{"config", func(value *edgedeployment.NodeArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.ConfigVersionID = uuid.New()
		}},
		{"artifact", func(value *edgedeployment.NodeArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.ArtifactID = uuid.New()
		}},
		{"recipient", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) {
			recipient := "x25519:" + string(bytes.Repeat([]byte{'0'}, 64))
			value.RecipientKeyID = &recipient
		}},
		{"kind", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		}},
		{"size", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) { value.SizeBytes++ }},
		{"signing", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.SigningKeyID += "x"
		}},
		{"compression", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
		}},
		{"media", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.MediaType += ";drift=1"
		}},
		{"encryption", func(_ *edgedeployment.NodeArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedBinding, changedArtifact := binding, artifact
			test.mutate(&changedBinding, &changedArtifact)
			if _, err := openUnitConfigurationArtifact(privateKey, changedBinding, changedArtifact); err == nil {
				t.Fatal("context drift authenticated")
			}
		})
	}
	tampered := artifact
	tampered.WireBytes = bytes.Clone(artifact.WireBytes)
	tampered.WireBytes[len(tampered.WireBytes)-1] ^= 1
	if _, err := openUnitConfigurationArtifact(privateKey, binding, tampered); err == nil {
		t.Fatal("tampered ciphertext authenticated")
	}
}

type unitConfigurationArtifactSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newUnitConfigurationArtifactSigner(t *testing.T) *unitConfigurationArtifactSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &unitConfigurationArtifactSigner{public: publicKey, private: privateKey}
}

func (*unitConfigurationArtifactSigner) KeyID() string                  { return "configuration-artifact-test-key" }
func (s *unitConfigurationArtifactSigner) PublicKey() ed25519.PublicKey { return bytes.Clone(s.public) }
func (s *unitConfigurationArtifactSigner) Sign(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(s.private, value), nil
}

func newUnitConfigurationArtifactBinding(t *testing.T, configID uuid.UUID) (edgedeployment.NodeArtifactBinding, []byte, []byte) {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.PublicKey().Bytes()
	digest := sha256.Sum256(publicKey)
	return edgedeployment.NodeArtifactBinding{
		NodeID: uuid.New(), DeploymentID: uuid.New(), EventID: uuid.New(), Attempt: 1,
		ConfigVersionID: configID, ArtifactID: uuid.New(),
		RecipientKeyID: "x25519:" + hex.EncodeToString(digest[:]),
	}, bytes.Clone(publicKey), privateKey.Bytes()
}

func openUnitConfigurationArtifact(privateKey []byte, binding edgedeployment.NodeArtifactBinding, artifact edgedeployment.ArtifactInput) ([]byte, error) {
	info, aad, err := configurationArtifactContext(configurationArtifactMetadataFrom(binding, artifact))
	if err != nil {
		return nil, err
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	key, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil || len(artifact.WireBytes) < scheme.CiphertextSize()+configurationArtifactHPKETagSize {
		return nil, errors.New("invalid private key or wire")
	}
	receiver, err := configurationArtifactSuite.NewReceiver(key, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(artifact.WireBytes[:scheme.CiphertextSize()])
	if err != nil {
		return nil, err
	}
	return opener.Open(artifact.WireBytes[scheme.CiphertextSize():], aad)
}
