package edgepublish

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"slices"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
)

const (
	configurationArtifactHPKEBindingDomain = "cdnca-edge-artifact-hpke-binding-v1\x00"
	configurationArtifactHPKEInfoDomain    = "cdnca-edge-artifact-hpke-info-v1\x00"
	configurationArtifactHPKEAADDomain     = "cdnca-edge-artifact-hpke-aad-v1\x00"
	configurationArtifactHPKETagSize       = 16
)

var configurationArtifactSuite = hpke.NewSuite(
	hpke.KEM_X25519_HKDF_SHA256,
	hpke.KDF_HKDF_SHA256,
	hpke.AEAD_AES256GCM,
)

type configurationArtifactProducer struct {
	signer ArtifactSigner
	random io.Reader
}

type configurationArtifactMetadata struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID, RecipientKeyID, SigningKeyID, MediaType string
	Attempt                                                                                     uint32
	Kind                                                                                        agentv1.ArtifactKind
	SizeBytes                                                                                   uint64
	SignatureAlgorithm                                                                          agentv1.ArtifactSignatureAlgorithm
	Compression                                                                                 agentv1.ArtifactCompression
	EncryptionAlgorithm                                                                         agentv1.ArtifactEncryptionAlgorithm
}

func newConfigurationArtifactProducer(signer ArtifactSigner, random io.Reader) (*configurationArtifactProducer, error) {
	if nilServiceDependency(signer) || random == nil || !labelPattern.MatchString(signer.KeyID()) ||
		len(signer.PublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &configurationArtifactProducer{signer: signer, random: random}, nil
}

func (producer *configurationArtifactProducer) Build(
	ctx context.Context,
	binding edgedeployment.NodeArtifactBinding,
	recipientPublicKey, plaintext []byte,
	mediaType string,
) (edgedeployment.ArtifactInput, error) {
	if producer == nil || producer.signer == nil || producer.random == nil || ctx == nil ||
		binding.EventID == uuid.Nil || binding.DeploymentID == uuid.Nil || binding.ConfigVersionID == uuid.Nil ||
		binding.ArtifactID == uuid.Nil || binding.NodeID == uuid.Nil || binding.Attempt != 1 ||
		mediaType != siteobject.KeyMediaType || len(plaintext) == 0 {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	recipient, err := configurationArtifactRecipient(binding.RecipientKeyID, recipientPublicKey)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	size := len(plaintext) + hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize() + configurationArtifactHPKETagSize
	if size > maxCanonicalSnapshotBytes {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	metadata := configurationArtifactMetadata{
		EventID: binding.EventID.String(), DeploymentID: binding.DeploymentID.String(), Attempt: binding.Attempt,
		ConfigVersionID: binding.ConfigVersionID.String(), ArtifactID: binding.ArtifactID.String(), RecipientKeyID: binding.RecipientKeyID,
		Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, SizeBytes: uint64(size), SigningKeyID: producer.signer.KeyID(),
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           mediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
	}
	info, aad, err := configurationArtifactContext(metadata)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	sender, err := configurationArtifactSuite.NewSender(recipient, info)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	encapsulation, sealer, err := sender.Setup(producer.random)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	wire := append(append(make([]byte, 0, size), encapsulation...), ciphertext...)
	publicKey := slices.Clone(producer.signer.PublicKey())
	signature, err := producer.signer.Sign(ctx, wire)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, wire, signature) {
		return edgedeployment.ArtifactInput{}, ErrSigningFailed
	}
	digest := sha256.Sum256(wire)
	recipientKeyID := binding.RecipientKeyID
	return edgedeployment.ArtifactInput{
		ID: binding.ArtifactID, Kind: metadata.Kind, WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: slices.Clone(digest[:]),
		Signature: signature, SigningKeyID: metadata.SigningKeyID, SigningPublicKey: publicKey,
		SignatureAlgorithm: metadata.SignatureAlgorithm, Compression: metadata.Compression, MediaType: metadata.MediaType,
		EncryptionAlgorithm: metadata.EncryptionAlgorithm, RecipientKeyID: &recipientKeyID,
	}, nil
}

func configurationArtifactRecipient(keyID string, publicKey []byte) (kem.PublicKey, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	if len(publicKey) != scheme.PublicKeySize() {
		return nil, ErrInvalidInput
	}
	digest := sha256.Sum256(publicKey)
	if keyID != "x25519:"+hex.EncodeToString(digest[:]) {
		return nil, ErrInvalidInput
	}
	key, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return key, nil
}

func configurationArtifactMetadataFrom(
	binding edgedeployment.NodeArtifactBinding,
	artifact edgedeployment.ArtifactInput,
) configurationArtifactMetadata {
	recipient := ""
	if artifact.RecipientKeyID != nil {
		recipient = *artifact.RecipientKeyID
	}
	return configurationArtifactMetadata{
		EventID: binding.EventID.String(), DeploymentID: binding.DeploymentID.String(), Attempt: binding.Attempt,
		ConfigVersionID: binding.ConfigVersionID.String(), ArtifactID: binding.ArtifactID.String(), RecipientKeyID: recipient,
		Kind: artifact.Kind, SizeBytes: artifact.SizeBytes, SigningKeyID: artifact.SigningKeyID,
		SignatureAlgorithm: artifact.SignatureAlgorithm, Compression: artifact.Compression, MediaType: artifact.MediaType,
		EncryptionAlgorithm: artifact.EncryptionAlgorithm,
	}
}

func configurationArtifactContext(metadata configurationArtifactMetadata) ([]byte, []byte, error) {
	binding := append([]byte(nil), configurationArtifactHPKEBindingDomain...)
	var err error
	for _, value := range []string{metadata.EventID, metadata.DeploymentID} {
		binding, err = appendConfigurationArtifactString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, metadata.Attempt)
	for _, value := range []string{metadata.ConfigVersionID, metadata.ArtifactID, metadata.RecipientKeyID} {
		binding, err = appendConfigurationArtifactString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Kind))
	binding = binary.BigEndian.AppendUint64(binding, metadata.SizeBytes)
	binding, err = appendConfigurationArtifactString(binding, metadata.SigningKeyID)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Compression))
	binding, err = appendConfigurationArtifactString(binding, metadata.MediaType)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	return append([]byte(configurationArtifactHPKEInfoDomain), digest[:]...),
		append([]byte(configurationArtifactHPKEAADDomain), binding...), nil
}

func appendConfigurationArtifactString(target []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint32 {
		return nil, ErrInvalidInput
	}
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...), nil
}
