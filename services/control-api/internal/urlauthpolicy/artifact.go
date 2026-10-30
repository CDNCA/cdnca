package urlauthpolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"strings"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
)

const (
	ArtifactMediaType         = "application/vnd.cdnca.edge-url-auth-bundle+json;version=1"
	ArtifactSchemaVersion     = "cdnca.edge.urlauth-artifact/v1"
	ArtifactActivationVersion = "cdnca.edge.urlauth-activation/v1"
	artifactHPKEBindingDomain = "cdnca-edge-artifact-hpke-binding-v1\x00"
	artifactHPKEInfoDomain    = "cdnca-edge-artifact-hpke-info-v1\x00"
	artifactHPKEAADDomain     = "cdnca-edge-artifact-hpke-aad-v1\x00"
	maxArtifactBytes          = 1 << 20
	artifactHPKETagSize       = 16
)

var (
	ErrArtifactRecipient = errors.New("invalid URL auth artifact recipient")
	ErrArtifactSigning   = errors.New("URL auth artifact signing failed")
	artifactSuite        = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
)

type ArtifactSigner interface {
	ArtifactSigningKeyID() string
	ArtifactSigningPublicKey() ed25519.PublicKey
	SignArtifact(context.Context, []byte) ([]byte, error)
}

type ArtifactBuildRequest struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID uuid.UUID
	// ConfigurationScopeID is the deployment command's configuration scope
	// (access_scopes.id), not the tenant; the agent requires them to match.
	ConfigurationScopeID uuid.UUID
	Attempt              uint32
	RecipientKeyID       string
	RecipientPublicKey   []byte
}

type ArtifactSecret struct {
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
	Secret  []byte `json:"secret"`
}

type ArtifactMaterial struct {
	PolicyID uuid.UUID
	TenantID uuid.UUID
	SiteID   uuid.UUID
	Revision uint64
	Snapshot EdgePolicy
	Keys     []ArtifactSecret
}

type artifactActivation struct {
	SchemaVersion   string `json:"schema_version"`
	EventID         string `json:"command_event_id"`
	DeploymentID    string `json:"deployment_id"`
	Attempt         uint32 `json:"attempt"`
	ConfigVersionID string `json:"config_version_id"`
	ArtifactID      string `json:"artifact_id"`
	RecipientKeyID  string `json:"recipient_key_id"`
	PolicyID        string `json:"policy_id"`
	TenantID        string `json:"tenant_id"`
	SiteID          string `json:"site_id"`
	PolicyVersion   uint64 `json:"policy_version"`
	// ConfigurationScopeID names the scope whose deployment command carries
	// the artifact; the agent rejects an activation without it.
	ConfigurationScopeID string `json:"configuration_scope_id"`
}

type artifactDocument struct {
	SchemaVersion string             `json:"schema_version"`
	Activation    artifactActivation `json:"activation"`
	Policy        EdgePolicy         `json:"policy"`
	Keys          []ArtifactSecret   `json:"keys"`
}

type ArtifactProducer struct {
	signer ArtifactSigner
	random io.Reader
}

func NewArtifactProducer(signer ArtifactSigner) (*ArtifactProducer, error) {
	return newArtifactProducer(signer, rand.Reader)
}

func newArtifactProducer(signer ArtifactSigner, random io.Reader) (*ArtifactProducer, error) {
	if signer == nil || random == nil || !validArtifactIdentifier(signer.ArtifactSigningKeyID()) ||
		len(signer.ArtifactSigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &ArtifactProducer{signer: signer, random: random}, nil
}

func (producer *ArtifactProducer) Build(ctx context.Context, request ArtifactBuildRequest, material ArtifactMaterial) (edgedeployment.ArtifactInput, error) {
	if producer == nil || producer.signer == nil || producer.random == nil || ctx == nil ||
		request.EventID == uuid.Nil || request.DeploymentID == uuid.Nil || request.ConfigVersionID == uuid.Nil ||
		request.ArtifactID == uuid.Nil || request.ConfigurationScopeID == uuid.Nil || request.Attempt != 1 {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	recipient, err := validateArtifactRecipient(request.RecipientKeyID, request.RecipientPublicKey)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	document, err := normalizeArtifactDocument(request, material)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	plaintext, err := json.Marshal(document)
	clearArtifactDocument(&document)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxArtifactBytes {
		zeroBytes(plaintext)
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	defer zeroBytes(plaintext)
	size := len(plaintext) + hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize() + artifactHPKETagSize
	metadata := artifactMetadata{
		EventID: request.EventID.String(), DeploymentID: request.DeploymentID.String(), Attempt: request.Attempt,
		ConfigVersionID: request.ConfigVersionID.String(), ArtifactID: request.ArtifactID.String(), RecipientKeyID: request.RecipientKeyID,
		Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE, SizeBytes: uint64(size),
		SigningKeyID: producer.signer.ArtifactSigningKeyID(), SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression: agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
	}
	info, aad, err := artifactContext(metadata)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	sender, err := artifactSuite.NewSender(recipient, info)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrEncryptionUnavailable
	}
	encapsulation, sealer, err := sender.Setup(producer.random)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrEncryptionUnavailable
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrEncryptionUnavailable
	}
	wire := append(append(make([]byte, 0, size), encapsulation...), ciphertext...)
	if len(wire) != size {
		zeroBytes(wire)
		return edgedeployment.ArtifactInput{}, ErrEncryptionUnavailable
	}
	signature, err := producer.signer.SignArtifact(ctx, wire)
	publicKey := slices.Clone(producer.signer.ArtifactSigningPublicKey())
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, wire, signature) {
		zeroBytes(wire)
		zeroBytes(signature)
		return edgedeployment.ArtifactInput{}, ErrArtifactSigning
	}
	digest := sha256.Sum256(wire)
	recipientKeyID := request.RecipientKeyID
	return edgedeployment.ArtifactInput{
		ID: request.ArtifactID, Kind: metadata.Kind, WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: slices.Clone(digest[:]),
		Signature: signature, SigningKeyID: metadata.SigningKeyID, SigningPublicKey: publicKey, SignatureAlgorithm: metadata.SignatureAlgorithm,
		Compression: metadata.Compression, MediaType: metadata.MediaType, EncryptionAlgorithm: metadata.EncryptionAlgorithm, RecipientKeyID: &recipientKeyID,
	}, nil
}

func normalizeArtifactDocument(request ArtifactBuildRequest, material ArtifactMaterial) (artifactDocument, error) {
	if material.PolicyID == uuid.Nil || material.TenantID == uuid.Nil || material.SiteID == uuid.Nil || material.Revision == 0 ||
		material.Snapshot.SchemaVersion != SchemaVersion || material.Snapshot.PolicyVersion != material.Revision ||
		material.Snapshot.TenantID != material.TenantID.String() || material.Snapshot.SiteID != material.SiteID.String() ||
		material.Snapshot.Algorithm != AlgorithmHMACSHA256 || len(material.Keys) < 1 || len(material.Keys) > 2 {
		return artifactDocument{}, ErrInvalidInput
	}
	want := []EdgeKey{material.Snapshot.CurrentKey}
	if material.Snapshot.PreviousKey != nil {
		want = append(want, *material.Snapshot.PreviousKey)
	}
	if len(want) != len(material.Keys) {
		return artifactDocument{}, ErrInvalidInput
	}
	keys := make([]ArtifactSecret, len(material.Keys))
	for index, key := range material.Keys {
		if key.KeyID != want[index].KeyID || key.KeyFile != want[index].KeyFile || len(key.Secret) < 32 || len(key.Secret) > 128 {
			clearArtifactSecrets(keys)
			return artifactDocument{}, ErrInvalidInput
		}
		keys[index] = ArtifactSecret{KeyID: key.KeyID, KeyFile: key.KeyFile, Secret: slices.Clone(key.Secret)}
	}
	return artifactDocument{
		SchemaVersion: ArtifactSchemaVersion,
		Activation: artifactActivation{SchemaVersion: ArtifactActivationVersion, EventID: request.EventID.String(), DeploymentID: request.DeploymentID.String(),
			Attempt: request.Attempt, ConfigVersionID: request.ConfigVersionID.String(), ArtifactID: request.ArtifactID.String(), RecipientKeyID: request.RecipientKeyID,
			PolicyID: material.PolicyID.String(), TenantID: material.TenantID.String(), SiteID: material.SiteID.String(), PolicyVersion: material.Revision,
			ConfigurationScopeID: request.ConfigurationScopeID.String()},
		Policy: material.Snapshot, Keys: keys,
	}, nil
}

func validateArtifactRecipient(keyID string, publicKey []byte) (kem.PublicKey, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	if len(publicKey) != scheme.PublicKeySize() {
		return nil, ErrArtifactRecipient
	}
	digest := sha256.Sum256(publicKey)
	if keyID != "x25519:"+hex.EncodeToString(digest[:]) {
		return nil, ErrArtifactRecipient
	}
	key, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, ErrArtifactRecipient
	}
	return key, nil
}

type artifactMetadata struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID, RecipientKeyID, SigningKeyID, MediaType string
	Attempt                                                                                     uint32
	Kind                                                                                        agentv1.ArtifactKind
	SignatureAlgorithm                                                                          agentv1.ArtifactSignatureAlgorithm
	Compression                                                                                 agentv1.ArtifactCompression
	EncryptionAlgorithm                                                                         agentv1.ArtifactEncryptionAlgorithm
	SizeBytes                                                                                   uint64
}

func artifactMetadataFrom(request ArtifactBuildRequest, artifact edgedeployment.ArtifactInput) artifactMetadata {
	recipient := ""
	if artifact.RecipientKeyID != nil {
		recipient = *artifact.RecipientKeyID
	}
	return artifactMetadata{EventID: request.EventID.String(), DeploymentID: request.DeploymentID.String(), Attempt: request.Attempt,
		ConfigVersionID: request.ConfigVersionID.String(), ArtifactID: request.ArtifactID.String(), RecipientKeyID: recipient,
		Kind: artifact.Kind, SizeBytes: artifact.SizeBytes, SigningKeyID: artifact.SigningKeyID,
		SignatureAlgorithm: artifact.SignatureAlgorithm, Compression: artifact.Compression, MediaType: artifact.MediaType,
		EncryptionAlgorithm: artifact.EncryptionAlgorithm}
}

func artifactContext(metadata artifactMetadata) ([]byte, []byte, error) {
	binding := append([]byte(nil), artifactHPKEBindingDomain...)
	var err error
	for _, value := range []string{metadata.EventID, metadata.DeploymentID} {
		binding, err = appendArtifactString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, metadata.Attempt)
	for _, value := range []string{metadata.ConfigVersionID, metadata.ArtifactID, metadata.RecipientKeyID} {
		binding, err = appendArtifactString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Kind))
	binding = binary.BigEndian.AppendUint64(binding, metadata.SizeBytes)
	binding, err = appendArtifactString(binding, metadata.SigningKeyID)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Compression))
	binding, err = appendArtifactString(binding, metadata.MediaType)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	return append([]byte(artifactHPKEInfoDomain), digest[:]...), append([]byte(artifactHPKEAADDomain), binding...), nil
}

func appendArtifactString(target []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint32 {
		return nil, ErrInvalidInput
	}
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...), nil
}

func validArtifactIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			index > 0 && strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func clearArtifactDocument(document *artifactDocument) { clearArtifactSecrets(document.Keys) }
func clearArtifactSecrets(keys []ArtifactSecret) {
	for index := range keys {
		zeroBytes(keys[index].Secret)
	}
}
func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
