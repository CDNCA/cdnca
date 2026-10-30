package edgepublish

import (
	"bytes"
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
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	OriginAuthArtifactMediaType         = "application/vnd.cdnca.edge-origin-auth-snapshot+hpke;version=1"
	originAuthArtifactSchema            = "cdnca.edge.originauth-snapshot/v1"
	originAuthArtifactActivationSchema  = "cdnca.edge.originauth-activation/v1"
	originAuthArtifactHPKEBindingDomain = "cdnca-edge-artifact-hpke-binding-v1\x00"
	originAuthArtifactHPKEInfoDomain    = "cdnca-edge-artifact-hpke-info-v1\x00"
	originAuthArtifactHPKEAADDomain     = "cdnca-edge-artifact-hpke-aad-v1\x00"
	originAuthArtifactHPKETagSize       = 16
	maxOriginAuthArtifactBytes          = 8 << 20
	maxOriginAuthArtifactRules          = 128
)

var (
	ErrOriginAuthArtifact   = errors.New("invalid origin authentication production artifact")
	originAuthArtifactSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
)

type OriginAuthArtifactSigner interface {
	ArtifactSigningKeyID() string
	ArtifactSigningPublicKey() ed25519.PublicKey
	SignArtifact(context.Context, []byte) ([]byte, error)
}

type OriginAuthProductionSource interface {
	Build(context.Context, pgx.Tx, uuid.UUID) (originauthcontrol.ProductionMaterial, error)
}

type OriginAuthArtifactProducer struct {
	signer OriginAuthArtifactSigner
	random io.Reader
}

type originAuthArtifactActivation struct {
	SchemaVersion       string `json:"schema_version"`
	EventID             string `json:"command_event_id"`
	DeploymentID        string `json:"deployment_id"`
	Attempt             uint32 `json:"attempt"`
	ConfigVersionID     string `json:"config_version_id"`
	ArtifactID          string `json:"artifact_id"`
	NodeID              string `json:"node_id"`
	RecipientKeyID      string `json:"recipient_key_id"`
	TenantID            string `json:"tenant_id"`
	TenantScopeID       string `json:"tenant_scope_id"`
	PublicationID       string `json:"publication_id"`
	PublicationRevision uint64 `json:"publication_revision"`
}

type originAuthArtifactCredential struct {
	RevisionRef     string `json:"revision_ref"`
	Provider        string `json:"provider"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	NotBeforeUnix   int64  `json:"not_before_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

type originAuthArtifactDocument struct {
	SchemaVersion string                                `json:"schema_version"`
	Activation    originAuthArtifactActivation          `json:"activation"`
	Publication   originauthcontrol.PublicationSnapshot `json:"publication"`
	Credentials   []originAuthArtifactCredential        `json:"credentials"`
}

type originAuthArtifactMetadata struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID, NodeID, RecipientKeyID, SigningKeyID, MediaType string
	Attempt                                                                                             uint32
	Kind                                                                                                agentv1.ArtifactKind
	SizeBytes                                                                                           uint64
	SignatureAlgorithm                                                                                  agentv1.ArtifactSignatureAlgorithm
	Compression                                                                                         agentv1.ArtifactCompression
	EncryptionAlgorithm                                                                                 agentv1.ArtifactEncryptionAlgorithm
}

func NewOriginAuthArtifactProducer(signer OriginAuthArtifactSigner) (*OriginAuthArtifactProducer, error) {
	return newOriginAuthArtifactProducer(signer, rand.Reader)
}

func newOriginAuthArtifactProducer(signer OriginAuthArtifactSigner, random io.Reader) (*OriginAuthArtifactProducer, error) {
	if signer == nil || random == nil || !validOriginAuthArtifactIdentifier(signer.ArtifactSigningKeyID()) ||
		len(signer.ArtifactSigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &OriginAuthArtifactProducer{signer: signer, random: random}, nil
}

func NewOriginAuthSecretRolloutSource(scopeID uuid.UUID, source OriginAuthProductionSource, producer *OriginAuthArtifactProducer) (edgedeployment.SecretRolloutSource, error) {
	if scopeID == uuid.Nil || source == nil || producer == nil {
		return nil, ErrInvalidInput
	}
	return func(ctx context.Context, tx pgx.Tx) (edgedeployment.SecretRolloutMaterial, error) {
		material, err := source.Build(ctx, tx, scopeID)
		if err != nil {
			return edgedeployment.SecretRolloutMaterial{}, err
		}
		canonical, canonicalErr := json.Marshal(material.Snapshot)
		if material.TenantScopeID != scopeID || len(material.CanonicalSnapshot) == 0 || canonicalErr != nil ||
			!bytes.Equal(canonical, material.CanonicalSnapshot) || len(material.Snapshot.Rules) == 0 ||
			len(material.Snapshot.Rules) > maxOriginAuthArtifactRules {
			clearOriginAuthProductionMaterial(&material)
			return edgedeployment.SecretRolloutMaterial{}, ErrOriginAuthArtifact
		}
		frozen := cloneOriginAuthProductionMaterial(material)
		return edgedeployment.SecretRolloutMaterial{
			CanonicalSnapshot: bytes.Clone(material.CanonicalSnapshot), PayloadDigest: sha256.Sum256(material.CanonicalSnapshot),
			Builder: func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
				return producer.Build(ctx, binding, frozen)
			},
		}, nil
	}, nil
}

func (producer *OriginAuthArtifactProducer) Build(ctx context.Context, binding edgedeployment.SecretArtifactBinding, material originauthcontrol.ProductionMaterial) (edgedeployment.ArtifactInput, error) {
	if producer == nil || producer.signer == nil || producer.random == nil || ctx == nil || binding.EventID == uuid.Nil ||
		binding.DeploymentID == uuid.Nil || binding.ConfigVersionID == uuid.Nil || binding.ArtifactID == uuid.Nil || binding.NodeID == uuid.Nil || binding.Attempt != 1 {
		return edgedeployment.ArtifactInput{}, ErrOriginAuthArtifact
	}
	recipient, err := validateOriginAuthRecipient(binding.RecipientKeyID, binding.RecipientPublicKey)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	document, err := normalizeOriginAuthArtifactDocument(binding, material)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	plaintext, err := json.Marshal(document)
	clearOriginAuthArtifactDocument(&document)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxOriginAuthArtifactBytes {
		zeroOriginAuthBytes(plaintext)
		return edgedeployment.ArtifactInput{}, ErrOriginAuthArtifact
	}
	defer zeroOriginAuthBytes(plaintext)
	size := len(plaintext) + hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize() + originAuthArtifactHPKETagSize
	metadata := originAuthArtifactMetadata{EventID: binding.EventID.String(), DeploymentID: binding.DeploymentID.String(), Attempt: binding.Attempt,
		ConfigVersionID: binding.ConfigVersionID.String(), ArtifactID: binding.ArtifactID.String(), NodeID: binding.NodeID.String(), RecipientKeyID: binding.RecipientKeyID,
		Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE, SizeBytes: uint64(size), SigningKeyID: producer.signer.ArtifactSigningKeyID(),
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: OriginAuthArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM}
	info, aad, err := originAuthArtifactContext(metadata)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	sender, err := originAuthArtifactSuite.NewSender(recipient, info)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrOriginAuthArtifact
	}
	encapsulation, sealer, err := sender.Setup(producer.random)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrOriginAuthArtifact
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrOriginAuthArtifact
	}
	wire := append(append(make([]byte, 0, size), encapsulation...), ciphertext...)
	signature, err := producer.signer.SignArtifact(ctx, wire)
	publicKey := slices.Clone(producer.signer.ArtifactSigningPublicKey())
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, wire, signature) {
		zeroOriginAuthBytes(wire)
		return edgedeployment.ArtifactInput{}, ErrOriginAuthArtifact
	}
	digest := sha256.Sum256(wire)
	recipientID := binding.RecipientKeyID
	return edgedeployment.ArtifactInput{ID: binding.ArtifactID, Kind: metadata.Kind, WireBytes: wire, SizeBytes: uint64(len(wire)), SHA256: slices.Clone(digest[:]),
		Signature: signature, SigningKeyID: metadata.SigningKeyID, SigningPublicKey: publicKey, SignatureAlgorithm: metadata.SignatureAlgorithm,
		Compression: metadata.Compression, MediaType: metadata.MediaType, EncryptionAlgorithm: metadata.EncryptionAlgorithm, RecipientKeyID: &recipientID}, nil
}

func normalizeOriginAuthArtifactDocument(binding edgedeployment.SecretArtifactBinding, material originauthcontrol.ProductionMaterial) (originAuthArtifactDocument, error) {
	if material.PublicationID == uuid.Nil || material.TenantID == uuid.Nil || material.TenantScopeID == uuid.Nil || material.PublicationRevision == 0 ||
		material.Snapshot.TenantScopeID != material.TenantScopeID || material.Snapshot.PublicationRevision != int64(material.PublicationRevision) || len(material.Snapshot.Rules) == 0 {
		return originAuthArtifactDocument{}, ErrOriginAuthArtifact
	}
	wanted := make(map[uuid.UUID]string)
	for _, rule := range material.Snapshot.Rules {
		wanted[rule.CurrentCredentialRevisionRef] = rule.Provider
		if rule.PreviousCredentialRevisionRef != nil {
			if current := wanted[*rule.PreviousCredentialRevisionRef]; current != "" && current != rule.Provider {
				return originAuthArtifactDocument{}, ErrOriginAuthArtifact
			}
			wanted[*rule.PreviousCredentialRevisionRef] = rule.Provider
		}
	}
	if len(wanted) != len(material.Credentials) {
		return originAuthArtifactDocument{}, ErrOriginAuthArtifact
	}
	credentials := make([]originAuthArtifactCredential, len(material.Credentials))
	seen := make(map[uuid.UUID]struct{}, len(material.Credentials))
	for index, credential := range material.Credentials {
		if credential.RevisionRef == uuid.Nil || wanted[credential.RevisionRef] != credential.Provider || credential.Secret.NotBefore.IsZero() ||
			!credential.Secret.ExpiresAt.After(credential.Secret.NotBefore) {
			clearOriginAuthArtifactCredentials(credentials)
			return originAuthArtifactDocument{}, ErrOriginAuthArtifact
		}
		if _, duplicate := seen[credential.RevisionRef]; duplicate {
			clearOriginAuthArtifactCredentials(credentials)
			return originAuthArtifactDocument{}, ErrOriginAuthArtifact
		}
		seen[credential.RevisionRef] = struct{}{}
		credentials[index] = originAuthArtifactCredential{RevisionRef: credential.RevisionRef.String(), Provider: credential.Provider,
			AccessKeyID: credential.Secret.AccessKeyID, SecretAccessKey: credential.Secret.SecretAccessKey, SessionToken: credential.Secret.SessionToken,
			NotBeforeUnix: credential.Secret.NotBefore.UTC().Unix(), ExpiresAtUnix: credential.Secret.ExpiresAt.UTC().Unix()}
	}
	sortOriginAuthCredentials(credentials)
	return originAuthArtifactDocument{SchemaVersion: originAuthArtifactSchema,
		Activation: originAuthArtifactActivation{SchemaVersion: originAuthArtifactActivationSchema, EventID: binding.EventID.String(), DeploymentID: binding.DeploymentID.String(),
			Attempt: binding.Attempt, ConfigVersionID: binding.ConfigVersionID.String(), ArtifactID: binding.ArtifactID.String(), NodeID: binding.NodeID.String(),
			RecipientKeyID: binding.RecipientKeyID, TenantID: material.TenantID.String(), TenantScopeID: material.TenantScopeID.String(),
			PublicationID: material.PublicationID.String(), PublicationRevision: material.PublicationRevision},
		Publication: material.Snapshot, Credentials: credentials}, nil
}

func validateOriginAuthRecipient(keyID string, publicKey []byte) (kem.PublicKey, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	if len(publicKey) != scheme.PublicKeySize() {
		return nil, ErrOriginAuthArtifact
	}
	digest := sha256.Sum256(publicKey)
	if keyID != "x25519:"+hex.EncodeToString(digest[:]) {
		return nil, ErrOriginAuthArtifact
	}
	key, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, ErrOriginAuthArtifact
	}
	return key, nil
}

func originAuthArtifactContext(metadata originAuthArtifactMetadata) ([]byte, []byte, error) {
	binding := append([]byte(nil), originAuthArtifactHPKEBindingDomain...)
	var err error
	for _, value := range []string{metadata.EventID, metadata.DeploymentID} {
		binding, err = appendOriginAuthArtifactString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, metadata.Attempt)
	for _, value := range []string{metadata.ConfigVersionID, metadata.ArtifactID, metadata.NodeID, metadata.RecipientKeyID} {
		binding, err = appendOriginAuthArtifactString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Kind))
	binding = binary.BigEndian.AppendUint64(binding, metadata.SizeBytes)
	binding, err = appendOriginAuthArtifactString(binding, metadata.SigningKeyID)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Compression))
	binding, err = appendOriginAuthArtifactString(binding, metadata.MediaType)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	return append([]byte(originAuthArtifactHPKEInfoDomain), digest[:]...), append([]byte(originAuthArtifactHPKEAADDomain), binding...), nil
}

func appendOriginAuthArtifactString(target []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint32 {
		return nil, ErrOriginAuthArtifact
	}
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...), nil
}

func validOriginAuthArtifactIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func sortOriginAuthCredentials(values []originAuthArtifactCredential) {
	slices.SortFunc(values, func(left, right originAuthArtifactCredential) int {
		return strings.Compare(left.RevisionRef, right.RevisionRef)
	})
}

func cloneOriginAuthProductionMaterial(material originauthcontrol.ProductionMaterial) originauthcontrol.ProductionMaterial {
	result := material
	result.CanonicalSnapshot = bytes.Clone(material.CanonicalSnapshot)
	result.Snapshot.Rules = append([]originauthcontrol.PublicationRule(nil), material.Snapshot.Rules...)
	result.Credentials = append([]originauthcontrol.ProductionCredentialMaterial(nil), material.Credentials...)
	return result
}

func clearOriginAuthProductionMaterial(material *originauthcontrol.ProductionMaterial) {
	if material == nil {
		return
	}
	zeroOriginAuthBytes(material.CanonicalSnapshot)
	for index := range material.Credentials {
		material.Credentials[index].Secret.AccessKeyID = ""
		material.Credentials[index].Secret.SecretAccessKey = ""
		material.Credentials[index].Secret.SessionToken = ""
	}
}

func clearOriginAuthArtifactDocument(document *originAuthArtifactDocument) {
	clearOriginAuthArtifactCredentials(document.Credentials)
}
func clearOriginAuthArtifactCredentials(values []originAuthArtifactCredential) {
	for index := range values {
		values[index].AccessKeyID = ""
		values[index].SecretAccessKey = ""
		values[index].SessionToken = ""
	}
}
func zeroOriginAuthBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
