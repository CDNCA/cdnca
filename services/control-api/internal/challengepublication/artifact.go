package challengepublication

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
	ArtifactMediaType         = "application/vnd.cdnca.edge-challenge-bundle+json;version=1"
	ArtifactSchemaVersion     = "cdnca.edge.challenge-artifact/v1"
	ArtifactActivationVersion = "cdnca.edge.challenge-activation/v1"
	PolicySchemaVersion       = "cdnca.edge.challenge/v1"
	artifactHPKEBindingDomain = "cdnca-edge-artifact-hpke-binding-v1\x00"
	artifactHPKEInfoDomain    = "cdnca-edge-artifact-hpke-info-v1\x00"
	artifactHPKEAADDomain     = "cdnca-edge-artifact-hpke-aad-v1\x00"
	maxArtifactBytes          = 1 << 20
	artifactHPKETagSize       = 16
)

var (
	ErrInvalidInput      = errors.New("invalid challenge publication input")
	ErrArtifactRecipient = errors.New("invalid challenge artifact recipient")
	ErrArtifactSigning   = errors.New("challenge artifact signing failed")
	ErrEncryption        = errors.New("challenge artifact encryption failed")
	artifactSuite        = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
)

type ArtifactSigner interface {
	ArtifactSigningKeyID() string
	ArtifactSigningPublicKey() ed25519.PublicKey
	SignArtifact(context.Context, []byte) ([]byte, error)
}

type ArtifactBuildRequest struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID uuid.UUID
	Attempt                                            uint32
	RecipientKeyID                                     string
	RecipientPublicKey                                 []byte
}

type BypassRoute struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type KeyReference struct {
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
}

type Rule struct {
	RuleID               string            `json:"rule_id"`
	Priority             uint32            `json:"priority"`
	TenantID             string            `json:"tenant_id"`
	SiteID               string            `json:"site_id"`
	Host                 string            `json:"host"`
	Mode                 string            `json:"mode"`
	MinDelaySeconds      uint32            `json:"min_delay_seconds"`
	ChallengeTTLSeconds  uint32            `json:"challenge_ttl_seconds"`
	PassTTLSeconds       uint32            `json:"pass_ttl_seconds"`
	ClockSkewSeconds     uint32            `json:"clock_skew_seconds"`
	AttemptsPerNonce     uint32            `json:"attempts_per_nonce"`
	FailureWindowSeconds uint32            `json:"failure_window_seconds"`
	MaxFailuresPerWindow uint32            `json:"max_failures_per_window"`
	IPBinding            string            `json:"ip_binding"`
	BindUserAgent        bool              `json:"bind_user_agent"`
	ExternalProvider     *ExternalProvider `json:"external_provider,omitempty"`
}

type ExternalProvider struct {
	Provider string `json:"provider"`
	AppID    string `json:"app_id"`
}

type Policy struct {
	SchemaVersion  string        `json:"schema_version"`
	PolicyVersion  uint64        `json:"policy_version"`
	Algorithm      string        `json:"algorithm"`
	CookieName     string        `json:"cookie_name"`
	TrustedProxies []string      `json:"trusted_proxies"`
	BypassRoutes   []BypassRoute `json:"bypass_routes"`
	CurrentKey     KeyReference  `json:"current_key"`
	PreviousKey    *KeyReference `json:"previous_key,omitempty"`
	Rules          []Rule        `json:"rules"`
}

type ArtifactSecret struct {
	KeyID  string `json:"key_id"`
	Secret []byte `json:"secret"`
}

type ArtifactMaterial struct {
	PolicyID            uuid.UUID
	TenantID            uuid.UUID
	Policy              Policy
	Keys                []ArtifactSecret
	ExternalCredentials []ExternalCredential
}

type ExternalCredential struct {
	TenantID    string `json:"tenant_id"`
	SiteID      string `json:"site_id"`
	Provider    string `json:"provider"`
	AppID       string `json:"app_id"`
	Secret      []byte `json:"secret"`
	Environment string `json:"environment"`
}

type ArtifactActivation struct {
	SchemaVersion   string `json:"schema_version"`
	EventID         string `json:"command_event_id"`
	DeploymentID    string `json:"deployment_id"`
	Attempt         uint32 `json:"attempt"`
	ConfigVersionID string `json:"config_version_id"`
	ArtifactID      string `json:"artifact_id"`
	RecipientKeyID  string `json:"recipient_key_id"`
	PolicyID        string `json:"policy_id"`
	TenantID        string `json:"tenant_id"`
	PolicyVersion   uint64 `json:"policy_version"`
}

type ArtifactDocument struct {
	SchemaVersion       string               `json:"schema_version"`
	Activation          ArtifactActivation   `json:"activation"`
	Policy              Policy               `json:"policy"`
	Keys                []ArtifactSecret     `json:"keys"`
	ExternalCredentials []ExternalCredential `json:"external_credentials,omitempty"`
}

type ArtifactProducer struct {
	signer ArtifactSigner
	random io.Reader
}

func NewArtifactProducer(signer ArtifactSigner) (*ArtifactProducer, error) {
	return newArtifactProducer(signer, rand.Reader)
}

func newArtifactProducer(signer ArtifactSigner, random io.Reader) (*ArtifactProducer, error) {
	if signer == nil || random == nil || !validIdentifier(signer.ArtifactSigningKeyID()) ||
		len(signer.ArtifactSigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &ArtifactProducer{signer: signer, random: random}, nil
}

func (producer *ArtifactProducer) Build(ctx context.Context, request ArtifactBuildRequest, material ArtifactMaterial) (edgedeployment.ArtifactInput, error) {
	if producer == nil || producer.signer == nil || producer.random == nil || ctx == nil ||
		request.EventID == uuid.Nil || request.DeploymentID == uuid.Nil || request.ConfigVersionID == uuid.Nil ||
		request.ArtifactID == uuid.Nil || request.Attempt != 1 {
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
		return edgedeployment.ArtifactInput{}, ErrEncryption
	}
	encapsulation, sealer, err := sender.Setup(producer.random)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrEncryption
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return edgedeployment.ArtifactInput{}, ErrEncryption
	}
	wire := append(append(make([]byte, 0, size), encapsulation...), ciphertext...)
	if len(wire) != size {
		zeroBytes(wire)
		return edgedeployment.ArtifactInput{}, ErrEncryption
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

func normalizeArtifactDocument(request ArtifactBuildRequest, material ArtifactMaterial) (ArtifactDocument, error) {
	if material.PolicyID == uuid.Nil || material.TenantID == uuid.Nil || material.Policy.SchemaVersion != PolicySchemaVersion ||
		material.Policy.PolicyVersion == 0 || material.Policy.PolicyVersion > 1<<53-1 || material.Policy.Algorithm != "hmac-sha256" ||
		material.Policy.CurrentKey.KeyFile != "" || len(material.Policy.Rules) == 0 || len(material.Policy.Rules) > 64 {
		return ArtifactDocument{}, ErrInvalidInput
	}
	want := []KeyReference{material.Policy.CurrentKey}
	if material.Policy.PreviousKey != nil {
		if material.Policy.PreviousKey.KeyFile != "" {
			return ArtifactDocument{}, ErrInvalidInput
		}
		want = append(want, *material.Policy.PreviousKey)
	}
	if len(want) != len(material.Keys) || len(want) > 2 {
		return ArtifactDocument{}, ErrInvalidInput
	}
	keys := make([]ArtifactSecret, len(material.Keys))
	for index, key := range material.Keys {
		if !validIdentifier(key.KeyID) || key.KeyID != want[index].KeyID || len(key.Secret) < 32 || len(key.Secret) > 128 {
			clearArtifactSecrets(keys)
			return ArtifactDocument{}, ErrInvalidInput
		}
		keys[index] = ArtifactSecret{KeyID: key.KeyID, Secret: slices.Clone(key.Secret)}
	}
	externalByScope := make(map[string]ExternalCredential, len(material.ExternalCredentials))
	credentials := make([]ExternalCredential, len(material.ExternalCredentials))
	for index, credential := range material.ExternalCredentials {
		if !canonicalUUID(credential.TenantID) || !canonicalUUID(credential.SiteID) ||
			credential.TenantID != material.TenantID.String() ||
			(credential.Provider != "tencent" && credential.Provider != "geetest-v4") ||
			!validIdentifier(credential.AppID) || len(credential.Secret) < 16 || len(credential.Secret) > 256 ||
			(credential.Environment != "sandbox" && credential.Environment != "production") {
			clearArtifactSecrets(keys)
			clearExternalCredentials(credentials)
			return ArtifactDocument{}, ErrInvalidInput
		}
		scope := credential.TenantID + "\x00" + credential.SiteID
		if _, duplicate := externalByScope[scope]; duplicate {
			clearArtifactSecrets(keys)
			clearExternalCredentials(credentials)
			return ArtifactDocument{}, ErrInvalidInput
		}
		credentials[index] = ExternalCredential{TenantID: credential.TenantID, SiteID: credential.SiteID,
			Provider: credential.Provider, AppID: credential.AppID, Secret: slices.Clone(credential.Secret),
			Environment: credential.Environment}
		externalByScope[scope] = credentials[index]
	}
	for _, rule := range material.Policy.Rules {
		if !canonicalUUID(rule.RuleID) || !canonicalUUID(rule.SiteID) || rule.TenantID != material.TenantID.String() {
			clearArtifactSecrets(keys)
			clearExternalCredentials(credentials)
			return ArtifactDocument{}, ErrInvalidInput
		}
		scope := rule.TenantID + "\x00" + rule.SiteID
		credential, exists := externalByScope[scope]
		if rule.Mode == "external" {
			if rule.ExternalProvider == nil || !exists || credential.Provider != rule.ExternalProvider.Provider ||
				credential.AppID != rule.ExternalProvider.AppID {
				clearArtifactSecrets(keys)
				clearExternalCredentials(credentials)
				return ArtifactDocument{}, ErrInvalidInput
			}
			delete(externalByScope, scope)
		} else if rule.ExternalProvider != nil || exists {
			clearArtifactSecrets(keys)
			clearExternalCredentials(credentials)
			return ArtifactDocument{}, ErrInvalidInput
		}
	}
	if len(externalByScope) != 0 {
		clearArtifactSecrets(keys)
		clearExternalCredentials(credentials)
		return ArtifactDocument{}, ErrInvalidInput
	}
	policy := material.Policy
	policy.TrustedProxies = slices.Clone(policy.TrustedProxies)
	policy.BypassRoutes = slices.Clone(policy.BypassRoutes)
	policy.Rules = slices.Clone(policy.Rules)
	return ArtifactDocument{
		SchemaVersion: ArtifactSchemaVersion,
		Activation: ArtifactActivation{
			SchemaVersion: ArtifactActivationVersion, EventID: request.EventID.String(), DeploymentID: request.DeploymentID.String(),
			Attempt: request.Attempt, ConfigVersionID: request.ConfigVersionID.String(), ArtifactID: request.ArtifactID.String(),
			RecipientKeyID: request.RecipientKeyID, PolicyID: material.PolicyID.String(), TenantID: material.TenantID.String(),
			PolicyVersion: material.Policy.PolicyVersion,
		},
		Policy: policy, Keys: keys, ExternalCredentials: credentials,
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

func validIdentifier(value string) bool {
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

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func clearArtifactDocument(document *ArtifactDocument) {
	clearArtifactSecrets(document.Keys)
	clearExternalCredentials(document.ExternalCredentials)
}
func clearArtifactSecrets(keys []ArtifactSecret) {
	for index := range keys {
		zeroBytes(keys[index].Secret)
	}
}
func clearExternalCredentials(credentials []ExternalCredential) {
	for index := range credentials {
		zeroBytes(credentials[index].Secret)
	}
}
func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
