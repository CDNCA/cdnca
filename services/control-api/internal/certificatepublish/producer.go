package certificatepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/google/uuid"
)

const (
	CertificateArtifactMediaType     = "application/vnd.cdnca.edge-certificate-bundle+json;version=1"
	CertificateArtifactSchemaVersion = "cdnca.edge.certificate-artifact/v1"
	CertificateActivationVersion     = "cdnca.edge.certificate-activation/v1"
	CertificateBundleVersion         = "cdnca.edge.certificates/v1"

	hpkeBindingDomain = "cdnca-edge-artifact-hpke-binding-v1\x00"
	hpkeInfoDomain    = "cdnca-edge-artifact-hpke-info-v1\x00"
	hpkeAADDomain     = "cdnca-edge-artifact-hpke-aad-v1\x00"
	hpkeTagSize       = 16

	// A publication carries the sites it changes, each with its binding
	// revision; the node keeps every site. Only the encrypted size is bounded.
	maxArtifactWireBytes = 4 << 20
	maxCertificateBytes  = 128 << 10
	maxPrivateKeyBytes   = 32 << 10
)

var (
	ErrInvalidInput = errors.New("invalid certificate publication input")
	ErrRecipientKey = errors.New("invalid certificate publication recipient key")
	ErrEncryption   = errors.New("certificate publication encryption failed")
	ErrSigning      = errors.New("certificate publication signing failed")
)

var artifactHPKESuite = hpke.NewSuite(
	hpke.KEM_X25519_HKDF_SHA256,
	hpke.KDF_HKDF_SHA256,
	hpke.AEAD_AES256GCM,
)

type ArtifactSigner interface {
	ArtifactSigningKeyID() string
	ArtifactSigningPublicKey() ed25519.PublicKey
	SignArtifact(context.Context, []byte) ([]byte, error)
}

type Producer struct {
	signer ArtifactSigner
	random io.Reader
}

type BuildRequest struct {
	EventID            uuid.UUID
	DeploymentID       uuid.UUID
	Attempt            uint32
	ConfigVersionID    uuid.UUID
	ArtifactID         uuid.UUID
	RecipientKeyID     string
	RecipientPublicKey []byte
	Materials          []certificateasset.PublicationMaterial
	// Set by BuildRemoval only.
	removalScopeID uuid.UUID
	removedSites   []RemovedSite
}

type RemovalBuildRequest struct {
	EventID            uuid.UUID
	DeploymentID       uuid.UUID
	Attempt            uint32
	ConfigVersionID    uuid.UUID
	ArtifactID         uuid.UUID
	RecipientKeyID     string
	RecipientPublicKey []byte
	TenantScopeID      uuid.UUID
	RemovedSites       []RemovedSite
}

// RemovedSite is a site whose binding was removed at BindingRevision (its
// unbind fact's sequence): the node drops it and refuses older bindings.
type RemovedSite struct {
	TenantID        uuid.UUID
	SiteID          uuid.UUID
	BindingRevision int64
}

func (request RemovalBuildRequest) buildRequest() BuildRequest {
	return BuildRequest{
		EventID: request.EventID, DeploymentID: request.DeploymentID, Attempt: request.Attempt,
		ConfigVersionID: request.ConfigVersionID, ArtifactID: request.ArtifactID,
		RecipientKeyID: request.RecipientKeyID, RecipientPublicKey: request.RecipientPublicKey,
		removalScopeID: request.TenantScopeID, removedSites: request.RemovedSites,
	}
}

func NewProducer(signer ArtifactSigner) (*Producer, error) {
	return newProducer(signer, rand.Reader)
}

func newProducer(signer ArtifactSigner, random io.Reader) (*Producer, error) {
	if signer == nil || random == nil || !validIdentifier(signer.ArtifactSigningKeyID()) ||
		len(signer.ArtifactSigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidInput
	}
	return &Producer{signer: signer, random: random}, nil
}

func (p *Producer) Build(ctx context.Context, request BuildRequest) (edgedeployment.ArtifactInput, error) {
	return p.build(ctx, request, false)
}

func (p *Producer) BuildRemoval(
	ctx context.Context,
	request RemovalBuildRequest,
) (edgedeployment.ArtifactInput, error) {
	return p.build(ctx, request.buildRequest(), true)
}

func (p *Producer) build(
	ctx context.Context,
	request BuildRequest,
	allowEmpty bool,
) (edgedeployment.ArtifactInput, error) {
	if p == nil || p.signer == nil || p.random == nil || ctx == nil ||
		request.EventID == uuid.Nil || request.DeploymentID == uuid.Nil || request.Attempt != 1 ||
		request.ConfigVersionID == uuid.Nil || request.ArtifactID == uuid.Nil ||
		allowEmpty != (len(request.Materials) == 0) || allowEmpty != (len(request.removedSites) != 0) {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	removedSites, err := normalizeRemovedSites(request.removalScopeID, request.removedSites)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	request.removedSites = removedSites

	recipientKey, err := validateRecipient(request.RecipientKeyID, request.RecipientPublicKey)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	materials, err := normalizeMaterials(request.Materials)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	plaintext, err := encodeDocument(request, materials)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	defer clearBytes(plaintext)

	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	size := len(plaintext) + scheme.CiphertextSize() + hpkeTagSize
	if size > maxArtifactWireBytes {
		return edgedeployment.ArtifactInput{}, ErrInvalidInput
	}
	metadata := artifactMetadata{
		EventID: request.EventID.String(), DeploymentID: request.DeploymentID.String(),
		Attempt: request.Attempt, ConfigVersionID: request.ConfigVersionID.String(),
		ArtifactID: request.ArtifactID.String(), RecipientKeyID: request.RecipientKeyID,
		Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE, SizeBytes: uint64(size),
		SigningKeyID:        p.signer.ArtifactSigningKeyID(),
		SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
		MediaType:           CertificateArtifactMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM,
	}
	info, aad, err := artifactHPKEContext(metadata)
	if err != nil {
		return edgedeployment.ArtifactInput{}, err
	}
	sender, err := artifactHPKESuite.NewSender(recipientKey, info)
	if err != nil {
		return edgedeployment.ArtifactInput{}, fmt.Errorf("%w: initialize sender", ErrEncryption)
	}
	encapsulation, sealer, err := sender.Setup(p.random)
	if err != nil {
		return edgedeployment.ArtifactInput{}, fmt.Errorf("%w: initialize envelope", ErrEncryption)
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		return edgedeployment.ArtifactInput{}, fmt.Errorf("%w: seal plaintext", ErrEncryption)
	}
	wire := make([]byte, 0, size)
	wire = append(wire, encapsulation...)
	wire = append(wire, ciphertext...)
	if len(wire) != size {
		clearBytes(wire)
		return edgedeployment.ArtifactInput{}, fmt.Errorf("%w: wire size mismatch", ErrEncryption)
	}

	signature, err := p.signer.SignArtifact(ctx, wire)
	if err != nil {
		clearBytes(wire)
		return edgedeployment.ArtifactInput{}, fmt.Errorf("%w: signer: %v", ErrSigning, err)
	}
	publicKey := slices.Clone(p.signer.ArtifactSigningPublicKey())
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, wire, signature) {
		clearBytes(wire)
		clearBytes(signature)
		return edgedeployment.ArtifactInput{}, fmt.Errorf("%w: invalid signature", ErrSigning)
	}
	digest := sha256.Sum256(wire)
	recipientKeyID := request.RecipientKeyID
	return edgedeployment.ArtifactInput{
		ID: request.ArtifactID, Kind: metadata.Kind, WireBytes: wire, SizeBytes: uint64(len(wire)),
		SHA256: slices.Clone(digest[:]), Signature: signature, SigningKeyID: metadata.SigningKeyID,
		SigningPublicKey: publicKey, SignatureAlgorithm: metadata.SignatureAlgorithm,
		Compression: metadata.Compression, MediaType: metadata.MediaType,
		EncryptionAlgorithm: metadata.EncryptionAlgorithm, RecipientKeyID: &recipientKeyID,
	}, nil
}

func validateRecipient(keyID string, publicKey []byte) (kem.PublicKey, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	if len(publicKey) != scheme.PublicKeySize() {
		return nil, ErrRecipientKey
	}
	digest := sha256.Sum256(publicKey)
	want := "x25519:" + hex.EncodeToString(digest[:])
	if keyID != want {
		return nil, ErrRecipientKey
	}
	key, err := scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, ErrRecipientKey
	}
	return key, nil
}

func normalizeMaterials(input []certificateasset.PublicationMaterial) ([]certificateasset.PublicationMaterial, error) {
	materials := slices.Clone(input)
	sort.Slice(materials, func(left, right int) bool {
		return bytes.Compare(materials[left].SiteID[:], materials[right].SiteID[:]) < 0
	})
	for index, material := range materials {
		if material.TenantID == uuid.Nil || material.TenantScopeID == uuid.Nil || material.SiteID == uuid.Nil ||
			material.AssetID == uuid.Nil || material.CertificateVersionID == uuid.Nil || material.CertificateVersion <= 0 ||
			material.BindingRevision <= 0 || !validMaterialDomains(materialDomains(material)) || len(material.CertificatePEM) == 0 ||
			len(material.CertificatePEM) > maxCertificateBytes || !utf8.Valid(material.CertificatePEM) ||
			len(material.PrivateKeyPEM) == 0 || len(material.PrivateKeyPEM) > maxPrivateKeyBytes ||
			!utf8.Valid(material.PrivateKeyPEM) || (index > 0 && (material.SiteID == materials[index-1].SiteID ||
			material.TenantID != materials[0].TenantID || material.TenantScopeID != materials[0].TenantScopeID)) {
			return nil, ErrInvalidInput
		}
	}
	return materials, nil
}

// materialDomains is every domain of the material's site (the node resolves
// the certificate for each); SiteDomain alone for a material without them.
func materialDomains(material certificateasset.PublicationMaterial) []string {
	if len(material.SiteDomains) != 0 {
		return material.SiteDomains
	}
	return []string{material.SiteDomain}
}

func validMaterialDomains(domains []string) bool {
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		if domain == "" || strings.TrimSpace(domain) != domain || !utf8.ValidString(domain) {
			return false
		}
		if _, duplicate := seen[domain]; duplicate {
			return false
		}
		seen[domain] = struct{}{}
	}
	return len(domains) != 0
}

func normalizeRemovedSites(scopeID uuid.UUID, input []RemovedSite) ([]RemovedSite, error) {
	if len(input) == 0 {
		return nil, nil
	}
	removed := slices.Clone(input)
	sort.Slice(removed, func(left, right int) bool {
		return bytes.Compare(removed[left].SiteID[:], removed[right].SiteID[:]) < 0
	})
	for index, site := range removed {
		if scopeID == uuid.Nil || site.TenantID == uuid.Nil || site.SiteID == uuid.Nil || site.BindingRevision <= 0 ||
			(index > 0 && (site.SiteID == removed[index-1].SiteID || site.TenantID != removed[0].TenantID)) {
			return nil, ErrInvalidInput
		}
	}
	return removed, nil
}

func encodeDocument(request BuildRequest, materials []certificateasset.PublicationMaterial) ([]byte, error) {
	capacity, err := certificateDocumentCapacity(request, materials)
	if err != nil {
		return nil, err
	}
	result := appendCertificateDocument(make([]byte, 0, capacity), request, materials)
	if len(result) != capacity || cap(result) != capacity {
		clearBytes(result)
		return nil, ErrInvalidInput
	}
	return result, nil
}

func certificateDocumentCapacity(request BuildRequest, materials []certificateasset.PublicationMaterial) (int, error) {
	maxDocumentBytes := maxArtifactWireBytes - hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize() - hpkeTagSize
	capacity := 0
	add := func(lengths ...int) bool {
		for _, length := range lengths {
			if length < 0 || capacity > maxDocumentBytes-length {
				return false
			}
			capacity += length
		}
		return true
	}
	addString := func(value []byte) bool {
		length, ok := encodedJSONStringLength(value)
		return ok && add(length)
	}

	if !add(
		len(`{"schema_version":"`), len(CertificateArtifactSchemaVersion),
		len(`","activation":{"schema_version":"`), len(CertificateActivationVersion),
		len(`","config_version_id":"`), len(request.ConfigVersionID.String()),
		len(`","recipient_key_id":`),
	) || !addString([]byte(request.RecipientKeyID)) || !add(
		len(`,"command_event_id":"`), len(request.EventID.String()),
		len(`","deployment_id":"`), len(request.DeploymentID.String()),
		len(`","attempt":`), len(strconv.FormatUint(uint64(request.Attempt), 10)),
		len(`,"artifact_id":"`), len(request.ArtifactID.String()),
		len(`","certificates":[`),
	) {
		return 0, ErrInvalidInput
	}
	for index, material := range materials {
		if index > 0 && !add(1) {
			return 0, ErrInvalidInput
		}
		if !add(
			len(`{"tenant_id":"`), len(material.TenantID.String()),
			len(`","tenant_scope_id":"`), len(material.TenantScopeID.String()),
			len(`","site_id":"`), len(material.SiteID.String()),
			len(`","certificate_id":"`), len(material.AssetID.String()),
			len(`","certificate_version_id":"`), len(material.CertificateVersionID.String()),
			len(`","version":`), len(strconv.FormatInt(material.CertificateVersion, 10)),
			len(`,"binding_revision":`), len(strconv.FormatInt(material.BindingRevision, 10)), len(`}`),
		) {
			return 0, ErrInvalidInput
		}
	}
	if !add(len(`]`)) {
		return 0, ErrInvalidInput
	}
	if len(request.removedSites) != 0 && !add(len(`,"removed_sites":[`), len(`]`)) {
		return 0, ErrInvalidInput
	}
	for index, removed := range request.removedSites {
		if index > 0 && !add(1) {
			return 0, ErrInvalidInput
		}
		if !add(
			len(`{"tenant_id":"`), len(removed.TenantID.String()),
			len(`","tenant_scope_id":"`), len(request.removalScopeID.String()),
			len(`","site_id":"`), len(removed.SiteID.String()),
			len(`","binding_revision":`), len(strconv.FormatInt(removed.BindingRevision, 10)), len(`}`),
		) {
			return 0, ErrInvalidInput
		}
	}
	if !add(
		len(`},"bundle":{"schema_version":"`), len(CertificateBundleVersion),
		len(`","version_id":"`), len(request.ConfigVersionID.String()),
		len(`","bindings":[`),
	) {
		return 0, ErrInvalidInput
	}
	for index, material := range materials {
		if index > 0 && !add(1) {
			return 0, ErrInvalidInput
		}
		if !add(len(`{"site_id":"`), len(material.SiteID.String()), len(`","domains":[`)) {
			return 0, ErrInvalidInput
		}
		for domainIndex, domain := range materialDomains(material) {
			if domainIndex > 0 && !add(1) || !addString([]byte(domain)) {
				return 0, ErrInvalidInput
			}
		}
		if !add(len(`],"certificate_chain_pem":`)) || !addString(material.CertificatePEM) ||
			!add(len(`,"private_key_pem":`)) || !addString(material.PrivateKeyPEM) || !add(len(`}`)) {
			return 0, ErrInvalidInput
		}
	}
	if !add(len(`]}}`)) {
		return 0, ErrInvalidInput
	}
	return capacity, nil
}

func encodedJSONStringLength(value []byte) (int, bool) {
	length := 2
	for _, character := range value {
		increment := 1
		switch character {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			increment = 2
		default:
			if character < 0x20 {
				increment = 6
			}
		}
		if length > maxArtifactWireBytes-increment {
			return 0, false
		}
		length += increment
	}
	return length, true
}

func appendCertificateDocument(
	result []byte,
	request BuildRequest,
	materials []certificateasset.PublicationMaterial,
) []byte {
	result = append(result, `{"schema_version":"`...)
	result = append(result, CertificateArtifactSchemaVersion...)
	result = append(result, `","activation":{"schema_version":"`...)
	result = append(result, CertificateActivationVersion...)
	result = append(result, `","config_version_id":"`...)
	result = append(result, request.ConfigVersionID.String()...)
	result = append(result, `","recipient_key_id":`...)
	result = appendJSONString(result, []byte(request.RecipientKeyID))
	result = append(result, `,"command_event_id":"`...)
	result = append(result, request.EventID.String()...)
	result = append(result, `","deployment_id":"`...)
	result = append(result, request.DeploymentID.String()...)
	result = append(result, `","attempt":`...)
	result = strconv.AppendUint(result, uint64(request.Attempt), 10)
	result = append(result, `,"artifact_id":"`...)
	result = append(result, request.ArtifactID.String()...)
	result = append(result, `","certificates":[`...)
	for index, material := range materials {
		if index > 0 {
			result = append(result, ',')
		}
		result = append(result, `{"tenant_id":"`...)
		result = append(result, material.TenantID.String()...)
		result = append(result, `","tenant_scope_id":"`...)
		result = append(result, material.TenantScopeID.String()...)
		result = append(result, `","site_id":"`...)
		result = append(result, material.SiteID.String()...)
		result = append(result, `","certificate_id":"`...)
		result = append(result, material.AssetID.String()...)
		result = append(result, `","certificate_version_id":"`...)
		result = append(result, material.CertificateVersionID.String()...)
		result = append(result, `","version":`...)
		result = strconv.AppendInt(result, material.CertificateVersion, 10)
		result = append(result, `,"binding_revision":`...)
		result = strconv.AppendInt(result, material.BindingRevision, 10)
		result = append(result, '}')
	}
	result = append(result, ']')
	if len(request.removedSites) != 0 {
		result = append(result, `,"removed_sites":[`...)
		for index, removed := range request.removedSites {
			if index > 0 {
				result = append(result, ',')
			}
			result = append(result, `{"tenant_id":"`...)
			result = append(result, removed.TenantID.String()...)
			result = append(result, `","tenant_scope_id":"`...)
			result = append(result, request.removalScopeID.String()...)
			result = append(result, `","site_id":"`...)
			result = append(result, removed.SiteID.String()...)
			result = append(result, `","binding_revision":`...)
			result = strconv.AppendInt(result, removed.BindingRevision, 10)
			result = append(result, '}')
		}
		result = append(result, ']')
	}
	result = append(result, `},"bundle":{"schema_version":"`...)
	result = append(result, CertificateBundleVersion...)
	result = append(result, `","version_id":"`...)
	result = append(result, request.ConfigVersionID.String()...)
	result = append(result, `","bindings":[`...)
	for index, material := range materials {
		if index > 0 {
			result = append(result, ',')
		}
		result = append(result, `{"site_id":"`...)
		result = append(result, material.SiteID.String()...)
		result = append(result, `","domains":[`...)
		for domainIndex, domain := range materialDomains(material) {
			if domainIndex > 0 {
				result = append(result, ',')
			}
			result = appendJSONString(result, []byte(domain))
		}
		result = append(result, `],"certificate_chain_pem":`...)
		result = appendJSONString(result, material.CertificatePEM)
		result = append(result, `,"private_key_pem":`...)
		result = appendJSONString(result, material.PrivateKeyPEM)
		result = append(result, '}')
	}
	result = append(result, `]}}`...)
	return result
}

func appendJSONString(target, value []byte) []byte {
	target = append(target, '"')
	const hexadecimal = "0123456789abcdef"
	for _, character := range value {
		switch character {
		case '"', '\\':
			target = append(target, '\\', character)
		case '\b':
			target = append(target, '\\', 'b')
		case '\f':
			target = append(target, '\\', 'f')
		case '\n':
			target = append(target, '\\', 'n')
		case '\r':
			target = append(target, '\\', 'r')
		case '\t':
			target = append(target, '\\', 't')
		default:
			if character < 0x20 {
				target = append(target, '\\', 'u', '0', '0', hexadecimal[character>>4], hexadecimal[character&0x0f])
			} else {
				target = append(target, character)
			}
		}
	}
	return append(target, '"')
}

type artifactMetadata struct {
	EventID             string
	DeploymentID        string
	Attempt             uint32
	ConfigVersionID     string
	ArtifactID          string
	RecipientKeyID      string
	Kind                agentv1.ArtifactKind
	SizeBytes           uint64
	SigningKeyID        string
	SignatureAlgorithm  agentv1.ArtifactSignatureAlgorithm
	Compression         agentv1.ArtifactCompression
	MediaType           string
	EncryptionAlgorithm agentv1.ArtifactEncryptionAlgorithm
}

func artifactHPKEContext(metadata artifactMetadata) ([]byte, []byte, error) {
	binding := make([]byte, 0, 512)
	binding = append(binding, hpkeBindingDomain...)
	var err error
	for _, value := range []string{metadata.EventID, metadata.DeploymentID} {
		binding, err = appendHPKEString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, metadata.Attempt)
	for _, value := range []string{metadata.ConfigVersionID, metadata.ArtifactID, metadata.RecipientKeyID} {
		binding, err = appendHPKEString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Kind))
	binding = binary.BigEndian.AppendUint64(binding, metadata.SizeBytes)
	binding, err = appendHPKEString(binding, metadata.SigningKeyID)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Compression))
	binding, err = appendHPKEString(binding, metadata.MediaType)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	info := append([]byte(hpkeInfoDomain), digest[:]...)
	aad := append([]byte(hpkeAADDomain), binding...)
	return info, aad, nil
}

func appendHPKEString(target []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint32 {
		return nil, ErrInvalidInput
	}
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...), nil
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
