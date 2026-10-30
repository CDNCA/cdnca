package originauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

const (
	ProductionSnapshotSchema           = "cdnca.edge.originauth-snapshot/v1"
	ProductionSnapshotActivationSchema = "cdnca.edge.originauth-activation/v1"
	ProductionSnapshotMediaType        = "application/vnd.cdnca.edge-origin-auth-snapshot+hpke;version=1"
	productionPublicationSchema        = "cdnca.control.originauth-publication/v1"
	productionHPKEBindingDomain        = "cdnca-edge-artifact-hpke-binding-v1\x00"
	productionHPKEInfoDomain           = "cdnca-edge-artifact-hpke-info-v1\x00"
	productionHPKEAADDomain            = "cdnca-edge-artifact-hpke-aad-v1\x00"
	maxProductionArtifactBytes         = 8 << 20
)

var (
	ErrProductionArtifact   = errors.New("invalid origin authentication production artifact")
	ErrProductionActivation = errors.New("origin authentication production activation failed")
	ErrProductionRollback   = errors.New("origin authentication production rollback failed")
	productionArtifactSuite = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
)

type ProductionArtifactTransport struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID, NodeID, RecipientKeyID, SigningKeyID, MediaType string
	Attempt                                                                                             uint32
	Kind                                                                                                agentv1.ArtifactKind
	SizeBytes                                                                                           uint64
	SHA256, Signature                                                                                   []byte
	SigningPublicKey                                                                                    ed25519.PublicKey
	SignatureAlgorithm                                                                                  agentv1.ArtifactSignatureAlgorithm
	Compression                                                                                         agentv1.ArtifactCompression
	EncryptionAlgorithm                                                                                 agentv1.ArtifactEncryptionAlgorithm
}

type EncryptedProductionSnapshot struct {
	ProductionArtifactTransport
	WireBytes             []byte
	RecipientPrivateKey   []byte
	ExpectedNodeID        string
	ExpectedTenantScopeID string
	// ExpectedPublicationRevision 0: the deployment command does not carry
	// it; the sealed activation's revision is used and the publisher still
	// refuses a revision older than the installed one.
	ExpectedPublicationRevision uint64
}

type productionSnapshotActivation struct {
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

type productionSnapshotRule struct {
	RuleID                        string  `json:"rule_id"`
	SiteID                        string  `json:"site_id"`
	SourcePosition                int     `json:"source_position"`
	Provider                      string  `json:"provider"`
	Algorithm                     string  `json:"algorithm"`
	Endpoint                      string  `json:"endpoint"`
	Bucket                        string  `json:"bucket"`
	PathPrefix                    string  `json:"path_prefix"`
	Region                        string  `json:"region"`
	Service                       string  `json:"service"`
	SignatureTTLSeconds           int     `json:"signature_ttl_seconds"`
	CurrentCredentialRevisionRef  string  `json:"current_credential_revision_ref"`
	PreviousCredentialRevisionRef *string `json:"previous_credential_revision_ref,omitempty"`
	ActivateCurrentAtUnix         int64   `json:"activate_current_at_unix"`
}

type productionSnapshotPublication struct {
	SchemaVersion       string                   `json:"schema_version"`
	TenantScopeID       string                   `json:"tenant_scope_id"`
	PublicationRevision uint64                   `json:"publication_revision"`
	Rules               []productionSnapshotRule `json:"rules"`
}

type productionSnapshotCredential struct {
	RevisionRef     string `json:"revision_ref"`
	Provider        string `json:"provider"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	NotBeforeUnix   int64  `json:"not_before_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

type productionSnapshotDocument struct {
	SchemaVersion string                         `json:"schema_version"`
	Activation    productionSnapshotActivation   `json:"activation"`
	Publication   productionSnapshotPublication  `json:"publication"`
	Credentials   []productionSnapshotCredential `json:"credentials"`
}

type OriginBinding struct {
	SiteID         string `json:"site_id"`
	SourcePosition int    `json:"source_position"`
	RuleID         string `json:"rule_id"`
	Endpoint       string `json:"endpoint"`
}

type ProductionCandidate struct {
	PublicationRevision uint64
	PolicyPath          string
	Bindings            []OriginBinding
}

type ProductionRuntime interface {
	Precheck(context.Context, ProductionCandidate) error
	Activate(context.Context, ProductionCandidate) error
}

type ProductionSnapshotInstaller struct {
	policyRoot, keyRoot string
	publisher           *Publisher
	runtime             ProductionRuntime
	mu                  sync.Mutex
	current             *ProductionCandidate
	// secrets, when set, also receives one worker-readable secret object
	// per rule (dynamic routing, secret_objects.go).
	secrets *SecretObjectDir
}

// WithSecretObjects makes Install write the per-rule secret objects the
// dynamic routing runtime signs with (dir.Root must differ from the policy
// and key roots).
func (installer *ProductionSnapshotInstaller) WithSecretObjects(dir SecretObjectDir) error {
	if installer == nil || !cleanProductionRoot(dir.Root) || dir.Root == installer.policyRoot || dir.Root == installer.keyRoot {
		return ErrProductionArtifact
	}
	installer.secrets = &dir
	return nil
}

const productionCandidateFilename = "production-current.json"

func NewProductionSnapshotInstaller(policyRoot, keyRoot string, runtime ProductionRuntime) (*ProductionSnapshotInstaller, error) {
	if !cleanProductionRoot(policyRoot) || !cleanProductionRoot(keyRoot) || policyRoot == keyRoot || runtime == nil {
		return nil, ErrProductionArtifact
	}
	publisher, err := NewPublisher(policyRoot)
	if err != nil {
		return nil, err
	}
	installer := &ProductionSnapshotInstaller{policyRoot: policyRoot, keyRoot: keyRoot, publisher: publisher, runtime: runtime}
	if candidate, found := loadProductionCandidate(filepath.Join(policyRoot, productionCandidateFilename), policyRoot); found {
		installer.current = candidate
	}
	return installer, nil
}

func (installer *ProductionSnapshotInstaller) Install(ctx context.Context, artifact EncryptedProductionSnapshot) (Publication, error) {
	if installer == nil || installer.publisher == nil || installer.runtime == nil || ctx == nil {
		return Publication{}, ErrProductionArtifact
	}
	plaintext, err := openProductionArtifact(artifact)
	if err != nil {
		return Publication{}, err
	}
	defer clear(plaintext)
	document, err := decodeProductionSnapshot(plaintext)
	if err != nil {
		return Publication{}, err
	}
	defer clearProductionCredentials(document.Credentials)
	if err := validateProductionActivation(document, artifact); err != nil {
		return Publication{}, err
	}
	policy, bindings, credentials, err := installer.productionPolicy(document)
	if err != nil {
		return Publication{}, err
	}
	defer clearProductionCredentials(credentials)
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		return Publication{}, ErrProductionArtifact
	}
	defer clear(policyRaw)

	installer.mu.Lock()
	defer installer.mu.Unlock()
	if err := installer.installProductionCredentials(document.Activation.TenantScopeID, credentials); err != nil {
		return Publication{}, err
	}
	currentPath := filepath.Join(installer.policyRoot, "current.json")
	previousRaw, previousExists := productionCurrent(currentPath)
	previousCandidate := cloneProductionCandidate(installer.current)
	publication, err := installer.publisher.PublishJSON(policyRaw)
	if err != nil {
		return Publication{}, err
	}
	candidate := ProductionCandidate{PublicationRevision: document.Activation.PublicationRevision, PolicyPath: publication.CurrentPath, Bindings: bindings}
	if err := installer.runtime.Precheck(ctx, candidate); err != nil {
		return Publication{}, installer.restoreProduction(ctx, currentPath, previousRaw, previousExists, previousCandidate, err, false)
	}
	if err := installer.runtime.Activate(ctx, candidate); err != nil {
		return Publication{}, installer.restoreProduction(ctx, currentPath, previousRaw, previousExists, previousCandidate, err, true)
	}
	manifest, err := json.Marshal(candidate)
	if err != nil || writeAtomic(filepath.Join(installer.policyRoot, productionCandidateFilename), manifest) != nil {
		return Publication{}, installer.restoreProduction(ctx, currentPath, previousRaw, previousExists, previousCandidate, ErrProductionArtifact, true)
	}
	if installer.secrets != nil {
		if err := installer.writeSecretObjects(policyRaw, document.Activation.PublicationRevision, credentials); err != nil {
			return Publication{}, fmt.Errorf("%w: %v", ErrProductionActivation, err)
		}
	}
	installer.current = &candidate
	return publication, nil
}

// writeSecretObjects compiles policyRaw (credentials are already installed
// under the key root) and writes one secret object per rule.
func (installer *ProductionSnapshotInstaller) writeSecretObjects(policyRaw []byte, revision uint64, credentials []productionSnapshotCredential) error {
	_, compiled, err := CompileJSON(policyRaw)
	if err != nil {
		return err
	}
	byRef := make(map[string]productionSnapshotCredential, len(credentials))
	for _, credential := range credentials {
		byRef[credential.RevisionRef] = credential
	}
	objects, err := secretObjects(compiled, revision, byRef)
	if err != nil {
		return err
	}
	defer func() {
		for index := range objects {
			clearCredential(&objects[index].Rule.CurrentKey.Credential)
			if objects[index].Rule.PreviousKey != nil {
				clearCredential(&objects[index].Rule.PreviousKey.Credential)
			}
		}
	}()
	return installer.secrets.Write(objects)
}

func openProductionArtifact(artifact EncryptedProductionSnapshot) ([]byte, error) {
	transport := artifact.ProductionArtifactTransport
	if !canonicalProductionUUID(transport.EventID) || !canonicalProductionUUID(transport.DeploymentID) || transport.Attempt != 1 ||
		!canonicalProductionUUID(transport.ConfigVersionID) || !canonicalProductionUUID(transport.ArtifactID) || !canonicalProductionUUID(transport.NodeID) ||
		transport.NodeID != artifact.ExpectedNodeID || transport.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
		transport.MediaType != ProductionSnapshotMediaType || transport.SizeBytes != uint64(len(artifact.WireBytes)) || transport.SizeBytes < 48 ||
		transport.SizeBytes > maxProductionArtifactBytes || len(transport.SHA256) != sha256.Size || len(transport.Signature) != ed25519.SignatureSize ||
		len(transport.SigningPublicKey) != ed25519.PublicKeySize || transport.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		transport.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		transport.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		!validProductionRecipientID(transport.RecipientKeyID) || !validIdentifier(transport.SigningKeyID, 128) {
		return nil, ErrProductionArtifact
	}
	digest := sha256.Sum256(artifact.WireBytes)
	if !bytes.Equal(digest[:], transport.SHA256) || !ed25519.Verify(transport.SigningPublicKey, artifact.WireBytes, transport.Signature) {
		return nil, ErrProductionArtifact
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(artifact.RecipientPrivateKey)
	if err != nil {
		return nil, ErrProductionArtifact
	}
	publicWire, err := privateKey.Public().MarshalBinary()
	if err != nil {
		return nil, ErrProductionArtifact
	}
	publicDigest := sha256.Sum256(publicWire)
	if transport.RecipientKeyID != "x25519:"+hex.EncodeToString(publicDigest[:]) {
		return nil, ErrProductionArtifact
	}
	info, aad, err := productionArtifactContext(transport)
	if err != nil {
		return nil, err
	}
	encapsulationSize := scheme.CiphertextSize()
	if len(artifact.WireBytes) <= encapsulationSize {
		return nil, ErrProductionArtifact
	}
	receiver, err := productionArtifactSuite.NewReceiver(privateKey, info)
	if err != nil {
		return nil, ErrProductionArtifact
	}
	opener, err := receiver.Setup(artifact.WireBytes[:encapsulationSize])
	if err != nil {
		return nil, ErrProductionArtifact
	}
	plaintext, err := opener.Open(artifact.WireBytes[encapsulationSize:], aad)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxProductionArtifactBytes {
		clear(plaintext)
		return nil, ErrProductionArtifact
	}
	return plaintext, nil
}

func decodeProductionSnapshot(raw []byte) (productionSnapshotDocument, error) {
	if rejectDuplicateJSONKeys(raw) != nil {
		return productionSnapshotDocument{}, ErrProductionArtifact
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document productionSnapshotDocument
	if decoder.Decode(&document) != nil || requireEOF(decoder) != nil {
		clearProductionCredentials(document.Credentials)
		return productionSnapshotDocument{}, ErrProductionArtifact
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		clearProductionCredentials(document.Credentials)
		return productionSnapshotDocument{}, ErrProductionArtifact
	}
	return document, nil
}

func validateProductionActivation(document productionSnapshotDocument, artifact EncryptedProductionSnapshot) error {
	a := document.Activation
	transport := artifact.ProductionArtifactTransport
	if document.SchemaVersion != ProductionSnapshotSchema || a.SchemaVersion != ProductionSnapshotActivationSchema ||
		a.EventID != transport.EventID || a.DeploymentID != transport.DeploymentID || a.Attempt != transport.Attempt ||
		a.ConfigVersionID != transport.ConfigVersionID || a.ArtifactID != transport.ArtifactID || a.NodeID != transport.NodeID ||
		a.RecipientKeyID != transport.RecipientKeyID || !canonicalProductionUUID(a.TenantID) || !canonicalProductionUUID(a.TenantScopeID) ||
		a.TenantScopeID != artifact.ExpectedTenantScopeID || !canonicalProductionUUID(a.PublicationID) || a.PublicationRevision == 0 ||
		artifact.ExpectedPublicationRevision != 0 && a.PublicationRevision != artifact.ExpectedPublicationRevision ||
		document.Publication.SchemaVersion != productionPublicationSchema ||
		document.Publication.TenantScopeID != a.TenantScopeID || document.Publication.PublicationRevision != a.PublicationRevision {
		return ErrProductionArtifact
	}
	return nil
}

func (installer *ProductionSnapshotInstaller) productionPolicy(document productionSnapshotDocument) (Policy, []OriginBinding, []productionSnapshotCredential, error) {
	if len(document.Publication.Rules) == 0 || len(document.Publication.Rules) > MaxRules {
		return Policy{}, nil, nil, ErrProductionArtifact
	}
	credentials := make(map[string]productionSnapshotCredential, len(document.Credentials))
	for _, credential := range document.Credentials {
		if !canonicalProductionUUID(credential.RevisionRef) || credential.Provider != ProviderS3 && credential.Provider != ProviderOSS && credential.Provider != ProviderCOS ||
			!validSecretField(credential.AccessKeyID, 256) || !validSecretField(credential.SecretAccessKey, 512) ||
			credential.SessionToken != "" && !validSecretField(credential.SessionToken, 4096) || credential.NotBeforeUnix < 0 ||
			credential.ExpiresAtUnix <= credential.NotBeforeUnix {
			return Policy{}, nil, nil, ErrProductionArtifact
		}
		if _, duplicate := credentials[credential.RevisionRef]; duplicate {
			return Policy{}, nil, nil, ErrProductionArtifact
		}
		credentials[credential.RevisionRef] = credential
	}
	policy := Policy{SchemaVersion: SchemaVersion, PolicyVersion: document.Activation.PublicationRevision, Rules: make([]Rule, len(document.Publication.Rules))}
	bindings := make([]OriginBinding, len(document.Publication.Rules))
	usedCredentials := make(map[string]struct{})
	usedOrigins := make(map[string]struct{})
	for index, rule := range document.Publication.Rules {
		if !canonicalProductionUUID(rule.RuleID) || !canonicalProductionUUID(rule.SiteID) || rule.SourcePosition < 1 || rule.SourcePosition > 32 ||
			!canonicalProductionUUID(rule.CurrentCredentialRevisionRef) {
			return Policy{}, nil, nil, ErrProductionArtifact
		}
		origin := fmt.Sprintf("%s/%d", rule.SiteID, rule.SourcePosition)
		if _, duplicate := usedOrigins[origin]; duplicate {
			return Policy{}, nil, nil, ErrProductionArtifact
		}
		usedOrigins[origin] = struct{}{}
		current, found := credentials[rule.CurrentCredentialRevisionRef]
		if !found || current.Provider != rule.Provider {
			return Policy{}, nil, nil, ErrProductionArtifact
		}
		usedCredentials[rule.CurrentCredentialRevisionRef] = struct{}{}
		currentRef := KeyRef{KeyID: rule.CurrentCredentialRevisionRef, SecretFile: installer.productionCredentialPath(document.Activation.TenantScopeID, rule.CurrentCredentialRevisionRef)}
		var previousRef *KeyRef
		if rule.PreviousCredentialRevisionRef != nil {
			previous, found := credentials[*rule.PreviousCredentialRevisionRef]
			if !found || previous.Provider != rule.Provider || rule.ActivateCurrentAtUnix <= 0 || *rule.PreviousCredentialRevisionRef == rule.CurrentCredentialRevisionRef {
				return Policy{}, nil, nil, ErrProductionArtifact
			}
			usedCredentials[*rule.PreviousCredentialRevisionRef] = struct{}{}
			value := KeyRef{KeyID: *rule.PreviousCredentialRevisionRef, SecretFile: installer.productionCredentialPath(document.Activation.TenantScopeID, *rule.PreviousCredentialRevisionRef)}
			previousRef = &value
		} else if rule.ActivateCurrentAtUnix != 0 {
			return Policy{}, nil, nil, ErrProductionArtifact
		}
		policy.Rules[index] = Rule{RuleID: rule.RuleID, Provider: rule.Provider, Algorithm: rule.Algorithm, Endpoint: rule.Endpoint, Bucket: rule.Bucket,
			PathPrefix: rule.PathPrefix, Region: rule.Region, Service: rule.Service, SignatureTTLSeconds: uint32(rule.SignatureTTLSeconds),
			CurrentKey: currentRef, PreviousKey: previousRef, ActivateCurrentAtUnix: rule.ActivateCurrentAtUnix}
		bindings[index] = OriginBinding{SiteID: rule.SiteID, SourcePosition: rule.SourcePosition, RuleID: rule.RuleID, Endpoint: rule.Endpoint}
	}
	if len(usedCredentials) != len(credentials) {
		return Policy{}, nil, nil, ErrProductionArtifact
	}
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].SiteID < bindings[j].SiteID || bindings[i].SiteID == bindings[j].SiteID && bindings[i].SourcePosition < bindings[j].SourcePosition
	})
	orderedCredentials := append([]productionSnapshotCredential(nil), document.Credentials...)
	sort.Slice(orderedCredentials, func(i, j int) bool { return orderedCredentials[i].RevisionRef < orderedCredentials[j].RevisionRef })
	return policy, bindings, orderedCredentials, nil
}

func (installer *ProductionSnapshotInstaller) installProductionCredentials(scopeID string, credentials []productionSnapshotCredential) error {
	directory := filepath.Join(installer.keyRoot, scopeID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return ErrProductionArtifact
	}
	for _, path := range []string{installer.keyRoot, directory} {
		if err := requirePrivateDirectory(path); err != nil {
			return ErrProductionArtifact
		}
	}
	for _, credential := range credentials {
		raw, err := json.Marshal(Credential{SchemaVersion: CredentialVersion, Provider: credential.Provider, AccessKeyID: credential.AccessKeyID,
			SecretAccessKey: credential.SecretAccessKey, SessionToken: credential.SessionToken, NotBeforeUnix: credential.NotBeforeUnix, ExpiresAtUnix: credential.ExpiresAtUnix})
		if err != nil {
			return ErrProductionArtifact
		}
		path := installer.productionCredentialPath(scopeID, credential.RevisionRef)
		existing, readErr := readPrivateRegular(path)
		if readErr == nil {
			if !bytes.Equal(existing, raw) {
				clear(raw)
				return ErrProductionArtifact
			}
			clear(raw)
			continue
		}
		if !errors.Is(readErr, os.ErrNotExist) || writeImmutable(path, raw) != nil {
			clear(raw)
			return ErrProductionArtifact
		}
		clear(raw)
	}
	return nil
}

func (installer *ProductionSnapshotInstaller) productionCredentialPath(scopeID, revisionRef string) string {
	return filepath.Join(installer.keyRoot, scopeID, revisionRef+".json")
}

func (installer *ProductionSnapshotInstaller) restoreProduction(ctx context.Context, currentPath string, previous []byte, existed bool, previousCandidate *ProductionCandidate, cause error, activated bool) error {
	var restoreErr error
	if existed {
		restoreErr = writeAtomic(currentPath, previous)
	} else if err := os.Remove(currentPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		restoreErr = err
	}
	if !existed {
		if err := os.Remove(filepath.Join(installer.policyRoot, "fallback.json")); err != nil && !errors.Is(err, os.ErrNotExist) && restoreErr == nil {
			restoreErr = err
		}
	}
	if restoreErr == nil && activated && previousCandidate != nil {
		restoreErr = installer.runtime.Activate(context.WithoutCancel(ctx), *previousCandidate)
	} else if restoreErr == nil && activated {
		restoreErr = ErrProductionRollback
	}
	if restoreErr != nil {
		return fmt.Errorf("%w: activation=%v rollback=%v", ErrProductionRollback, cause, restoreErr)
	}
	return fmt.Errorf("%w: %v", ErrProductionActivation, cause)
}

func loadProductionCandidate(path, policyRoot string) (*ProductionCandidate, bool) {
	raw, err := readPrivateRegular(path)
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var candidate ProductionCandidate
	if decoder.Decode(&candidate) != nil || requireEOF(decoder) != nil || candidate.PublicationRevision == 0 ||
		candidate.PolicyPath != filepath.Join(policyRoot, "current.json") || len(candidate.Bindings) == 0 || len(candidate.Bindings) > MaxRules {
		return nil, false
	}
	for _, binding := range candidate.Bindings {
		if _, _, err := OpenRestyIncludes(candidate.PolicyPath, binding); err != nil {
			return nil, false
		}
	}
	return &candidate, true
}

func productionCurrent(path string) ([]byte, bool) {
	raw, err := readPrivateRegular(path)
	return raw, err == nil
}

func cloneProductionCandidate(value *ProductionCandidate) *ProductionCandidate {
	if value == nil {
		return nil
	}
	result := *value
	result.Bindings = append([]OriginBinding(nil), value.Bindings...)
	return &result
}

func productionArtifactContext(metadata ProductionArtifactTransport) ([]byte, []byte, error) {
	binding := append([]byte(nil), productionHPKEBindingDomain...)
	var err error
	for _, value := range []string{metadata.EventID, metadata.DeploymentID} {
		binding, err = appendProductionString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, metadata.Attempt)
	for _, value := range []string{metadata.ConfigVersionID, metadata.ArtifactID, metadata.NodeID, metadata.RecipientKeyID} {
		binding, err = appendProductionString(binding, value)
		if err != nil {
			return nil, nil, err
		}
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Kind))
	binding = binary.BigEndian.AppendUint64(binding, metadata.SizeBytes)
	binding, err = appendProductionString(binding, metadata.SigningKeyID)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Compression))
	binding, err = appendProductionString(binding, metadata.MediaType)
	if err != nil {
		return nil, nil, err
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	return append([]byte(productionHPKEInfoDomain), digest[:]...), append([]byte(productionHPKEAADDomain), binding...), nil
}

func appendProductionString(target []byte, value string) ([]byte, error) {
	if len(value) > math.MaxUint32 {
		return nil, ErrProductionArtifact
	}
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...), nil
}

func OpenRestyIncludes(policyPath string, binding OriginBinding) (string, string, error) {
	parsed, err := url.Parse(binding.Endpoint)
	if !cleanProductionRoot(policyPath) || !canonicalProductionUUID(binding.SiteID) || binding.SourcePosition < 1 || binding.SourcePosition > 32 ||
		!canonicalProductionUUID(binding.RuleID) || err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return "", "", ErrProductionArtifact
	}
	httpInclude := "init_by_lua_block {\n  require(\"originauth.engine\").init({ policy_path = " + strconv.Quote(policyPath) + ", reload_interval = 1 })\n}\n"
	accessInclude := "# site=" + binding.SiteID + " source_position=" + strconv.Itoa(binding.SourcePosition) + "\naccess_by_lua_block {\n" +
		"  local ok = require(\"originauth.engine\").access({ rule_id = " + strconv.Quote(binding.RuleID) + ", endpoint = " + strconv.Quote(binding.Endpoint) + " })\n" +
		"  if not ok and not ngx.headers_sent then return ngx.exit(ngx.HTTP_BAD_GATEWAY) end\n}\n"
	return httpInclude, accessInclude, nil
}

func cleanProductionRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && !strings.ContainsAny(path, "\x00\r\n\"'`;{}")
}

func canonicalProductionUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func validProductionRecipientID(value string) bool {
	if !strings.HasPrefix(value, "x25519:") || len(value) != len("x25519:")+64 {
		return false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "x25519:"))
	return err == nil && len(raw) == 32
}
func clearProductionCredentials(values []productionSnapshotCredential) {
	for index := range values {
		values[index].AccessKeyID = ""
		values[index].SecretAccessKey = ""
		values[index].SessionToken = ""
	}
}

// ActiveProductionCandidate is the installed policy and its origin bindings
// as the site runtime renders them; none when nothing is installed.
func ActiveProductionCandidate(policyRoot string) (*ProductionCandidate, bool) {
	if !cleanProductionRoot(policyRoot) {
		return nil, false
	}
	return loadProductionCandidate(filepath.Join(policyRoot, productionCandidateFilename), policyRoot)
}
