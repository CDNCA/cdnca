package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
)

const (
	ArtifactSchemaVersion   = "cdnca.edge.challenge-artifact/v1"
	ActivationSchemaVersion = "cdnca.edge.challenge-activation/v1"
	MaxArtifactBytes        = MaxPolicyBytes + 4096
)

type ArtifactBinding struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID, RecipientKeyID string
	PolicyID, TenantID                                                 string
	Attempt                                                            uint32
	PolicyVersion                                                      uint64
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

type ArtifactKey struct {
	KeyID  string `json:"key_id"`
	Secret []byte `json:"secret"`
}

type ArtifactDocument struct {
	SchemaVersion       string                       `json:"schema_version"`
	Activation          ArtifactActivation           `json:"activation"`
	Policy              Policy                       `json:"policy"`
	Keys                []ArtifactKey                `json:"keys"`
	ExternalCredentials []ArtifactExternalCredential `json:"external_credentials,omitempty"`
}

type ArtifactExternalCredential struct {
	TenantID    string              `json:"tenant_id"`
	SiteID      string              `json:"site_id"`
	Provider    ExternalProvider    `json:"provider"`
	AppID       string              `json:"app_id"`
	Secret      []byte              `json:"secret"`
	Environment ExternalEnvironment `json:"environment"`
}

type ArtifactResult struct {
	PolicyID       string
	TenantID       string
	PolicyVersion  uint64
	SHA256         [sha256.Size]byte
	CurrentPath    string
	CredentialPath string
}

type ArtifactInstaller struct {
	stateRoot string
	mu        sync.Mutex
}

func NewArtifactInstaller(stateRoot string) (*ArtifactInstaller, error) {
	if !cleanAbsoluteNonRoot(stateRoot) {
		return nil, invalid("challenge artifact state root must be a clean absolute non-root path")
	}
	info, err := os.Lstat(stateRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, invalid("challenge artifact state root must be a real non-symlink directory")
	}
	return &ArtifactInstaller{stateRoot: stateRoot}, nil
}

func (installer *ArtifactInstaller) InstallJSON(raw []byte, binding ArtifactBinding) (ArtifactResult, error) {
	if installer == nil || len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return ArtifactResult{}, invalid("invalid challenge artifact")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return ArtifactResult{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ArtifactDocument
	if err := decoder.Decode(&document); err != nil {
		return ArtifactResult{}, invalid("decode challenge artifact: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ArtifactResult{}, invalid("challenge artifact has trailing data")
	}
	defer clearArtifactDocumentSecrets(&document)
	if err := installer.validateDocument(document, binding); err != nil {
		return ArtifactResult{}, err
	}

	installer.mu.Lock()
	defer installer.mu.Unlock()
	keysRoot := filepath.Join(installer.stateRoot, "challenge", "keys")
	keyRoot, err := openDirectoryPath(keysRoot, true)
	if err != nil {
		return ArtifactResult{}, err
	}
	defer keyRoot.Close()
	if err := requirePrivateDirectory(keyRoot); err != nil {
		return ArtifactResult{}, err
	}
	policyRoot := filepath.Join(installer.stateRoot, "challenge", "policies", binding.PolicyID)
	publisher, err := NewPublisher(policyRoot)
	if err != nil {
		return ArtifactResult{}, err
	}
	lock, err := publisher.lock(keyRoot)
	if err != nil {
		return ArtifactResult{}, err
	}
	defer lock.Close()
	if err := installer.installKeys(keyRoot, document.Keys, binding.PolicyID); err != nil {
		return ArtifactResult{}, err
	}
	credentialPath, err := installer.installExternalCredentials(document.ExternalCredentials, binding)
	if err != nil {
		return ArtifactResult{}, err
	}
	for index := range document.Keys {
		path := filepath.Join(keysRoot, binding.PolicyID, document.Keys[index].KeyID+".key")
		if index == 0 {
			document.Policy.CurrentKey.KeyFile = path
		} else {
			document.Policy.PreviousKey.KeyFile = path
		}
	}
	policy, err := json.Marshal(document.Policy)
	if err != nil {
		return ArtifactResult{}, fmt.Errorf("marshal challenge policy: %w", err)
	}
	defer clearArtifactBytes(policy)
	publication, err := publisher.PublishJSON(policy)
	if err != nil {
		return ArtifactResult{}, err
	}
	immutablePath := filepath.Join(policyRoot, "versions", fmt.Sprintf("%020d.json", publication.PolicyVersion))
	return ArtifactResult{
		PolicyID: binding.PolicyID, TenantID: binding.TenantID, PolicyVersion: publication.PolicyVersion,
		SHA256: publication.SHA256, CurrentPath: immutablePath, CredentialPath: credentialPath,
	}, nil
}

func (installer *ArtifactInstaller) validateDocument(document ArtifactDocument, binding ArtifactBinding) error {
	activation := document.Activation
	if !canonicalArtifactUUID(binding.EventID) || !canonicalArtifactUUID(binding.DeploymentID) ||
		!canonicalArtifactUUID(binding.ConfigVersionID) || !canonicalArtifactUUID(binding.ArtifactID) ||
		!canonicalArtifactUUID(binding.PolicyID) || !canonicalArtifactUUID(binding.TenantID) ||
		!validArtifactRecipientKeyID(binding.RecipientKeyID) || document.SchemaVersion != ArtifactSchemaVersion ||
		activation.SchemaVersion != ActivationSchemaVersion || activation.EventID != binding.EventID ||
		activation.DeploymentID != binding.DeploymentID || activation.Attempt != binding.Attempt ||
		activation.ConfigVersionID != binding.ConfigVersionID || activation.ArtifactID != binding.ArtifactID ||
		activation.RecipientKeyID != binding.RecipientKeyID || activation.PolicyID != binding.PolicyID ||
		activation.TenantID != binding.TenantID || activation.PolicyVersion != binding.PolicyVersion ||
		binding.Attempt != 1 || binding.PolicyVersion == 0 || document.Policy.SchemaVersion != SchemaVersion ||
		document.Policy.PolicyVersion != binding.PolicyVersion || document.Policy.CurrentKey.KeyFile != "" {
		return invalid("challenge artifact binding mismatch")
	}
	want := []KeyRef{document.Policy.CurrentKey}
	if document.Policy.PreviousKey != nil {
		if document.Policy.PreviousKey.KeyFile != "" {
			return invalid("challenge artifact key path must be assigned by the agent")
		}
		want = append(want, *document.Policy.PreviousKey)
	}
	if len(document.Keys) != len(want) || len(want) > 2 {
		return invalid("challenge artifact key set mismatch")
	}
	for index, key := range document.Keys {
		if err := validateIdentifier(key.KeyID, MaxKeyIDBytes); err != nil || key.KeyID != want[index].KeyID ||
			len(key.Secret) < MinKeyBytes || len(key.Secret) > MaxKeyBytes {
			return invalid("challenge artifact key binding mismatch")
		}
	}
	for _, rule := range document.Policy.Rules {
		if rule.TenantID != binding.TenantID || !canonicalArtifactUUID(rule.RuleID) || !canonicalArtifactUUID(rule.SiteID) {
			return invalid("challenge artifact rule scope mismatch")
		}
	}
	credentials := make(map[string]ArtifactExternalCredential, len(document.ExternalCredentials))
	for _, credential := range document.ExternalCredentials {
		if credential.TenantID != binding.TenantID || !canonicalArtifactUUID(credential.SiteID) ||
			(credential.Provider != ProviderTencent && credential.Provider != ProviderGeetestV4) ||
			validateIdentifier(credential.AppID, MaxIdentifierBytes) != nil || len(credential.Secret) < 16 ||
			len(credential.Secret) > 256 ||
			(credential.Environment != ExternalSandbox && credential.Environment != ExternalProduction) {
			return invalid("challenge external credential binding mismatch")
		}
		scope := credential.TenantID + "\x00" + credential.SiteID
		if _, duplicate := credentials[scope]; duplicate {
			return invalid("challenge external credential binding mismatch")
		}
		credentials[scope] = credential
	}
	for _, rule := range document.Policy.Rules {
		scope := rule.TenantID + "\x00" + rule.SiteID
		credential, exists := credentials[scope]
		if rule.Mode == ModeExternal {
			if rule.RuleID != binding.PolicyID || rule.ExternalProvider == nil || !exists || credential.Provider != rule.ExternalProvider.Provider ||
				credential.AppID != rule.ExternalProvider.AppID {
				return invalid("challenge external credential scope mismatch")
			}
			delete(credentials, scope)
		} else if rule.ExternalProvider != nil || exists {
			return invalid("challenge external credential scope mismatch")
		}
	}
	if len(credentials) != 0 {
		return invalid("challenge external credential scope mismatch")
	}
	return nil
}

type externalCredentialDocument struct {
	SchemaVersion string                       `json:"schema_version"`
	PolicyID      string                       `json:"policy_id"`
	TenantID      string                       `json:"tenant_id"`
	PolicyVersion uint64                       `json:"policy_version"`
	Credentials   []ArtifactExternalCredential `json:"credentials"`
}

type ExternalCredentialBinding struct {
	PolicyID      string
	PolicyVersion uint64
	TenantID      string
	SiteID        string
	Provider      ExternalProvider
	AppID         string
}

func (installer *ArtifactInstaller) installExternalCredentials(credentials []ArtifactExternalCredential,
	binding ArtifactBinding) (string, error) {
	if len(credentials) == 0 {
		return "", nil
	}
	document := externalCredentialDocument{SchemaVersion: "cdnca.edge.challenge-external-credentials/v1",
		PolicyID: binding.PolicyID, TenantID: binding.TenantID, PolicyVersion: binding.PolicyVersion,
		Credentials: credentials}
	content, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("marshal challenge external credentials: %w", err)
	}
	defer clearArtifactBytes(content)
	root, err := openDirectoryPath(filepath.Join(installer.stateRoot, "challenge", "credentials"), true)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := requirePrivateDirectory(root); err != nil {
		return "", err
	}
	policyDirectory, err := openPrivateDirectoryAt(root, binding.PolicyID)
	if err != nil {
		return "", err
	}
	defer policyDirectory.Close()
	versions, err := openPrivateDirectoryAt(policyDirectory, "versions")
	if err != nil {
		return "", err
	}
	defer versions.Close()
	name := versionFilename(binding.PolicyVersion)
	stored, readErr := readPrivateRegularAt(versions, name)
	if readErr == nil {
		defer clearArtifactBytes(stored)
		if !bytes.Equal(stored, content) {
			return "", invalid("challenge external credential version conflicts with sealed state")
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", invalid("challenge external credential version is unsafe")
	} else if err := writeImmutable(versions, name, content); err != nil {
		return "", err
	}
	return filepath.Join(installer.stateRoot, "challenge", "credentials", binding.PolicyID, "versions", name), nil
}

func LoadExternalCredentials(stateRoot string, binding ExternalCredentialBinding) (ExternalCredential, error) {
	if !cleanAbsoluteNonRoot(stateRoot) || !canonicalArtifactUUID(binding.PolicyID) || binding.PolicyVersion == 0 ||
		!canonicalArtifactUUID(binding.TenantID) || !canonicalArtifactUUID(binding.SiteID) ||
		(binding.Provider != ProviderTencent && binding.Provider != ProviderGeetestV4) ||
		validateIdentifier(binding.AppID, MaxIdentifierBytes) != nil {
		return ExternalCredential{}, ErrExternalVerification
	}
	versions, err := openDirectoryPath(filepath.Join(stateRoot, "challenge", "credentials", binding.PolicyID, "versions"), false)
	if err != nil {
		return ExternalCredential{}, ErrExternalVerification
	}
	defer versions.Close()
	if err := requirePrivateDirectory(versions); err != nil {
		return ExternalCredential{}, ErrExternalVerification
	}
	content, err := readPrivateRegularAt(versions, versionFilename(binding.PolicyVersion))
	if err != nil {
		return ExternalCredential{}, ErrExternalVerification
	}
	defer clearArtifactBytes(content)
	var document externalCredentialDocument
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || requireJSONEOF(decoder) != nil ||
		document.SchemaVersion != "cdnca.edge.challenge-external-credentials/v1" ||
		document.PolicyID != binding.PolicyID || document.PolicyVersion != binding.PolicyVersion ||
		document.TenantID != binding.TenantID || len(document.Credentials) == 0 || len(document.Credentials) > MaxRules {
		clearArtifactCredentials(document.Credentials)
		return ExternalCredential{}, ErrExternalVerification
	}
	defer clearArtifactCredentials(document.Credentials)
	for _, credential := range document.Credentials {
		if credential.TenantID == binding.TenantID && credential.SiteID == binding.SiteID &&
			credential.Provider == binding.Provider && credential.AppID == binding.AppID {
			return ExternalCredential{Provider: credential.Provider, AppID: credential.AppID,
				Secret: bytes.Clone(credential.Secret), Environment: credential.Environment}, nil
		}
	}
	return ExternalCredential{}, ErrExternalVerification
}

func (installer *ArtifactInstaller) installKeys(root *os.File, keys []ArtifactKey, policyID string) error {
	policyDirectory, err := openPrivateDirectoryAt(root, policyID)
	if err != nil {
		return err
	}
	defer policyDirectory.Close()
	for _, key := range keys {
		name := key.KeyID + ".key"
		content, err := readPrivateRegularAt(policyDirectory, name)
		if err == nil {
			if !bytes.Equal(content, key.Secret) {
				clearArtifactBytes(content)
				return invalid("challenge artifact conflicts with installed key %q", key.KeyID)
			}
			clearArtifactBytes(content)
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return invalid("installed challenge key is unsafe")
		}
		if err := writeImmutable(policyDirectory, name, key.Secret); err != nil {
			return err
		}
	}
	return nil
}

func cleanAbsoluteNonRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func canonicalArtifactUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validArtifactRecipientKeyID(value string) bool {
	if !strings.HasPrefix(value, "x25519:") || len(value) != len("x25519:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "x25519:"))
	return err == nil && len(decoded) == 32
}

func clearArtifactSecrets(keys []ArtifactKey) {
	for index := range keys {
		clearArtifactBytes(keys[index].Secret)
	}
}

func clearArtifactDocumentSecrets(document *ArtifactDocument) {
	clearArtifactSecrets(document.Keys)
	clearArtifactCredentials(document.ExternalCredentials)
}

func clearArtifactCredentials(credentials []ArtifactExternalCredential) {
	for index := range credentials {
		clearArtifactBytes(credentials[index].Secret)
	}
}

func clearArtifactBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
