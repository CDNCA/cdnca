package urlauth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const (
	ArtifactSchemaVersion   = "cdnca.edge.urlauth-artifact/v1"
	ActivationSchemaVersion = "cdnca.edge.urlauth-activation/v1"
	MaxArtifactBytes        = MaxPolicyBytes + 4096
)

type ArtifactBinding struct {
	EventID, DeploymentID, ConfigVersionID, ArtifactID, RecipientKeyID string
	PolicyID, TenantID, SiteID                                         string
	// ConfigurationScopeID is the access scope that published the artifact.
	// It is distinct from TenantID; empty for artifacts produced before the
	// field existed.
	ConfigurationScopeID string
	Attempt              uint32
	PolicyVersion        uint64
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
	SiteID          string `json:"site_id"`
	PolicyVersion   uint64 `json:"policy_version"`
	// ConfigurationScopeID binds the artifact to the deployment command's
	// configuration_scope_id. Optional so older artifacts still decode.
	ConfigurationScopeID string `json:"configuration_scope_id,omitempty"`
}

type ArtifactKey struct {
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
	Secret  []byte `json:"secret"`
}

type ArtifactDocument struct {
	SchemaVersion string             `json:"schema_version"`
	Activation    ArtifactActivation `json:"activation"`
	Policy        Policy             `json:"policy"`
	Keys          []ArtifactKey      `json:"keys"`
}

type ArtifactInstaller struct {
	policyRoot string
	keyRoot    string
	publisher  *Publisher
}

func NewArtifactInstaller(policyRoot, keyRoot string) (*ArtifactInstaller, error) {
	if !cleanAbsoluteNonRoot(policyRoot) || !cleanAbsoluteNonRoot(keyRoot) || policyRoot == keyRoot {
		return nil, invalid("artifact roots must be distinct clean absolute non-root paths")
	}
	publisher, err := NewPublisher(policyRoot)
	if err != nil {
		return nil, err
	}
	return &ArtifactInstaller{policyRoot: policyRoot, keyRoot: keyRoot, publisher: publisher}, nil
}

func (installer *ArtifactInstaller) InstallJSON(raw []byte, binding ArtifactBinding) (Publication, error) {
	if installer == nil || installer.publisher == nil || len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return Publication{}, invalid("invalid URL auth artifact")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Publication{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ArtifactDocument
	if err := decoder.Decode(&document); err != nil {
		return Publication{}, invalid("decode URL auth artifact: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Publication{}, invalid("URL auth artifact has trailing data")
	}
	defer clearArtifactSecrets(document.Keys)
	if err := installer.validateDocument(document, binding); err != nil {
		return Publication{}, err
	}
	keyRoot, err := openDirectoryPath(installer.keyRoot, true)
	if err != nil {
		return Publication{}, err
	}
	defer keyRoot.Close()
	if err := requirePrivateDirectory(keyRoot); err != nil {
		return Publication{}, err
	}
	lock, err := lockPublisherAt(keyRoot)
	if err != nil {
		return Publication{}, err
	}
	defer lock.Close()
	// Under the key lock, before any key byte is written: on a node shared by
	// several tenants a policy ID never changes owner.
	if err := installer.publisher.checkOwner(binding.TenantID, binding.SiteID); err != nil {
		return Publication{}, err
	}
	if err := installer.installKeys(keyRoot, document.Keys, binding.PolicyID); err != nil {
		return Publication{}, err
	}
	policy, err := json.Marshal(document.Policy)
	if err != nil {
		return Publication{}, fmt.Errorf("marshal URL auth policy: %w", err)
	}
	defer clearArtifactBytes(policy)
	return installer.publisher.PublishJSON(policy)
}

func (installer *ArtifactInstaller) validateDocument(document ArtifactDocument, binding ArtifactBinding) error {
	activation := document.Activation
	if !canonicalArtifactUUID(binding.EventID) || !canonicalArtifactUUID(binding.DeploymentID) ||
		!canonicalArtifactUUID(binding.ConfigVersionID) || !canonicalArtifactUUID(binding.ArtifactID) ||
		!canonicalArtifactUUID(binding.PolicyID) || !canonicalArtifactUUID(binding.TenantID) || !canonicalArtifactUUID(binding.SiteID) ||
		!validArtifactRecipientKeyID(binding.RecipientKeyID) || document.SchemaVersion != ArtifactSchemaVersion || activation.SchemaVersion != ActivationSchemaVersion ||
		activation.EventID != binding.EventID || activation.DeploymentID != binding.DeploymentID ||
		activation.Attempt != binding.Attempt || activation.ConfigVersionID != binding.ConfigVersionID ||
		activation.ArtifactID != binding.ArtifactID || activation.RecipientKeyID != binding.RecipientKeyID ||
		activation.PolicyID != binding.PolicyID || activation.TenantID != binding.TenantID ||
		activation.SiteID != binding.SiteID || activation.PolicyVersion != binding.PolicyVersion ||
		activation.ConfigurationScopeID != binding.ConfigurationScopeID ||
		(binding.ConfigurationScopeID != "" && !canonicalArtifactUUID(binding.ConfigurationScopeID)) ||
		binding.Attempt != 1 || binding.PolicyVersion == 0 || document.Policy.PolicyVersion != binding.PolicyVersion ||
		document.Policy.TenantID != binding.TenantID || document.Policy.SiteID != binding.SiteID {
		return invalid("URL auth artifact binding mismatch")
	}
	want := []KeyRef{document.Policy.CurrentKey}
	if document.Policy.PreviousKey != nil {
		want = append(want, *document.Policy.PreviousKey)
	}
	if len(document.Keys) != len(want) {
		return invalid("URL auth artifact key set mismatch")
	}
	for index, key := range document.Keys {
		if err := validateKeyID(key.KeyID); err != nil || key.KeyID != want[index].KeyID || key.KeyFile != want[index].KeyFile ||
			key.KeyFile != filepath.Join(installer.keyRoot, binding.PolicyID, key.KeyID+".key") ||
			len(key.Secret) < MinKeyBytes || len(key.Secret) > MaxKeyBytes {
			return invalid("URL auth artifact key binding mismatch")
		}
	}
	return nil
}

func (installer *ArtifactInstaller) installKeys(root *os.File, keys []ArtifactKey, policyID string) error {
	policyDirectory, err := openPrivateDirectoryAt(root, policyID)
	if err != nil {
		return err
	}
	defer policyDirectory.Close()
	for _, key := range keys {
		name := key.KeyID + ".key"
		file, exists, err := openArtifactKeyAt(policyDirectory, name)
		if err != nil {
			return err
		}
		if exists {
			content, readErr := io.ReadAll(io.LimitReader(file, MaxKeyBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || !bytes.Equal(content, key.Secret) {
				clearArtifactBytes(content)
				return invalid("URL auth artifact conflicts with installed key %q", key.KeyID)
			}
			clearArtifactBytes(content)
			continue
		}
		if err := writeImmutableAt(policyDirectory, name, key.Secret); err != nil {
			return err
		}
	}
	return nil
}

func openArtifactKeyAt(directory *os.File, name string) (*os.File, bool, error) {
	file, err := openPrivateRegularAt(directory, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, invalid("installed URL auth key is unsafe")
	}
	return file, true, nil
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

func clearArtifactBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
