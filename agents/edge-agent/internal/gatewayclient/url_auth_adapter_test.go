package gatewayclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/urlauth"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

type recordingURLAuthConsumer struct {
	binding urlauth.ArtifactBinding
	calls   int
}

func (consumer *recordingURLAuthConsumer) InstallJSON(_ []byte, binding urlauth.ArtifactBinding) (urlauth.Publication, error) {
	consumer.calls++
	consumer.binding = binding
	return urlauth.Publication{PolicyVersion: binding.PolicyVersion, CurrentPath: "/state/current.json"}, nil
}

func TestApplyURLAuthArtifactBindsSignedDocumentToCommand(t *testing.T) {
	command, descriptor, raw := gatewayURLAuthFixture(t)
	consumer := new(recordingURLAuthConsumer)
	publication, err := applyURLAuthArtifact(raw, command, descriptor, consumer)
	if err != nil {
		t.Fatal(err)
	}
	if consumer.calls != 1 || publication.PolicyVersion != 7 || consumer.binding.EventID != command.Event.EventId ||
		consumer.binding.ArtifactID != descriptor.ArtifactId || consumer.binding.ConfigVersionID != command.ConfigVersionId {
		t.Fatalf("consumer=%+v publication=%+v", consumer, publication)
	}
	command.DeploymentId = uuid.NewString()
	if _, err := applyURLAuthArtifact(raw, command, descriptor, consumer); err == nil || consumer.calls != 1 {
		t.Fatalf("command mismatch accepted: calls=%d err=%v", consumer.calls, err)
	}
}

func gatewayURLAuthFixture(t *testing.T) (*agentv1.DeploymentCommand, *agentv1.ArtifactDescriptor, []byte) {
	t.Helper()
	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := signedBundleTestCommand(t, signingKey)
	command.ConfigVersionId = uuid.NewString()
	scopeID := uuid.NewString()
	command.ConfigurationScopeId = &scopeID
	descriptor := command.Artifacts[0]
	descriptor.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
	descriptor.MediaType = URLAuthArtifactMediaType
	descriptor.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
	recipient := "x25519:" + strings.Repeat("a", 64)
	descriptor.RecipientKeyId = &recipient
	binding := urlauth.ArtifactBinding{EventID: command.Event.EventId, DeploymentID: command.DeploymentId, Attempt: command.Attempt,
		ConfigVersionID: command.ConfigVersionId, ArtifactID: descriptor.ArtifactId, RecipientKeyID: recipient,
		PolicyID: uuid.NewString(), TenantID: uuid.NewString(), SiteID: uuid.NewString(), PolicyVersion: 7,
		ConfigurationScopeID: scopeID}
	keyRoot := filepath.Join("/var/lib/cdnca-edge/urlauth/keys", binding.PolicyID)
	document := urlauth.ArtifactDocument{SchemaVersion: urlauth.ArtifactSchemaVersion,
		Activation: urlauth.ArtifactActivation{SchemaVersion: urlauth.ActivationSchemaVersion, EventID: binding.EventID, DeploymentID: binding.DeploymentID,
			Attempt: binding.Attempt, ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID, RecipientKeyID: binding.RecipientKeyID,
			PolicyID: binding.PolicyID, TenantID: binding.TenantID, SiteID: binding.SiteID, PolicyVersion: binding.PolicyVersion,
			ConfigurationScopeID: binding.ConfigurationScopeID},
		Policy: urlauth.Policy{SchemaVersion: urlauth.SchemaVersion, PolicyVersion: 7, TenantID: binding.TenantID, SiteID: binding.SiteID,
			Algorithm: urlauth.AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
			MaxValiditySeconds: 300, ExcludedQueryParameters: []string{}, TrustedProxies: []string{},
			CurrentKey: urlauth.KeyRef{KeyID: "k-current", KeyFile: filepath.Join(keyRoot, "k-current.key")}},
		Keys: []urlauth.ArtifactKey{{KeyID: "k-current", KeyFile: filepath.Join(keyRoot, "k-current.key"), Secret: []byte("secret-current-32-bytes-exactly!")}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return command, descriptor, raw
}

// The control plane allocates a tenant id and a distinct configuration scope
// id per user. A URL auth artifact names both; the command's scope must match
// the artifact's scope and the tenant is checked separately.
func TestURLAuthArtifactBindsCommandScopeSeparatelyFromTenant(t *testing.T) {
	scopedFixture := func(t *testing.T, mutate func(*urlauth.ArtifactDocument)) (*agentv1.DeploymentCommand, *agentv1.ArtifactDescriptor, []byte) {
		t.Helper()
		command, descriptor, raw := gatewayURLAuthFixture(t)
		var document urlauth.ArtifactDocument
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		tenantID := uuid.NewString()
		document.Activation.TenantID, document.Policy.TenantID = tenantID, tenantID
		document.Activation.ConfigurationScopeID = command.GetConfigurationScopeId()
		if mutate != nil {
			mutate(&document)
		}
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return command, descriptor, raw
	}
	command, descriptor, raw := scopedFixture(t, nil)
	consumer := &recordingURLAuthConsumer{}
	if _, err := applyURLAuthArtifact(raw, command, descriptor, consumer); err != nil || consumer.calls != 1 {
		t.Fatalf("scope != tenant artifact rejected: calls=%d err=%v", consumer.calls, err)
	}
	for name, mutate := range map[string]func(*urlauth.ArtifactDocument){
		"artifact scope differs from command": func(document *urlauth.ArtifactDocument) {
			document.Activation.ConfigurationScopeID = uuid.NewString()
		},
		"no artifact scope": func(document *urlauth.ArtifactDocument) {
			document.Activation.ConfigurationScopeID = ""
		},
		// The old convention: the command scope sent as the tenant id.
		"tenant id in place of the scope": func(document *urlauth.ArtifactDocument) {
			commandScope := document.Activation.ConfigurationScopeID
			document.Activation.ConfigurationScopeID = ""
			document.Activation.TenantID, document.Policy.TenantID = commandScope, commandScope
		},
	} {
		t.Run(name, func(t *testing.T) {
			command, descriptor, raw := scopedFixture(t, mutate)
			consumer := &recordingURLAuthConsumer{}
			if _, err := applyURLAuthArtifact(raw, command, descriptor, consumer); err == nil || consumer.calls != 0 {
				t.Fatalf("mis-scoped URL auth artifact accepted: calls=%d err=%v", consumer.calls, err)
			}
		})
	}
}
