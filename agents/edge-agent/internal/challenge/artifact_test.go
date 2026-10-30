package challenge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactInstallerPublishesVersionScopedKeysAndPolicyIdempotently(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	installer, err := NewArtifactInstaller(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := testChallengeArtifactBinding()
	raw := testChallengeArtifactJSON(t, binding, "current-challenge-secret-material-01", "previous-challenge-secret-material-1")
	first, err := installer.InstallJSON(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := installer.InstallJSON(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.PolicyVersion != 7 || first.PolicyID != binding.PolicyID {
		t.Fatalf("non-idempotent installation: first=%+v second=%+v", first, second)
	}
	for _, keyID := range []string{"key-current", "key-previous"} {
		path := filepath.Join(root, "challenge", "keys", binding.PolicyID, keyID+".key")
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe key mode for %s: %v", keyID, info.Mode())
		}
	}
	wantPolicy := filepath.Join(root, "challenge", "policies", binding.PolicyID, "versions", "00000000000000000007.json")
	if first.CurrentPath != wantPolicy {
		t.Fatalf("immutable policy path = %q, want %q", first.CurrentPath, wantPolicy)
	}
}

func TestArtifactInstallerRejectsBindingsRotationAndConflictsWithoutMutatingLKG(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	installer, err := NewArtifactInstaller(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := testChallengeArtifactBinding()
	valid := testChallengeArtifactJSON(t, binding, "current-challenge-secret-material-01", "previous-challenge-secret-material-1")
	publication, err := installer.InstallJSON(valid, binding)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(publication.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}

	var incomplete ArtifactDocument
	if err := json.Unmarshal(valid, &incomplete); err != nil {
		t.Fatal(err)
	}
	incomplete.Keys = incomplete.Keys[:1]
	incompleteRaw, err := json.Marshal(incomplete)
	if err != nil {
		t.Fatal(err)
	}
	var conflicting ArtifactDocument
	if err := json.Unmarshal(valid, &conflicting); err != nil {
		t.Fatal(err)
	}
	conflicting.Keys[0].Secret = []byte("changed-challenge-secret-material-01")
	conflictingRaw, err := json.Marshal(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		raw     []byte
		binding ArtifactBinding
	}{
		{name: "command event", raw: valid, binding: func() ArtifactBinding {
			value := binding
			value.EventID = "01990000-0000-7000-8000-000000000099"
			return value
		}()},
		{name: "incomplete rotation", raw: incompleteRaw, binding: binding},
		{name: "duplicate JSON", raw: bytes.Replace(valid, []byte(`"policy_version":7`), []byte(`"policy_version":7,"policy_version":7`), 1), binding: binding},
		{name: "conflicting replay", raw: conflictingRaw, binding: binding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := installer.InstallJSON(test.raw, test.binding); err == nil {
				t.Fatal("invalid artifact accepted")
			}
			current, readErr := os.ReadFile(publication.CurrentPath)
			if readErr != nil || !bytes.Equal(current, baseline) {
				t.Fatalf("sealed LKG changed after rejection: read=%v", readErr)
			}
		})
	}
}

func TestArtifactInstallerPublishesExternalCredentialAsPrivateImmutableVersion(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	installer, err := NewArtifactInstaller(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := testChallengeArtifactBinding()
	var document ArtifactDocument
	if err := json.Unmarshal(testChallengeArtifactJSON(t, binding,
		"current-challenge-secret-material-01", "previous-challenge-secret-material-1"), &document); err != nil {
		t.Fatal(err)
	}
	document.Policy.Rules[0].Mode = ModeExternal
	document.Policy.Rules[0].RuleID = binding.PolicyID
	document.Policy.Rules[0].ExternalProvider = &ExternalProviderConfig{Provider: ProviderTencent, AppID: "2060000000"}
	document.ExternalCredentials = []ArtifactExternalCredential{{
		TenantID: binding.TenantID, SiteID: document.Policy.Rules[0].SiteID, Provider: ProviderTencent,
		AppID: "2060000000", Secret: []byte("tencent-controlled-secret-0001"), Environment: ExternalProduction,
	}}
	raw, _ := json.Marshal(document)
	result, err := installer.InstallJSON(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	credentialPath := filepath.Join(root, "challenge", "credentials", binding.PolicyID, "versions", "00000000000000000007.json")
	info, err := os.Lstat(credentialPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential file info=%v err=%v", info, err)
	}
	if result.CredentialPath != credentialPath {
		t.Fatalf("credential path=%q want=%q", result.CredentialPath, credentialPath)
	}
	stored, err := LoadExternalCredentials(root, ExternalCredentialBinding{
		PolicyID: binding.PolicyID, PolicyVersion: binding.PolicyVersion, TenantID: binding.TenantID,
		SiteID: document.Policy.Rules[0].SiteID, Provider: ProviderTencent, AppID: "2060000000",
	})
	if err != nil || string(stored.Secret) != "tencent-controlled-secret-0001" {
		t.Fatalf("LoadExternalCredentials()=(%+v,%v)", stored, err)
	}
}

func TestArtifactInstallerExternalCredentialBadCandidateKeepsActiveLKG(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	installer, _ := NewArtifactInstaller(root)
	binding := testChallengeArtifactBinding()
	var document ArtifactDocument
	_ = json.Unmarshal(testChallengeArtifactJSON(t, binding,
		"current-challenge-secret-material-01", "previous-challenge-secret-material-1"), &document)
	document.Policy.Rules[0].Mode = ModeExternal
	document.Policy.Rules[0].RuleID = binding.PolicyID
	document.Policy.Rules[0].ExternalProvider = &ExternalProviderConfig{Provider: ProviderTencent, AppID: "2060000000"}
	document.ExternalCredentials = []ArtifactExternalCredential{{TenantID: binding.TenantID,
		SiteID: document.Policy.Rules[0].SiteID, Provider: ProviderTencent, AppID: "2060000000",
		Secret: []byte("tencent-controlled-secret-0001"), Environment: ExternalProduction}}
	valid, _ := json.Marshal(document)
	result, err := installer.InstallJSON(valid, binding)
	if err != nil {
		t.Fatal(err)
	}
	baselinePolicy, _ := os.ReadFile(result.CurrentPath)
	baselineCredential, _ := os.ReadFile(result.CredentialPath)
	document.ExternalCredentials[0].SiteID = "01990000-0000-7000-8000-000000000099"
	invalid, _ := json.Marshal(document)
	if _, err := installer.InstallJSON(invalid, binding); err == nil {
		t.Fatal("cross-site candidate accepted")
	}
	policy, _ := os.ReadFile(result.CurrentPath)
	credential, _ := os.ReadFile(result.CredentialPath)
	if !bytes.Equal(policy, baselinePolicy) || !bytes.Equal(credential, baselineCredential) {
		t.Fatal("bad candidate mutated active policy or credential LKG")
	}
}

func testChallengeArtifactBinding() ArtifactBinding {
	return ArtifactBinding{
		EventID: "01990000-0000-7000-8000-000000000001", DeploymentID: "01990000-0000-7000-8000-000000000002",
		Attempt: 1, ConfigVersionID: "01990000-0000-7000-8000-000000000003",
		ArtifactID: "01990000-0000-7000-8000-000000000004", RecipientKeyID: "x25519:" + strings.Repeat("a", 64),
		PolicyID: "01990000-0000-7000-8000-000000000005", TenantID: "01990000-0000-7000-8000-000000000006", PolicyVersion: 7,
	}
}

func testChallengeArtifactJSON(t *testing.T, binding ArtifactBinding, currentSecret, previousSecret string) []byte {
	t.Helper()
	document := ArtifactDocument{
		SchemaVersion: ArtifactSchemaVersion,
		Activation: ArtifactActivation{
			SchemaVersion: ActivationSchemaVersion, EventID: binding.EventID, DeploymentID: binding.DeploymentID,
			Attempt: binding.Attempt, ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
			RecipientKeyID: binding.RecipientKeyID, PolicyID: binding.PolicyID, TenantID: binding.TenantID, PolicyVersion: binding.PolicyVersion,
		},
		Policy: Policy{
			SchemaVersion: SchemaVersion, PolicyVersion: binding.PolicyVersion, Algorithm: AlgorithmHMACSHA256,
			CookieName: "__Host-cdnca_challenge", TrustedProxies: []string{}, BypassRoutes: []BypassRoute{},
			CurrentKey: KeyRef{KeyID: "key-current"}, PreviousKey: &KeyRef{KeyID: "key-previous"},
			Rules: []Rule{{RuleID: "01990000-0000-7000-8000-000000000007", Priority: 10,
				TenantID: binding.TenantID, SiteID: "01990000-0000-7000-8000-000000000008", Host: "edge.example.test",
				Mode: ModeClick, ChallengeTTLSeconds: 60, PassTTLSeconds: 300, ClockSkewSeconds: 10,
				AttemptsPerNonce: 1, FailureWindowSeconds: 60, MaxFailuresPerWindow: 5, IPBinding: IPBindingExact, BindUserAgent: true}},
		},
		Keys: []ArtifactKey{{KeyID: "key-current", Secret: []byte(currentSecret)}, {KeyID: "key-previous", Secret: []byte(previousSecret)}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
