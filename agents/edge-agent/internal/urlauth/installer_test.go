package urlauth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestArtifactInstallerPublishesKeysAndPolicyIdempotently(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policyRoot := filepath.Join(root, "policy")
	keyRoot := filepath.Join(root, "keys")
	installer, err := NewArtifactInstaller(policyRoot, keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	binding := testArtifactBinding()
	raw := testArtifactJSON(t, keyRoot, binding, "secret-current-32-bytes-exactly!", "secret-previous-32-bytes-exactly")
	first, err := installer.InstallJSON(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	second, err := installer.InstallJSON(raw, binding)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.PolicyVersion != 7 {
		t.Fatalf("non-idempotent publication: first=%+v second=%+v", first, second)
	}
	var wait sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := installer.InstallJSON(raw, binding)
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent exact replay failed: %v", err)
		}
	}
	for _, keyID := range []string{"k-current", "k-previous"} {
		path := filepath.Join(keyRoot, binding.PolicyID, keyID+".key")
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe key mode for %s: %v", keyID, info.Mode())
		}
	}
	if _, err := os.Stat(filepath.Join(policyRoot, "current.json")); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactInstallerRejectsBindingPathsDuplicatesAndConflictsWithoutReplacingLKG(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	policyRoot := filepath.Join(root, "policy")
	keyRoot := filepath.Join(root, "keys")
	installer, err := NewArtifactInstaller(policyRoot, keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	binding := testArtifactBinding()
	valid := testArtifactJSON(t, keyRoot, binding, "secret-current-32-bytes-exactly!", "secret-previous-32-bytes-exactly")
	publication, err := installer.InstallJSON(valid, binding)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(publication.CurrentPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		raw  []byte
		bind ArtifactBinding
	}{
		{name: "event binding", raw: valid, bind: func() ArtifactBinding {
			value := binding
			value.EventID = "01990000-0000-7000-8000-000000000099"
			return value
		}()},
		{name: "duplicate nested key", raw: []byte(strings.Replace(string(valid), `"policy_version":7`, `"policy_version":7,"policy_version":7`, 1)), bind: binding},
		{name: "path escape", raw: []byte(strings.Replace(string(valid), filepath.Join(keyRoot, binding.PolicyID, "k-current.key"), filepath.Join(root, "escaped.key"), 1)), bind: binding},
		{name: "conflicting replay secret", raw: []byte(strings.Replace(string(valid),
			base64.StdEncoding.EncodeToString([]byte("secret-current-32-bytes-exactly!")),
			base64.StdEncoding.EncodeToString([]byte("changed-current-32-bytes-exactly")), 1)), bind: binding},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := installer.InstallJSON(test.raw, test.bind); err == nil {
				t.Fatal("invalid artifact accepted")
			}
			current, readErr := os.ReadFile(publication.CurrentPath)
			if readErr != nil || string(current) != string(baseline) {
				t.Fatalf("LKG changed after rejection: read=%v", readErr)
			}
		})
	}
}

func testArtifactBinding() ArtifactBinding {
	return ArtifactBinding{
		EventID: "01990000-0000-7000-8000-000000000001", DeploymentID: "01990000-0000-7000-8000-000000000002",
		Attempt: 1, ConfigVersionID: "01990000-0000-7000-8000-000000000003",
		ArtifactID: "01990000-0000-7000-8000-000000000004", RecipientKeyID: "x25519:" + strings.Repeat("a", 64),
		PolicyID: "01990000-0000-7000-8000-000000000005", TenantID: "01990000-0000-7000-8000-000000000006",
		SiteID: "01990000-0000-7000-8000-000000000007", PolicyVersion: 7,
	}
}

func testArtifactJSON(t *testing.T, keyRoot string, binding ArtifactBinding, currentSecret, previousSecret string) []byte {
	t.Helper()
	return testArtifactJSONWithKeys(t, keyRoot, binding, "k-current", "k-previous", currentSecret, previousSecret)
}

func testArtifactJSONWithKeys(t *testing.T, keyRoot string, binding ArtifactBinding, currentID, previousID, currentSecret, previousSecret string) []byte {
	t.Helper()
	document := ArtifactDocument{
		SchemaVersion: ArtifactSchemaVersion,
		Activation: ArtifactActivation{
			SchemaVersion: ActivationSchemaVersion, EventID: binding.EventID, DeploymentID: binding.DeploymentID,
			Attempt: binding.Attempt, ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
			RecipientKeyID: binding.RecipientKeyID, PolicyID: binding.PolicyID, TenantID: binding.TenantID,
			SiteID: binding.SiteID, PolicyVersion: binding.PolicyVersion,
		},
		Policy: Policy{
			SchemaVersion: SchemaVersion, PolicyVersion: binding.PolicyVersion, TenantID: binding.TenantID, SiteID: binding.SiteID,
			Algorithm: AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
			MaxValiditySeconds: 300, ExcludedQueryParameters: []string{}, TrustedProxies: []string{},
			CurrentKey:  KeyRef{KeyID: currentID, KeyFile: filepath.Join(keyRoot, binding.PolicyID, currentID+".key")},
			PreviousKey: &KeyRef{KeyID: previousID, KeyFile: filepath.Join(keyRoot, binding.PolicyID, previousID+".key")},
		},
		Keys: []ArtifactKey{{KeyID: currentID, KeyFile: filepath.Join(keyRoot, binding.PolicyID, currentID+".key"), Secret: []byte(currentSecret)},
			{KeyID: previousID, KeyFile: filepath.Join(keyRoot, binding.PolicyID, previousID+".key"), Secret: []byte(previousSecret)}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// On a node shared by several tenants a policy ID stays bound to the tenant and
// site that first installed it; another tenant's artifact must not replace its
// keys or policy, even with a higher policy version.
func TestArtifactInstallerKeepsPolicyBoundToItsTenant(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyRoot := filepath.Join(root, "keys")
	installer, err := NewArtifactInstaller(filepath.Join(root, "policy"), keyRoot)
	if err != nil {
		t.Fatal(err)
	}
	owner := testArtifactBinding()
	if _, err := installer.InstallJSON(testArtifactJSON(t, keyRoot, owner, "secret-current-32-bytes-exactly!", "secret-previous-32-bytes-exactly"), owner); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyRoot, owner.PolicyID, "k-current.key")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ArtifactBinding){
		"other tenant": func(binding *ArtifactBinding) { binding.TenantID = "01990000-0000-7000-8000-0000000000aa" },
		"other site":   func(binding *ArtifactBinding) { binding.SiteID = "01990000-0000-7000-8000-0000000000bb" },
	} {
		t.Run(name, func(t *testing.T) {
			intruder := owner
			mutate(&intruder)
			intruder.PolicyVersion = owner.PolicyVersion + 1
			// Fresh key IDs, so the immutable-key check alone cannot stop it.
			raw := testArtifactJSONWithKeys(t, keyRoot, intruder, "x-current", "x-previous",
				"intruder-current-32-bytes-exact!", "intruder-previous-32-bytes-exact")
			if _, err := installer.InstallJSON(raw, intruder); err == nil {
				t.Fatal("another tenant replaced an installed URL auth policy")
			}
			if _, err := os.Lstat(filepath.Join(keyRoot, owner.PolicyID, "x-current.key")); !os.IsNotExist(err) {
				t.Fatalf("rejected install still wrote a key into the owner's policy: %v", err)
			}
			after, err := os.ReadFile(keyPath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("owner key changed after rejected install: err=%v", err)
			}
		})
	}
	next := owner
	next.PolicyVersion = owner.PolicyVersion + 1
	if _, err := installer.InstallJSON(testArtifactJSON(t, keyRoot, next, "secret-current-32-bytes-exactly!", "secret-previous-32-bytes-exactly"), next); err != nil {
		t.Fatalf("owner's next policy version rejected: %v", err)
	}
}
