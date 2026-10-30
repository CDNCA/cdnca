package urlauth

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestArtifactRuntimeRoutesPoliciesToIsolatedRoots(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewArtifactRuntime(filepath.Join(root, "urlauth"))
	if err != nil {
		t.Fatal(err)
	}
	policyIDs := []string{"00000000-0000-0000-0000-000000000005", "00000000-0000-0000-0000-000000000006"}
	siteIDs := []string{"00000000-0000-0000-0000-000000000007", "00000000-0000-0000-0000-000000000008"}
	for index := range policyIDs {
		binding := testArtifactBinding()
		binding.PolicyID = policyIDs[index]
		binding.SiteID = siteIDs[index]
		raw := testRuntimeArtifactJSON(t, runtime, binding)
		publication, err := runtime.InstallJSON(raw, binding)
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(root, "urlauth", "policies", binding.PolicyID, "current.json")
		if publication.CurrentPath != want {
			t.Fatalf("policy %d path=%q want=%q", index, publication.CurrentPath, want)
		}
	}
}

func TestMetricsExporterRejectsCardinalityAndRaisesStableAlerts(t *testing.T) {
	baseline, err := DecodeMetricsJSON([]byte(`{"allow":10,"block":2,"error":0,"reload_rejected":1,"reasons":{"signature_valid":10,"signature_invalid":2,"other":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	current, err := DecodeMetricsJSON([]byte(`{"allow":12,"block":3,"error":1,"reload_rejected":2,"reasons":{"signature_valid":12,"signature_invalid":3,"other":0}}`))
	if err != nil {
		t.Fatal(err)
	}
	text := current.Prometheus()
	for _, name := range []string{"cdnca_url_auth_allow_total 12", "cdnca_url_auth_block_total 3", "cdnca_url_auth_error_total 1", "cdnca_url_auth_reload_rejected_total 2"} {
		if !strings.Contains(text, name) {
			t.Fatalf("missing metric %q in %q", name, text)
		}
	}
	alerts := current.AlertsSince(baseline)
	if len(alerts) != 2 || alerts[0].Code != "URL_AUTH_DEPENDENCY_ERROR" || alerts[1].Code != "URL_AUTH_RELOAD_REJECTED" {
		t.Fatalf("alerts=%+v", alerts)
	}
	for _, invalid := range []string{
		`{"allow":1,"block":0,"error":0,"reload_rejected":0,"reasons":{"uri=/secret":1}}`,
		`{"allow":1,"block":0,"error":0,"reload_rejected":0,"reasons":{},"signature":"secret"}`,
		`{"allow":1,"allow":2,"block":0,"error":0,"reload_rejected":0,"reasons":{}}`,
	} {
		if _, err := DecodeMetricsJSON([]byte(invalid)); err == nil {
			t.Fatalf("invalid metrics accepted: %s", invalid)
		}
	}
}

func testRuntimeArtifactJSON(t *testing.T, runtime *ArtifactRuntime, binding ArtifactBinding) []byte {
	t.Helper()
	keyRoot := filepath.Join(runtime.root, "keys")
	document := ArtifactDocument{
		SchemaVersion: ArtifactSchemaVersion,
		Activation: ArtifactActivation{SchemaVersion: ActivationSchemaVersion, EventID: binding.EventID, DeploymentID: binding.DeploymentID,
			Attempt: binding.Attempt, ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID, RecipientKeyID: binding.RecipientKeyID,
			PolicyID: binding.PolicyID, TenantID: binding.TenantID, SiteID: binding.SiteID, PolicyVersion: binding.PolicyVersion},
		Policy: Policy{SchemaVersion: SchemaVersion, PolicyVersion: binding.PolicyVersion, TenantID: binding.TenantID, SiteID: binding.SiteID,
			Algorithm: AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid",
			MaxValiditySeconds: 300, ExcludedQueryParameters: []string{}, TrustedProxies: []string{},
			CurrentKey: KeyRef{KeyID: "k-current", KeyFile: filepath.Join(keyRoot, binding.PolicyID, "k-current.key")}},
		Keys: []ArtifactKey{{KeyID: "k-current", KeyFile: filepath.Join(keyRoot, binding.PolicyID, "k-current.key"), Secret: []byte("secret-current-32-bytes-exactly!")}},
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
