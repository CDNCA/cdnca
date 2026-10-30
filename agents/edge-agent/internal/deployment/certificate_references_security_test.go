package deployment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/certstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// G8-a 缺陷 4：证书引用重评曾用 site_runtime 3、不带 cc/waf 的固定能力集，带监听
// 安全策略（cc + waf；1.0.35 起 site_runtime 统一为基线 6）的 v2 release 被判 missing_capability，部署走
// CERTIFICATE_REFERENCE_FAILED。部署状态机端到端：带 CC/WAF 与 TLS 监听的 v2 文档
// 必须走到 healthy，且证书版本被设为 Current。
func TestCertificateReferencesAcceptSecurityPolicyRelease(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("../../../../api/schemas/edge/v2/testdata", "site-runtime-capability-v4-security.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Since 1.0.35 every document declares the site_runtime v6 baseline.
	var capabilities map[string]any
	if err := json.Unmarshal(raw, &capabilities); err != nil {
		t.Fatal(err)
	}
	for _, item := range capabilities["required_capabilities"].([]any) {
		if capability := item.(map[string]any); capability["name"] == "site_runtime" {
			capability["api_version"] = edgeconfig.MinSiteRuntimeVersion
		}
	}
	if raw, err = json.Marshal(capabilities); err != nil {
		t.Fatal(err)
	}
	var document struct {
		ScopeID   string `json:"configuration_scope_id"`
		VersionID string `json:"config_version_id"`
		Sites     []struct {
			ID        string   `json:"id"`
			Domains   []string `json:"domains"`
			Listeners []struct {
				TLS *struct {
					CertificateVersionID string `json:"certificate_version_id"`
				} `json:"tls"`
			} `json:"listeners"`
		} `json:"sites"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || len(document.Sites) != 1 {
		t.Fatalf("security fixture = %+v, %v", document, err)
	}
	site := document.Sites[0]
	certificateVersionID := ""
	for _, listener := range site.Listeners {
		if listener.TLS != nil {
			certificateVersionID = listener.TLS.CertificateVersionID
		}
	}
	if certificateVersionID == "" {
		t.Fatal("security fixture has no TLS listener")
	}

	root := filepath.Join(t.TempDir(), "deployment")
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	certificates := newTestCertificateVersionStore(t)
	template := certificates.versions[testCertificateV1]
	certificates.versions[certificateVersionID] = certstore.ResolvedCertificateVersion{
		TenantScopeID: document.ScopeID, SiteID: site.ID, CertificateVersionID: certificateVersionID,
		Domains: site.Domains, CertificatePath: template.CertificatePath, PrivateKeyPath: template.PrivateKeyPath,
	}
	manager := newCertificateDeploymentManager(t, root, runtime, certificates)
	command := testCommand(t, "certificate-security", 1, document.VersionID, "", map[string][]byte{siteRuntimeV2File: raw})
	result, err := manager.Process(t.Context(), command)
	if err != nil || result.State != StateHealthy {
		t.Fatalf("Process(security policy release) = (%+v, %v)", result, err)
	}
	want := certstore.CertificateVersionReferences{Current: []string{certificateVersionID}}
	if !reflect.DeepEqual(certificates.references.Current, want.Current) || len(certificates.references.Previous) != 0 {
		t.Fatalf("references = %+v, want %+v", certificates.references, want)
	}
	if err := manager.RecoverCertificateVersionReferences(t.Context()); err != nil {
		t.Fatalf("RecoverCertificateVersionReferences() after restart = %v", err)
	}
}
