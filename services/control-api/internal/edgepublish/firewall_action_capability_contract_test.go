package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestFirewallActionOnlyDeclaresRequiredSiteRuntimeCapability(t *testing.T) {
	for _, test := range []struct {
		name, fixture               string
		empty, missing, invalidFact bool
		documentRejects             bool
		invalidVersion, want        uint32
		wantErr                     error
	}{
		// A firewall action no longer raises site_runtime: every document is
		// already at the 1.0.35 baseline (6), whatever else it carries.
		{name: "only-firewall", fixture: "v2", want: edgeconfig.MinSiteRuntimeVersion},
		{name: "empty-facts", fixture: "v2", empty: true, want: edgeconfig.MinSiteRuntimeVersion},
		{name: "with-http-policy", fixture: "v3", want: edgeconfig.MinSiteRuntimeVersion},
		{name: "with-package-limits", fixture: "v4-package", want: edgeconfig.MinSiteRuntimeVersion},
		{name: "missing-capability", fixture: "v2", missing: true, wantErr: ErrInvalidInput},
		{name: "invalid-fact", fixture: "v2", invalidFact: true, wantErr: ErrPersistence},
		{name: "unsupported-old-version", fixture: "v2", invalidVersion: 1, wantErr: ErrInvalidInput},
		{name: "below-the-baseline", fixture: "v2", invalidVersion: edgeconfig.MinSiteRuntimeVersion - 1, wantErr: ErrInvalidInput},
		// The producer only enforces the floor; the whole-document compiler
		// still refuses anything above the maximum.
		{name: "unsupported-new-version", fixture: "v2", invalidVersion: edgeconfig.MaxSiteRuntimeVersion + 1, documentRejects: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../../../../api/schemas/edge/v2/testdata", "site-runtime-capability-"+test.fixture+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var document siteRuntimeV2Document
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			// The shared fixtures still declare their historical site_runtime
			// (2/3/4); since 1.0.35 every document declares the baseline.
			setSiteRuntimeV2CapabilityExact(document.RequiredCapabilities, "site_runtime", edgeconfig.MinSiteRuntimeVersion)
			document.Sites[0].FirewallAction = nil
			baseline, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, err := compileSiteRuntimeV2Document(baseline); err != nil {
				t.Fatalf("baseline document is invalid: %v", err)
			}
			for index := range document.RequiredCapabilities {
				if document.RequiredCapabilities[index].Name != "site_runtime" {
					continue
				}
				if test.missing {
					document.RequiredCapabilities = append(document.RequiredCapabilities[:index], document.RequiredCapabilities[index+1:]...)
				} else if test.invalidVersion != 0 {
					document.RequiredCapabilities[index].APIVersion = test.invalidVersion
				}
				break
			}
			capabilitiesBefore, err := json.Marshal(document.RequiredCapabilities)
			if err != nil {
				t.Fatal(err)
			}
			scopeID := uuid.MustParse(document.ConfigurationScopeID)
			siteID := uuid.MustParse(document.Sites[0].ID)
			policyID := uuid.New()
			policy := firewallActionControlPolicy(t, scopeID, siteID, policyID, 7)
			facts := []firewallActionFact{{siteID: siteID, policyID: policyID, revision: 7, document: policy, digest: sha256.Sum256(policy)}}
			if test.empty {
				facts = nil
			}
			if test.invalidFact {
				facts[0].digest[0] ^= 0x80
			}
			artifacts, err := compileFirewallActionArtifacts(scopeID, &document, facts)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) || artifacts != nil {
					t.Fatalf("invalid input result: err=%v artifacts=%d", err, len(artifacts))
				}
				capabilitiesAfter, _ := json.Marshal(document.RequiredCapabilities)
				if !bytes.Equal(capabilitiesBefore, capabilitiesAfter) {
					t.Fatal("failed compilation changed capabilities")
				}
				if test.missing || test.invalidVersion != 0 {
					candidate, _ := json.Marshal(document)
					if _, _, _, _, err := compileSiteRuntimeV2Document(candidate); err == nil {
						t.Fatal("whole-document compiler accepted unsupported capabilities")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(artifacts) != len(facts) {
				t.Fatal("unexpected firewall artifacts")
			}
			candidate, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSiteRuntimeV2FirewallActionArtifacts(candidate, artifacts); err != nil {
				t.Fatalf("firewall sidecar binding is invalid: %v", err)
			}
			if test.documentRejects {
				capabilitiesAfter, _ := json.Marshal(document.RequiredCapabilities)
				if !bytes.Equal(capabilitiesBefore, capabilitiesAfter) {
					t.Fatal("firewall producer changed capabilities")
				}
				if _, _, _, _, err := compileSiteRuntimeV2Document(candidate); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("whole-document compiler accepted unsupported capabilities: %v", err)
				}
				return
			}
			_, _, capabilities, _, err := compileSiteRuntimeV2Document(candidate)
			if err != nil {
				t.Fatalf("firewall producer output rejected by document compiler: %v; declared=%v", err, document.RequiredCapabilities)
			}
			for _, capability := range capabilities {
				if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
					if capability.ApiVersion != test.want {
						t.Fatalf("site_runtime=%d want=%d", capability.ApiVersion, test.want)
					}
					return
				}
			}
			t.Fatal("site_runtime capability missing")
		})
	}
}
