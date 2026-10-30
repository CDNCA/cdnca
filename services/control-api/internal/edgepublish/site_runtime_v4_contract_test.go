package edgepublish

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestSiteRuntimeV4SharedPayloadContract(t *testing.T) {
	for _, name := range []string{"v2", "v3", "v4-package", "v4-security", "v4-streams"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../../../../api/schemas/edge/v2/testdata", "site-runtime-capability-"+name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			// The shared fixtures still declare their historical site_runtime
			// (2/3/4); since 1.0.35 that is below the baseline and refused.
			if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
				t.Fatal("shared payload below the 1.0.35 baseline accepted")
			}
			var baseline siteRuntimeV2Document
			if err := json.Unmarshal(raw, &baseline); err != nil {
				t.Fatal(err)
			}
			setSiteRuntimeV2CapabilityExact(baseline.RequiredCapabilities, "site_runtime", edgeconfig.MinSiteRuntimeVersion)
			raw, err = json.Marshal(baseline)
			if err != nil {
				t.Fatal(err)
			}
			canonical, _, capabilities, tls, err := compileSiteRuntimeV2Document(raw)
			if err != nil || !tls {
				t.Fatalf("shared payload rejected: %v tls=%t", err, tls)
			}
			var document siteRuntimeV2Document
			if err := json.Unmarshal(canonical, &document); err != nil {
				t.Fatal(err)
			}
			var version uint32
			for _, capability := range capabilities {
				if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
					version = capability.ApiVersion
				}
			}
			// HTTP policy, package limits, security and streams no longer
			// raise site_runtime: every payload stays at the baseline.
			want := edgeconfig.MinSiteRuntimeVersion
			if version != want {
				t.Fatalf("runtime capability=%d want=%d", version, want)
			}
			if name == "v4-package" && (document.Sites[0].PackageLimits == nil || document.Sites[0].PackageLimits.Connections != 20) {
				t.Fatal("package limit dropped")
			}
			if name == "v4-security" {
				fragments, err := siteRuntimeSecurityFragments(document)
				if err != nil || !fragments.NeedsCC || len(fragments.Files) == 0 {
					t.Fatalf("security dropped: %+v %v", fragments, err)
				}
			}
			if name == "v4-streams" {
				_, files, err := siteRuntimeStreamFragment(document, 0)
				if err != nil || len(files[edgeconfig.L4RuntimeV2ArtifactPath]) == 0 {
					t.Fatalf("streams dropped: %v", err)
				}
			}
			unknown := bytes.Replace(canonical, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)
			if _, _, _, _, err := compileSiteRuntimeV2Document(unknown); err == nil {
				t.Fatal("unknown field accepted")
			}
			// 7 (lazy certificates) is the highest version; the next does not exist.
			for _, capability := range []uint32{1, edgeconfig.MinSiteRuntimeVersion - 1, edgeconfig.MaxSiteRuntimeVersion + 1} {
				for i := range document.RequiredCapabilities {
					if document.RequiredCapabilities[i].Name == "site_runtime" {
						document.RequiredCapabilities[i].APIVersion = capability
					}
				}
				invalid, _ := json.Marshal(document)
				if _, _, _, _, err := compileSiteRuntimeV2Document(invalid); err == nil {
					t.Fatalf("unknown runtime capability %d accepted", capability)
				}
			}
		})
	}
}
