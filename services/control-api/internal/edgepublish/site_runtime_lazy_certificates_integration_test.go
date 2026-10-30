//go:build integration

package edgepublish

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// A real publication of an HTTPS site: every v2 release is delivered as site
// objects, so a target must declare site runtime v8, which implies lazy
// certificates (v7). A v7 node is refused by name with nothing persisted; a
// v8 node gets lazy certificates (the document requires v7, the rollout v8).
func TestSiteRuntimeV2PublishChoosesLazyCertificatesByNodeCapability(t *testing.T) {
	for _, version := range []uint32{edgeconfig.LazyCertificateSiteRuntimeVersion, edgeconfig.DynamicRoutingSiteRuntimeVersion} {
		t.Run(fmt.Sprintf("v%d node", version), func(t *testing.T) {
			fixture := newPublishFixture(t)
			fixture.service.config.LazyCertificateCacheMax = 4321
			site := fixture.createSiteWithPortSets(t, "lazy-cert.example.test", []string{"80"}, []string{"443"}, true)
			seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
			features := append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
				&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: version})
			seedSiteRuntimeV2Capabilities(t, fixture, "", features)
			result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
				fixture, fmt.Sprintf("lazy-cert-v%d", version), fixture.nodeID, siteRuntimeV2Schema))
			if version < edgeconfig.DynamicRoutingSiteRuntimeVersion {
				if !errors.Is(err, ErrTargetIneligible) {
					t.Fatalf("v%d target publish error = %v, want ineligible target", version, err)
				}
				assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
				return
			}
			if err != nil {
				t.Fatalf("Publish: %v", err)
			}
			var encoded []byte
			if err := fixture.pool.QueryRow(t.Context(), `SELECT canonical_snapshot FROM config_versions WHERE id=$1`,
				result.ConfigVersionID).Scan(&encoded); err != nil {
				t.Fatal(err)
			}
			var document siteRuntimeV2Document
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			if document.LazyCertificates == nil || document.LazyCertificates.CacheMax != 4321 {
				t.Fatalf("lazy_certificates = %+v", document.LazyCertificates)
			}
			if requiredSiteRuntime(document) != edgeconfig.LazyCertificateSiteRuntimeVersion {
				t.Fatalf("document site_runtime = %d, want %d", requiredSiteRuntime(document), edgeconfig.LazyCertificateSiteRuntimeVersion)
			}
		})
	}
}
