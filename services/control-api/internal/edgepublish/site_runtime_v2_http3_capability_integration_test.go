//go:build integration

package edgepublish

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// fix-mktsiteconf2 ③: an HTTPS site with HTTP/3 off publishes to a node
// without SITE_QUIC; turning HTTP/3 on needs the capability again
// (TestSiteRuntimeV2PublishRejectsEveryMissingDurableCapabilityBeforePersistence/http3).
func TestSiteRuntimeV2PublishHTTPSWithHTTP3OffWithoutSiteQUIC(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSiteWithPortSets(t, "runtime-v2-no-quic.example.test", []string{"80"}, []string{"443"}, true)
	seedSiteRuntimeV2CertificateBinding(t, fixture, site.Site)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET http3_enabled=false WHERE id=$1`, site.Site.ID); err != nil {
		t.Fatal(err)
	}
	features := siteRuntimeV2NodeFeatures()
	filtered := features[:0:0]
	for _, feature := range features {
		if feature.Name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC {
			filtered = append(filtered, feature)
		}
	}
	seedSiteRuntimeV2Capabilities(t, fixture, "", filtered)
	if _, err := fixture.service.Publish(t.Context(),
		siteRuntimeV2PublishRequest(fixture, "runtime-v2-no-quic", fixture.nodeID, "cdnca.edge.site-runtime/v2")); err != nil {
		t.Fatalf("HTTPS site with HTTP/3 off refused on a node without SITE_QUIC: %v", err)
	}
}
