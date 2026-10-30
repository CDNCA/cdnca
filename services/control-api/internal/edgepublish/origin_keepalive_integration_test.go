//go:build integration

package edgepublish

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// NF01 end to end in PG: the site's keepalive setting reaches the signed
// site runtime document. Keepalive needs site_runtime 5 and every v2 release
// is delivered as site objects (v8): a v5 node is refused before anything is
// persisted, a v8 node receives it.
func TestSiteRuntimeV2PublishCarriesOriginKeepalive(t *testing.T) {
	for _, siteRuntime := range []uint32{5, edgeconfig.DynamicRoutingSiteRuntimeVersion} {
		fixture := newPublishFixture(t)
		// Plain HTTP: the keepalive path does not depend on TLS material.
		site := fixture.createSiteWithPortSets(t, "runtime-v2-keepalive.example.test", []string{"80"}, []string{}, false)
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_origin_pools
			SET keepalive_enabled=true,keepalive_idle_timeout_ms=15000 WHERE site_id=$1`, site.Site.ID); err != nil {
			t.Fatal(err)
		}
		features := siteRuntimeV2RequiredCapabilities()
		for _, feature := range features {
			if feature.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME {
				feature.ApiVersion = siteRuntime
			}
		}
		seedSiteRuntimeV2Capabilities(t, fixture, "keepalive", features)
		result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
			fixture, "runtime-v2-keepalive", fixture.nodeID, siteRuntimeV2Schema))
		if siteRuntime == 5 {
			// The readable per-node reason needs a session declaration
			// (TestSiteRuntimeV2OriginKeepaliveRequiresV5 covers its wording).
			if !errors.Is(err, ErrTargetIneligible) {
				t.Fatalf("v5 target publish error = %v, want ineligible target", err)
			}
			assertPublishState(t, fixture.pool, 0, 0, 0, 0, 0)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var canonical string
		if err := fixture.pool.QueryRow(t.Context(), `SELECT convert_from(canonical_snapshot,'UTF8') FROM config_versions WHERE id=$1`,
			result.ConfigVersionID).Scan(&canonical); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(canonical, `"keepalive_idle_timeout_ms":15000`) ||
			!strings.Contains(canonical, `{"api_version":6,"name":"site_runtime"}`) {
			t.Fatalf("published document lacks keepalive or site_runtime 6:\n%s", canonical)
		}
	}
}
