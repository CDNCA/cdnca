package edgepublish

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// a refusal for SITE_SERVER_TIMING names the switch and the way out.
func TestGatedFeatureServerTiming(t *testing.T) {
	text, ok := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING, ApiVersion: 1})
	if !ok || !strings.Contains(text, "SITE_SERVER_TIMING") || !strings.Contains(text, "Server-Timing") {
		t.Fatalf("gatedFeature(SITE_SERVER_TIMING) = %q %v", text, ok)
	}
}

// A release whose root does not require site_server_timing never carries
// server_timing in a site object (an older node decodes strictly and would
// refuse the whole object): the fact is dropped, not delivered.
func TestServerTimingNeedsRootCapability(t *testing.T) {
	facts := map[string]siteObjectV2Facts{"a": {ServerTiming: true, CacheStatusHeader: true}, "b": {}}
	withoutServerTimingCapability(siteObjectsV2Source{Capabilities: []siteobject.Capability{{Name: "site_runtime", APIVersion: 9}}}, facts)
	if facts["a"].ServerTiming || !facts["a"].CacheStatusHeader {
		t.Fatalf("without the root capability: %+v", facts["a"])
	}
	facts["a"] = siteObjectV2Facts{ServerTiming: true}
	withoutServerTimingCapability(siteObjectsV2Source{Capabilities: []siteobject.Capability{
		{Name: siteobject.ServerTimingCapability, APIVersion: siteobject.ServerTimingAPIVersion}}}, facts)
	if !facts["a"].ServerTiming || facts["b"].ServerTiming {
		t.Fatalf("with the root capability: %+v %+v", facts["a"], facts["b"])
	}
}
