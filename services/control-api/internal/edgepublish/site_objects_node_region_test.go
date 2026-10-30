package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// fz-x12: only an Agent declaring NODE_REGION gets its region code in the
// key document; an older node gets none and picks nothing by region.
func TestNodeRegionForNeedsTheCapability(t *testing.T) {
	declares := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_REGION, ApiVersion: siteobject.NodeRegionAPIVersion}}
	if got := nodeRegionFor(declares, "region-7"); got != "region-7" {
		t.Fatalf("declaring node = %q", got)
	}
	older := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1}}
	if got := nodeRegionFor(older, "region-7"); got != "" {
		t.Fatalf("older node = %q", got)
	}
	if got := nodeRegionFor(declares, ""); got != "" {
		t.Fatalf("node without a region = %q", got)
	}
}
