package edgepublish

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Only a node that declares L4_TRAFFIC_STOP is told to cut the stopped
// forwards' sessions off; an older node gets nothing and drains them.
func TestTrafficStopForDeclaringNodesOnly(t *testing.T) {
	stopped := []string{"33333333-3333-4333-8333-333333333331"}
	declares := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS, ApiVersion: 2},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_TRAFFIC_STOP, ApiVersion: 1},
	}
	if got := trafficStopFor(declares, stopped); len(got) != 1 || got[0] != stopped[0] {
		t.Fatalf("declaring node = %v", got)
	}
	older := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS, ApiVersion: 2}}
	if got := trafficStopFor(older, stopped); got != nil {
		t.Fatalf("older node = %v", got)
	}
	if got := trafficStopFor(declares, nil); got != nil {
		t.Fatalf("nothing stopped = %v", got)
	}
}
