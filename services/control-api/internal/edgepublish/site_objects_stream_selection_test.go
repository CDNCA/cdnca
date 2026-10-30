package edgepublish

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A node that declares L4_STREAM_SELECTION is withheld the forwards of line
// groups it does not serve; a forward without a line group goes everywhere;
// an older node is withheld nothing (it serves them all, as before).
func TestWithheldStreamsForServingNodesOnly(t *testing.T) {
	const a, b, c = "33333333-3333-4333-8333-333333333331", "33333333-3333-4333-8333-333333333332", "33333333-3333-4333-8333-333333333333"
	nodeA, nodeB := uuid.MustParse("44444444-4444-4444-8444-444444444441"), uuid.MustParse("44444444-4444-4444-8444-444444444442")
	streams := &edgeconfig.StreamRuntime{StreamsV2: []edgeconfig.L4StreamRuntimeV2{{StreamID: b}, {StreamID: a}, {StreamID: c}}}
	serving := map[string]map[uuid.UUID]struct{}{
		a: {nodeA: {}}, // group of node A
		b: {nodeB: {}}, // group of node B
		// c: no line group: every node
	}
	declares := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1}}
	if got := withheldStreamsFor(declares, nodeA, streams, serving); !slices.Equal(got, []string{b}) {
		t.Fatalf("node A withheld = %v", got)
	}
	if got := withheldStreamsFor(declares, nodeB, streams, serving); !slices.Equal(got, []string{a}) {
		t.Fatalf("node B withheld = %v", got)
	}
	// A group with no serving node: its forward goes to none (sorted).
	serving[c] = map[uuid.UUID]struct{}{}
	if got := withheldStreamsFor(declares, nodeA, streams, serving); !slices.Equal(got, []string{b, c}) {
		t.Fatalf("node A withheld with c unserved = %v", got)
	}
	older := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_EDGE_OPTIONS, ApiVersion: 1}}
	if got := withheldStreamsFor(older, nodeA, streams, serving); got != nil {
		t.Fatalf("older node withheld = %v", got)
	}
	if got := withheldStreamsFor(declares, nodeA, nil, serving); got != nil {
		t.Fatalf("no streams withheld = %v", got)
	}
}
