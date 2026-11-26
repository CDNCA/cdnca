package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Only an Agent declaring NODE_STORAGE v2 gets the node facts time in its
// key document; a NODE_STORAGE v1 Agent refuses the unknown field, so it gets
// none (and still gets the storage settings).
func TestNodeFactsAtNeedsNodeStorageV2(t *testing.T) {
	storageCap := func(version uint32) []*agentv1.Capability {
		return []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE, ApiVersion: version}}
	}
	if got := nodeFactsAtFor(storageCap(siteobject.NodeStorageNodeFactsAPIVersion), 42); got != 42 {
		t.Fatalf("NODE_STORAGE v2 node = %d", got)
	}
	if got := nodeFactsAtFor(storageCap(siteobject.NodeStorageAPIVersion), 42); got != 0 {
		t.Fatalf("NODE_STORAGE v1 node = %d", got)
	}
	storage := siteobject.NodeStorage{LogDirectory: "/data/logs"}
	if nodeStorageFor(storageCap(siteobject.NodeStorageAPIVersion), storage, true) == nil ||
		nodeStorageFor(storageCap(siteobject.NodeStorageNodeFactsAPIVersion), storage, true) == nil {
		t.Fatal("storage settings must still reach NODE_STORAGE v1 and v2 nodes")
	}
}
