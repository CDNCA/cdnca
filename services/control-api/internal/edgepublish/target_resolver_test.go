package edgepublish

import "testing"

func TestSnapshotTargetResolverImplementsTargetResolver(t *testing.T) {
	var resolver TargetResolver = NewSnapshotTargetResolver()
	if resolver == nil {
		t.Fatal("snapshot target resolver is nil")
	}
}
