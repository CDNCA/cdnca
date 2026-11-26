package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// NODE_STORAGE v2: the node's region and storage come from the release whose
// key document control read them for last, on an apply, a reapply and a
// rollback alike. Scope A still holds an older release with the old region
// and a storage setting (its newer publications were refused); scope B's
// newer one, activated, has a new region and storage back to the defaults:
// a restart (reapply), an apply of A's old release again and a rollback of B
// to its own older release never bring the old values back.
func TestDynamicRoutingNodeFactsTakeTheLatestKeyDocument(t *testing.T) {
	const scopeA, scopeB = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &dynamicRoutingManager{objects: objects, root: filepath.Join(root, "scopes")}
	if err := os.MkdirAll(manager.root, 0o700); err != nil {
		t.Fatal(err)
	}
	storage := &siteobject.NodeStorage{LogDirectory: "/data/old-logs"}
	release := func(scopeID, site, host, version string, at int64) *dynamicRoutingRelease {
		digest, raw := dynamicTestSite(t, scopeID, site, host)
		if err := objects.Put(digest, raw); err != nil {
			t.Fatal(err)
		}
		return &dynamicRoutingRelease{ConfigVersionID: version, RootSHA256: digest, Sites: []string{digest}, NodeFactsAt: at}
	}
	oldA := release(scopeA, "a0000000-0000-4000-8000-000000000001", "a.example.test", "c0000000-0000-4000-8000-00000000000a", 100)
	oldA.NodeStorage, oldA.NodeRegion = storage, "region-old"
	oldB := release(scopeB, "b0000000-0000-4000-8000-000000000002", "b.example.test", "c0000000-0000-4000-8000-00000000000b", 90)
	oldB.NodeStorage, oldB.NodeRegion = storage, "region-old"
	newB := release(scopeB, "b0000000-0000-4000-8000-000000000002", "b.example.test", "c0000000-0000-4000-8000-00000000000c", 200)
	newB.NodeRegion = "region-new" // storage back to the defaults
	if err := manager.save(scopeA, dynamicRoutingScope{Current: oldA}); err != nil {
		t.Fatal(err)
	}
	if err := manager.save(scopeB, dynamicRoutingScope{Current: newB, Previous: oldB}); err != nil {
		t.Fatal(err)
	}
	manager.keepNodeFacts(newB) // as its activation did
	manager.keepNodeFacts(oldA) // older: the kept facts stay B's
	want := func(name string, override map[string]*dynamicRoutingRelease, supplied gatewayclient.DynamicRoutingRelease,
		region string, storage *siteobject.NodeStorage) {
		t.Helper()
		input, err := manager.input(override, supplied)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if input.NodeRegion != region || !reflect.DeepEqual(input.NodeStorage, storage) {
			t.Fatalf("%s: region %q storage %+v, want %q %+v", name, input.NodeRegion, input.NodeStorage, region, storage)
		}
	}
	// A restart reapplies every scope's current release: B's is the latest.
	want("reapply", nil, gatewayclient.DynamicRoutingRelease{}, "region-new", nil)
	// A's old release delivered again: applied, it still does not win.
	again := *oldA
	want("apply", map[string]*dynamicRoutingRelease{scopeA: &again},
		gatewayclient.DynamicRoutingRelease{ConfigurationScopeID: scopeA, ConfigVersionID: again.ConfigVersionID,
			NodeRegion: again.NodeRegion, NodeStorage: again.NodeStorage, NodeFactsAt: again.NodeFactsAt},
		"region-new", nil)
	// B rolled back to its older release: the kept facts (B's newer
	// release) still win over A's (100) and B's old one (90).
	want("rollback", map[string]*dynamicRoutingRelease{scopeB: oldB}, gatewayclient.DynamicRoutingRelease{},
		"region-new", nil)
	// Without the kept file (lost or never written) the releases in effect
	// decide: the rollback then takes A's.
	if err := os.Remove(manager.nodeFactsPath()); err != nil {
		t.Fatal(err)
	}
	want("rollback without kept facts", map[string]*dynamicRoutingRelease{scopeB: oldB}, gatewayclient.DynamicRoutingRelease{},
		"region-old", storage)
	// A newer release applied wins, storage set again included.
	newA := release(scopeA, "a0000000-0000-4000-8000-000000000001", "a.example.test", "c0000000-0000-4000-8000-00000000000d", 300)
	newA.NodeStorage = storage
	want("newer apply", map[string]*dynamicRoutingRelease{scopeA: newA},
		gatewayclient.DynamicRoutingRelease{ConfigurationScopeID: scopeA, ConfigVersionID: newA.ConfigVersionID, NodeStorage: storage, NodeFactsAt: 300},
		"", storage)
	// Key documents from before NODE_STORAGE v2 (no time): as before, the
	// release being applied, else the first scope's that names each.
	oldA.NodeFactsAt, newB.NodeFactsAt = 0, 0
	if err := manager.save(scopeA, dynamicRoutingScope{Current: oldA}); err != nil {
		t.Fatal(err)
	}
	if err := manager.save(scopeB, dynamicRoutingScope{Current: newB, Previous: oldB}); err != nil {
		t.Fatal(err)
	}
	want("reapply without times", nil, gatewayclient.DynamicRoutingRelease{}, "region-old", storage)
	want("apply without times", map[string]*dynamicRoutingRelease{scopeB: newB},
		gatewayclient.DynamicRoutingRelease{ConfigurationScopeID: scopeB, ConfigVersionID: newB.ConfigVersionID, NodeRegion: "region-new"},
		"region-new", nil)
}
