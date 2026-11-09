package gatewayclient

import (
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// A node withheld more than about 92 websites of its scope
// failed every deployment of it: the key envelope was bounded at 4096 bytes
// while the key document listed each withheld website by ID. The release
// goes through the production command validation, fetch and selection.
func TestDynamicRoutingWithholdsHundredSites(t *testing.T) {
	applier := &fakeDynamicRouting{}
	h := newDynamicRoutingHarness(t, applier)
	const sites, withheld = 120, 100
	release := newSiteObjectRelease(t, h.key, h.client.config.ArtifactDecryptionPrivateKey, h.client.config.ArtifactEncryptionKeyID,
		h.contentKey, "5c0b0000-0000-4000-8000-0000000000ae", sites, []byte(`{"cc":1}`),
		func(key *siteobject.KeyDocument) { withholdTestSites(key, sites, withheld) })
	status := executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, &siteObjectGateway{release: release}), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
		t.Fatalf("withholding %d of %d websites: state %v: %v", withheld, sites, status.State, status.Error)
	}
	if got := applier.applied[len(applier.applied)-1]; len(got.Sites) != sites-withheld {
		t.Fatalf("node got %d websites, want %d", len(got.Sites), sites-withheld)
	}
}

// withholdTestSites withholds the first withheld of the release's websites
// (testSiteID 1..withheld, newSiteObjectRelease's IDs, in ID order).
func withholdTestSites(key *siteobject.KeyDocument, sites, withheld int) {
	all, skip := make([]string, sites), map[string]bool{}
	for index := range all {
		all[index] = testSiteID(index + 1)
		if index < withheld {
			skip[all[index]] = true
		}
	}
	key.WithheldSites = siteobject.NewSiteBitmap(all, skip)
}

// Tiers: 0, 90, 95 withheld of 1,000 websites always; 10,000 and
// 99,000 of 100,000 with CDNCA_SITESEL_SCALE=1 (about a minute: 100,000
// sealed objects through the fake gateway). Each tier goes through command
// validation, the key envelope, the fetch and SelectNodeSites and reports
// the time from command to the release handed to the runtime.
func TestDynamicRoutingWithheldSitesTiers(t *testing.T) {
	tiers := []struct{ sites, withheld int }{{1000, 0}, {1000, 90}, {1000, 95}}
	if os.Getenv("CDNCA_SITESEL_SCALE") != "" {
		tiers = append(tiers, struct{ sites, withheld int }{100000, 0}, struct{ sites, withheld int }{100000, 10000},
			struct{ sites, withheld int }{100000, 99000})
	}
	for _, tier := range tiers {
		applier := &fakeDynamicRouting{}
		h := newDynamicRoutingHarness(t, applier)
		release := newSiteObjectRelease(t, h.key, h.client.config.ArtifactDecryptionPrivateKey, h.client.config.ArtifactEncryptionKeyID,
			h.contentKey, "5c0b0000-0000-4000-8000-0000000000af", tier.sites, []byte(`{"cc":1}`),
			func(key *siteobject.KeyDocument) { withholdTestSites(key, tier.sites, tier.withheld) })
		gateway := &siteObjectGateway{release: release}
		started := time.Now()
		status := executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, gateway), release.command)
		elapsed := time.Since(started)
		if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
			t.Fatalf("%d of %d withheld: state %v: %v", tier.withheld, tier.sites, status.State, status.Error)
		}
		got := applier.applied[len(applier.applied)-1]
		if len(got.Sites) != tier.sites-tier.withheld {
			t.Fatalf("%d of %d withheld: node got %d websites", tier.withheld, tier.sites, len(got.Sites))
		}
		var keySize uint64
		for _, artifact := range release.command.Artifacts {
			if artifact.MediaType == siteobject.KeyMediaType {
				keySize = artifact.SizeBytes
			}
		}
		t.Logf("%d websites, %d withheld: key envelope %d bytes, %d objects requested, command to release %v",
			tier.sites, tier.withheld, keySize, len(gateway.requested), elapsed.Round(time.Millisecond))
	}
}
