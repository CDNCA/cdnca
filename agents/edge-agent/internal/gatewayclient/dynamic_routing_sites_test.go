package gatewayclient

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func testSiteID(index int) string { return fmt.Sprintf("a0000000-0000-4000-8000-%012d", index) }

// SITE_SELECTION: the node serves the root's websites but
// those its key document withholds. A withheld website's object is neither
// fetched nor handed to the runtime, as if the root did not carry it; the
// websites it serves are the same objects, byte for byte.
func TestDynamicRoutingLeavesWithheldSitesOut(t *testing.T) {
	applier := &fakeDynamicRouting{}
	h := newDynamicRoutingHarness(t, applier)
	referenced := []byte(`{"cc":1}`)
	full := h.dynamicRoutingRelease(t, 3, referenced)
	withheld := testSiteID(2)
	release := newSiteObjectRelease(t, h.key, h.client.config.ArtifactDecryptionPrivateKey, h.client.config.ArtifactEncryptionKeyID,
		h.contentKey, "5c0b0000-0000-4000-8000-0000000000ab", 3, referenced,
		func(key *siteobject.KeyDocument) { withholdTestSiteIDs(key, 3, withheld) })
	gateway := &siteObjectGateway{release: release}
	status := executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, gateway), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
		t.Fatalf("state %v: %v", status.State, status.Error)
	}
	got := applier.applied[len(applier.applied)-1]
	if len(got.Sites) != 2 {
		t.Fatalf("node got %d websites, want 2 (one withheld)", len(got.Sites))
	}
	withheldDigest := siteobject.Digest([]byte(`{"site":"` + withheld + `"}`))
	if _, found := got.Sites[withheldDigest]; found {
		t.Fatal("the withheld website reached the runtime")
	}
	if slices.Contains(gateway.requested, withheldDigest) {
		t.Fatal("the withheld website's object was fetched")
	}
	for _, index := range []int{1, 3} {
		plaintext := []byte(`{"site":"` + testSiteID(index) + `"}`)
		if string(got.Sites[siteobject.Digest(plaintext)]) != string(plaintext) {
			t.Fatalf("served website %d = %q, want its object unchanged", index, got.Sites[siteobject.Digest(plaintext)])
		}
	}
	// The scope's own objects (referenced, files) are unaffected.
	if string(got.Referenced[siteobject.Digest(referenced)]) != string(referenced) || len(full.objects) == 0 {
		t.Fatalf("referenced = %v", got.Referenced)
	}
}

// Withholding every website leaves the node none of the scope's websites;
// a bitmap over another number of websites than the root carries is an
// integrity failure (control derives it from the same release).
func TestDynamicRoutingWithheldSitesEdges(t *testing.T) {
	applier := &fakeDynamicRouting{}
	h := newDynamicRoutingHarness(t, applier)
	release := newSiteObjectRelease(t, h.key, h.client.config.ArtifactDecryptionPrivateKey, h.client.config.ArtifactEncryptionKeyID,
		h.contentKey, "5c0b0000-0000-4000-8000-0000000000ac", 2, []byte(`{"cc":1}`),
		func(key *siteobject.KeyDocument) { withholdTestSites(key, 2, 2) })
	status := executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, &siteObjectGateway{release: release}), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
		t.Fatalf("withhold all: state %v: %v", status.State, status.Error)
	}
	if got := applier.applied[len(applier.applied)-1]; len(got.Sites) != 0 {
		t.Fatalf("withhold all: node got %d websites", len(got.Sites))
	}

	applied := applier.activationCount()
	release = newSiteObjectRelease(t, h.key, h.client.config.ArtifactDecryptionPrivateKey, h.client.config.ArtifactEncryptionKeyID,
		h.contentKey, "5c0b0000-0000-4000-8000-0000000000ad", 1, []byte(`{"cc":1}`),
		func(key *siteobject.KeyDocument) { withholdTestSites(key, 2, 1) }) // a bitmap of 2 websites, the root has 1
	status = executeSiteObjectRelease(t, h.client, newSiteObjectGatewayClient(t, &siteObjectGateway{release: release}), release.command)
	if status.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || !status.RunningConfigUnchanged ||
		!strings.Contains(status.GetError().GetMessage(), "withholds websites of a root of 2 websites") {
		t.Fatalf("unknown withheld website: state %v unchanged %v error %v", status.State, status.RunningConfigUnchanged, status.Error)
	}
	if applier.activationCount() != applied {
		t.Fatal("a release withholding an unknown website was applied")
	}
}

// withholdTestSiteIDs withholds ids of a release of sites websites.
func withholdTestSiteIDs(key *siteobject.KeyDocument, sites int, ids ...string) {
	all, skip := make([]string, sites), map[string]bool{}
	for index := range all {
		all[index] = testSiteID(index + 1)
	}
	for _, id := range ids {
		skip[id] = true
	}
	key.WithheldSites = siteobject.NewSiteBitmap(all, skip)
}
