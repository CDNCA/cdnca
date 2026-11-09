package edgepublish

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A node that declares SITE_SELECTION is withheld the websites
// of line groups it does not serve; a website without a line group goes
// everywhere; an older node is withheld nothing (it serves them all, as
// before) and is reported when it would have been withheld some.
func TestWithheldSitesForServingNodesOnly(t *testing.T) {
	const a, b, c = "55555555-5555-4555-8555-555555555551", "55555555-5555-4555-8555-555555555552", "55555555-5555-4555-8555-555555555553"
	nodeA, nodeB := uuid.MustParse("44444444-4444-4444-8444-444444444441"), uuid.MustParse("44444444-4444-4444-8444-444444444442")
	sites := []string{b, a, c}
	serving := map[string]map[uuid.UUID]struct{}{
		a: {nodeA: {}}, // group of node A
		b: {nodeB: {}}, // group of node B
		// c: no line group: every node
	}
	declares := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION, ApiVersion: 1}}
	if got, unsupported := withheldSitesFor(declares, nodeA, sites, serving); !slices.Equal(got, []string{b}) || unsupported {
		t.Fatalf("node A withheld = %v (unsupported %v)", got, unsupported)
	}
	if got, _ := withheldSitesFor(declares, nodeB, sites, serving); !slices.Equal(got, []string{a}) {
		t.Fatalf("node B withheld = %v", got)
	}
	// A group with no serving node: its website goes to none (sorted).
	serving[c] = map[uuid.UUID]struct{}{}
	if got, _ := withheldSitesFor(declares, nodeA, sites, serving); !slices.Equal(got, []string{b, c}) {
		t.Fatalf("node A withheld with c unserved = %v", got)
	}
	// L4_STREAM_SELECTION alone does not select websites.
	older := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION, ApiVersion: 1}}
	if got, unsupported := withheldSitesFor(older, nodeA, sites, serving); got != nil || !unsupported {
		t.Fatalf("older node withheld = %v, unsupported = %v (want none, reported)", got, unsupported)
	}
	// An older node serving every website is not reported.
	all := map[string]map[uuid.UUID]struct{}{a: {nodeA: {}}}
	if got, unsupported := withheldSitesFor(older, nodeA, sites, all); got != nil || unsupported {
		t.Fatalf("older node serving all withheld = %v, unsupported = %v", got, unsupported)
	}
	if got, unsupported := withheldSitesFor(declares, nodeA, nil, serving); got != nil || unsupported {
		t.Fatalf("no sites withheld = %v, unsupported = %v", got, unsupported)
	}
}

// The key envelope a node declaring SITE_SELECTION gets for a
// scope of 100,000 websites stays far below the shared bound whatever the
// number withheld (0, 90, 95, 10,000, 99,000), sealed by the production
// producer; an older node's envelope over its 4096 bytes is refused with
// the node and the reason, and so is one over the bound.
func TestSiteSelectionKeyEnvelopeAtScale(t *testing.T) {
	producer, err := newConfigurationArtifactProducer(newUnitConfigurationArtifactSigner(t), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding, publicKey, _ := newUnitConfigurationArtifactBinding(t, uuid.New())
	declares := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SELECTION, ApiVersion: 1}}
	const sites = 100000
	siteIDs := make([]string, sites)
	for index := range siteIDs {
		siteIDs[index] = fmt.Sprintf("55555555-5555-4555-8555-%012d", index)
	}
	for _, withheld := range []int{0, 90, 95, 10000, 99000} {
		serving := map[string]map[uuid.UUID]struct{}{}
		for _, id := range siteIDs[:withheld] {
			serving[id] = map[uuid.UUID]struct{}{} // a group without the node
		}
		started := time.Now()
		ids, unsupported := withheldSitesFor(declares, binding.NodeID, siteIDs, serving)
		plaintext, err := siteobject.Encode(siteobject.KeyDocument{Schema: siteobject.KeySchema,
			ConfigurationScopeID: uuid.NewString(), ConfigVersionID: uuid.NewString(), RootSHA256: strings.Repeat("a", 64),
			KeyEpoch: 1, ContentKey: make([]byte, siteobject.ContentKeySize),
			WithheldSites: siteobject.NewSiteBitmap(siteIDs, withheldSet(ids))})
		if err != nil || unsupported || len(ids) != withheld {
			t.Fatalf("%d withheld: %d ids, unsupported %v, %v", withheld, len(ids), unsupported, err)
		}
		envelope, err := producer.Build(context.Background(), binding, publicKey, plaintext, siteobject.KeyMediaType)
		if err != nil {
			t.Fatal(err)
		}
		if err := keyEnvelopeFits(binding.NodeID, declares, envelope.SizeBytes); err != nil {
			t.Fatalf("%d withheld: %v", withheld, err)
		}
		t.Logf("100,000 websites, %d withheld: key envelope %d bytes (bound %d), built in %v",
			withheld, envelope.SizeBytes, siteobject.MaxKeyEnvelopeBytes, time.Since(started).Round(time.Millisecond))
	}
	nodeID := uuid.New()
	if err := keyEnvelopeFits(nodeID, nil, siteobject.LegacyMaxKeyEnvelopeBytes); err != nil {
		t.Fatalf("older node at its bound: %v", err)
	}
	var refusal *TargetCapabilityError
	if err := keyEnvelopeFits(nodeID, nil, siteobject.LegacyMaxKeyEnvelopeBytes+1); !errors.As(err, &refusal) ||
		refusal.NodeID != nodeID || !strings.Contains(err.Error(), "4097 bytes") || !strings.Contains(err.Error(), "SITE_SELECTION") {
		t.Fatalf("older node over its bound: %v", err)
	}
	if err := keyEnvelopeFits(nodeID, declares, siteobject.MaxKeyEnvelopeBytes+1); !errors.Is(err, ErrInvalidInput) ||
		!strings.Contains(err.Error(), nodeID.String()) {
		t.Fatalf("over the bound: %v", err)
	}
}
