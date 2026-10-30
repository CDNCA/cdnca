package edgepublish

import (
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// ge36: a site that follows origin redirects carries forwarding.follow_redirect
// and its document needs ORIGIN_FOLLOW_REDIRECT.
func TestOriginFollowRedirectForwarding(t *testing.T) {
	site := siteRuntimeV2Site{OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin"}}}
	fact := siteFact{forwarding: &originForwardingFact{requestHostMode: "visitor", scheme: "http", websocketEnabled: true,
		followRedirect: true, followRedirectMaxHops: 4, followRedirectCrossOrigin: true}}
	if err := applySiteRuntimeV2OriginForwarding(&site, 0, fact); err != nil {
		t.Fatal(err)
	}
	redirect := site.Forwarding.FollowRedirect
	if redirect == nil || redirect.MaxHops != 4 || !redirect.CrossOrigin {
		t.Fatalf("forwarding %+v", site.Forwarding)
	}
	websocket := true
	site.WebSocket = &websocket
	if err := validateSiteRuntimeV2Forwarding(site, map[string]siteRuntimeV2OriginPool{}); err != nil {
		t.Fatalf("valid forwarding refused: %v", err)
	}
	site.Forwarding.FollowRedirect.MaxHops = 6
	if validateSiteRuntimeV2Forwarding(site, map[string]siteRuntimeV2OriginPool{}) == nil {
		t.Fatal("6 hops accepted")
	}
	off := siteRuntimeV2Site{OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin"}}}
	fact.forwarding.followRedirect = false
	if err := applySiteRuntimeV2OriginForwarding(&off, 0, fact); err != nil || off.Forwarding != nil && off.Forwarding.FollowRedirect != nil {
		t.Fatalf("off: %+v %v", off.Forwarding, err)
	}
	if name, ok := siteruntimecap.Name(edgeconfig.OriginFollowRedirectCapability); !ok || name.String() != "CAPABILITY_NAME_ORIGIN_FOLLOW_REDIRECT" {
		t.Fatalf("capability %v", name)
	}
}
