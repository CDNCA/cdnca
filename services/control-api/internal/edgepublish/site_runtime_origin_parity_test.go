package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
)

// tp-b3a-be (migration 490): 跟随协议和端口 and 访问域名+端口 reach the v2
// document and the node's site object.
func TestSiteRuntimeV2OriginForwardingParity(t *testing.T) {
	disabled := false
	site := siteRuntimeV2Site{L2: siteRuntimeV2L2Policy{Enabled: &disabled}, DefaultPoolID: "primary", OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin", Algorithm: "round_robin",
		Origins: []siteRuntimeV2Origin{{ID: "origin-0", Scheme: "http", Host: "192.0.2.10", Port: 80, Weight: 1}}}}}
	fact := siteFact{originExtras: []originExtraFact{{}}, forwarding: &originForwardingFact{
		requestHostMode: "visitor_port", scheme: "follow", httpsPort: 443, tlsTrust: "system", followPort: true, websocketEnabled: true}}
	if err := applySiteRuntimeV2OriginForwarding(&site, 0, fact); err != nil {
		t.Fatal(err)
	}
	if len(site.OriginPools) != 2 || site.Forwarding == nil || site.Forwarding.HTTPSPoolID == nil ||
		*site.Forwarding.HTTPSPoolID != siteRuntimeV2HTTPSPoolID {
		t.Fatalf("follow keeps an HTTPS pool for TLS listeners: %+v", site)
	}
	for _, pool := range site.OriginPools {
		if pool.FollowPort == nil || !*pool.FollowPort {
			t.Fatalf("pool %s does not follow the visitor's port", pool.ID)
		}
		if pool.RequestHost == nil || pool.RequestHost.Mode != "visitor_port" || pool.RequestHost.Value != nil {
			t.Fatalf("pool %s request host %+v", pool.ID, pool.RequestHost)
		}
		if err := validateSiteRuntimeV2PoolForwarding(pool); err != nil {
			t.Fatalf("pool %s: %v", pool.ID, err)
		}
	}
	if https := site.OriginPools[1]; https.Origins[0].Scheme != "https" {
		t.Fatalf("HTTPS pool origin %+v", https.Origins[0])
	}
	origin, err := convertSiteOriginV2(site, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range origin.Pools {
		if !pool.FollowPort || pool.RequestHost == nil || pool.RequestHost.Mode != edgesite.RequestHostVisitorPort {
			t.Fatalf("site object pool %s: follow_port=%v request_host=%+v", pool.ID, pool.FollowPort, pool.RequestHost)
		}
	}
}

// The site's origin auth switch off: its rules are left out of the site
// objects, other sites' rules stay; the publication itself is untouched.
func TestOriginAuthEnabledRules(t *testing.T) {
	on, off := uuid.New(), uuid.New()
	snapshot := originauthcontrol.PublicationSnapshot{PublicationRevision: 3,
		Rules: []originauthcontrol.PublicationRule{{RuleID: uuid.New(), SiteID: on}, {RuleID: uuid.New(), SiteID: off}}}
	got := originAuthEnabledRules(snapshot, map[uuid.UUID]bool{off: true})
	if len(got.Rules) != 1 || got.Rules[0].SiteID != on || got.PublicationRevision != 3 || len(snapshot.Rules) != 2 {
		t.Fatalf("rules %+v (input %d)", got.Rules, len(snapshot.Rules))
	}
	if same := originAuthEnabledRules(snapshot, nil); len(same.Rules) != 2 {
		t.Fatalf("no switch off: %+v", same.Rules)
	}
}
