package edgepublish

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"github.com/google/uuid"
)

// fix-originnoverify: a pool that does not verify the origin certificate
// (tls_trust none, 不校验源站证书) publishes trust_ref "none" on every HTTPS
// origin (both pools of follow), and its document needs ORIGIN_TLS_NO_VERIFY.
func TestOriginTLSNoVerifyForwarding(t *testing.T) {
	for _, scheme := range []string{"https", "follow"} {
		site := siteRuntimeV2Site{OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin",
			Origins: []siteRuntimeV2Origin{{ID: "o1", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}}}}}
		fact := siteFact{forwarding: &originForwardingFact{requestHostMode: "visitor", scheme: scheme, httpsPort: 443,
			websocketEnabled: true, tlsTrust: "none"}, originExtras: []originExtraFact{{}}}
		if err := applySiteRuntimeV2OriginForwarding(&site, 0, fact); err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		https := 0
		for _, pool := range site.OriginPools {
			for _, origin := range pool.Origins {
				if origin.Scheme == "https" {
					https++
					if origin.TrustRef == nil || *origin.TrustRef != siteRuntimeV2NoVerifyTrust {
						t.Fatalf("%s: trust %v", scheme, origin.TrustRef)
					}
				}
			}
		}
		if https == 0 || !siteRuntimeV2UsesOriginTLSNoVerify(site) {
			t.Fatalf("%s: pools %+v", scheme, site.OriginPools)
		}
		if digests := siteRuntimeV2TrustDigests(siteRuntimeV2Document{Sites: []siteRuntimeV2Site{site}}); len(digests) != 0 {
			t.Fatalf("%s: none referenced a CA object: %v", scheme, digests)
		}
	}
	plain := siteRuntimeV2Site{OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin",
		Origins: []siteRuntimeV2Origin{{ID: "o1", Scheme: "https", Host: "192.0.2.1", Port: 443, Weight: 1, TrustRef: new(string)}}}}}
	*plain.OriginPools[0].Origins[0].TrustRef = siteRuntimeV2SystemTrust
	if siteRuntimeV2UsesOriginTLSNoVerify(plain) {
		t.Fatal("system trust needs ORIGIN_TLS_NO_VERIFY")
	}
	if name, ok := siteruntimecap.Name(edgeconfig.OriginTLSNoVerifyCapability); !ok ||
		name != agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY {
		t.Fatalf("capability %v", name)
	}
	reason, ok := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY, ApiVersion: 1})
	if !ok || !strings.Contains(reason, "不校验源站证书") || !strings.Contains(reason, "ORIGIN_TLS_NO_VERIFY") {
		t.Fatalf("reason %q", reason)
	}
	// a node without it is refused before publication, with the reason
	required := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY, ApiVersion: 1}}
	node := uuid.New()
	err := targetCapabilityError(node, "1.0.35", required, nil)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID != node || refusal.Feature != reason {
		t.Fatalf("refusal %v", err)
	}
	if err := targetCapabilityError(node, "1.0.35", required, required); err != nil {
		t.Fatalf("declaring node refused: %v", err)
	}
}
