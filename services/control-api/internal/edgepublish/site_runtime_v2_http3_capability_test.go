package edgepublish

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// fix-mktsiteconf2 ③: an HTTPS site needs http2 (it follows TLS) but http3
// (SITE_QUIC) only when one of its listeners serves HTTP/3, so a site with
// HTTP/3 off can be published to a node without QUIC.
func TestSiteRuntimeV2HTTP3CapabilityFollowsSiteSwitch(t *testing.T) {
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "secure.example.test",
		httpPorts: []string{"80"}, httpsPorts: []string{"443"}, httpsEnabled: true, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	withoutQUIC := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV4, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_IPV6, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WEBSOCKET, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.MinSiteRuntimeVersion},
	}
	for name, test := range map[string]struct {
		protocols []string
		wantHTTP3 bool
	}{
		"http3 off": {[]string{"http1", "http2"}, false},
		"http3 on":  {[]string{"http1", "http2", "http3"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			site, err := compileForceHTTPSFact(fact)
			if err != nil {
				t.Fatal(err)
			}
			site.Listeners[1].Protocols = test.protocols
			required := map[string]uint32{"http1": 1, "ipv4": 1, "ipv6": 1, "websocket": 1, "site_runtime": edgeconfig.MinSiteRuntimeVersion}
			addSiteRuntimeV2ProtocolCapabilities(required, site)
			if required["http2"] != 1 {
				t.Fatalf("TLS site without http2: %v", required)
			}
			if _, has := required["http3"]; has != test.wantHTTP3 {
				t.Fatalf("http3 required = %v, want %v", has, test.wantHTTP3)
			}
			document := siteRuntimeV2Document{
				Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
				ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
			}
			for name, version := range required {
				document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{name, version})
			}
			slices.SortFunc(document.RequiredCapabilities, func(a, b siteRuntimeV2Capability) int {
				if a.Name < b.Name {
					return -1
				}
				return 1
			})
			raw, _ := json.Marshal(document)
			_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
			if err != nil {
				t.Fatalf("document rejected: %v", err)
			}
			refusal := targetCapabilityError(uuid.New(), "1.0.35", capabilities, withoutQUIC)
			if (refusal != nil) != test.wantHTTP3 {
				t.Fatalf("node without SITE_QUIC refusal = %v, want refused %v", refusal, test.wantHTTP3)
			}
		})
	}
}
