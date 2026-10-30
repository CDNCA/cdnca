package securitypublication

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// renderSiteSecurityForTest renders a compiled site's security as the site
// runtime does (one listener per site: RenderSecurityFragments) and returns
// the http-level and per-listener nginx text joined.
func renderSiteSecurityForTest(t *testing.T, scopeID string, sites ...edgeconfig.Site) string {
	t.Helper()
	listeners := make([]edgeconfig.SecurityListener, 0, len(sites))
	for _, site := range sites {
		protocol := site.Protocol
		if protocol == "" {
			protocol = edgeconfig.ProtocolHTTP
		}
		listener := edgeconfig.SecurityListener{SiteID: site.ID, Domain: site.Domain, Port: site.ListenPort, Protocol: protocol,
			Security: edgeconfig.ListenerSecurity{Policies: site.SecurityPolicies, CC: site.CCV2}}
		if site.ManagedWAF != nil {
			managed, err := edgeconfig.CanonicalListenerManagedWAF(*site.ManagedWAF)
			if err != nil {
				t.Fatal(err)
			}
			listener.Security.ManagedWAF = managed
		}
		listeners = append(listeners, listener)
	}
	fragments, err := edgeconfig.RenderSecurityFragments(scopeID, "security-render-test", listeners)
	if err != nil {
		t.Fatalf("RenderSecurityFragments: %v", err)
	}
	return fragments.HTTP + strings.Join(fragments.Server, "") + strings.Join(fragments.Location, "")
}
