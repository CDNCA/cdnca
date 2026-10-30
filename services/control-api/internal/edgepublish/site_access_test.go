package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// Forced HTTPS carries its status and excluded domains, and
// site.access reaches the v2 document, validated as the node validates it.
func TestSiteRuntimeV2SiteAccess(t *testing.T) {
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "secure.example.test",
		domains:   []string{"old.example.test", "secure.example.test"},
		httpPorts: []string{"80"}, httpsPorts: []string{"443"}, httpsEnabled: true, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000, forceHTTPS: true, httpsRedirectStatus: 308,
		httpsRedirectExclude: []string{"gone.example.test", "old.example.test"},
		origins:              []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	site, err := compileForceHTTPSFact(fact)
	if err != nil || site.ForceHTTPS == nil || site.ForceHTTPS.Status != 308 ||
		len(site.ForceHTTPS.ExcludeHosts) != 1 || site.ForceHTTPS.ExcludeHosts[0] != "old.example.test" {
		t.Fatalf("forced HTTPS = %+v %v (a removed domain is dropped from the exclusions)", site.ForceHTTPS, err)
	}
	fact.httpsRedirectStatus, fact.httpsRedirectExclude = 301, nil
	if site, _ := compileForceHTTPSFact(fact); site.ForceHTTPS.Status != 0 || site.ForceHTTPS.ExcludeHosts != nil {
		t.Fatalf("default forced HTTPS must stay {redirect_port}: %+v", site.ForceHTTPS)
	}
	fact.httpsRedirectExclude = []string{"old.example.test", "secure.example.test"}
	if site, _ := compileForceHTTPSFact(fact); site.ForceHTTPS != nil {
		t.Fatal("forcing with every domain excluded publishes a redirect")
	}

	fact.httpsRedirectExclude = nil
	site, _ = compileForceHTTPSFact(fact)
	site.Domains = []string{"secure.example.test", "old.example.test"}
	site.Access = &edgeconfig.SiteAccess{
		HSTS: &edgeconfig.SiteHSTS{MaxAgeSeconds: 600},
		HostRedirects: []edgeconfig.HostRedirect{{SourceHost: "old.example.test", TargetHost: "secure.example.test",
			TargetScheme: "https", Status: 301, PreserveURI: true}},
	}
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: []siteRuntimeV2Capability{{"http1", 1}, {"http2", 1}, {"http3", 1}, {"ipv4", 1}, {"ipv6", 1}, {"site_runtime", edgeconfig.MinSiteRuntimeVersion}, {"websocket", 1}},
	}
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err != nil {
		t.Fatalf("site access rejected: %v", err)
	}
	site.Access.HostRedirects[0].SourceHost = "other.example.test"
	document.Sites[0] = site
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("host redirect for a domain the site does not serve accepted")
	}
	site.Access = &edgeconfig.SiteAccess{}
	document.Sites[0] = site
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("empty access object accepted")
	}
}
