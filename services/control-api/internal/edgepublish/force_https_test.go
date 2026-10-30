package edgepublish

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// FX07: forced HTTPS is published on the v2 site (site runtime baseline); port 0
// means the lowest HTTPS port.
func TestSiteRuntimeV2ForceHTTPS(t *testing.T) {
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "secure.example.test",
		httpPorts: []string{"80"}, httpsPorts: []string{"8443", "443"}, httpsEnabled: true, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000, forceHTTPS: true,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	site := siteRuntimeV2Site{}
	var err error
	site, err = compileForceHTTPSFact(fact)
	if err != nil || site.ForceHTTPS == nil || site.ForceHTTPS.RedirectPort != 443 {
		t.Fatalf("default redirect port = %+v %v, want the lowest HTTPS port 443", site.ForceHTTPS, err)
	}
	fact.httpsRedirectPort = 8443
	if site, err = compileForceHTTPSFact(fact); err != nil || site.ForceHTTPS.RedirectPort != 8443 {
		t.Fatalf("chosen redirect port = %+v %v", site.ForceHTTPS, err)
	}
	fact.httpsRedirectPort = 9443
	if _, err := compileForceHTTPSFact(fact); err == nil {
		t.Fatal("redirect port outside the HTTPS ports accepted")
	}
	fact.forceHTTPS, fact.httpsRedirectPort = false, 0
	if site, _ = compileForceHTTPSFact(fact); site.ForceHTTPS != nil {
		t.Fatal("site without forced HTTPS publishes it")
	}

	// Document validation needs the 1.0.35 baseline (as every document does)
	// and a TLS listener on the port.
	fact.forceHTTPS = true
	site, _ = compileForceHTTPSFact(fact)
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: []siteRuntimeV2Capability{{"http1", 1}, {"http2", 1}, {"http3", 1}, {"ipv4", 1}, {"ipv6", 1}, {"site_runtime", 5}, {"websocket", 1}},
	}
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("forced HTTPS below the site_runtime baseline accepted")
	}
	document.RequiredCapabilities[5].APIVersion = edgeconfig.MinSiteRuntimeVersion
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err != nil {
		t.Fatalf("baseline forced HTTPS rejected: %v", err)
	}
	// The port must still be a TLS listener of the site.
	document.Sites[0].ForceHTTPS.RedirectPort = 9443
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("forced HTTPS to a port without a TLS listener accepted")
	}
}

// compileForceHTTPSFact builds the parts of the site the redirect depends on:
// its listeners (as compile does, without the TLS binding store) and the
// forced HTTPS.
func compileForceHTTPSFact(fact siteFact) (siteRuntimeV2Site, error) {
	trueValue, falseValue := true, false
	httpsPorts, _ := parseSiteRuntimeV2Ports(fact.httpsPorts)
	site := siteRuntimeV2Site{ID: fact.id.String(), Revision: fact.revision, Domains: []string{fact.domain},
		DefaultPoolID: "primary", WebSocket: &trueValue, Range: &trueValue,
		L2: siteRuntimeV2L2Policy{Enabled: &falseValue, ProbeIntervalMS: 10000, FailureThreshold: 3, RecoveryThreshold: 3,
			SingleHalfOpenProbe: &trueValue, MaxHops: 1},
		Listeners: []siteRuntimeV2Listener{{ID: "public-80", AddressFamily: "dual_stack", Port: 80, Protocols: []string{"http1"}}},
		OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin", Algorithm: "round_robin",
			Origins: []siteRuntimeV2Origin{{ID: "origin-0", Tier: "origin", Scheme: "http", Host: "192.0.2.10", Port: 80, Weight: 100}},
			Retry: siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: &trueValue, ResponseNotStarted: &trueValue,
				RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
				MaxAttempts: 2, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, TotalBudgetMS: 60000}}},
	}
	for index, port := range httpsPorts {
		site.Listeners = append(site.Listeners, siteRuntimeV2Listener{ID: "public-" + strconv.Itoa(port), Position: int64(index + 1),
			AddressFamily: "dual_stack", Port: int64(port), Protocols: []string{"http1", "http2", "http3"},
			TLS: &siteRuntimeV2ListenerTLS{CertificateVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7104"}})
	}
	forced, err := siteRuntimeV2ForcedHTTPS(fact, httpsPorts)
	site.ForceHTTPS = forced
	return site, err
}
