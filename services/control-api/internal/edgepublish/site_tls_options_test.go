package edgepublish

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"github.com/google/uuid"
)

// fp-site5a: the site's HTTP/2, HTTP/3 and ssl_prefer_server_ciphers
// (migration 515) reach the v2 listener; HTTP/2 off and a prefer value
// other than the preset's need SITE_TLS_OPTIONS, the defaults add nothing.
func TestSiteTLSOptionsPublication(t *testing.T) {
	tls13 := edgeconfig.TLSProfile{Protocols: []string{"TLSv1.2", "TLSv1.3"}}
	tls12 := edgeconfig.TLSProfile{Protocols: []string{"TLSv1.2"}}
	for name, test := range map[string]struct {
		fact    siteFact
		profile edgeconfig.TLSProfile
		want    []string
	}{
		"default":           {siteFact{}, tls13, []string{"http1", "http2", "http3"}},
		"tls12 has no quic": {siteFact{}, tls12, []string{"http1", "http2"}},
		"http2 off":         {siteFact{http2Off: true}, tls13, []string{"http1", "http3"}},
		"http3 off":         {siteFact{http3Off: true}, tls13, []string{"http1", "http2"}},
		"both off":          {siteFact{http2Off: true, http3Off: true}, tls13, []string{"http1"}},
	} {
		if got := siteFactHTTPSProtocols(test.fact, test.profile); !slices.Equal(got, test.want) {
			t.Errorf("%s: protocols %v, want %v", name, got, test.want)
		}
	}

	on, off := true, false
	base := siteFact{tlsProtocols: []string{"TLSv1.2", "TLSv1.3"}, tlsCipherPreset: edgeconfig.TLSCipherModern,
		tlsClientAuth: edgeconfig.ClientAuthOff}
	for name, test := range map[string]struct {
		preset string
		prefer *bool
		want   *bool
	}{
		"by preset (modern)":      {edgeconfig.TLSCipherModern, nil, nil},
		"modern equal is dropped": {edgeconfig.TLSCipherModern, &off, nil},
		"modern on":               {edgeconfig.TLSCipherModern, &on, &on},
		"compatible equal":        {edgeconfig.TLSCipherCompatible, &on, nil},
		"compatible off":          {edgeconfig.TLSCipherCompatible, &off, &off},
	} {
		fact := base
		fact.tlsCipherPreset, fact.tlsPreferServerCiphers = test.preset, test.prefer
		profile, err := siteFactTLSProfile(fact)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (profile.PreferServerCiphers == nil) != (test.want == nil) ||
			profile.PreferServerCiphers != nil && *profile.PreferServerCiphers != *test.want {
			t.Errorf("%s: prefer %v, want %v", name, profile.PreferServerCiphers, test.want)
		}
	}

	listener := func(protocols []string, prefer *bool) siteRuntimeV2Listener {
		return siteRuntimeV2Listener{ID: "public-443", AddressFamily: "dual_stack", Port: 443, Protocols: protocols,
			TLS: &siteRuntimeV2ListenerTLS{CertificateVersionID: uuid.NewString(), PreferServerCiphers: prefer}}
	}
	if listener([]string{"http1", "http2", "http3"}, nil).usesTLSOptions() {
		t.Fatal("default listener needs SITE_TLS_OPTIONS")
	}
	if !listener([]string{"http1", "http3"}, nil).usesTLSOptions() || !listener([]string{"http1", "http2"}, &on).usesTLSOptions() {
		t.Fatal("HTTP/2 off or explicit prefer without SITE_TLS_OPTIONS")
	}
	plain := siteRuntimeV2Listener{ID: "public-80", AddressFamily: "dual_stack", Port: 80, Protocols: []string{"http1"}}
	if plain.usesTLSOptions() {
		t.Fatal("plain HTTP listener needs SITE_TLS_OPTIONS")
	}
	if name, ok := siteruntimecap.Name(edgeconfig.SiteTLSOptionsCapability); !ok ||
		name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS || agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS != 63 {
		t.Fatal("site_tls_options is CAPABILITY_NAME_SITE_TLS_OPTIONS 63")
	}
	if _, ok := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS, ApiVersion: 1}); !ok {
		t.Fatal("SITE_TLS_OPTIONS has no refusal wording")
	}
}

// The document compiler: an explicit prefer_server_ciphers needs
// site_tls_options (the publisher also adds it for HTTP/2 off, which older
// documents with an http1-only TLS listener may carry without it).
func TestSiteTLSOptionsDocumentCapability(t *testing.T) {
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "secure.example.test",
		httpPorts: []string{"80"}, httpsPorts: []string{"443"}, httpsEnabled: true, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	site, err := compileForceHTTPSFact(fact)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	site.Listeners[1].Protocols = []string{"http1"}
	site.Listeners[1].TLS.PreferServerCiphers = &on
	base := []siteRuntimeV2Capability{{"http1", 1}, {"ipv4", 1}, {"ipv6", 1},
		{"site_runtime", edgeconfig.MinSiteRuntimeVersion}, {"websocket", 1}}
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: base,
	}
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("prefer_server_ciphers without site_tls_options accepted")
	}
	document.RequiredCapabilities = append(slices.Clone(base[:4]), siteRuntimeV2Capability{edgeconfig.SiteTLSOptionsCapability, 1}, base[4])
	raw, _ = json.Marshal(document)
	_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("prefer_server_ciphers with site_tls_options refused: %v", err)
	}
	if !slices.ContainsFunc(capabilities, func(capability *agentv1.Capability) bool {
		return capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_OPTIONS && capability.ApiVersion == 1
	}) {
		t.Fatalf("capabilities %v", capabilities)
	}
	// prefer equal to the preset's is not canonical
	off := false
	document.Sites[0].Listeners[1].TLS.PreferServerCiphers = &off
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("prefer_server_ciphers equal to the preset accepted")
	}
}
