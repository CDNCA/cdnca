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

// tls-custom: the custom cipher preset's list reaches the v2 listener and
// the site object; a listener with it needs SITE_TLS_CUSTOM_CIPHERS (67).
func TestSiteTLSCustomCiphersPublication(t *testing.T) {
	suites := []string{"ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-SHA"}
	base := siteFact{tlsProtocols: []string{"TLSv1.2", "TLSv1.3"}, tlsCipherPreset: edgeconfig.TLSCipherCustom,
		tlsClientAuth: edgeconfig.ClientAuthOff, tlsCipherSuites: suites}
	profile, err := siteFactTLSProfile(base)
	if err != nil || profile.CipherPreset != edgeconfig.TLSCipherCustom || !slices.Equal(profile.CipherSuites, suites) {
		t.Fatalf("profile %+v err %v", profile, err)
	}
	// stored suites with another preset are not published
	modern := base
	modern.tlsCipherPreset = edgeconfig.TLSCipherModern
	if profile, err := siteFactTLSProfile(modern); err != nil || profile.CipherSuites != nil {
		t.Fatalf("modern profile %+v err %v", profile, err)
	}
	for name, fact := range map[string]siteFact{
		"not whitelisted": func() siteFact { f := base; f.tlsCipherSuites = []string{"RC4-SHA"}; return f }(),
		"empty":           func() siteFact { f := base; f.tlsCipherSuites = nil; return f }(),
		"tls13 only":      func() siteFact { f := base; f.tlsProtocols = []string{"TLSv1.3"}; return f }(),
	} {
		if _, err := siteFactTLSProfile(fact); err == nil {
			t.Errorf("%s published", name)
		}
	}

	listener := siteRuntimeV2Listener{ID: "public-443", AddressFamily: "dual_stack", Port: 443, Protocols: []string{"http1", "http2"},
		TLS: &siteRuntimeV2ListenerTLS{CertificateVersionID: uuid.NewString(), Protocols: []string{"TLSv1.2", "TLSv1.3"},
			CipherPreset: edgeconfig.TLSCipherCustom, CipherSuites: suites}}
	if !listener.usesTLSCustomCiphers() {
		t.Fatal("custom listener without SITE_TLS_CUSTOM_CIPHERS")
	}
	converted, err := convertSiteListenerV2(listener)
	if err != nil || converted.TLS.CipherPreset != edgeconfig.TLSCipherCustom || !slices.Equal(converted.TLS.CipherSuites, suites) {
		t.Fatalf("site object listener %+v err %v", converted.TLS, err)
	}
	listener.TLS.CipherPreset, listener.TLS.CipherSuites = "", nil
	if listener.usesTLSCustomCiphers() {
		t.Fatal("modern listener needs SITE_TLS_CUSTOM_CIPHERS")
	}
	if name, ok := siteruntimecap.Name(edgeconfig.SiteTLSCustomCiphersCapability); !ok ||
		name != agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS || agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS != 67 {
		t.Fatal("site_tls_custom_ciphers is CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS 67")
	}
	if _, ok := gatedFeature(&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS, ApiVersion: 1}); !ok {
		t.Fatal("SITE_TLS_CUSTOM_CIPHERS has no refusal wording")
	}
}

// The document compiler: a custom listener needs site_tls_custom_ciphers,
// and its list is checked against the whitelist.
func TestSiteTLSCustomCiphersDocumentCapability(t *testing.T) {
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
	site.Listeners[1].TLS.CipherPreset = edgeconfig.TLSCipherCustom
	site.Listeners[1].TLS.CipherSuites = []string{"ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305"}
	base := []siteRuntimeV2Capability{{"http1", 1}, {"http2", 1}, {"http3", 1}, {"ipv4", 1}, {"ipv6", 1},
		{"site_runtime", edgeconfig.MinSiteRuntimeVersion}, {"websocket", 1}}
	document := siteRuntimeV2Document{
		Schema: siteRuntimeV2Schema, ConfigurationScopeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7101", SourceRevision: 3,
		ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7102", Sites: []siteRuntimeV2Site{site},
		RequiredCapabilities: base,
	}
	raw, _ := json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("custom ciphers without site_tls_custom_ciphers accepted")
	}
	document.RequiredCapabilities = append(slices.Clone(base[:6]), siteRuntimeV2Capability{edgeconfig.SiteTLSCustomCiphersCapability, 1}, base[6])
	raw, _ = json.Marshal(document)
	_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("custom ciphers with site_tls_custom_ciphers refused: %v", err)
	}
	if !slices.ContainsFunc(capabilities, func(capability *agentv1.Capability) bool {
		return capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS && capability.ApiVersion == 1
	}) {
		t.Fatalf("capabilities %v", capabilities)
	}
	document.Sites[0].Listeners[1].TLS.CipherSuites = []string{"ECDHE-ECDSA-CHACHA20-POLY1305", "ALL:@SECLEVEL=0"}
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err == nil {
		t.Fatal("non-whitelisted suite accepted")
	}
}
