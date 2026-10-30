package edgepublish

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestL4AdditionalListenerCapabilitiesAndHealthPort(t *testing.T) {
	stream := l4V2ContractStream("tcp")
	stream.ProxyProtocolOutbound = false
	stream.AdditionalListeners = []edgeconfig.L4AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: "udp", Address: "*", Port: 18444}}
	if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err != nil {
		t.Fatal(err)
	}
	versions := map[agentv1.CapabilityName]uint32{}
	for _, capability := range siteRuntimeV2StreamsRequired([]edgeconfig.L4StreamRuntimeV2{stream}) {
		versions[capability.Name] = capability.ApiVersion
	}
	if versions[agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY] != 12 || versions[agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY] != 12 {
		t.Fatalf("multi-listener capabilities=%v", versions)
	}
	stream.AdditionalListeners[0].Port = 18080
	if err := siteRuntimeV2StreamsFragmentError(stream.TenantID, 18080, stream); err == nil {
		t.Fatal("extra listener claimed health port")
	}
	passthrough := l4V2ContractStream("tcp")
	passthrough.ProxyProtocolOutbound = false
	passthrough.TLSPassthrough = true
	passthrough.ServerNames = []string{"sni.example.com"}
	if err := siteRuntimeV2StreamsFragmentError(passthrough.TenantID, 18080, passthrough); err != nil {
		t.Fatal(err)
	}
	document := siteRuntimeV2Document{}
	bindSiteRuntimeV2Streams(&document, uuid.MustParse(passthrough.TenantID),
		[]snapshotStream{{RuntimeV2: &passthrough}}, nil)
	if !slices.Contains(document.RequiredCapabilities, siteRuntimeV2Capability{Name: "tcp", APIVersion: 12}) {
		t.Fatalf("site runtime TLS passthrough capabilities=%v", document.RequiredCapabilities)
	}
	// Every stream needs v12 (no website, migration 506): alone, on a website
	// port or sharing a socket with another stream.
	plain := l4V2ContractStream("udp")
	plain.ProxyProtocolOutbound = false
	for name, c := range map[string]struct {
		sites []siteRuntimeV2Site
		other *edgeconfig.L4StreamRuntimeV2
		want  uint32
	}{
		"alone": {nil, nil, 12},
		"website port": {[]siteRuntimeV2Site{{Listeners: []siteRuntimeV2Listener{{Port: int64(plain.Listener.Port)}}}},
			nil, 12},
		"socket shared with another stream": {nil, func() *edgeconfig.L4StreamRuntimeV2 {
			other := plain
			other.StreamID = "44444444-4444-4444-8444-444444444444"
			return &other
		}(), 12},
	} {
		document := siteRuntimeV2Document{Sites: c.sites}
		facts := []snapshotStream{{RuntimeV2: &plain}}
		if c.other != nil {
			facts = append(facts, snapshotStream{RuntimeV2: c.other})
		}
		bindSiteRuntimeV2Streams(&document, uuid.MustParse(plain.TenantID), facts, nil)
		if !slices.Contains(document.RequiredCapabilities, siteRuntimeV2Capability{Name: "udp", APIVersion: c.want}) {
			t.Errorf("%s: capabilities=%v, want udp %d", name, document.RequiredCapabilities, c.want)
		}
	}
	// Publication validates shared sockets under the sharing rules.
	tcpOnSitePort := l4V2ContractStream("tcp")
	tcpOnSitePort.ProxyProtocolOutbound = false
	site := func(tls bool) siteRuntimeV2Site {
		listener := siteRuntimeV2Listener{Port: int64(tcpOnSitePort.Listener.Port), Protocols: []string{"http1"}}
		if tls {
			listener.TLS = &siteRuntimeV2ListenerTLS{CertificateVersionID: "cert"}
		}
		return siteRuntimeV2Site{ID: "site", Domains: []string{"www.example.com"}, Listeners: []siteRuntimeV2Listener{listener}}
	}
	for _, tls := range []bool{true, false} {
		document := siteRuntimeV2Document{ConfigVersionID: "l4-shared", SourceRevision: 9, Sites: []siteRuntimeV2Site{site(tls)},
			Streams: &edgeconfig.StreamRuntime{TenantID: tcpOnSitePort.TenantID, StreamsV2: []edgeconfig.L4StreamRuntimeV2{tcpOnSitePort}}}
		_, _, err := siteRuntimeStreamFragment(document, 18080)
		if tls != (err == nil) {
			t.Errorf("plain TCP stream on a website port (TLS=%t): err=%v", tls, err)
		}
	}
	// Removal still uses historical version 3 requirements, including a removed protocol.
	for _, capability := range siteRuntimeV2StreamsLifecycleRequired(nil, []l4ProtocolCapability{{"tcp", 3}, {"udp", 3}}) {
		if (capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) && capability.ApiVersion != 3 {
			t.Fatal("removal downgraded runtime capability")
		}
	}
}
