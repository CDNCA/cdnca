package edgeconfig

import (
	"testing"
)

func sharedStream(id string, protocol string, port int, names ...string) L4StreamRuntimeV2 {
	stream := multiListenerBundleSpec().L4StreamsV2[0]
	stream.StreamID, stream.Geo.StreamID = id, id
	stream.Listener = L4ListenerV2{Protocol: protocol, Address: "*", Port: port}
	stream.AdditionalListeners = nil
	stream.TLSPassthrough, stream.ServerNames = len(names) > 0, names
	return stream
}

func proxied(stream L4StreamRuntimeV2) L4StreamRuntimeV2 {
	stream.ProxyProtocolOutbound = true
	return stream
}

func TestRenderSharedStreamFragmentAppliesPortSharingRules(t *testing.T) {
	const (
		first  = "aaaaaaaa-aaaa-4aaa-8aaa-000000000001"
		second = "aaaaaaaa-aaaa-4aaa-8aaa-000000000002"
	)
	tenant := multiListenerBundleSpec().TenantID
	tlsSite := SiteListenerPortClaims("", "site", 443, true, true, []string{"www.example.com"})
	plainSite := SiteListenerPortClaims("", "site", 443, false, false, nil)
	for name, c := range map[string]struct {
		streams []L4StreamRuntimeV2
		sites   []PortClaim
		ok      bool
	}{
		"passthrough split by SNI":          {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443, "a.example.com"), sharedStream(second, "tcp", 443, "*.example.com")}, nil, true},
		"plain TCP next to passthrough":     {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443), sharedStream(second, "tcp", 443, "a.example.com")}, nil, true},
		"plain TCP next to a TLS website":   {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443)}, tlsSite, true},
		"passthrough next to a TLS website": {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443, "a.example.com")}, tlsSite, true},
		"UDP next to a plaintext website":   {[]L4StreamRuntimeV2{sharedStream(first, "udp", 443)}, plainSite, true},
		"same SNI twice":                    {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443, "a.example.com"), sharedStream(second, "tcp", 443, "a.example.com")}, nil, false},
		"SNI of the TLS website":            {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443, "www.example.com")}, tlsSite, false},
		"two plain TCP streams":             {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443), sharedStream(second, "tcp", 443)}, nil, false},
		"plain TCP next to plaintext":       {[]L4StreamRuntimeV2{sharedStream(first, "tcp", 443)}, plainSite, false},
		"UDP next to HTTP/3":                {[]L4StreamRuntimeV2{sharedStream(first, "udp", 443)}, tlsSite, false},
		"PROXY on a split socket":           {[]L4StreamRuntimeV2{proxied(sharedStream(first, "tcp", 443)), sharedStream(second, "tcp", 443, "a.example.com")}, nil, false},
		"PROXY alone":                       {[]L4StreamRuntimeV2{proxied(sharedStream(first, "tcp", 443))}, nil, true},
		"health port":                       {[]L4StreamRuntimeV2{sharedStream(first, "udp", 18080)}, nil, false},
	} {
		runtime := StreamRuntime{TenantID: tenant, StreamsV2: c.streams}
		_, files, err := RenderSharedStreamFragment("shared-v2", 9, runtime, 18080, c.sites)
		if c.ok && (err != nil || files[L4RuntimeV2ArtifactPath] == nil) {
			t.Errorf("%s: shared fragment refused: %v", name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: shared fragment accepted", name)
		}
	}
	// The exclusive entry point keeps refusing any shared port.
	runtime := StreamRuntime{TenantID: tenant, StreamsV2: []L4StreamRuntimeV2{
		sharedStream(first, "tcp", 443, "a.example.com"), sharedStream(second, "tcp", 443, "b.example.com")}}
	if _, _, err := RenderStreamFragment("shared-v2", 9, runtime, []uint16{18080}); err == nil {
		t.Fatal("exclusive fragment accepted a shared port")
	}
}
