package l4runtime

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func toaV2Spec() StreamRuntimeSpecV2 {
	spec := multiListenerV2Spec()
	spec.AdditionalListeners = spec.AdditionalListeners[1:] // TCP only
	spec.TOA = true
	return spec
}

// toa=true renders proxy_toa on every socket server of the stream; unset
// leaves the rendered config without the directive (older OpenResty builds
// reject unknown directives).
func TestV2TOARendersProxyTOAOnlyWhenSet(t *testing.T) {
	addresses := map[string][]netip.Addr{l403Stream: {netip.MustParseAddr("8.8.8.8")}}
	config, err := AggregateStreamRuntimeSpecsV2("toa", 9, []StreamRuntimeSpecV2{toaV2Spec()})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileV2(config, addresses)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(compiled.NginxConfig), "        proxy_toa on;\n"); got != 2 {
		t.Fatalf("proxy_toa directives = %d, want 2 (main + additional TCP socket): %s", got, compiled.NginxConfig)
	}
	canonical, err := CanonicalV2(config)
	if err != nil || !strings.Contains(string(canonical), `"toa":true`) {
		t.Fatalf("canonical config lost toa: %s %v", canonical, err)
	}

	plain := toaV2Spec()
	plain.TOA = false
	config, err = AggregateStreamRuntimeSpecsV2("plain", 9, []StreamRuntimeSpecV2{plain})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err = CompileV2(config, addresses)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ = CanonicalV2(config)
	if strings.Contains(string(compiled.NginxConfig), "proxy_toa") || strings.Contains(string(canonical), `"toa"`) {
		t.Fatalf("unset toa changed the runtime: %s", compiled.NginxConfig)
	}
}

func TestV2TOARejectsUDPAndProxyProtocol(t *testing.T) {
	for name, mutate := range map[string]func(*StreamRuntimeSpecV2){
		"UDP listener":          func(s *StreamRuntimeSpecV2) { s.Listener.Protocol = ProtocolUDP },
		"UDP additional socket": func(s *StreamRuntimeSpecV2) { s.AdditionalListeners = multiListenerV2Spec().AdditionalListeners },
		"outbound PROXY":        func(s *StreamRuntimeSpecV2) { s.ProxyProtocolOutbound = true },
		"inbound PROXY": func(s *StreamRuntimeSpecV2) {
			s.ProxyProtocolInbound = true
			s.Geo.TrustedProxyCIDRs = []string{"203.0.113.0/24"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := toaV2Spec()
			mutate(&spec)
			if _, err := AggregateStreamRuntimeSpecsV2("toa", 9, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
			spec.TOA = false
			if _, err := AggregateStreamRuntimeSpecsV2("toa", 9, []StreamRuntimeSpecV2{spec}); err != nil && name != "UDP listener" && name != "UDP additional socket" {
				t.Fatalf("fixture without toa is invalid: %v", err)
			}
		})
	}
}
