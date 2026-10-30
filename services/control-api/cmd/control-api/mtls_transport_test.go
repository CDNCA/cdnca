package main

import (
	"os"
	"strings"
	"testing"
)

func TestMTLSDialerDefaultsToTunnel(t *testing.T) {
	for _, component := range []string{pluginRuntimeMTLSComponent, marketMTLSComponent} {
		t.Setenv(component+"_MTLS_TRANSPORT", "")
		t.Setenv(component+"_MTLS_TUNNEL_URL", "")
		if dial, err := mtlsDialer(component, "https://auth.cdnca.com:9448", "plugin-runtime"); err != nil || dial == nil {
			t.Fatalf("%s default = %v %v, want tunnel", component, dial != nil, err)
		}
		t.Setenv(component+"_MTLS_TRANSPORT", "direct")
		if dial, err := mtlsDialer(component, "https://auth.cdnca.com:9448", "plugin-runtime"); err != nil || dial != nil {
			t.Fatalf("%s direct = %v %v, want direct dial", component, dial != nil, err)
		}
		t.Setenv(component+"_MTLS_TRANSPORT", "wss")
		if _, err := mtlsDialer(component, "https://auth.cdnca.com:9448", "plugin-runtime"); err == nil ||
			!strings.Contains(err.Error(), component+"_MTLS_TRANSPORT") {
			t.Fatalf("%s invalid mode error = %v", component, err)
		}
		t.Setenv(component+"_MTLS_TRANSPORT", "tunnel")
		t.Setenv(component+"_MTLS_TUNNEL_URL", "https://edge.cdnca.com/path")
		if _, err := mtlsDialer(component, "https://auth.cdnca.com:9448", "plugin-runtime"); err == nil {
			t.Fatalf("%s accepted a tunnel URL with a path", component)
		}
	}
}

// 社区版连授权端 9448 的插件运行时客户端与 MARKET_URL 客户端都经 mtls_transport.go 选拨号方式（只改拨号）。
func TestMTLSClientsUseConfiguredTransport(t *testing.T) {
	for file, fragments := range map[string][]string{
		"plugin_runtime_composition.go": {"pluginRuntimeDialer(environment.ProviderURL)", "pluginRuntimeDialer(environment.ProjectionURL)",
			"DialContext: providerDial", "DialContext: projectionDial"},
		"plugin_installation_runtime.go": {"pluginRuntimeDialer(environment.providerURL)", "DialContext: dial"},
		"market_runtime.go":              {"mtlsDialer(marketMTLSComponent, baseURL, mtlstunnel.TargetMarketMember)", "DialContext: dial})"},
	} {
		encoded, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range fragments {
			if !strings.Contains(string(encoded), fragment) {
				t.Errorf("%s lacks %q", file, fragment)
			}
		}
	}
}
