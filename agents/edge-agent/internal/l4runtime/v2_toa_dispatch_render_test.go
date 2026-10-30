package l4runtime

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// toaDispatchConfig compiles two TOA streams sharing TCP port 9443 (one TLS
// passthrough by SNI, one plain), so the runtime dispatches both through the
// PROXY-protocol unix sockets: the proxy_toa directive must then sit in the
// per-stream servers (behind set_real_ip_from unix:), never in the
// dispatcher, so the address it hands to the kernel is the real client.
func toaDispatchConfig(t *testing.T, upstream netip.Addr) CompiledConfigV2 {
	t.Helper()
	tls := sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "toa.example")
	plain := sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamC, 9443, false)
	var specs []StreamRuntimeSpecV2
	for _, spec := range []StreamRuntimeSpecV2{tls, plain} {
		spec.TOA = true
		spec.Endpoint = EndpointV2{Address: upstream.String(), Port: 8000}
		spec.DNS = DNSPolicyV2{}
		spec.Geo.UnknownRegionAction = GeoActionAllow
		spec.Geo.BlockedRegions = nil
		specs = append(specs, spec)
	}
	config, err := AggregateStreamRuntimeSpecsV2("toa-dispatch", 1, specs)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{sharedStreamA: {upstream}, sharedStreamC: {upstream}})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestV2TOAOnADispatchedPortStaysInTheStreamServers(t *testing.T) {
	nginx := string(toaDispatchConfig(t, netip.MustParseAddr("8.8.8.8")).NginxConfig)
	dispatcher := nginx[strings.Index(nginx, "listen 0.0.0.0:9443"):]
	dispatcher = dispatcher[:strings.Index(dispatcher, "    }\n")]
	if strings.Contains(dispatcher, "proxy_toa") {
		t.Fatalf("dispatcher must not send TOA (its peer is the node itself):\n%s", dispatcher)
	}
	for _, stream := range []string{sharedStreamA, sharedStreamC} {
		server := nginx[strings.Index(nginx, "listen unix:"+L4DispatchSocketPath(stream)+" proxy_protocol;"):]
		server = server[:strings.Index(server, "    }\n")]
		if !strings.Contains(server, "set_real_ip_from unix:;") || !strings.Contains(server, "proxy_toa on;") {
			t.Fatalf("stream %s internal server lacks realip + proxy_toa:\n%s", stream, server)
		}
	}
}

// TestRenderTOADispatchRuntime writes the compiled runtime (nginx.conf and
// the geo config.json) for scripts/l4-toa-poc/run-dispatch.sh, which runs it
// in a real OpenResty with the TOA eBPF programs attached.
func TestRenderTOADispatchRuntime(t *testing.T) {
	dir := os.Getenv("CDNCA_TOA_DISPATCH_RENDER")
	if dir == "" {
		t.Skip("set CDNCA_TOA_DISPATCH_RENDER=<dir> to write the runtime")
	}
	compiled := toaDispatchConfig(t, netip.MustParseAddr("10.10.2.2"))
	for name, content := range map[string][]byte{"nginx.conf": compiled.NginxConfig, "config.json": compiled.GeoJSON} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
