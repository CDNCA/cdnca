package l4runtime

import (
	"net/netip"
	"strings"
	"testing"
)

// 源站列表 / 定源 / IPv6开启 (tcp/udp v11): weights and down origins render as
// upstream server parameters, ip_hash as a consistent client hash, retries
// count only origins that are up, and listen_ipv6 adds the [::] socket.
func poolSpec() StreamRuntimeSpecV2 {
	spec := portRangeSpec()
	spec.Listener.PortEnd = 0
	spec.Endpoint = EndpointV2{Address: "8.8.8.8", Port: 9000}
	return spec
}

func TestV2OriginPoolRendersWeightsDownHashAndIPv6(t *testing.T) {
	spec := poolSpec()
	spec.Endpoint = EndpointV2{Address: "8.8.8.8", Port: 9000, Balance: "ip_hash", Origins: []OriginV2{
		{Address: "8.8.8.8", Weight: 3}, {Address: "8.8.4.4", Weight: 1, Down: true}, {Address: "1.1.1.1", Weight: 1}}}
	spec.ListenIPv6 = true
	config, err := AggregateStreamRuntimeSpecsV2("pool-v1", 1, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileV2(config, map[string][]netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	conf := string(compiled.NginxConfig)
	for _, want := range []string{"hash $remote_addr consistent;", "server 8.8.8.8:9000 weight=3;", "server 8.8.4.4:9000 down;",
		"server 1.1.1.1:9000;", "proxy_next_upstream_tries 2;", "listen 0.0.0.0:", "listen [::]:"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("config lacks %q:\n%s", want, conf)
		}
	}
}

func TestV2OriginPoolRejectsInvalidOrigins(t *testing.T) {
	for name, endpoint := range map[string]EndpointV2{
		"first differs":  {Address: "8.8.8.8", Port: 9000, Origins: []OriginV2{{Address: "1.1.1.1", Weight: 1}}},
		"all down":       {Address: "8.8.8.8", Port: 9000, Origins: []OriginV2{{Address: "8.8.8.8", Weight: 1, Down: true}}},
		"weight 0":       {Address: "8.8.8.8", Port: 9000, Origins: []OriginV2{{Address: "8.8.8.8"}}},
		"duplicate":      {Address: "8.8.8.8", Port: 9000, Origins: []OriginV2{{Address: "8.8.8.8", Weight: 1}, {Address: "8.8.8.8", Weight: 2}}},
		"unknown method": {Address: "8.8.8.8", Port: 9000, Balance: "least_conn"},
		"with follow":    {Address: "8.8.8.8", Port: 9000, FollowPort: true, Origins: []OriginV2{{Address: "8.8.8.8", Weight: 1}}},
	} {
		spec := poolSpec()
		spec.Endpoint = endpoint
		if endpoint.FollowPort {
			spec.Endpoint.Port = spec.Listener.Port
		}
		if _, err := AggregateStreamRuntimeSpecsV2("pool-v1", 1, []StreamRuntimeSpecV2{spec}); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
