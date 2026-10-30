package edgeskeleton

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func testPaths() Paths {
	return Paths{SharedRoot: "/var/lib/cdnca-edge/shared", LuaRoot: "/usr/local/share/cdnca", StateRoot: "/var/lib/cdnca-edge/state",
		PlaceholderCertificate: "/etc/cdnca/placeholder.crt", PlaceholderKey: "/etc/cdnca/placeholder.key",
		OriginTrustPlaceholder: "/etc/cdnca/origin-trust-placeholder.crt"}
}

func testInput() Input {
	return Input{
		Ports: []edgesite.PortProfile{
			{Port: 8443, TLS: true, HTTP2: false, IPv4: true, SiteCount: 1},
			{Port: 80, IPv4: true, IPv6: true, SiteCount: 3},
			{Port: 443, TLS: true, HTTP2: true, HTTP3: true, IPv4: true, IPv6: true, SiteCount: 2},
		},
		IndexKeys: 12,
		Cache:     CachePool{Zones: 2, KeysZoneBytes: 16 << 20, MaxBytes: 1 << 30, Inactive: time.Hour},
		Paths:     testPaths(),
	}
}

func render(t *testing.T, input Input) string {
	t.Helper()
	output, err := Render(input)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}

// server returns the server block that listens on port.
func server(t *testing.T, config string, port int) string {
	t.Helper()
	for _, block := range strings.Split(config, "  server {\n")[1:] {
		if strings.Contains(block, fmt.Sprintf(":%d ", port)) {
			return block
		}
	}
	t.Fatalf("no server for port %d", port)
	return ""
}

func TestRenderIsDeterministic(t *testing.T) {
	input := testInput()
	first := render(t, input)
	// Port order is not part of the input.
	reversed := input
	reversed.Ports = []edgesite.PortProfile{input.Ports[2], input.Ports[0], input.Ports[1]}
	for range 20 {
		if again := render(t, reversed); again != first {
			t.Fatal("same input rendered different bytes")
		}
	}
	if strings.Index(first, ":80 ") > strings.Index(first, ":443 ") || strings.Index(first, ":443 ") > strings.Index(first, ":8443 ") {
		t.Fatal("servers are not in port order")
	}
}

func TestRenderPorts(t *testing.T) {
	config := render(t, testInput())
	if strings.Count(config, "  server {\n") != 4 {
		t.Fatalf("want one shared server per port:\n%s", config)
	}
	plain := server(t, config, 80)
	for _, want := range []string{"listen 0.0.0.0:80 default_server;", "listen [::]:80 default_server;", "server_name _;",
		"server_rewrite_by_lua_block { require(\"dynroute.cdnca_dynroute\").server_rewrite() }"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("port 80 lacks %q:\n%s", want, plain)
		}
	}
	for _, unwanted := range []string{"ssl", "http2", "quic", "client_hello"} {
		if strings.Contains(strings.ReplaceAll(plain, "proxy_ssl", ""), unwanted) && unwanted != "ssl" ||
			unwanted == "ssl" && strings.Contains(plain, " ssl ") {
			t.Fatalf("plain port renders %q", unwanted)
		}
	}
	tls := server(t, config, 443)
	for _, want := range []string{"listen 0.0.0.0:443 ssl default_server;", "listen 0.0.0.0:443 quic reuseport default_server;",
		"listen [::]:443 ssl default_server;", "listen [::]:443 quic reuseport default_server;", "http2 on;", "http3 on;",
		"ssl_protocols TLSv1.2 TLSv1.3;", "ssl_certificate \"/etc/cdnca/placeholder.crt\";",
		"ssl_client_hello_by_lua_block", "ssl_certificate_by_lua_block"} {
		if !strings.Contains(tls, want) {
			t.Fatalf("port 443 lacks %q:\n%s", want, tls)
		}
	}
	noH2 := server(t, config, 8443)
	if !strings.Contains(noH2, "http2 off;") || strings.Contains(noH2, "quic") || strings.Contains(noH2, "http3") ||
		strings.Contains(noH2, "[::]") {
		t.Fatalf("port 8443 (no h2, no h3, IPv4 only):\n%s", noH2)
	}
}

func TestRenderNoSiteServerAndSafeUpstream(t *testing.T) {
	config := render(t, testInput())
	if regexp.MustCompile(`(?m)^\s*server_name (?:[^_]|_[^;])`).MatchString(config) {
		t.Fatal("a site server_name was rendered")
	}
	upstream := regexp.MustCompile(`(?s)upstream cdnca_dynamic \{.*?\n  \}`).FindString(config)
	if upstream == "" || !strings.Contains(upstream, "keepalive 0;") || !strings.Contains(upstream, "balancer_by_lua_block") {
		t.Fatalf("dynamic upstream must disable nginx keepalive (PoC section 3):\n%s", upstream)
	}
	if strings.Count(config, "\n  upstream ") != 1 {
		t.Fatal("want exactly one upstream")
	}
	for _, want := range []string{"proxy_ssl_verify on;", "lua_upstream_skip_openssl_default_verify on;",
		"proxy_ssl_name $cdnca_origin_sni;", "proxy_pass $cdnca_origin_scheme://cdnca_dynamic;",
		"client_max_body_size $cdnca_site_max_body;", "proxy_cache $cdnca_cache_zone;",
		"lua_shared_dict cdnca_site_index 4m;", "lua_shared_dict cdnca_site_state 8m;", "lua_shared_dict cdnca_site_lock 1m;",
		"keys_zone=cdnca_cache_0:16m max_size=1024m inactive=3600s", "keys_zone=cdnca_cache_1:16m",
		`lua_package_path "/usr/local/share/cdnca/dynroute/?.lua;/usr/local/share/cdnca/?.lua;/usr/local/share/cdnca/security/?.lua;;";`,
		"lua_shared_dict cdnca_cc_state 64m;", "lua_shared_dict cdnca_challenge_state 16m;", "lua_shared_dict cdnca_firewall_action 16m;", "lua_shared_dict cdnca_waf_state 32m;", "lua_shared_dict cdnca_security_bans 16m;",
		`challenge_lua = "/usr/local/share/cdnca/challenge",`,
		"uninitialized_variable_warn off;",
		`objects_root = "/var/lib/cdnca-edge/state/site-objects"`, `index_root = "/var/lib/cdnca-edge/state/site-index"`,
		`tls_pool_root = "/var/lib/cdnca-edge/state/tls-pool"`, "system_max_body = 1048576,",
		"init_worker_by_lua_block { require(\"dynroute.cdnca_dynroute\").init_worker() }",
		"map $uri $cdnca_node_location {", `listen "unix:/var/lib/cdnca-edge/state/run/cdnca-site-admin.sock";`,
		`require("cdnca_site_admin").handle()`, "location = /__cdnca_site_vars {\n      internal;",
		`set $cdnca_site_max_body "1";`, "    balancer_keepalive 256;\n",
		"proxy_next_upstream error timeout http_502 http_503 http_504;", "proxy_next_upstream_tries 0;", "proxy_next_upstream_timeout 0;",
		"access_by_lua_block { require(\"dynroute.cdnca_dynroute\").access() }", "log_by_lua_block { require(\"dynroute.cdnca_dynroute\").log() }",
		`node_region = "",`, "resolvers = {  },", "set $cdnca_origin_pool \"\";",
		// D5a forwarding headers, D5b system CA and origin auth secrets
		"proxy_set_header X-Forwarded-For $cdnca_origin_xff;", "proxy_set_header X-Real-IP $cdnca_origin_real_ip;",
		"proxy_set_header X-Forwarded-Proto $cdnca_origin_proto;", "proxy_set_header Upgrade $cdnca_origin_upgrade;",
		"proxy_set_header Connection $cdnca_origin_connection;", "set $cdnca_origin_xff \"\";",
		// L2_ROUTING v2 loop guard: the hop mark, replaced on every request
		"proxy_set_header X-Cdnca-L2-Hop $cdnca_origin_l2_hop;", "set $cdnca_origin_l2_hop \"\";",
		`system_ca_file = "/etc/ssl/certs/ca-certificates.crt",`, `origin_auth_root = "/var/lib/cdnca-edge/state/origin-auth-secrets",`,
		// D8: zone pool size to the cache module, generation dictionary, patch 24
		// TTL table, cacheable variants, cache admin on the control socket
		"cache_zones = 2,", "lua_shared_dict cdnca_cache_purge 1m;", "$cdnca_cache_valid {", "proxy_cache_valid any $cdnca_cache_valid;",
		"location @cdnca_cache_override {", "location @cdnca_cache_bypass {", "location @cdnca_cache_follow_stalebg_s65536 {", "slice 67108864;", "proxy_set_header Range $cdnca_cache_range;",
		"add_header X-CDN-Cache $cdnca_cache_status_header always;", "map $cdnca_cache_show $cdnca_cache_status_header {", `location /cache/ { content_by_lua_block { require("cdnca_cache").admin() } }`} {
		if !strings.Contains(config, want) {
			t.Fatalf("skeleton lacks %q", want)
		}
	}
	// Variables are declared once, in a location that never runs, never at
	// server level (contract §6.2).
	for _, name := range append(append([]string{}, SiteVariables...), Variables...) {
		if strings.Count(config, "set $"+name+" ") != 1 {
			t.Fatalf("variable %s is not declared exactly once", name)
		}
	}
	for _, port := range []int{80, 443, 8443} {
		if strings.Contains(server(t, config, port), "set $") {
			t.Fatalf("port %d declares variables at server level", port)
		}
	}
	noCache := testInput()
	noCache.Cache = CachePool{}
	if out := render(t, noCache); strings.Contains(out, "proxy_cache") || strings.Contains(out, "cdnca_cache_purge") ||
		!strings.Contains(out, "cache_zones = 0,") {
		t.Fatal("no zones still renders a cache")
	}
}

func TestRenderSystemConfiguration(t *testing.T) {
	settings := edgeconfig.NginxSettings{
		WorkerProcesses: 3, WorkerRlimitNoFile: 65535, WorkerShutdownTimeout: 30 * time.Second, WorkerConnections: 8192,
		ResolverAddresses: []string{"192.0.2.53"}, ResolverTimeout: 5 * time.Second,
		GzipLevel: 4, GzipMinimumBytes: 1024, GzipVary: true, ProxyBuffering: true,
		ProxyCacheMethods: []string{"HEAD", "GET"}, ProxyCacheMaxBytes: 1 << 30, ProxyCacheZoneBytes: 64 << 20,
		ProxyMaxTempFileBytes: 1 << 20, ProxyConnectTimeout: 10 * time.Second, ProxySendTimeout: 60 * time.Second,
		ProxyReadTimeout: 60 * time.Second, StreamProxyTimeout: 10 * time.Minute, ServerHeader: "cdnca",
		ClientMaxBodyBytes: 100 << 20, DefaultMIMEType: "text/html", KeepaliveRequests: 1000,
		KeepaliveTimeout: 75 * time.Second, ServerNamesHashMaxSize: 4096,
	}
	system, err := edgeconfig.NewSiteRuntimeSystem("00000000-0000-4000-8000-000000000001", 7, strings.Repeat("a", 64), settings)
	if err != nil {
		t.Fatal(err)
	}
	input := testInput()
	input.System = &system
	input.Node = Node{Region: "cn-east", ID: "018f47a2-5b9c-7d31-8a60-104c9c0b7a20", IngressSourceIPv4: "192.0.2.10", IngressSourceIPv6: "2001:db8::10"}
	config := render(t, input)
	for _, want := range []string{"worker_processes 3;", "events { worker_connections 8192; }", "resolver 192.0.2.53;", "gzip_comp_level 4;",
		"system_max_body = 104857600,", `node_region = "cn-east",`, `node_id = "018f47a2-5b9c-7d31-8a60-104c9c0b7a20",`, `ingress_source_ipv4 = "192.0.2.10",`,
		`ingress_source_ipv6 = "2001:db8::10",`, `resolvers = { "192.0.2.53" },`} {
		if !strings.Contains(config, want) {
			t.Fatalf("system configuration lacks %q", want)
		}
	}
	if strings.Contains(config, "server_addr_outgoing = true") ||
		!strings.Contains(config, "proxy_http_version 1.1;") ||
		!strings.Contains(config, "proxy_next_upstream error timeout http_502 http_503 http_504;") {
		t.Fatal("an older system document changed the location defaults")
	}
	// proxy_http_version / proxy_next_upstream / 入口 IP 回源
	settings.ProxyHTTPVersion, settings.ProxyNextUpstream, settings.ServerAddrOutgoing = "1.0", []string{"off"}, true
	tuned, err := edgeconfig.NewSiteRuntimeSystem("00000000-0000-4000-8000-000000000001", 8, strings.Repeat("b", 64), settings)
	if err != nil {
		t.Fatal(err)
	}
	input.System = &tuned
	config = render(t, input)
	if strings.Contains(config, "proxy_http_version 1.1;") || strings.Contains(config, "proxy_next_upstream error") {
		t.Fatal("location keeps the built-in proxy values")
	}
	for _, want := range []string{"      proxy_http_version 1.0;\n", "      proxy_next_upstream off;\n", "server_addr_outgoing = true,"} {
		if !strings.Contains(config, want) {
			t.Fatalf("tuned system configuration lacks %q", want)
		}
	}
	bad := system
	bad.Revision = 0
	input.System = &bad
	if _, err := Render(input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid system accepted: %v", err)
	}
}

func TestRenderRejects(t *testing.T) {
	cases := map[string]func(*Input){
		"duplicate port":   func(in *Input) { in.Ports = append(in.Ports, in.Ports[0]) },
		"port 0":           func(in *Input) { in.Ports[0].Port = 0 },
		"no family":        func(in *Input) { in.Ports[0].IPv4, in.Ports[0].IPv6 = false, false },
		"plain h2":         func(in *Input) { in.Ports[1].HTTP2 = true },
		"plain h3":         func(in *Input) { in.Ports[1].HTTP3 = true },
		"no sites":         func(in *Input) { in.Ports[0].SiteCount = 0 },
		"relative path":    func(in *Input) { in.Paths.LuaRoot = "lua" },
		"path with quote":  func(in *Input) { in.Paths.SharedRoot = "/var/\"x" },
		"path with dollar": func(in *Input) { in.Paths.PlaceholderKey = "/etc/$x" },
		"no state root":    func(in *Input) { in.Paths.StateRoot = "" },
		"long state root":  func(in *Input) { in.Paths.StateRoot = "/" + strings.Repeat("s", 90) },
		"region quote":     func(in *Input) { in.Node.Region = `a"b` },
		"region upper":     func(in *Input) { in.Node.Region = "CN" },
		"node id quote":    func(in *Input) { in.Node.ID = `a"b` },
		"node id upper":    func(in *Input) { in.Node.ID = "018F47A2-5B9C-7D31-8A60-104C9C0B7A20" },
		"ingress v4 as v6": func(in *Input) { in.Node.IngressSourceIPv6 = "192.0.2.1" },
		"ingress name":     func(in *Input) { in.Node.IngressSourceIPv4 = "host.example" },
		"resolver port":    func(in *Input) { in.Node.Resolvers = []string{"192.0.2.53:53"} },
		"many resolvers": func(in *Input) {
			in.Node.Resolvers = []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}
		},
		"too many zones":   func(in *Input) { in.Cache.Zones = MaxCacheZones + 1 },
		"tiny zone":        func(in *Input) { in.Cache.KeysZoneBytes = 1 << 10 },
		"partial MiB":      func(in *Input) { in.Cache.MaxBytes = 3<<20 + 1 },
		"short inactive":   func(in *Input) { in.Cache.Inactive = time.Second },
		"settings no zone": func(in *Input) { in.Cache.Zones = 0 },
		"index too large":  func(in *Input) { in.IndexKeys = IndexTiers[len(IndexTiers)-1].Keys + 1 },
		"negative keys":    func(in *Input) { in.IndexKeys = -1 },
		"unknown site 500": func(in *Input) {
			in.UnknownSite = &NodePage{Status: 500, MIMEType: "text/plain", BodyFile: "/var/lib/cdnca/unknown"}
		},
		"unknown site mime": func(in *Input) {
			in.UnknownSite = &NodePage{Status: 404, MIMEType: "image/png", BodyFile: "/var/lib/cdnca/unknown"}
		},
		"unknown site relative": func(in *Input) {
			in.UnknownSite = &NodePage{Status: 404, MIMEType: "text/plain", BodyFile: "unknown"}
		},
		"unknown site quote": func(in *Input) {
			in.UnknownSite = &NodePage{Status: 404, MIMEType: "text/plain", BodyFile: "/var/\"x"}
		},
		"unknown site style on text": func(in *Input) {
			in.UnknownSite = &NodePage{Status: 404, MIMEType: "text/plain", BodyFile: "/var/x",
				StyleHash: "sha256-" + strings.Repeat("A", 43) + "="}
		},
	}
	for name, mutate := range cases {
		input := testInput()
		input.Ports = append([]edgesite.PortProfile{}, input.Ports...)
		mutate(&input)
		if _, err := Render(input); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestIndexTiers(t *testing.T) {
	for _, tc := range []struct {
		keys int
		mib  int64
	}{{0, 4}, {26214, 4}, {26215, 16}, {1_000_000, 160}, {1_048_576, 160}, {1_048_577, 640}} {
		tier, err := SelectIndexTier(tc.keys)
		if err != nil || tier.Bytes != tc.mib<<20 {
			t.Errorf("%d keys: tier %+v %v, want %d MiB", tc.keys, tier, err, tc.mib)
		}
	}
	// 1M keys x 128 B x 1.25 = 160 MiB (PoC section 1).
	if tier, _ := SelectIndexTier(1_000_000); tier.Keys < 1_000_000 {
		t.Fatal("the 160 MiB tier must hold one million keys")
	}
}

// tenThousandSites: 10 000 sites over 80/443 (h2, h3) and 8080, each with
// one alias; the shapes PortProfiles would accept.
func tenThousandSites() []edgesite.Site {
	sites := make([]edgesite.Site, 0, 10000)
	for index := range 10000 {
		listeners := []edgesite.Listener{{Port: 80, AddressFamily: edgesite.FamilyDualStack},
			{Port: 443, AddressFamily: edgesite.FamilyDualStack, HTTP2: true, HTTP3: index%2 == 0,
				TLS: &edgesite.TLS{CertificateVersionID: fmt.Sprintf("00000000-0000-4000-8000-%012d", index), Protocols: []string{"TLSv1.2", "TLSv1.3"}}}}
		if index%10 == 0 {
			listeners = append(listeners, edgesite.Listener{Port: 8080, AddressFamily: edgesite.FamilyIPv4})
		}
		sites = append(sites, edgesite.Site{SiteID: fmt.Sprintf("10000000-0000-4000-8000-%012d", index),
			Hosts:     edgesite.Hosts{Primary: fmt.Sprintf("s%d.example.test", index), Aliases: []string{fmt.Sprintf("*.s%d.example.test", index)}},
			Listeners: listeners})
	}
	return sites
}

func TestRenderTenThousandSites(t *testing.T) {
	sites := tenThousandSites()
	started := time.Now()
	ports, keys, err := FromSites(sites)
	if err != nil {
		t.Fatal(err)
	}
	table := time.Since(started)
	input := testInput()
	input.Ports, input.IndexKeys = ports, keys
	started = time.Now()
	config, err := Render(input)
	if err != nil {
		t.Fatal(err)
	}
	rendered := time.Since(started)
	small := render(t, testInput())
	if len(ports) != 3 || keys != 42000 {
		t.Fatalf("%d ports, %d keys", len(ports), keys)
	}
	if !strings.Contains(string(config), "lua_shared_dict cdnca_site_index 16m;") {
		t.Fatal("42000 keys must select the 16 MiB tier")
	}
	again, _ := Render(input)
	if !bytes.Equal(config, again) {
		t.Fatal("10k-site skeleton is not deterministic")
	}
	t.Logf("10000 sites: port table %v, render %v, nginx.conf %d bytes (3-port fixture %d bytes), index keys %d",
		table, rendered, len(config), len(small), keys)
}

// TestDumpForRealOpenResty writes the fixtures tests/edge-skeleton/
func TestRenderTelemetry(t *testing.T) {
	if config := render(t, testInput()); strings.Contains(config, "access_log \"") || strings.Contains(config, "cdnca_telemetry") {
		t.Fatal("telemetry off still logs")
	}
	input := testInput()
	input.Telemetry = true
	config := render(t, input)
	if !strings.Contains(config, "  log_format cdnca_access_json escape=json '") || strings.Count(config, "log_format ") != 4 {
		t.Fatal("telemetry formats missing")
	}
	for _, port := range []int{80, 443, 8443} {
		block := server(t, config, port)
		if strings.Count(block, "access_log ") != 4 ||
			!strings.Contains(block, `access_log "/var/lib/cdnca-edge/shared/telemetry/dynroute/access.jsonl" cdnca_access_json if=$cdnca_telemetry_plain;`) {
			t.Fatalf("port %d access_log directives:\n%s", port, block)
		}
	}
	// Declared once, in the control server's never executed location.
	for _, name := range append(append([]string{}, Variables...), edgeconfig.DynamicRoutingTelemetryVariables...) {
		if strings.Count(config, "set $"+name+" ") != 1 {
			t.Fatalf("%s declared %d times", name, strings.Count(config, "set $"+name+" "))
		}
	}
	input.Paths.SharedRoot = "/var/lib/cdnca edge"
	if _, err := Render(input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe log root: %v", err)
	}
}

// real-openresty.sh runs: small.conf (80 dual / 443 TLS h2 h3 dual / 8443 TLS
// no h2 IPv4) and tenk.conf (the 10 000-site port table). Paths are under /t.
func TestDumpForRealOpenResty(t *testing.T) {
	dir := os.Getenv("CDNCA_SKELETON_DUMP_DIR")
	if dir == "" {
		t.Skip("CDNCA_SKELETON_DUMP_DIR not set")
	}
	paths := Paths{SharedRoot: "/t/shared", LuaRoot: "/t/lua", StateRoot: "/t/state", PlaceholderCertificate: "/t/etc/placeholder.crt",
		PlaceholderKey: "/t/etc/placeholder.key", OriginTrustPlaceholder: "/t/etc/origin-trust-placeholder.crt"}
	small := testInput()
	small.Paths = paths
	ports, keys, err := FromSites(tenThousandSites())
	if err != nil {
		t.Fatal(err)
	}
	tenk := small
	tenk.Ports, tenk.IndexKeys = ports, keys
	for name, input := range map[string]Input{"small.conf": small, "tenk.conf": tenk} {
		if err := os.WriteFile(dir+"/"+name, []byte(render(t, input)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// D7: preloaded challenge versions are sorted and unique; the list renders
// into configure(), and the security variables are declared.
func TestRenderChallenges(t *testing.T) {
	input := testInput()
	first := edgesite.Ref{ID: "0a1b200d-0000-4000-8000-0000000000c0", Revision: 7}
	second := edgesite.Ref{ID: first.ID, Revision: 8}
	input.Challenges = []edgesite.Ref{first, second}
	config, err := Render(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), `challenges = { { id = "0a1b200d-0000-4000-8000-0000000000c0", revision = 7 }, { id = "0a1b200d-0000-4000-8000-0000000000c0", revision = 8 } },`) {
		t.Fatalf("challenges not rendered:\n%s", config)
	}
	for _, name := range SecurityVariables {
		if !strings.Contains(string(config), "set $"+name+" \"\";") {
			t.Fatalf("variable %s not declared", name)
		}
	}
	for name, bad := range map[string][]edgesite.Ref{
		"unsorted":  {second, first},
		"duplicate": {first, first},
		"id":        {{ID: "x", Revision: 1}},
		"revision":  {{ID: first.ID, Revision: 0}},
	} {
		input.Challenges = bad
		if _, err := Render(input); err == nil {
			t.Fatalf("%s challenges accepted", name)
		}
	}
	sites := []edgesite.Site{{Security: edgesite.Security{Challenge: &edgesite.Ref{Kind: edgesite.RefChallenge, ID: "b", Revision: 2}}},
		{Security: edgesite.Security{Challenge: &edgesite.Ref{Kind: edgesite.RefChallenge, ID: "a", Revision: 3}}},
		{Security: edgesite.Security{Challenge: &edgesite.Ref{Kind: edgesite.RefChallenge, ID: "b", Revision: 2}}}, {}}
	if got := ChallengesFromSites(sites); len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("ChallengesFromSites = %+v", got)
	}
}

func testManagedWAF() *ManagedWAF {
	return &ManagedWAF{ModulePath: "/opt/cdnca/waf/modules/ngx_http_modsecurity_module.so",
		UnicodeMapPath: "/opt/cdnca/waf/unicode.mapping", RulesPath: "/var/lib/cdnca-edge/waf/main.conf",
		Tiers: map[string]string{
			"bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000": "/var/lib/cdnca-edge/waf/tier-b.conf",
			"aaaaaaaaaaaaaaaa_b1048576_n131072_p_a1000_j512_p100000": "/var/lib/cdnca-edge/waf/tier-a.conf",
		}}
}

// locationBlock is the location starting with header in a server block.
func locationBlock(t *testing.T, block, header string) string {
	t.Helper()
	start := strings.Index(block, header)
	if start < 0 {
		t.Fatalf("no %q", header)
	}
	rest := block[start:]
	return rest[:strings.Index(rest, "\n    }\n")+1]
}

// The managed WAF is node-level (D11): the module, the node rules at http
// level and one tier location per tier with location /'s proxying; location
// / itself never enables the engine.
func TestRenderManagedWAF(t *testing.T) {
	input := testInput()
	input.ManagedWAF = testManagedWAF()
	const hot = "0d110000-0000-4000-8000-00000000000a"
	const bucket = "@cdnca_waf_bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000_x0"
	input.ManagedWAF.Buckets = map[string]string{bucket: "/var/lib/cdnca-edge/waf/buckets/x0.conf"}
	input.ManagedWAF.SiteBuckets = map[string]string{hot: bucket}
	config := render(t, input)
	if !strings.HasPrefix(config, "# generated by cdnca node skeleton (site_runtime 9); no site is compiled in\nload_module \"/opt/cdnca/waf/modules/ngx_http_modsecurity_module.so\";\n") {
		t.Fatalf("load_module must come first in the main context:\n%.300s", config)
	}
	if !strings.Contains(config, "  modsecurity_rules 'SecUnicodeMapFile /opt/cdnca/waf/unicode.mapping 20127';\n  modsecurity_rules_file \"/var/lib/cdnca-edge/waf/main.conf\";\n") {
		t.Fatal("no http-level node rules")
	}
	for _, port := range []int{80, 443, 8443} {
		block := server(t, config, port)
		root := locationBlock(t, block, "    location / {\n")
		if strings.Contains(root, "modsecurity") || !strings.Contains(root, "      set $cdnca_waf_engine 1;\n") {
			t.Fatalf("port %d: location / runs ModSecurity or lacks the engine flag:\n%s", port, root)
		}
		a := strings.Index(block, "    location @cdnca_waf_aaaaaaaaaaaaaaaa_b1048576_n131072_p_a1000_j512_p100000 {\n")
		b := strings.Index(block, "    location @cdnca_waf_bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000 {\n")
		if a < 0 || b < a {
			t.Fatalf("port %d: tier locations missing or unsorted", port)
		}
		tier := locationBlock(t, block, "    location @cdnca_waf_aaaaaaaaaaaaaaaa")
		want := "      modsecurity on;\n      modsecurity_rules_file \"/var/lib/cdnca-edge/waf/tier-a.conf\";\n      modsecurity_transaction_id $cdnca_waf_txid;\n"
		if !strings.Contains(tier, want) {
			t.Fatalf("tier lacks the engine lines:\n%s", tier)
		}
		// the same proxying as location /
		body := func(text string) string { return text[strings.Index(text, "      proxy_http_version"):] }
		if body(tier) != body(root) {
			t.Fatalf("tier proxying differs from location /:\n%s\n---\n%s", body(tier), body(root))
		}
		// an exclusion bucket: a location like its tier's, same body
		own := locationBlock(t, block, "    location "+bucket+" {\n")
		if !strings.Contains(own, "      modsecurity_rules_file \"/var/lib/cdnca-edge/waf/buckets/x0.conf\";\n") || body(own) != body(root) {
			t.Fatalf("port %d: bucket location:\n%s", port, own)
		}
		// grey zone challenge (ADR 0011 RI-03): 599 -> the challenge location
		if !strings.Contains(block, "    error_page 599 = @cdnca_waf_challenge;\n    location @cdnca_waf_challenge {\n      rewrite_by_lua_block { }\n      access_by_lua_block { }\n"+
			"      content_by_lua_block { require(\"cdnca_managed_waf\").challenge() }\n    }\n") {
			t.Fatalf("port %d: no grey zone challenge location", port)
		}
		// retest N3: a ModSecurity 403 gets the site's block page; an
		// origin 403 is never intercepted (proxy_intercept_errors off)
		if !strings.Contains(block, "    location @cdnca_waf_block {\n      rewrite_by_lua_block { }\n      access_by_lua_block { }\n"+
			"      content_by_lua_block { ngx.var.cdnca_security_block_page = \"1\"; return ngx.exit(403) }\n    }\n") {
			t.Fatalf("port %d: no managed WAF block location", port)
		}
		for _, name := range []string{"@cdnca_waf_aaaaaaaaaaaaaaaa_b1048576_n131072_p_a1000_j512_p100000",
			"@cdnca_waf_bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000", bucket} {
			own := locationBlock(t, block, "    location "+name+" {\n")
			if !strings.Contains(own, "      modsecurity_transaction_id $cdnca_waf_txid;\n      error_page 403 = @cdnca_waf_block;\n      error_page 599 = @cdnca_waf_challenge;\n") {
				t.Fatalf("port %d: %s lacks error_page 403:\n%s", port, name, own)
			}
			if strings.Contains(own, "proxy_intercept_errors") {
				t.Fatalf("port %d: %s intercepts origin errors:\n%s", port, name, own)
			}
		}
	}
	for _, want := range []string{"  lua_shared_dict cdnca_waf_adapt 16m;\n", "  lua_shared_dict cdnca_waf_grey 8m;\n", "      managed_waf_grey = {  },\n",
		"      managed_waf_buckets = { [\"" + hot + "\"] = \"" + bucket + "\" },\n",
		"    location ^~ /waf-adapt/ { content_by_lua_block { require(\"cdnca_managed_waf\").admin() } }\n"} {
		if !strings.Contains(config, want) {
			t.Fatalf("no %q", want)
		}
	}
	if strings.Contains(config, "_c {\n") || strings.Contains(config, "managed_waf_cookie") {
		t.Fatal("cookie variant rendered without CookieTiers")
	}
	// waf-cookie-fp2: a two-level tier's cookie variant, right after its tier
	cookies := testInput()
	cookies.ManagedWAF = testManagedWAF()
	cookies.ManagedWAF.CookieTiers = map[string]string{"bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000": "/var/lib/cdnca-edge/waf/tier-b_c.conf"}
	withCookies := render(t, cookies)
	block := server(t, withCookies, 443)
	tierB := strings.Index(block, "    location @cdnca_waf_bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000 {\n")
	variant := locationBlock(t, block, "    location @cdnca_waf_bbbbbbbbbbbbbbbb_b1048576_n131072_r_a1000_j512_p100000_c {\n")
	if tierB < 0 || !strings.Contains(variant, "      modsecurity_rules_file \"/var/lib/cdnca-edge/waf/tier-b_c.conf\";\n") ||
		strings.Contains(block, "@cdnca_waf_aaaaaaaaaaaaaaaa_b1048576_n131072_p_a1000_j512_p100000_c") ||
		!strings.Contains(withCookies, "      managed_waf_cookie = true,\n") {
		t.Fatalf("cookie variant location:\n%s", variant)
	}
	// ri-wire: an exclusion bucket of that tier has its own cookie variant
	// (<bucket>_c); one without it, or one of a tier without a variant, is refused
	cookies.ManagedWAF.Buckets = map[string]string{bucket: "/var/lib/cdnca-edge/waf/buckets/x0.conf"}
	cookies.ManagedWAF.SiteBuckets = map[string]string{hot: bucket}
	cookies.ManagedWAF.CookieBuckets = map[string]string{bucket: "/var/lib/cdnca-edge/waf/buckets/x0_c.conf"}
	bucketVariant := locationBlock(t, server(t, render(t, cookies), 443), "    location "+bucket+"_c {\n")
	if !strings.Contains(bucketVariant, "      modsecurity_rules_file \"/var/lib/cdnca-edge/waf/buckets/x0_c.conf\";\n") {
		t.Fatalf("bucket cookie variant location:\n%s", bucketVariant)
	}
	cookies.ManagedWAF.CookieBuckets = nil
	if _, err := Render(cookies); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bucket of a cookie variant tier without its variant accepted: %v", err)
	}
	cookies.ManagedWAF.CookieBuckets = map[string]string{bucket: "/a", bucket + "x": "/b"}
	if _, err := Render(cookies); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cookie variant of an unknown bucket accepted: %v", err)
	}
	cookies.ManagedWAF.Buckets, cookies.ManagedWAF.SiteBuckets, cookies.ManagedWAF.CookieBuckets = nil, nil, nil
	cookies.ManagedWAF.CookieTiers = map[string]string{"cccccccccccccccc_b1_n1_r_a1_j1_p1": "/a"}
	if _, err := Render(cookies); err == nil {
		t.Fatal("cookie variant of an unknown tier accepted")
	}
	plain := render(t, testInput())
	if strings.Contains(plain, "modsecurity") || strings.Contains(plain, "set $cdnca_waf_engine 1;") ||
		strings.Contains(plain, "cdnca_waf_adapt") || strings.Contains(plain, "error_page 599") {
		t.Fatal("no managed WAF still renders the engine")
	}
	for name, mutate := range map[string]func(*ManagedWAF){
		"no tiers":        func(w *ManagedWAF) { w.Tiers = map[string]string{} },
		"bad tier key":    func(w *ManagedWAF) { w.Tiers["x;y"] = "/a" },
		"relative rules":  func(w *ManagedWAF) { w.RulesPath = "main.conf" },
		"quote in map":    func(w *ManagedWAF) { w.UnicodeMapPath = "/a'b" },
		"tier path brace": func(w *ManagedWAF) { w.Tiers["aaaaaaaaaaaaaaaa_b1_n1_r_a1_j1_p1"] = "/a{b" },
		"bucket of no tier": func(w *ManagedWAF) {
			w.Buckets = map[string]string{"@cdnca_waf_cccccccccccccccc_b1_n1_r_a1_j1_p1_x0": "/a"}
		},
		"bucket name":       func(w *ManagedWAF) { w.Buckets = map[string]string{bucketOf(w) + "x;": "/a"} },
		"bucket number":     func(w *ManagedWAF) { w.Buckets = map[string]string{bucketOf(w)[:len(bucketOf(w))-1] + "01": "/a"} },
		"bucket path quote": func(w *ManagedWAF) { w.Buckets = map[string]string{bucketOf(w): "/a'b"} },
		"bad site id": func(w *ManagedWAF) {
			w.Buckets = map[string]string{bucketOf(w): "/a"}
			w.SiteBuckets = map[string]string{"x y": bucketOf(w)}
		},
		"site of no bucket": func(w *ManagedWAF) {
			w.SiteBuckets = map[string]string{"0d110000-0000-4000-8000-00000000000a": bucketOf(w)}
		},
	} {
		waf := testManagedWAF()
		mutate(waf)
		bad := testInput()
		bad.ManagedWAF = waf
		if _, err := Render(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// bucketOf is the first exclusion bucket location of a test tier.
func bucketOf(w *ManagedWAF) string {
	keys := sortedTierKeys(w.Tiers)
	return "@cdnca_waf_" + keys[0] + "_x0"
}

// The loopback health server carries the ban list endpoint:
// the Agent posts the ban list library's snapshot and drains the WAF kernel
// ban queue there.
func TestHealthServerCarriesSecurityBans(t *testing.T) {
	var output bytes.Buffer
	writeHealthServer(&output, 18080)
	config := output.String()
	for _, want := range []string{"listen 127.0.0.1:18080;", "location = /healthz/cc-kernel-bans {",
		"location = /healthz/security-bans {", `require("cdnca_banlist").handle()`} {
		if !strings.Contains(config, want) {
			t.Fatalf("health server lacks %q:\n%s", want, config)
		}
	}
	if strings.Count(config, "server {") != 1 || !strings.HasSuffix(config, "    }\n  }\n") {
		t.Fatalf("health server is malformed:\n%s", config)
	}
}

// The global unknown_site page reaches cdnca_site through
// configure(); without one the node keeps its bare 421.
func TestRenderUnknownSitePage(t *testing.T) {
	plain, err := Render(testInput())
	if err != nil || !strings.Contains(string(plain), "unknown_site = nil,") {
		t.Fatalf("no page: %v", err)
	}
	input := testInput()
	input.UnknownSite = &NodePage{Status: 410, MIMEType: "text/html", BodyFile: "/var/lib/cdnca/unknown-site.html",
		StyleHash: "sha256-" + strings.Repeat("A", 43) + "="}
	conf, err := Render(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `unknown_site = { status = 410, mime_type = "text/html", body_file = "/var/lib/cdnca/unknown-site.html", style_hash = "sha256-` +
		strings.Repeat("A", 43) + `=" },`
	if !strings.Contains(string(conf), want) {
		t.Fatalf("configure() lacks %s", want)
	}
}

func TestRenderAutoDefense(t *testing.T) {
	if config := render(t, testInput()); strings.Contains(config, AutoDefenseGateDictionary) || strings.Contains(config, "cdnca_autodefense") {
		t.Fatal("auto defense rendered without Input.AutoDefense")
	}
	input := testInput()
	input.AutoDefense = true
	config := render(t, input)
	for _, want := range []string{
		"  lua_shared_dict cdnca_autodefense 64m;\n  lua_shared_dict cdnca_autodefense_count 32m;\n",
		"    location ^~ /autodefense/ { content_by_lua_block { require(\"cdnca_autodefense\").admin() } }\n",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Count(config, "/autodefense/") != 1 {
		t.Fatal("gate location must be on the control socket only")
	}
	// ri-wire: the sample label reads $cdnca_security_policy_id, declared
	// once (control server) without telemetry too, and once with it
	if strings.Count(config, "set $cdnca_security_policy_id ") != 1 {
		t.Fatal("auto defense without telemetry does not declare $cdnca_security_policy_id once")
	}
	input.Telemetry = true
	if strings.Count(render(t, input), "set $cdnca_security_policy_id ") != 1 {
		t.Fatal("telemetry and auto defense declare $cdnca_security_policy_id twice")
	}
}

// A dispatched port (D13-c0) listens on its internal socket with PROXY
// protocol instead of 0.0.0.0, restores the client from the header, keeps
// IPv6 and QUIC direct and has no 302 landing.
func TestRenderDispatchedPorts(t *testing.T) {
	input := testInput()
	input.Schedule302 = true
	input.Paths.MuxRoot = "/run/cdnca/mux"
	input.DispatchedPorts = map[int]bool{443: true, 80: true}
	config := render(t, input)
	tlsServer := server(t, config, 443)
	for _, want := range []string{"listen \"unix:/run/cdnca/mux/443-tls.sock\" ssl proxy_protocol default_server;",
		"listen [::]:443 ssl default_server;", "listen 0.0.0.0:443 quic reuseport default_server;",
		"set_real_ip_from unix:;\n    real_ip_header proxy_protocol;"} {
		if !strings.Contains(tlsServer, want) {
			t.Fatalf("443 lacks %q:\n%s", want, tlsServer)
		}
	}
	if strings.Contains(tlsServer, "listen 0.0.0.0:443 ssl") {
		t.Fatalf("443 still binds IPv4 TCP:\n%s", tlsServer)
	}
	plain := server(t, config, 80)
	if !strings.Contains(plain, "listen \"unix:/run/cdnca/mux/80-plain.sock\" proxy_protocol default_server;") ||
		strings.Contains(plain, "listen 0.0.0.0:80 ") || strings.Contains(plain, "X-Cdnca-S302-Client") {
		t.Fatalf("80:\n%s", plain)
	}
	if other := server(t, config, 8443); strings.Contains(other, "unix:") {
		t.Fatalf("8443 is not dispatched:\n%s", other)
	}
	if got := DispatchSocket("/m", 443, false); got != "/m/443-plain.sock" {
		t.Fatal(got)
	}
	for name, mutate := range map[string]func(*Input){
		"no mux root":       func(input *Input) { input.Paths.MuxRoot = "" },
		"port without site": func(input *Input) { input.DispatchedPorts = map[int]bool{9999: true} },
		"mux root too long": func(input *Input) { input.Paths.MuxRoot = "/" + strings.Repeat("m", 100) },
	} {
		value := testInput()
		value.Paths.MuxRoot, value.DispatchedPorts = "/run/cdnca/mux", map[int]bool{443: true}
		mutate(&value)
		if _, err := Render(value); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRenderNodeLocations(t *testing.T) {
	// off: no node location, no probe server
	config := render(t, testInput())
	for _, unwanted := range []string{"acme-challenge", "cdnca-market-probe", "cdnca_market_benchmark"} {
		if strings.Contains(config, unwanted) {
			t.Fatalf("%q rendered while off", unwanted)
		}
	}
	input := testInput()
	input.ACMEOverlayRoot, input.MarketProbe, input.MarketBenchmark = "/var/lib/cdnca-edge/acme", true, true
	config = render(t, input)
	plain, secure := server(t, config, 80), server(t, config, 443)
	acme := edgeconfig.ACMEHTTP01RouteMarker + "\n    location ~ \"^/\\.well-known/acme-challenge/(?<cdnca_acme_token>[A-Za-z0-9_-]{22,256})$\" {\n" +
		"      rewrite_by_lua_block { return }\n      access_by_lua_block { return }\n"
	for _, block := range []string{plain, secure} {
		if !strings.Contains(block, acme) || !strings.Contains(block, "root /var/lib/cdnca-edge/acme/acme-http01/current;") {
			t.Fatalf("ACME overlay location (own phases, overlay root):\n%s", block)
		}
	}
	// the probe paths: plain servers only, known Host proxied as location /
	probe := locationBlock(t, plain, "    location = /.well-known/cdnca-market-probe {\n")
	if !strings.Contains(probe, `access_by_lua_block { return require("dynroute.cdnca_dynroute").probe() }`) ||
		!strings.Contains(probe, "proxy_pass $cdnca_origin_scheme://cdnca_dynamic;") || strings.Contains(probe, "limit_conn") {
		t.Fatalf("probe location:\n%s", probe)
	}
	benchmark := locationBlock(t, plain, "    location = /.well-known/cdnca-market-benchmark {\n")
	if !strings.Contains(benchmark, "limit_req zone=cdnca_market_benchmark_rate burst=40 nodelay;") ||
		!strings.Contains(benchmark, "proxy_pass $cdnca_origin_scheme://cdnca_dynamic;") {
		t.Fatalf("benchmark location:\n%s", benchmark)
	}
	if strings.Contains(secure, "cdnca-market-probe") {
		t.Fatalf("probe on a TLS server:\n%s", secure)
	}
	for _, want := range []string{"    /.well-known/cdnca-market-probe probe;\n", "    /.well-known/cdnca-market-benchmark probe;\n",
		"limit_conn_zone $cdnca_probe_client zone=cdnca_market_benchmark_ip:1m;", `set $cdnca_probe_client "";`} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// port 80 is a site port here: no probe server
	if strings.Contains(config, "listen 0.0.0.0:80 default_server;\n    server_name _;\n    location = /.well-known/cdnca-market-probe {\n      content_by_lua") {
		t.Fatal("probe server rendered beside a site port 80")
	}
	// no site on 80: the probe server, without site selection
	input.Ports = input.Ports[:1]
	config = render(t, input)
	probeServer := server(t, config, 80)
	if !strings.Contains(probeServer, "listen 0.0.0.0:80 default_server;") || strings.Contains(probeServer, "server_rewrite_by_lua") ||
		!strings.Contains(probeServer, `content_by_lua_block { return require("dynroute.cdnca_dynroute").probe() }`) ||
		!strings.Contains(probeServer, "set $cdnca_probe_client $binary_remote_addr;") ||
		!strings.Contains(probeServer, `require("cdnca_site").reject_unknown()`) {
		t.Fatalf("probe server:\n%s", probeServer)
	}
	// an L4 forward owns 80, or a probe-only node: no server / no benchmark
	input.ProbePortTaken = true
	if strings.Contains(render(t, input), ":80 default_server;") {
		t.Fatal("probe server on a port an L4 forward owns")
	}
	input.ProbePortTaken, input.MarketBenchmark = false, false
	if config = render(t, input); strings.Contains(config, "benchmark") || !strings.Contains(config, "cdnca-market-probe") {
		t.Fatal("probe-only node")
	}
	for _, bad := range []Input{{ACMEOverlayRoot: "relative"}, {MarketBenchmark: true}} {
		input := testInput()
		input.ACMEOverlayRoot, input.MarketBenchmark = bad.ACMEOverlayRoot, bad.MarketBenchmark
		if _, err := Render(input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v accepted: %v", bad, err)
		}
	}
}

// B11: nginx refuses an HTTP/1.1 request without or with an empty Host
// while parsing (built-in 400) before any Lua phase. The shared and probe
// servers send that 400 to a named location whose content is
// cdnca_site.no_host(); the site phases are off there. Also
// without a no_host page (the node's built-in default page answers), so
// the location is in every public server either way.
func TestRenderNoHostErrorPage(t *testing.T) {
	want := "    error_page 400 " + NoHostLocation + ";\n    location " + NoHostLocation + " {\n" +
		"      rewrite_by_lua_block { return }\n      access_by_lua_block { return }\n" +
		"      content_by_lua_block { return require(\"cdnca_site\").no_host() }\n    }\n"
	for _, page := range []*NodePage{nil, {Status: 400, MIMEType: "text/html", BodyFile: "/var/lib/cdnca/no-host.html"}} {
		input := testInput()
		input.MarketProbe = true
		input.NoHost = page
		config := render(t, input)
		servers := strings.Count(config, "    server_name _;\n")
		if got := strings.Count(config, want); got == 0 || got != servers {
			t.Fatalf("page %v: %d no_host locations for %d public servers:\n%s", page != nil, got, servers, config)
		}
		// without pages the node's tables are empty / nil (the Lua side
		// answers with its built-in default pages)
		if page == nil && !strings.Contains(config, "      unknown_site = nil,\n      no_host = nil,\n      slot_pages = {},\n") {
			t.Fatal("node pages rendered without pages")
		}
	}
}

// An exclusion bucket of a tier with application packs (tier key ending in
// _x<8 hex> parts) is accepted; its tier key is cut at the last "_x".
func TestManagedWAFBucketOfAppTier(t *testing.T) {
	waf := testManagedWAF()
	const appTier = "dddddddddddddddd_b1_n1_r_a1_j1_p1_x0a1b2c3d_xdeadbeef"
	waf.Tiers[appTier] = "/state/managed-waf/app-tier.conf"
	bucket := "@cdnca_waf_" + appTier + "_x2"
	waf.Buckets = map[string]string{bucket: "/state/managed-waf/app-bucket.conf"}
	waf.SiteBuckets = map[string]string{"0d110000-0000-4000-8000-00000000000a": bucket}
	input := testInput()
	input.ManagedWAF = waf
	if _, err := Render(input); err != nil {
		t.Fatal(err)
	}
	waf.Buckets = map[string]string{"@cdnca_waf_" + appTier: "/state/managed-waf/app-bucket.conf"}
	waf.SiteBuckets = nil
	if _, err := Render(input); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a tier key without a bucket number was accepted as a bucket: %v", err)
	}
}

// TestRenderMaintenance: a stopped node (ADR 0014 LIC-BAN-05) keeps every
// site port's listeners and TLS handshake, answers 503 with the fixed page
// and Retry-After, renders no site phase handlers or proxy, and keeps the
// health and control servers.
func TestRenderMaintenance(t *testing.T) {
	input := testInput()
	input.HealthPort, input.MarketProbe = 19080, true
	input.Maintenance = &Maintenance{RetryAfter: "Sat, 16 Mar 2030 17:46:40 GMT"}
	config := render(t, input)
	for _, port := range []int{80, 443, 8443} {
		block := server(t, config, port)
		for _, want := range []string{"return 503 ", "Retry-After \"Sat, 16 Mar 2030 17:46:40 GMT\" always;", "服务已暂停"} {
			if !strings.Contains(block, want) {
				t.Fatalf("port %d lacks %q:\n%s", port, want, block)
			}
		}
		for _, unwanted := range []string{"proxy_pass", "access_by_lua", "server_rewrite_by_lua"} {
			if strings.Contains(block, unwanted) {
				t.Fatalf("stopped port %d renders %q", port, unwanted)
			}
		}
	}
	tls := server(t, config, 443)
	for _, want := range []string{"listen 0.0.0.0:443 ssl default_server;", "listen [::]:443 quic reuseport default_server;",
		"ssl_certificate_by_lua_block", "http3 on;"} {
		if !strings.Contains(tls, want) {
			t.Fatalf("stopped TLS port lacks %q:\n%s", want, tls)
		}
	}
	if !strings.Contains(config, "listen 127.0.0.1:19080;") || !strings.Contains(config, ControlSocket) {
		t.Fatal("the health and control servers must stay while stopped")
	}
	if strings.Contains(config, fmt.Sprintf(":%d default_server;\n    server_name _;\n    location = /", MarketProbePort)) {
		t.Fatal("the market probe server must not answer while stopped")
	}
	input.Maintenance = &Maintenance{}
	if permanent := render(t, input); strings.Contains(permanent, "Retry-After") {
		t.Fatal("a permanent stop has no Retry-After")
	}
}
