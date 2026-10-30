package l4runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	guardRule1 = "66666666-6666-4666-8666-666666666661"
	guardRule2 = "66666666-6666-4666-8666-666666666662"
)

func guardSpec() StreamRuntimeSpecV2 {
	spec := l403StreamSpec()
	spec.GuardRules = []GuardRuleV2{
		{ID: guardRule1, Action: edgeconfig.L4GuardActionBan, BanSeconds: 600, Threshold: 5, WindowSeconds: 60,
			FirstPacket: &edgeconfig.L4GuardFirstPacket{Match: edgeconfig.L4GuardMatchRegex, Value: `^\x16\x03`}},
		{ID: guardRule2, Action: edgeconfig.L4GuardActionDrop,
			ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"198.51.100.0/24"}},
			Geo:      []edgeconfig.WAFIPIntel{{Field: edgeconfig.WAFIPIntelTag, Values: []string{"idc:global"}}}},
	}
	return spec
}

// guard_rules (tcp/udp v10) rides from the spec through the aggregate into
// config.json (for cdnca_l4_geo); unset it changes neither the canonical
// bytes, nginx.conf nor config.json.
func TestGuardRulesAreOptionalAndCarried(t *testing.T) {
	base, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	empty := l403StreamSpec()
	empty.GuardRules = []GuardRuleV2{}
	emptyConfig, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{empty})
	if err != nil {
		t.Fatal(err)
	}
	plain, emptyCompiled := mustCompileV2(t, base), mustCompileV2(t, emptyConfig)
	if !bytes.Equal(plain.CanonicalJSON, emptyCompiled.CanonicalJSON) || !bytes.Equal(plain.NginxConfig, emptyCompiled.NginxConfig) ||
		!bytes.Equal(plain.GeoJSON, emptyCompiled.GeoJSON) {
		t.Fatal("empty guard rules changed the compiled release")
	}
	for _, content := range [][]byte{plain.CanonicalJSON, plain.NginxConfig, plain.GeoJSON} {
		if bytes.Contains(content, []byte("guard")) || bytes.Contains(content, []byte("l4_v2_rate")) {
			t.Fatalf("unset guard rules changed the release:\n%s", content)
		}
	}

	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{guardSpec()})
	if err != nil {
		t.Fatal(err)
	}
	compiled := mustCompileV2(t, config)
	if !bytes.Contains(compiled.CanonicalJSON, []byte(`"guard_rules":[{"id":"`+guardRule1+`"`)) {
		t.Fatalf("canonical bytes: %s", compiled.CanonicalJSON)
	}
	var geo struct {
		Listeners []struct {
			Guard []map[string]any `json:"guard"`
		} `json:"listeners"`
	}
	if err := json.Unmarshal(compiled.GeoJSON, &geo); err != nil || len(geo.Listeners) != 1 || len(geo.Listeners[0].Guard) != 2 {
		t.Fatalf("config.json guard: %s %v", compiled.GeoJSON, err)
	}
	rule := geo.Listeners[0].Guard[1]
	if specs, _ := rule["geo"].([]any); len(specs) != 1 || specs[0] != "tag=0000000000020000" {
		t.Fatalf("geo condition not rendered as an iplib spec: %v", rule["geo"])
	}
	// The agent re-checks the contract itself.
	for name, change := range map[string]func(*StreamRuntimeSpecV2){
		"no condition":   func(spec *StreamRuntimeSpecV2) { spec.GuardRules[1].ClientIP, spec.GuardRules[1].Geo = nil, nil },
		"sni plain":      func(spec *StreamRuntimeSpecV2) { spec.GuardRules[1].ServerNames = []string{"a.example.com"} },
		"bad regex":      func(spec *StreamRuntimeSpecV2) { spec.GuardRules[0].FirstPacket.Value = "(" },
		"duplicate rule": func(spec *StreamRuntimeSpecV2) { spec.GuardRules[1].ID = guardRule1 },
	} {
		spec := guardSpec()
		change(&spec)
		if _, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

// A guarded server calls guard() after enforce() and before the rate limit,
// waits for first packets within preread_timeout 3s, bounds regex
// backtracking, and serves the control socket for the kernel ban queue.
func TestGuardRulesRenderThePreread(t *testing.T) {
	spec := guardSpec()
	spec.NewConnRate = &NewConnRateV2{RatePerSecond: 20, Burst: 5, BanSeconds: 60}
	spec.AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolTCP, Address: "*", Port: 9444}}
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(mustCompileV2(t, config).NginxConfig)
	call := `preread_by_lua_block { local geo = require("cdnca_l4_geo"); local ok, reason, client = geo.enforce("` + l403Stream +
		`"); if not ok then ngx.log(ngx.WARN, "l4_geo ", reason) return end; if not geo.guard("` + l403Stream +
		`", client, false, true) then return end; geo.limit_new_connections("` + l403Stream + `", client, 20, 5, 60) geo.session_track(`
	for _, want := range []struct {
		text  string
		count int
	}{
		{call, 2}, {"        preread_timeout 3s;\n", 2}, {"    lua_shared_dict l4_v2_rate 16m;\n", 1},
		{"    lua_regex_match_limit 100000;\n", 1}, {"listen unix:" + L4ControlSocketPath + ";", 1},
	} {
		if got := strings.Count(nginx, want.text); got != want.count {
			t.Fatalf("%q rendered %d times, want %d:\n%s", want.text, got, want.count, nginx)
		}
	}

	// A session log stream: guard() records the end reason; without first
	// packet / regex / ban rules none of their directives appear.
	spec = l403StreamSpec()
	spec.SessionLog = true
	spec.GuardRules = []GuardRuleV2{{ID: guardRule2, Action: edgeconfig.L4GuardActionDrop,
		ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"198.51.100.0/24"}}}}
	config, err = AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx = string(mustCompileV2(t, config).NginxConfig)
	if !strings.Contains(nginx, `return end; if not geo.guard("`+l403Stream+`", client, true, true) then return end; geo.session_track(`) {
		t.Fatalf("guard not between enforce and session_track:\n%s", nginx)
	}
	for _, absent := range []string{"preread_timeout", "lua_regex_match_limit", "limit_new_connections"} {
		if strings.Contains(nginx, absent) {
			t.Fatalf("%s rendered without a rule needing it:\n%s", absent, nginx)
		}
	}

	// A plain drop-only UDP stream: no control socket (no ban to queue, no
	// live TCP session to track; TCP sockets always track them, L4-USAGE-01).
	spec.SessionLog = false
	spec.Listener.Protocol = ProtocolUDP
	spec.ProxyProtocolInbound, spec.ProxyProtocolOutbound = false, false
	spec.Geo.TrustedProxyCIDRs = nil
	config, err = AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	if nginx = string(mustCompileV2(t, config).NginxConfig); strings.Contains(nginx, L4ControlSocketPath) {
		t.Fatalf("control socket without a ban rule:\n%s", nginx)
	}
}

// Kernel bans cover a stream's own sockets (exclusive or a passthrough port
// it alone holds), never a port shared through a dispatcher.
func TestKernelBanTargetsSkipSharedPorts(t *testing.T) {
	ban := []GuardRuleV2{{ID: guardRule1, Action: edgeconfig.L4GuardActionBan, BanSeconds: 60, Threshold: 1,
		ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"0.0.0.0/0"}}}}
	shared := passthroughSpecs()
	shared[0].GuardRules = ban
	shared[0].AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolTCP, Address: "*", Port: 9500}}
	alone := sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamC, 9600, true, "c.example")
	alone.GuardRules = ban
	ranged := multiListenerV2Spec()
	ranged.TenantID, ranged.Geo.TenantID = sharedTenantB, sharedTenantB
	ranged.StreamID, ranged.Geo.StreamID = "dddddddd-2222-4222-8222-00000000000d", "dddddddd-2222-4222-8222-00000000000d"
	ranged.AdditionalListeners = []AdditionalListenerV2{{ID: "55555555-5555-4555-8555-555555555555", Protocol: ProtocolUDP, Address: "*", Port: 9700, PortEnd: 9710}}
	ranged.Listener = ListenerSocketV2{Protocol: ProtocolTCP, Address: "*", Port: 9800}
	ranged.GuardRules = ban
	config, err := AggregateStreamRuntimeSpecsV2("shared-v1", 1, append(shared, alone, ranged))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := KernelBanTargets(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %+v", targets)
	}
	if got := targets[sharedStreamA].Sockets; len(got) != 1 || got[0] != (KernelBanSocket{Protocol: ProtocolTCP, Port: 9500, PortEnd: 9500}) {
		t.Fatalf("shared port 9443 must be left out: %+v", got)
	}
	if got := targets[sharedStreamC]; got.TenantID != sharedTenantB || len(got.Sockets) != 1 || got.Sockets[0].Port != 9600 {
		t.Fatalf("passthrough port held alone: %+v", got)
	}
	got := targets["dddddddd-2222-4222-8222-00000000000d"].Sockets
	if len(got) != 2 || got[0] != (KernelBanSocket{Protocol: ProtocolTCP, Port: 9800, PortEnd: 9800}) ||
		got[1] != (KernelBanSocket{Protocol: ProtocolUDP, Port: 9700, PortEnd: 9710}) {
		t.Fatalf("exclusive sockets and ranges: %+v", got)
	}
	if _, ok := targets[sharedStreamB]; ok {
		t.Fatal("a stream without ban rules is a target")
	}
}

// SNI guard rules read the ClientHello: a passthrough port held alone already
// prereads it (and needs a larger variables hash bucket for its SNI map); a
// socket behind a shared port's dispatcher prereads it again only for them.
func TestGuardRulesOnSNIPrereadTheClientHello(t *testing.T) {
	sni := []GuardRuleV2{{ID: guardRule1, Action: edgeconfig.L4GuardActionDrop, ServerNames: []string{"bad.a.example"}}}
	alone := sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "*.a.example")
	compiled, err := compileShared(t, nil, alone)
	if err != nil {
		t.Fatal(err)
	}
	if nginx := string(compiled.NginxConfig); strings.Count(nginx, "    variables_hash_bucket_size 128;\n") != 1 {
		t.Fatalf("lone passthrough port without a variables hash bucket for its SNI map:\n%s", nginx)
	}
	plain, err := compileShared(t, nil, sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, false))
	if err != nil || strings.Contains(string(plain.NginxConfig), "variables_hash_bucket_size") {
		t.Fatalf("plain port changed: %v\n%s", err, plain.NginxConfig)
	}
	shared := passthroughSpecs()
	compiled, err = compileShared(t, nil, shared...)
	if err != nil {
		t.Fatal(err)
	}
	before := strings.Count(string(compiled.NginxConfig), "ssl_preread on;")
	shared[0].GuardRules = sni
	compiled, err = compileShared(t, nil, shared...)
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(compiled.NginxConfig)
	if got := strings.Count(nginx, "ssl_preread on;"); got != before+1 {
		t.Fatalf("ssl_preread on %d servers, want %d (the guarded consumer again):\n%s", got, before+1, nginx)
	}
	if !strings.Contains(nginx, "listen unix:"+L4DispatchSocketPath(sharedStreamA)+" proxy_protocol;\n        set_real_ip_from unix:;\n        ssl_preread on;\n") {
		t.Fatalf("guarded dispatched consumer does not preread:\n%s", nginx)
	}
}

// passthroughSpecs: two tenants sharing one TLS passthrough port (moved here
// when the 1.0.33 legacy-release tests were deleted).
func passthroughSpecs() []StreamRuntimeSpecV2 {
	return []StreamRuntimeSpecV2{
		sharedPortSpec(sharedTenantA, sharedSiteA, sharedStreamA, 9443, true, "a.example", "*.a.example"),
		sharedPortSpec(sharedTenantB, sharedSiteB, sharedStreamB, 9443, true, "b.example"),
	}
}
