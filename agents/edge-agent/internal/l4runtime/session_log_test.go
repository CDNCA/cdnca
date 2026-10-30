package l4runtime

import (
	"bytes"
	"strings"
	"testing"
)

// session_log (tcp/udp v7) rides from the stream spec through the
// aggregate; unset it leaves the canonical bytes and nginx.conf unchanged.
func TestSessionLogIsOptionalAndCarried(t *testing.T) {
	base, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{l403StreamSpec()})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalV2(base)
	if err != nil {
		t.Fatal(err)
	}
	plain := mustCompileV2(t, base)
	// The live registry and its control socket are rendered for every TCP
	// socket (usage checkpoints, L4-USAGE-01); the session log's own fields
	// only with session_log.
	for _, marker := range []string{"session_log", "l4_session_v2", "cdnca_l4_client", "cdnca_l4_end_reason"} {
		if bytes.Contains(canonical, []byte(marker)) || bytes.Contains(plain.NginxConfig, []byte(marker)) {
			t.Fatalf("unset session log rendered %q:\n%s", marker, plain.NginxConfig)
		}
	}
	spec := l403StreamSpec()
	spec.SessionLog = true
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	if !config.Listeners[0].SessionLog {
		t.Fatal("aggregate dropped session_log")
	}
	canonical, err = CanonicalV2(config)
	if err != nil || !bytes.Contains(canonical, []byte(`"session_log":true`)) {
		t.Fatalf("canonical=%s err=%v", canonical, err)
	}
}

// A logging TCP socket records the client and the end reason, registers the
// live session after the Geo and rate checks, removes it when the session
// ends and writes the v2 format; the control socket is declared once.
func TestSessionLogRendersTrackingAndTheV2Format(t *testing.T) {
	spec := l403StreamSpec()
	spec.SessionLog = true
	spec.NewConnRate = &NewConnRateV2{RatePerSecond: 20, Burst: 5}
	spec.AdditionalListeners = []AdditionalListenerV2{{ID: "44444444-4444-4444-8444-444444444444", Protocol: ProtocolTCP, Address: "*", Port: 9444}}
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(mustCompileV2(t, config).NginxConfig)
	for marker, want := range map[string]int{
		"lua_shared_dict l4_v2_live 64m;":                                                                1,
		"log_format l4_session_v2 escape=json":                                                           1,
		"listen unix:" + L4ControlSocketPath + ";":                                                       1,
		`content_by_lua_block { require("cdnca_l4_geo").control() }`:                                     1,
		`set $cdnca_l4_client "";`:                                                                       2,
		`set $cdnca_l4_end_reason "";`:                                                                   2,
		`set $cdnca_l4_live_key "";`:                                                                     2,
		`log_by_lua_block { require("cdnca_l4_geo").session_end() }`:                                     2,
		`l4_session_v2;`:                                                                                 2,
		`"client":"$cdnca_l4_client","remote_addr":"$remote_addr"`:                                       1,
		`"end_reason":"$cdnca_l4_end_reason"`:                                                            1,
		`geo.enforce("` + l403Stream + `", true)`:                                                        2,
		`geo.limit_new_connections("` + l403Stream + `", client, 20, 5, 0, true) then return end`:        2,
		`geo.session_track("` + l403Stream + `", "` + l403Stream + `", client, false)`:                   1,
		`geo.session_track("` + l403Stream + `", "44444444-4444-4444-8444-444444444444", client, false)`: 1,
	} {
		if got := strings.Count(nginx, marker); got != want {
			t.Fatalf("%q rendered %d times, want %d:\n%s", marker, got, want, nginx)
		}
	}
	if strings.Contains(nginx, "l4_session_v1;") {
		t.Fatalf("a logging socket kept the v1 format:\n%s", nginx)
	}
}

// UDP sessions are logged but not tracked (each ends with its reply): no
// registry, no control socket, no log phase.
func TestSessionLogOnUDPDoesNotTrackSessions(t *testing.T) {
	spec := l403StreamSpec()
	spec.Listener.Protocol = ProtocolUDP
	spec.ProxyProtocolInbound, spec.ProxyProtocolOutbound = false, false
	spec.Geo.TrustedProxyCIDRs = nil
	spec.SessionLog = true
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(mustCompileV2(t, config).NginxConfig)
	for _, absent := range []string{"l4_v2_live", L4ControlSocketPath, "session_track", "log_by_lua", "cdnca_l4_live_key"} {
		if strings.Contains(nginx, absent) {
			t.Fatalf("UDP session log rendered %q:\n%s", absent, nginx)
		}
	}
	for _, present := range []string{`set $cdnca_l4_client "";`, `geo.enforce("` + l403Stream + `", true)`, "l4_session_v2;"} {
		if !strings.Contains(nginx, present) {
			t.Fatalf("UDP session log missing %q:\n%s", present, nginx)
		}
	}
}

// Behind a dispatcher the kernel tuple is the public connection the PROXY
// header names, and the port comes from the header.
func TestSessionLogBehindADispatcher(t *testing.T) {
	plain := l403StreamSpec()
	plain.ProxyProtocolInbound, plain.ProxyProtocolOutbound = false, false
	plain.Geo.TrustedProxyCIDRs = nil
	plain.SessionLog = true
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{plain},
		SiteSocketsV2{Port: 9443, TLSSocket: "/run/site/tls.sock", TLSServerNames: []string{"www.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(mustCompileV2(t, config).NginxConfig)
	for _, present := range []string{"log_format l4_session_dispatched_v2 escape=json", `"server_port":"$proxy_protocol_server_port"`,
		"l4_session_dispatched_v2;", `geo.session_track("` + l403Stream + `", "` + l403Stream + `", client, true)`} {
		if !strings.Contains(nginx, present) {
			t.Fatalf("dispatched session log missing %q:\n%s", present, nginx)
		}
	}
}
