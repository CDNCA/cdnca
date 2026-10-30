package l4runtime

import (
	"os"
	"strings"
	"testing"
)

// The live session registry now covers every TCP socket (L4-USAGE-01), so a
// replayed TCP configuration prepares the control socket directory: tests
// prepare a temporary one instead of /var/lib/cdnca-edge.
func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "l4ctl-")
	if err != nil {
		panic(err)
	}
	restore := UseControlDirectoryForTesting(directory)
	code := m.Run()
	restore()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

// L4-USAGE-01：没开会话日志的 TCP 转发也登记活会话（供 agent 每 60 秒写用量
// 检查点），日志行带 $pid（结束行对上登记的 worker:连接）；UDP 不登记。
func TestEveryTCPSocketTracksLiveSessionsForUsageCheckpoints(t *testing.T) {
	spec := l403StreamSpec()
	config, err := AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx := string(mustCompileV2(t, config).NginxConfig)
	for _, want := range []string{
		"    lua_shared_dict l4_v2_live 64m;\n",
		`set $cdnca_l4_live_key "";`,
		`geo.session_track("` + l403Stream + `", "` + l403Stream + `", client, false); }`,
		`log_by_lua_block { require("cdnca_l4_geo").session_end() }`,
		"listen unix:" + L4ControlSocketPath + ";",
		`"connection":"$connection","pid":"$pid","protocol":"$protocol"`,
	} {
		if !strings.Contains(nginx, want) {
			t.Fatalf("TCP forward lacks %q:\n%s", want, nginx)
		}
	}
	if strings.Contains(nginx, "l4_session_v2") || strings.Contains(nginx, "cdnca_l4_client") {
		t.Fatalf("usage tracking turned the session log on:\n%s", nginx)
	}
	spec.Listener.Protocol = ProtocolUDP
	spec.ProxyProtocolInbound, spec.ProxyProtocolOutbound = false, false
	spec.Geo.TrustedProxyCIDRs = nil
	config, err = AggregateStreamRuntimeSpecsV2("l403-revision-7", 7, []StreamRuntimeSpecV2{spec})
	if err != nil {
		t.Fatal(err)
	}
	nginx = string(mustCompileV2(t, config).NginxConfig)
	for _, absent := range []string{"l4_v2_live", "session_track", L4ControlSocketPath} {
		if strings.Contains(nginx, absent) {
			t.Fatalf("UDP forward renders %q:\n%s", absent, nginx)
		}
	}
}
