// Command l4-pool-check is the stream-be acceptance (源站列表 / 定源 / ACL /
// IPv6开启, tcp/udp v11) against a real OpenResty: tests/l4-origin-pool/run.sh
// starts it in the node runtime image (one --rm --network none container).
// The agent's own v2 compiler (CompileV2) renders the streams, openresty -t
// checks the configuration, then TCP clients drive them:
//   - weight: origins weighted 3 and 1 share 40 sessions 30 / 10;
//   - down: a down origin gets no session;
//   - ip_hash: every session of one client reaches the same origin;
//   - acl-deny: ACL 默认拒绝 without a matching allow rule closes the session,
//     acl-allow: the allow rule for the client lets it through (the ACL is
//     the stream's guard rules: client_ip allow, then a catch-all drop);
//   - ipv6: listen_ipv6 also serves [::1].
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

var (
	luaRoot   = flag.String("lua", "/opt/cdnca/l4geo", "L4 Lua tree")
	stateRoot = flag.String("state", "/tmp/l4pool", "state directory")
)

const (
	tenant     = "0e4b0000-0000-4000-8000-000000000001"
	originPort = 19600
)

var failures int

func check(name string, ok bool, format string, args ...any) {
	state := "PASS"
	if !ok {
		state, failures = "FAIL", failures+1
	}
	fmt.Printf("%s %s %s\n", state, name, fmt.Sprintf(format, args...))
}

// origins listen on 127.0.0.2..4 (loopback answers all of 127/8) and answer
// their own address, so a client sees which origin a session reached.
func origins() {
	for _, address := range []string{"127.0.0.2", "127.0.0.3", "127.0.0.4"} {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", address, originPort))
		if err != nil {
			panic(err)
		}
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_, _ = fmt.Fprintf(conn, "%s\n", address)
				_ = conn.Close()
			}
		}()
	}
}

type stream struct {
	name    string
	port    int
	origins []l4runtime.OriginV2
	balance string
	guard   []l4runtime.GuardRuleV2
	ipv6    bool
}

func streams() []stream {
	all := "0.0.0.0/0"
	return []stream{
		{name: "weight", port: 18601, origins: []l4runtime.OriginV2{{Address: "127.0.0.2", Weight: 3}, {Address: "127.0.0.3", Weight: 1}}},
		{name: "down", port: 18602, origins: []l4runtime.OriginV2{{Address: "127.0.0.2", Weight: 1}, {Address: "127.0.0.3", Weight: 1, Down: true}}},
		{name: "ip_hash", port: 18603, balance: edgeconfig.L4BalanceIPHash,
			origins: []l4runtime.OriginV2{{Address: "127.0.0.2", Weight: 1}, {Address: "127.0.0.3", Weight: 1}, {Address: "127.0.0.4", Weight: 1}}},
		// ACL 默认拒绝 + an allow rule for another network: the client is dropped.
		{name: "acl-deny", port: 18604, origins: []l4runtime.OriginV2{{Address: "127.0.0.2", Weight: 1}}, guard: []l4runtime.GuardRuleV2{
			{ID: "0e4b0000-0000-4000-8000-000000000101", Action: edgeconfig.L4GuardActionAllow, ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"10.0.0.0/8"}}},
			{ID: "0e4b0000-0000-4000-8000-000000000102", Action: edgeconfig.L4GuardActionDrop, ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{all}}},
		}},
		// ACL 默认拒绝 + an allow rule for the client: it passes.
		{name: "acl-allow", port: 18605, origins: []l4runtime.OriginV2{{Address: "127.0.0.2", Weight: 1}}, guard: []l4runtime.GuardRuleV2{
			{ID: "0e4b0000-0000-4000-8000-000000000103", Action: edgeconfig.L4GuardActionAllow, ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"127.0.0.1/32"}}},
			{ID: "0e4b0000-0000-4000-8000-000000000104", Action: edgeconfig.L4GuardActionDrop, ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{all}}},
		}},
		{name: "ipv6", port: 18606, ipv6: true, origins: []l4runtime.OriginV2{{Address: "127.0.0.2", Weight: 1}}},
	}
}

func spec(index int, value stream) l4runtime.StreamRuntimeSpecV2 {
	id := fmt.Sprintf("0e4b0000-0000-4000-8000-0000000002%02d", index+10)
	return l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: value.port},
		Endpoint: l4runtime.EndpointV2{Address: value.origins[0].Address, Port: originPort, Origins: value.origins, Balance: value.balance},
		Geo: l4runtime.GeoPolicyV2{TenantID: tenant, StreamID: id, Revision: 1,
			UnknownRegionAction: l4runtime.GeoActionAllow, TrustedProxyCIDRs: []string{}, BlockedRegions: []string{}, RegionCIDRs: []l4runtime.RegionCIDRsV2{}},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		GuardRules: value.guard, ListenIPv6: value.ipv6,
	}
}

// reply is the origin a session through address reached, "" when the node
// closed it.
func reply(network, address string) string {
	conn, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.TrimSpace(line)
}

func openresty(args ...string) error {
	command := exec.Command("openresty", append([]string{"-p", *stateRoot + "/", "-c", "nginx.conf"}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("openresty %v: %v: %s", args, err, output)
	}
	return nil
}

func start(all []stream) (string, error) {
	specs := make([]l4runtime.StreamRuntimeSpecV2, len(all))
	for index, value := range all {
		specs[index] = spec(index, value)
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("pool-v11", 1, specs)
	if err != nil {
		return "", err
	}
	compiled, err := l4runtime.CompileV2(config, map[string][]netip.Addr{})
	if err != nil {
		return "", err
	}
	// The agent's stream configuration; telemetry under the state directory,
	// the Lua tree from -lua (as tests/l4-subscription-limits).
	conf := string(compiled.NginxConfig)
	conf = strings.Replace(conf, "error_log stderr notice;", "error_log logs/error.log notice;\npid logs/nginx.pid;", 1)
	conf = strings.ReplaceAll(conf, "'/opt/cdnca/l4geo/?.lua;/opt/cdnca/?.lua;;'", "'"+*luaRoot+"/?.lua;;'")
	conf = strings.ReplaceAll(conf, "/var/lib/cdnca-edge/shared/", *stateRoot+"/shared/")
	_ = os.RemoveAll(*stateRoot)
	for _, dir := range []string{"logs", "shared"} {
		if err := os.MkdirAll(filepath.Join(*stateRoot, dir), 0o777); err != nil {
			return "", err
		}
	}
	for _, line := range strings.Split(conf, "\n") {
		if field := strings.Fields(line); len(field) == 3 && field[0] == "access_log" {
			if err := os.MkdirAll(filepath.Dir(strings.Trim(field[1], `"`)), 0o777); err != nil {
				return "", err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(*stateRoot, "nginx.conf"), []byte(conf), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(*stateRoot, "config.json"), compiled.GeoJSON, 0o644); err != nil {
		return "", err
	}
	_ = filepath.Walk(*stateRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			_ = os.Chmod(path, info.Mode()|0o755)
		}
		return nil
	})
	if err := openresty("-t"); err != nil {
		return conf, err
	}
	check("openresty-t", true, "configuration test ok")
	return conf, openresty()
}

func main() {
	flag.Parse()
	all := streams()
	origins()
	conf, err := start(all)
	if err != nil {
		check("start", false, "%v\n%s", err, conf)
		fmt.Printf("RESULT failures=%d\n", failures)
		os.Exit(1)
	}
	if os.Getenv("DUMP") != "" {
		fmt.Println(conf)
	}
	check("render", strings.Contains(conf, "server 127.0.0.2:19600 weight=3;") && strings.Contains(conf, "server 127.0.0.3:19600 down;") &&
		strings.Contains(conf, "hash $remote_addr consistent;") && strings.Contains(conf, "listen [::]:18606 ipv6only=on;"),
		"weight=3, down, hash, [::] listen rendered")
	time.Sleep(500 * time.Millisecond)
	local := func(port int) string { return reply("tcp4", fmt.Sprintf("127.0.0.1:%d", port)) }

	counts := map[string]int{}
	for range 40 {
		counts[local(18601)]++
	}
	check("weight", counts["127.0.0.2"] >= 27 && counts["127.0.0.2"] <= 33 && counts["127.0.0.2"]+counts["127.0.0.3"] == 40,
		"3:1 over 40 sessions: %v", counts)

	counts = map[string]int{}
	for range 20 {
		counts[local(18602)]++
	}
	check("down", counts["127.0.0.2"] == 20, "down origin removed: %v", counts)

	counts = map[string]int{}
	for range 20 {
		counts[local(18603)]++
	}
	check("ip_hash", len(counts) == 1 && counts[""] == 0, "one origin for one client: %v", counts)

	got := local(18604)
	check("acl-deny", got == "", "default deny closes an unlisted client: %q", got)
	got = local(18605)
	check("acl-allow", got == "127.0.0.2", "allow rule passes the client: %q", got)

	got = local(18606)
	check("ipv6-v4", got == "127.0.0.2", "IPv4 still served: %q", got)
	if conn, err := net.Listen("tcp6", "[::1]:0"); err != nil {
		fmt.Printf("SKIP ipv6 no ::1 in this network namespace: %v\n", err)
	} else {
		_ = conn.Close()
		got = reply("tcp6", "[::1]:18606")
		check("ipv6", got == "127.0.0.2", "[::1] served with listen_ipv6: %q", got)
		got = reply("tcp6", "[::1]:18601")
		check("ipv6-off", got == "", "[::1] not served without listen_ipv6: %q", got)
	}
	_ = openresty("-s", "stop")
	fmt.Printf("RESULT failures=%d\n", failures)
	if failures != 0 {
		os.Exit(1)
	}
}
