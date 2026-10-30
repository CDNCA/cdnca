//go:build integration && linux

package l4runtime_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type staticProcessDNS []netip.Addr

func (answers staticProcessDNS) LookupIP(context.Context, string) (l4runtime.DNSLookupResult, error) {
	return l4runtime.DNSLookupResult{Addresses: append([]netip.Addr(nil), answers...), TTL: time.Minute}, nil
}

// L4F-E01：域名源站 3 个 DNS 回答 + 跟随端口 + 定源（ip_hash），同一客户端 20 次
// 连接必须全部到同一源站；固定端口 ip_hash 作对照。DNS 回答过滤拒绝私网地址，
// 所以需要在 --network none 容器内给 lo 加上 L4_V2_FOLLOW_HASH_ADDRESSES 列出的
// 三个公网格式地址（如 "1.1.1.1,8.8.8.8,9.9.9.9"，不会向外发包）。
// 两个地址可能因连接号步长碰巧稳定，必须用 3 个。
func TestV2FollowPortIPHashInOpenResty(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	rawAddresses := os.Getenv("L4_V2_FOLLOW_HASH_ADDRESSES")
	if binary == "" || rawAddresses == "" {
		t.Skip("L4_V2_OPENRESTY and L4_V2_FOLLOW_HASH_ADDRESSES (three public addresses on lo) required")
	}
	var answers staticProcessDNS
	for _, raw := range strings.Split(rawAddresses, ",") {
		answers = append(answers, netip.MustParseAddr(strings.TrimSpace(raw)))
	}
	if len(answers) != 3 {
		t.Fatalf("L4_V2_FOLLOW_HASH_ADDRESSES needs exactly 3 addresses, got %d", len(answers))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root := filepath.Join(t.TempDir(), "state")
	controller, err := l4runtime.NewOpenResty(binary, filepath.Join(root, "run", "nginx.pid"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := l4runtime.NewManager(root, controller)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = controller.Stop(stopCtx, filepath.Join(root, "current"))
	})
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), answers, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const followPort, fixedPort, fixedOrigin = 18621, 18622, 19621
	for _, address := range answers {
		for _, port := range []int{followPort, fixedOrigin} {
			listener, err := net.Listen("tcp4", net.JoinHostPort(address.String(), fmt.Sprint(port)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			name := address.String()
			go func() {
				for {
					connection, err := listener.Accept()
					if err != nil {
						return
					}
					_, _ = fmt.Fprintln(connection, name)
					_ = connection.Close()
				}
			}()
		}
	}
	const tenant = "0e4b0000-0000-4000-8000-000000000001"
	stream := func(index, port, origin int, follow bool, balance string) l4runtime.StreamRuntimeSpecV2 {
		id := fmt.Sprintf("0e4b0000-0000-4000-8000-0000000003%02d", index)
		return l4runtime.StreamRuntimeSpecV2{
			SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
			Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "127.0.0.1", Port: port},
			Endpoint: l4runtime.EndpointV2{Host: "l4-follow.example", Port: origin, FollowPort: follow, Balance: balance},
			DNS:      l4runtime.DNSPolicyV2{PositiveMinTTLSeconds: 30, PositiveMaxTTLSeconds: 300, NegativeTTLSeconds: 10, StaleIfErrorSeconds: 600},
			Geo: l4runtime.GeoPolicyV2{TenantID: tenant, StreamID: id, Revision: 1,
				UnknownRegionAction: l4runtime.GeoActionAllow},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
		}
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("follow-hash-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(1, followPort, followPort, true, edgeconfig.L4BalanceIPHash),
		stream(2, fixedPort, fixedOrigin, false, edgeconfig.L4BalanceIPHash),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, listener := range config.Listeners {
		path, err := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", config.VersionID, listener)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", config.VersionID)) })
	if result, err := manager.ApplyV2(ctx, config, dns); err != nil || result.State != l4runtime.StateApplied {
		t.Fatalf("ApplyV2 = %+v, %v", result, err)
	}
	for name, port := range map[string]int{"follow_port": followPort, "fixed_port": fixedPort} {
		counts := map[string]int{}
		for range 20 {
			counts[tcpPortReply(t, port)]++
		}
		if len(counts) != 1 || counts[""] != 0 {
			t.Fatalf("%s ip_hash: one client reached %v, want a single origin", name, counts)
		}
	}
}
