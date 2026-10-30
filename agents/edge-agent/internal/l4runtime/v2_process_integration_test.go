//go:build integration && linux

package l4runtime_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

type unusedProcessDNS struct{}

func (unusedProcessDNS) LookupIP(context.Context, string) (l4runtime.DNSLookupResult, error) {
	return l4runtime.DNSLookupResult{}, fmt.Errorf("static-address test must not query DNS")
}

// Run only in an isolated Linux network namespace with the pinned OpenResty
// runtime. Every request below traverses real stream listeners and echo origins.
func TestV2OpenRestyProcessLifecycle(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" {
		t.Skip("L4_V2_OPENRESTY requires an isolated Linux runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
		stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := controller.Stop(stopCtx, filepath.Join(root, "current")); err != nil {
			t.Errorf("stop owned OpenResty: %v", err)
		}
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			if info.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return os.Chmod(path, 0o600)
		})
	})
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), unusedProcessDNS{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:19180")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	go func() {
		for {
			connection, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:19181")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buffer := make([]byte, 256)
		for {
			n, address, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buffer[:n], address)
		}
	}()
	streams := []l4runtime.StreamRuntimeSpecV2{}
	for i, protocol := range []l4runtime.Protocol{l4runtime.ProtocolTCP, l4runtime.ProtocolUDP} {
		id := fmt.Sprintf("33333333-3333-4333-8333-%012d", i+1)
		streams = append(streams, l4runtime.StreamRuntimeSpecV2{
			SchemaVersion: l4runtime.SchemaVersionV2, TenantID: "11111111-1111-4111-8111-111111111111", StreamID: id, Revision: int64(3 + i),
			Listener: l4runtime.ListenerSocketV2{Protocol: protocol, Address: "0.0.0.0", Port: 18180 + i},
			Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: 19180 + i},
			Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: "11111111-1111-4111-8111-111111111111",
				StreamID: id, Revision: int64(3 + i),
				UnknownRegionAction: l4runtime.GeoActionAllow},
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 1000, MaxConnectionsPerClient: 10, DrainTimeoutMS: 1000,
		})
	}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("process-v2", 9, streams)
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
	first, err := manager.ApplyV2(ctx, config, dns)
	if err != nil {
		t.Fatal(err)
	}
	assertTraffic := func(want bool) {
		t.Helper()
		for i, network := range []string{"tcp4", "udp4"} {
			connection, err := net.DialTimeout(network, fmt.Sprintf("127.0.0.1:%d", 18180+i), time.Second)
			var response string
			if err == nil {
				_ = connection.SetDeadline(time.Now().Add(time.Second))
				_, err = connection.Write([]byte("real-v2-traffic"))
				if err == nil {
					buffer := make([]byte, len("real-v2-traffic"))
					_, err = io.ReadFull(connection, buffer)
					response = string(buffer)
				}
				_ = connection.Close()
			}
			if got := err == nil && response == "real-v2-traffic"; got != want {
				t.Fatalf("%s traffic=%v want=%v response=%q error=%v", network, got, want, response, err)
			}
		}
	}
	assertTraffic(true)
	if _, err := manager.Apply(ctx, l4runtime.Config{SchemaVersion: l4runtime.SchemaVersionV1, VersionID: "process-empty"}); err != nil {
		t.Fatal(err)
	}
	assertTraffic(false)
	for i, network := range []string{"tcp4", "udp4"} {
		address := fmt.Sprintf("0.0.0.0:%d", 18180+i)
		if network == "tcp4" {
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Fatalf("removed TCP port retained: %v", err)
			}
			_ = listener.Close()
		} else {
			listener, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatalf("removed UDP port retained: %v", err)
			}
			_ = listener.Close()
		}
	}
	rolledBack, err := manager.Rollback(ctx, first.VersionID, first.Digest)
	if err != nil || rolledBack.Digest != first.Digest {
		t.Fatalf("restore immutable v2: result=%+v error=%v", rolledBack, err)
	}
	assertTraffic(true)
	restarted, err := l4runtime.NewManager(root, controller)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.ApplyV2(ctx, config, nil)
	if err != nil || replay.Digest != first.Digest {
		t.Fatalf("offline immutable replay: result=%+v error=%v", replay, err)
	}
	assertTraffic(true)
	t.Logf("real TCP/UDP + Geo; source=9 resources=3,4; removal released both ports; rollback/restart digest=%s", first.Digest)
}
