//go:build integration && linux

package l4runtime_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// Run in an isolated network namespace; the same origin endpoint serves both
// TCP and UDP. This is a runtime test, not evidence of a production deployment.
func TestV2AdditionalListenersOpenRestyProcessLifecycle(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" {
		t.Skip("L4_V2_OPENRESTY requires an isolated Linux runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
			t.Errorf("stop owned runtime: %v", err)
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
	tcp, err := net.Listen("tcp4", "127.0.0.1:19190")
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
	udp, err := net.ListenPacket("udp4", "127.0.0.1:19190")
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
	stream := l4runtime.StreamRuntimeSpecV2{SchemaVersion: l4runtime.SchemaVersionV2,
		TenantID: "11111111-1111-4111-8111-111111111111",
		StreamID: "33333333-3333-4333-8333-333333333333", Revision: 3,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "*", Port: 18190},
		Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: 19190},
		Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: "11111111-1111-4111-8111-111111111111",
			StreamID: "33333333-3333-4333-8333-333333333333", Revision: 3, UnknownRegionAction: l4runtime.GeoActionAllow},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 1000, MaxConnectionsPerClient: 10, DrainTimeoutMS: 1000,
	}
	makeConfig := func(version string, source int64) l4runtime.ConfigV2 {
		t.Helper()
		config, err := l4runtime.AggregateStreamRuntimeSpecsV2(version, source, []l4runtime.StreamRuntimeSpecV2{stream})
		if err != nil {
			t.Fatal(err)
		}
		sockets := append([]l4runtime.AdditionalListenerV2{{ID: stream.StreamID, Protocol: stream.Listener.Protocol, Address: "0.0.0.0", Port: stream.Listener.Port}}, config.Listeners[0].AdditionalListeners...)
		for _, socket := range sockets {
			path, err := l4runtime.L4TelemetryLogPathForIdentity("/var/lib/cdnca-edge", version, stream.StreamID, stream.StreamID, socket.ID, socket.Protocol, socket.Address, socket.Port)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", version)) })
		return config
	}
	traffic := func(network string, port int, want bool) {
		t.Helper()
		connection, err := net.DialTimeout(network, fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		var response string
		if err == nil {
			_ = connection.SetDeadline(time.Now().Add(time.Second))
			_, err = connection.Write([]byte("multi-socket-traffic"))
			if err == nil {
				buffer := make([]byte, len("multi-socket-traffic"))
				_, err = io.ReadFull(connection, buffer)
				response = string(buffer)
			}
			_ = connection.Close()
		}
		if got := err == nil && response == "multi-socket-traffic"; got != want {
			t.Fatalf("%s:%d traffic=%v want=%v response=%q err=%v", network, port, got, want, response, err)
		}
	}
	assertTraffic := func(primary, extras bool) {
		t.Helper()
		traffic("tcp4", 18190, primary)
		traffic("tcp4", 18191, extras)
		traffic("udp4", 18192, extras)
	}
	assertPortsFree := func(ports ...int) {
		t.Helper()
		for _, port := range ports {
			address := fmt.Sprintf("0.0.0.0:%d", port)
			if port == 18192 {
				listener, err := net.ListenPacket("udp4", address)
				if err != nil {
					t.Fatalf("removed UDP port retained: %v", err)
				}
				_ = listener.Close()
			} else {
				listener, err := net.Listen("tcp4", address)
				if err != nil {
					t.Fatalf("removed TCP port retained: %v", err)
				}
				_ = listener.Close()
			}
		}
	}
	baseline, err := manager.ApplyV2(ctx, makeConfig("multi-primary", 9), dns)
	if err != nil {
		t.Fatal(err)
	}
	assertTraffic(true, false)
	stream.Revision, stream.Geo.Revision = 4, 4
	stream.AdditionalListeners = []l4runtime.AdditionalListenerV2{
		{ID: "44444444-4444-4444-8444-444444444444", Protocol: l4runtime.ProtocolTCP, Address: "*", Port: 18191},
		{ID: "55555555-5555-4555-8555-555555555555", Protocol: l4runtime.ProtocolUDP, Address: "*", Port: 18192},
	}
	config := makeConfig("multi-active", 10)
	// A conflict on an extra socket must reject before disturbing the primary.
	occupied, err := net.Listen("tcp4", "0.0.0.0:18191")
	if err != nil {
		t.Fatal(err)
	}
	err = manager.PrecheckV2(ctx, config, dns)
	_ = occupied.Close()
	if err == nil {
		t.Fatal("extra TCP bind conflict was ignored")
	}
	assertTraffic(true, false)
	active, err := manager.ApplyV2(ctx, config, dns)
	if err != nil {
		t.Fatal(err)
	}
	assertTraffic(true, true)
	if len(active.ListenerResults) != 2 {
		t.Fatalf("expected exactly two added socket results: %+v", active.ListenerResults)
	}
	// The current Lua engine is unchanged: all sockets resolve one stream policy.
	geo, err := os.ReadFile(filepath.Join(root, "current", "config.json"))
	if err != nil || strings.Count(string(geo), `"id":`) != 1 {
		t.Fatalf("Geo policy identity split: %s %v", geo, err)
	}
	stream.Revision, stream.Geo.Revision, stream.AdditionalListeners = 5, 5, nil
	removed, err := manager.ApplyV2(ctx, makeConfig("multi-reduced", 11), dns)
	if err != nil {
		t.Fatal(err)
	}
	assertTraffic(true, false)
	assertPortsFree(18191, 18192)
	if len(removed.ListenerResults) != 2 {
		t.Fatalf("extra socket removals missing: %+v", removed.ListenerResults)
	}
	if result, err := manager.Rollback(ctx, active.VersionID, active.Digest); err != nil || result.Digest != active.Digest {
		t.Fatalf("multi rollback: %+v %v", result, err)
	}
	assertTraffic(true, true)
	restarted, err := l4runtime.NewManager(root, controller)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := restarted.ApplyV2(ctx, config, nil); err != nil || result.Digest != active.Digest {
		t.Fatalf("offline replay: %+v %v", result, err)
	}
	assertTraffic(true, true)
	if _, err := restarted.Apply(ctx, l4runtime.Config{SchemaVersion: l4runtime.SchemaVersionV1, VersionID: "multi-empty"}); err != nil {
		t.Fatal(err)
	}
	assertTraffic(false, false)
	assertPortsFree(18190, 18191, 18192)
	// Finalization on reload must leave nonempty, independently named logs.
	for _, socket := range config.Listeners[0].AdditionalListeners {
		path, err := l4runtime.L4TelemetryLogPathForIdentity("/var/lib/cdnca-edge", config.VersionID, stream.StreamID, stream.StreamID, socket.ID, socket.Protocol, socket.Address, socket.Port)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), `"status":"200"`) {
			t.Fatalf("extra socket emitted no successful telemetry: %s %q %v", path, data, err)
		}
	}
	if _, err := restarted.Rollback(ctx, baseline.VersionID, baseline.Digest); err != nil {
		t.Fatal(err)
	}
	assertTraffic(true, false)
	t.Logf("one Stream/single origin: primary + extra TCP + extra UDP passed; conflict rejected; partial/full removal freed all ports; rollback/offline replay digest=%s; per-listener logs verified", active.Digest)
}
