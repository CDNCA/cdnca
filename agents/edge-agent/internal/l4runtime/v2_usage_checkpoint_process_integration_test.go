//go:build integration && linux

package l4runtime_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4live"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4usage"
)

type collectingSink struct{ envelopes []eventspool.Envelope }

func (sink *collectingSink) AppendBatch(_ context.Context, envelopes []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	sink.envelopes = append(sink.envelopes, envelopes...)
	return make([]eventspool.AppendResult, len(envelopes)), nil
}

// L4-USAGE-01 against a real kernel and L4 OpenResty (not run by subtasks;
// L4_V2_OPENRESTY as root): a TCP forward without a session log registers
// its live session; two ledger rounds (injected clock) while the client
// keeps sending write two checkpoints of the kernel counters' deltas; the
// session's end line ($pid:$connection) settles them, and the checkpoints
// plus the end's remainder equal the bytes nginx logged.
func TestV2UsageCheckpointsInOpenResty(t *testing.T) {
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" || os.Geteuid() != 0 {
		t.Skip("L4_V2_OPENRESTY as root requires an isolated Linux runtime")
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
	dns, err := l4runtime.NewDNSCoordinator(filepath.Join(root, "dns"), unusedProcessDNS{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	startRateEchoOrigins(t, 19590, 19591)
	const tenant = "11111111-1111-4111-8111-111111111111"
	const stream = "77777777-7777-4777-8777-000000000091"
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("usage-v1", 1, []l4runtime.StreamRuntimeSpecV2{{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: stream, Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: 18590},
		Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: 19590},
		Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: tenant, StreamID: stream, Revision: 1,
			UnknownRegionAction: l4runtime.GeoActionAllow},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 60000, MaxConnectionsPerClient: 100, DrainTimeoutMS: 30000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	logPath, _ := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", config.VersionID, config.Listeners[0])
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", config.VersionID)) })
	if result, err := manager.ApplyV2(ctx, config, dns); err != nil || result.State != l4runtime.StateApplied {
		t.Fatalf("ApplyV2 = %+v, %v", result, err)
	}
	now := time.Now().UTC()
	ledger, err := l4usage.New(l4usage.Config{StatePath: filepath.Join(t.TempDir(), "l4-usage.json"),
		NodeID: "33333333-3333-4333-8333-333333333333", Now: func() time.Time { return now },
		Kernel: l4live.LinuxKernel{}, Registry: l4live.ControlRegistry{Path: l4runtime.L4ControlSocketPath},
		Sockets: func(ctx context.Context) (map[string]l4runtime.UsageSocketV2, error) {
			active, err := manager.ActiveConfigV2(ctx)
			if err != nil || active == nil {
				return nil, err
			}
			return l4runtime.UsageSocketsV2(*active), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("tcp4", "127.0.0.1:18590")
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(size int) {
		payload := make([]byte, size)
		if _, err := connection.Write(payload); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(connection, payload); err != nil {
			t.Fatal(err)
		}
	}
	sink := &collectingSink{}
	exchange(4096)
	time.Sleep(200 * time.Millisecond)
	if err := ledger.Checkpoint(ctx, sink); err != nil {
		t.Fatal(err)
	}
	now = now.Add(l4usage.Interval)
	exchange(8192)
	time.Sleep(200 * time.Millisecond)
	if err := ledger.Checkpoint(ctx, sink); err != nil {
		t.Fatal(err)
	}
	if len(sink.envelopes) != 2 || sink.envelopes[0].CheckpointSequence != 1 || sink.envelopes[1].CheckpointSequence != 2 ||
		sink.envelopes[0].StreamID != stream || sink.envelopes[1].RequestBytes == 0 {
		t.Fatalf("checkpoints = %+v", sink.envelopes)
	}
	_ = connection.Close()
	var line []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && len(line) == 0; time.Sleep(100 * time.Millisecond) {
		content, _ := os.ReadFile(logPath)
		if index := len(content); index > 0 {
			line = content[:index-1]
		}
	}
	end, err := eventspool.ParseL4SourceLineBound(line, eventspool.TrustedIdentity{EnrollmentNodeID: "33333333-3333-4333-8333-333333333333",
		TenantID: tenant, SiteID: stream, ConfigVersionID: config.VersionID, StreamID: stream, ListenerID: stream, ConfigRevision: 1})
	if err != nil || end.L4WorkerConnection() == "" {
		t.Fatalf("end line %q: %+v, %v", line, end, err)
	}
	settled := ledger.Settle(end)
	up := sink.envelopes[0].RequestBytes + sink.envelopes[1].RequestBytes
	down := sink.envelopes[0].ResponseBytes + sink.envelopes[1].ResponseBytes
	if settled.CheckpointedRequestBytes != min(up, end.RequestBytes) || settled.CheckpointedResponseBytes != min(down, end.ResponseBytes) {
		t.Fatalf("settled %d/%d, checkpoints %d/%d, session %d/%d", settled.CheckpointedRequestBytes,
			settled.CheckpointedResponseBytes, up, down, end.RequestBytes, end.ResponseBytes)
	}
	t.Logf("checkpoints %d/%d bytes, session %d/%d, remainder %d/%d", up, down, end.RequestBytes, end.ResponseBytes,
		end.RequestBytes-settled.CheckpointedRequestBytes, end.ResponseBytes-settled.CheckpointedResponseBytes)
}
