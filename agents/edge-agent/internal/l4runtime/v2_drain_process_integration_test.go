//go:build integration && linux

package l4runtime_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
)

// drainProcessHarness runs one owned L4 OpenResty against a TCP echo origin.
type drainProcessHarness struct {
	t          *testing.T
	ctx        context.Context
	controller *l4runtime.OpenResty
	manager    *l4runtime.Manager
	dns        *l4runtime.DNSCoordinator
	origin     int
}

func newDrainProcessHarness(t *testing.T, origin int) *drainProcessHarness {
	t.Helper()
	binary := os.Getenv("L4_V2_OPENRESTY")
	if binary == "" {
		t.Skip("L4_V2_OPENRESTY requires an isolated Linux runtime")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
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
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", origin))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); _, _ = io.Copy(connection, connection) }()
		}
	}()
	return &drainProcessHarness{t: t, ctx: ctx, controller: controller, manager: manager, dns: dns, origin: origin}
}

// stream is one TCP v2 stream on port with the production drain timeout.
func (h *drainProcessHarness) stream(index, port int, drainMaxMS *int) l4runtime.StreamRuntimeSpecV2 {
	id := fmt.Sprintf("44444444-4444-4444-8444-%012d", index)
	return l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: "11111111-1111-4111-8111-111111111111", StreamID: id, Revision: 1,
		Listener: l4runtime.ListenerSocketV2{Protocol: l4runtime.ProtocolTCP, Address: "0.0.0.0", Port: port},
		Endpoint: l4runtime.EndpointV2{Address: "127.0.0.1", Port: h.origin},
		Geo: l4runtime.GeoPolicyV2{Enabled: true, TenantID: "11111111-1111-4111-8111-111111111111",
			StreamID: id, Revision: 1,
			UnknownRegionAction: l4runtime.GeoActionAllow},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 600000, MaxConnectionsPerClient: 100,
		DrainTimeoutMS: 30000, DrainMaxMS: drainMaxMS,
	}
}

// apply publishes revision with the given streams and returns how long the
// activation took.
func (h *drainProcessHarness) apply(revision int64, streams ...l4runtime.StreamRuntimeSpecV2) time.Duration {
	h.t.Helper()
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2(fmt.Sprintf("drain-v%d", revision), revision, streams)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, listener := range config.Listeners {
		path, err := l4runtime.L4TelemetryLogPathForConfigListener("/var/lib/cdnca-edge", config.VersionID, listener)
		if err != nil {
			h.t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			h.t.Fatal(err)
		}
	}
	h.t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("/var/lib/cdnca-edge/shared/telemetry", config.VersionID)) })
	started := time.Now()
	result, err := h.manager.ApplyV2(h.ctx, config, h.dns)
	if err != nil || result.State != l4runtime.StateApplied {
		h.t.Fatalf("ApplyV2(revision %d) = %+v, %v", revision, result, err)
	}
	return time.Since(started)
}

func exchangeOnce(t *testing.T, port int) {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("dial new port %d: %v", port, err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 5)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "fresh" {
		t.Fatalf("new port %d exchange = %q, %v", port, buffer, err)
	}
}

// liveConnection keeps one proxied TCP session busy (a game client's
// heartbeat) and records when it first fails.
type liveConnection struct {
	mu       sync.Mutex
	failedAt time.Time
	failure  error
	sent     int
	stop     chan struct{}
	done     chan struct{}
}

func openLiveConnection(t *testing.T, port int) *liveConnection {
	t.Helper()
	connection, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatalf("dial %d: %v", port, err)
	}
	live := &liveConnection{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(live.done)
		defer connection.Close()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for sequence := 0; ; sequence++ {
			payload := []byte(fmt.Sprintf("heartbeat-%06d", sequence))
			_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
			_, err := connection.Write(payload)
			if err == nil {
				echo := make([]byte, len(payload))
				_, err = io.ReadFull(connection, echo)
				if err == nil && string(echo) != string(payload) {
					err = fmt.Errorf("echo %q, want %q", echo, payload)
				}
			}
			live.mu.Lock()
			if err != nil {
				live.failedAt, live.failure = time.Now(), err
				live.mu.Unlock()
				return
			}
			live.sent++
			live.mu.Unlock()
			select {
			case <-live.stop:
				return
			case <-ticker.C:
			}
		}
	}()
	t.Cleanup(live.close)
	return live
}

func (live *liveConnection) close() {
	select {
	case <-live.stop:
	default:
		close(live.stop)
	}
	<-live.done
}

func (live *liveConnection) state() (time.Time, error, int) {
	live.mu.Lock()
	defer live.mu.Unlock()
	return live.failedAt, live.failure, live.sent
}

// Adding a port reloads the L4 OpenResty. A long-lived session on an existing
// port must keep working past the old fixed 30 s drain, and the new port must
// serve immediately.
func TestV2LongConnectionSurvivesPortAdditionPastDrainTimeout(t *testing.T) {
	h := newDrainProcessHarness(t, 19380)
	first := h.stream(1, 18380, nil)
	h.apply(1, first)
	live := openLiveConnection(t, 18380)
	time.Sleep(time.Second)

	reloadedAt := time.Now()
	elapsed := h.apply(2, first, h.stream(2, 18381, nil))
	exchangeOnce(t, 18381)
	for time.Since(reloadedAt) < 40*time.Second {
		if failedAt, err, sent := live.state(); err != nil {
			t.Fatalf("existing long connection dropped %s after the port was added (after %d heartbeats; apply took %s): %v",
				failedAt.Sub(reloadedAt).Round(time.Millisecond), sent, elapsed, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if elapsed > 15*time.Second {
		t.Fatalf("adding a port blocked the deployment for %s", elapsed)
	}
	exchangeOnce(t, 18380)
	_, _, sent := live.state()
	t.Logf("apply with new port took %s; long connection alive 40s later (%d heartbeats); new port served", elapsed, sent)
}

// Each reload leaves the previous worker generation draining while it holds a
// session. At most four such generations are kept: the fifth reload ends the
// oldest one, and every reload still confirms while generations linger.
func TestV2DrainingGenerationsAreCapped(t *testing.T) {
	h := newDrainProcessHarness(t, 19390)
	streams := []l4runtime.StreamRuntimeSpecV2{h.stream(1, 18390, nil)}
	h.apply(1, streams...)
	lives := make([]*liveConnection, 0, 5)
	for revision := int64(2); revision <= 6; revision++ {
		lives = append(lives, openLiveConnection(t, 18390))
		time.Sleep(500 * time.Millisecond)
		streams = append(streams, h.stream(int(revision), 18390+int(revision)-1, nil))
		if elapsed := h.apply(revision, streams...); elapsed > 15*time.Second {
			t.Fatalf("reload %d with draining generations took %s", revision, elapsed)
		}
		exchangeOnce(t, 18390+int(revision)-1)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err, _ := lives[0].state(); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the oldest draining generation was not ended after a fifth one was retired")
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(2 * time.Second)
	for index, live := range lives[1:] {
		if _, err, _ := live.state(); err != nil {
			t.Fatalf("session on retained draining generation %d dropped: %v", index+1, err)
		}
	}
	t.Log("five retired generations: oldest ended, four retained sessions alive, every reload confirmed")
}

// A configured drain limit ends sessions of a retired generation once it has
// drained that long; until then they keep working.
func TestV2DrainLimitEndsRetiredSessionsAfterTheLimit(t *testing.T) {
	h := newDrainProcessHarness(t, 19400)
	limit := 4000
	first := h.stream(1, 18400, &limit)
	h.apply(1, first)
	live := openLiveConnection(t, 18400)
	time.Sleep(500 * time.Millisecond)
	h.apply(2, first, h.stream(2, 18401, &limit))
	reloadedAt := time.Now()
	exchangeOnce(t, 18401)
	deadline := reloadedAt.Add(15 * time.Second)
	for {
		failedAt, err, _ := live.state()
		if err != nil {
			after := failedAt.Sub(reloadedAt)
			if after < 3*time.Second {
				t.Fatalf("retired session ended %s after reload, before the 4s limit: %v", after, err)
			}
			t.Logf("retired session ended %s after reload (limit 4s)", after.Round(time.Millisecond))
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retired session outlived the drain limit")
		}
		time.Sleep(100 * time.Millisecond)
	}
	exchangeOnce(t, 18400)
}
