//go:build integration

package edgestatus

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// 11-26 fresh install (fault injection): NATS stopped (SIGSTOP) for 8 s. Every
// pull sent meanwhile was held; on resume the ones over the consumer's
// MaxWaiting were answered 409 "Exceeded MaxWaiting", which ended the edge
// deployment runtime and exited control-api. With FetchTimeout 500 ms and
// MaxWaiting 8, an 8 s stop overflows the same way; the status runtime must
// keep running and still project statuses afterwards.
func TestStatusRuntimeSurvivesNATSFreezeOverflowingMaxWaiting(t *testing.T) {
	h := newGapHarness(t)
	proxy := newStatusFreezeProxy(t, strings.TrimPrefix(os.Getenv("CDNCA_TEST_NATS_URL"), "nats://"))
	connection, err := nats.Connect("nats://"+proxy.listener.Addr().String(), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	consumer, err := NewNATSConsumer(connection, h.consumerConfig)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{consumer: consumer, processor: h.processor, logger: slog.Default()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- runtime.Run(ctx) }()

	time.Sleep(time.Second)
	proxy.mu.Lock()
	time.Sleep(8 * time.Second)
	proxy.mu.Unlock()
	select {
	case err := <-stopped:
		t.Fatalf("status runtime stopped after an 8 s NATS freeze: %v", err)
	case <-time.After(4 * time.Second):
	}
	fixture := seedDeployment(t, h.pool, "apply", uuid.Nil, uuid.Nil)
	publishStatus(t, h.js, h.prefix, fixture.nodeID,
		fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1))
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		var state string
		if err := h.pool.QueryRow(ctx, `SELECT state FROM node_deployments WHERE id=$1`, fixture.deploymentID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "delivered" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status after the freeze not projected, state %q", state)
		}
	}
	cancel()
	if err := <-stopped; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error after cancel = %v", err)
	}
}

// statusFreezeProxy forwards TCP to NATS; holding mu holds every byte in both
// directions, as a stopped server process does.
type statusFreezeProxy struct {
	listener net.Listener
	mu       sync.RWMutex
}

func newStatusFreezeProxy(t *testing.T, target string) *statusFreezeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &statusFreezeProxy{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			go proxy.pipe(server, client)
			go proxy.pipe(client, server)
		}
	}()
	return proxy
}

func (p *statusFreezeProxy) pipe(dst, src net.Conn) {
	defer func() { _ = dst.Close(); _ = src.Close() }()
	buffer := make([]byte, 32<<10)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			p.mu.RLock()
			_, werr := dst.Write(buffer[:n])
			p.mu.RUnlock()
			if werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
