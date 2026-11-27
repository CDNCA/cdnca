//go:build integration

package firewalldispatch

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// 11-26 fresh install (fault injection): NATS stopped (SIGSTOP) for 8 s. The
// dispatcher polls statuses every 500 ms, so the stopped server queued ~16
// pull requests; on resume the consumer's MaxWaiting (16) answered the
// overflow with 409 "Exceeded MaxWaiting", Run returned it and the whole
// control-api exited ("edge deployment runtime stopped"). A 5 s stop stayed
// under the limit. The overflow is transient: Run must keep running.
func TestRunSurvivesNATSFreezeOverflowingMaxWaiting(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	proxy := newFreezeProxy(t, strings.TrimPrefix(natsURL, "nats://"))
	connection, err := nats.Connect("nats://"+proxy.address(), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	config := DefaultConfig()
	suffix := strings.ReplaceAll(t.Name()[len(t.Name())-8:], "_", "") + time.Now().Format("150405")
	config.StatusStream, config.StatusConsumer = "FW_FREEZE_"+suffix, "fw_freeze_"+suffix
	config.StatusSubjectPrefix = "cdnca.test.fwfreeze." + strings.ToLower(suffix)
	js, err := connection.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{Name: config.StatusStream, Subjects: []string{config.StatusSubjectPrefix + ".>"}}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(config.StatusStream) }()
	transport, err := newNATSTransport(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := newDispatcher(&fakeDB{tx: &fakeTx{}}, transport, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- dispatcher.Run(ctx) }()

	time.Sleep(time.Second)
	proxy.freeze()
	time.Sleep(8 * time.Second)
	proxy.thaw()
	select {
	case err := <-stopped:
		t.Fatalf("Run stopped after an 8 s NATS freeze: %v", err)
	case <-time.After(4 * time.Second):
	}
	cancel()
	if err := <-stopped; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error after cancel = %v", err)
	}
}

// freezeProxy forwards TCP to NATS and, while frozen, holds every byte in
// both directions, as a stopped server process does.
type freezeProxy struct {
	listener net.Listener
	target   string
	mu       sync.RWMutex
}

func newFreezeProxy(t *testing.T, target string) *freezeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &freezeProxy{listener: listener, target: target}
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

func (p *freezeProxy) address() string { return p.listener.Addr().String() }
func (p *freezeProxy) freeze()         { p.mu.Lock() }
func (p *freezeProxy) thaw()           { p.mu.Unlock() }

func (p *freezeProxy) pipe(dst, src net.Conn) {
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
