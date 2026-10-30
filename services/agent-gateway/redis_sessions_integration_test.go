//go:build integration

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisSessionCoordinatorWithRealRedis(t *testing.T) {
	server := newRealRedisServer(t)

	t.Run("invalid acquire input is rejected", func(t *testing.T) {
		coordinator := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-input", integrationKeyPrefix())
		if _, err := coordinator.Acquire(context.Background(), "not-a-node-id"); err == nil {
			t.Fatal("non-canonical node ID was accepted")
		}
		if _, err := coordinator.Acquire(nil, testNodeID); err == nil {
			t.Fatal("nil acquire context was accepted")
		}
	})

	t.Run("concurrent takeover leaves one active owner", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		const contenders = 32
		leases := make([]SessionLease, contenders)
		epochs := make([]uint64, contenders)
		contexts := make([]context.CancelFunc, contenders)
		var wait sync.WaitGroup
		start := make(chan struct{})
		for index := range contenders {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				ctx, cancel := context.WithCancel(context.Background())
				contexts[index] = cancel
				coordinator := newIntegrationCoordinator(t, ctx, server.client, fmt.Sprintf("gateway-%d", index), prefix)
				<-start
				lease, err := coordinator.Acquire(context.Background(), testNodeID)
				if err != nil {
					t.Errorf("acquire %d: %v", index, err)
					return
				}
				leases[index] = lease
				epochs[index] = lease.Epoch()
			}(index)
		}
		close(start)
		wait.Wait()
		defer func() {
			for index, lease := range leases {
				if lease != nil {
					lease.Release()
				}
				if contexts[index] != nil {
					contexts[index]()
				}
			}
		}()

		var callbacks atomic.Int32
		active := 0
		for _, lease := range leases {
			if lease == nil {
				continue
			}
			err := lease.FencedSend(func() error {
				callbacks.Add(1)
				return nil
			})
			if err == nil {
				active++
			} else if !errors.Is(err, ErrSessionSuperseded) {
				t.Fatalf("fenced send error = %v", err)
			}
		}
		if active != 1 || callbacks.Load() != 1 {
			t.Fatalf("active owners = %d, callbacks = %d, want 1 and 1", active, callbacks.Load())
		}
		tokens := make(map[string]struct{}, contenders)
		for _, lease := range leases {
			redisLease := lease.(*redisSessionLease)
			if _, exists := tokens[redisLease.token]; exists {
				t.Fatalf("duplicate fencing token for contenders: %q", redisLease.token)
			}
			tokens[redisLease.token] = struct{}{}
		}
		sorted := append([]uint64(nil), epochs...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		for index := 1; index < len(sorted); index++ {
			if sorted[index] <= sorted[index-1] {
				t.Fatalf("epochs are not unique and monotonic: %v", sorted)
			}
		}
	})

	t.Run("takeover drains concurrent in-flight sends", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		first := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-send-burst", prefix)
		second := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-send-takeover", prefix)
		oldLease, err := first.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		defer oldLease.Release()

		const sends = 24
		started := make(chan struct{}, sends)
		release := make(chan struct{})
		sendErrors := make(chan error, sends)
		for range sends {
			go func() {
				sendErrors <- oldLease.FencedSend(func() error {
					started <- struct{}{}
					<-release
					return nil
				})
			}()
		}
		for range sends {
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("concurrent send did not enter its fenced callback")
			}
		}

		type acquireResult struct {
			lease SessionLease
			err   error
		}
		acquired := make(chan acquireResult, 1)
		go func() {
			lease, err := second.Acquire(context.Background(), testNodeID)
			acquired <- acquireResult{lease: lease, err: err}
		}()
		select {
		case takeover := <-acquired:
			if takeover.lease != nil {
				takeover.lease.Release()
			}
			t.Fatal("takeover completed while concurrent sends were in flight")
		case <-time.After(75 * time.Millisecond):
		}

		close(release)
		for range sends {
			if err := <-sendErrors; err != nil {
				t.Fatalf("in-flight send: %v", err)
			}
		}
		takeover := <-acquired
		if takeover.err != nil {
			t.Fatal(takeover.err)
		}
		defer takeover.lease.Release()
		if takeover.lease.Epoch() <= oldLease.Epoch() {
			t.Fatalf("new epoch = %d, old epoch = %d", takeover.lease.Epoch(), oldLease.Epoch())
		}
		called := false
		if err := oldLease.FencedSend(func() error { called = true; return nil }); !errors.Is(err, ErrSessionSuperseded) || called {
			t.Fatalf("stale send error = %v, callback called = %v", err, called)
		}
	})

	t.Run("takeover waits for in-flight send", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		first := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-first", prefix)
		second := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-second", prefix)
		oldLease, err := first.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan struct{})
		release := make(chan struct{})
		sendDone := make(chan error, 1)
		go func() {
			sendDone <- oldLease.FencedSend(func() error {
				close(started)
				<-release
				return nil
			})
		}()
		<-started
		type acquireResult struct {
			lease SessionLease
			err   error
		}
		acquired := make(chan acquireResult, 1)
		go func() {
			lease, err := second.Acquire(context.Background(), testNodeID)
			acquired <- acquireResult{lease: lease, err: err}
		}()
		select {
		case takeover := <-acquired:
			if takeover.lease != nil {
				takeover.lease.Release()
			}
			t.Fatal("takeover completed while the old send was in flight")
		case <-time.After(75 * time.Millisecond):
		}
		close(release)
		if err := <-sendDone; err != nil {
			t.Fatal(err)
		}
		takeover := <-acquired
		if takeover.err != nil {
			t.Fatal(takeover.err)
		}
		defer takeover.lease.Release()
		if takeover.lease.Epoch() <= oldLease.Epoch() {
			t.Fatalf("new epoch = %d, old epoch = %d", takeover.lease.Epoch(), oldLease.Epoch())
		}
		called := false
		if err := oldLease.FencedSend(func() error { called = true; return nil }); !errors.Is(err, ErrSessionSuperseded) || called {
			t.Fatalf("stale send error = %v, callback called = %v", err, called)
		}
		oldLease.Release()
		if err := takeover.lease.FencedSend(func() error { return nil }); err != nil {
			t.Fatalf("old release affected the new owner: %v", err)
		}
	})

	t.Run("different nodes progress independently", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		coordinator := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-nodes", prefix)
		nodes := []string{uuid.NewString(), uuid.NewString()}
		var wait sync.WaitGroup
		var callbacks atomic.Int32
		for _, nodeID := range nodes {
			wait.Add(1)
			go func(nodeID string) {
				defer wait.Done()
				lease, err := coordinator.Acquire(context.Background(), nodeID)
				if err != nil {
					t.Errorf("acquire %s: %v", nodeID, err)
					return
				}
				defer lease.Release()
				if err := lease.FencedSend(func() error { callbacks.Add(1); return nil }); err != nil {
					t.Errorf("send %s: %v", nodeID, err)
				}
			}(nodeID)
		}
		wait.Wait()
		if callbacks.Load() != int32(len(nodes)) {
			t.Fatalf("callbacks = %d, want %d", callbacks.Load(), len(nodes))
		}
	})

	t.Run("renew and token-matched release", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		coordinator := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-renew", prefix)
		lease, err := coordinator.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		stateKey, epochKey := coordinator.keys(testNodeID)
		time.Sleep(2 * coordinator.config.LeaseTTL)
		if ttl := server.client.PTTL(context.Background(), stateKey).Val(); ttl <= 0 {
			t.Fatalf("renewed state TTL = %v", ttl)
		}
		lease.Release()
		if exists := server.client.Exists(context.Background(), stateKey).Val(); exists != 0 {
			t.Fatalf("released state exists = %d", exists)
		}
		if exists := server.client.Exists(context.Background(), epochKey).Val(); exists != 1 {
			t.Fatalf("persistent epoch exists = %d, want 1", exists)
		}
		next, err := coordinator.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		defer next.Release()
		if next.Epoch() <= lease.Epoch() {
			t.Fatalf("next epoch = %d, released epoch = %d", next.Epoch(), lease.Epoch())
		}
	})

	t.Run("crashed owner recovers after lease expiry", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		firstContext, crash := context.WithCancel(context.Background())
		first := newIntegrationCoordinator(t, firstContext, server.client, "gateway-crash", prefix)
		second := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-recovery", prefix)
		oldLease, err := first.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		oldRedisLease := oldLease.(*redisSessionLease)
		if begun, err := oldRedisLease.beginSend(); err != nil || !begun {
			t.Fatalf("leave crashed in-flight state: begun=%v err=%v", begun, err)
		}
		crash()
		select {
		case <-oldLease.Superseded():
		case <-time.After(time.Second):
			t.Fatal("crashed coordinator did not fence its local lease")
		}
		startedAcquire := time.Now()
		newLease, err := second.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		defer newLease.Release()
		if elapsed := time.Since(startedAcquire); elapsed < 100*time.Millisecond {
			t.Fatalf("takeover elapsed = %v, expected in-flight lease expiry", elapsed)
		}
		if newLease.Epoch() <= oldLease.Epoch() {
			t.Fatalf("recovered epoch = %d, old epoch = %d", newLease.Epoch(), oldLease.Epoch())
		}
		called := false
		if err := oldLease.FencedSend(func() error { called = true; return nil }); !errors.Is(err, ErrSessionSuperseded) || called {
			t.Fatalf("crashed owner send error = %v, callback called = %v", err, called)
		}
		oldLease.Release()
	})

	t.Run("coordinator cancellation fences the local lease", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		coordinatorContext, cancelCoordinator := context.WithCancel(context.Background())
		coordinator := newIntegrationCoordinator(t, coordinatorContext, server.client, "gateway-cancel", prefix)
		lease, err := coordinator.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		cancelCoordinator()
		select {
		case <-lease.Superseded():
		case <-time.After(time.Second):
			t.Fatal("coordinator cancellation left the local lease active")
		}
		called := false
		if err := lease.FencedSend(func() error { called = true; return nil }); !errors.Is(err, ErrSessionSuperseded) || called {
			t.Fatalf("canceled coordinator send error = %v, callback called = %v", err, called)
		}
		lease.Release()
	})

	t.Run("hard Redis outage fails closed and restart preserves epoch", func(t *testing.T) {
		prefix := integrationKeyPrefix()
		coordinator := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-outage", prefix)
		lease, err := coordinator.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		oldEpoch := lease.Epoch()
		server.kill(t)
		select {
		case <-lease.Superseded():
		case <-time.After(time.Second):
			t.Fatal("lease stayed active after Redis became unavailable")
		}
		failed := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-fail-closed", prefix)
		if acquired, err := failed.Acquire(context.Background(), testNodeID); err == nil || acquired != nil {
			if acquired != nil {
				acquired.Release()
			}
			t.Fatalf("Redis outage acquire = %v, %v", acquired, err)
		}
		server.start(t)
		recovered := newIntegrationCoordinator(t, context.Background(), server.client, "gateway-restarted", prefix)
		newLease, err := recovered.Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		defer newLease.Release()
		if newLease.Epoch() <= oldEpoch {
			t.Fatalf("post-restart epoch = %d, old epoch = %d", newLease.Epoch(), oldEpoch)
		}
	})
}

func newIntegrationCoordinator(t *testing.T, ctx context.Context, client redis.UniversalClient, gatewayID, prefix string) *RedisSessionCoordinator {
	t.Helper()
	coordinator, err := NewRedisSessionCoordinator(ctx, client, RedisSessionCoordinatorConfig{
		GatewayInstanceID:    gatewayID,
		KeyPrefix:            prefix,
		LeaseTTL:             360 * time.Millisecond,
		RenewInterval:        80 * time.Millisecond,
		OperationTimeout:     50 * time.Millisecond,
		AcquireTimeout:       2 * time.Second,
		AcquireRetryInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func integrationKeyPrefix() string {
	return "cdnca:agent-gateway:integration:" + uuid.NewString()
}

type realRedisServer struct {
	path   string
	port   int
	dir    string
	cmd    *exec.Cmd
	client *redis.Client
}

func newRealRedisServer(t *testing.T) *realRedisServer {
	t.Helper()
	path, err := exec.LookPath("redis-server")
	if err != nil {
		t.Fatalf("integration tests require redis-server: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server := &realRedisServer{path: path, port: port, dir: t.TempDir()}
	server.client = redis.NewClient(&redis.Options{
		Addr:                  fmt.Sprintf("127.0.0.1:%d", port),
		DialTimeout:           50 * time.Millisecond,
		ReadTimeout:           50 * time.Millisecond,
		WriteTimeout:          50 * time.Millisecond,
		MaxRetries:            0,
		ContextTimeoutEnabled: true,
	})
	server.start(t)
	t.Cleanup(func() {
		if server.cmd != nil {
			server.stop(t)
		}
		_ = server.client.Close()
	})
	return server
}

func (s *realRedisServer) start(t *testing.T) {
	t.Helper()
	if s.cmd != nil {
		t.Fatal("Redis test server is already running")
	}
	s.cmd = exec.Command(s.path,
		"--bind", "127.0.0.1",
		"--port", fmt.Sprint(s.port),
		"--dir", s.dir,
		"--dbfilename", "sessions.rdb",
		"--appendonly", "yes",
		"--appendfsync", "always",
		"--save", "",
		"--logfile", filepath.Join(s.dir, "redis.log"),
	)
	s.cmd.Stdout = io.Discard
	s.cmd.Stderr = io.Discard
	if err := s.cmd.Start(); err != nil {
		s.cmd = nil
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := s.client.Ping(ctx).Err()
		cancel()
		if err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Redis test server on port %d did not become ready", s.port)
}

func (s *realRedisServer) stop(t *testing.T) {
	t.Helper()
	if s.cmd == nil {
		return
	}
	cmd := s.cmd
	s.cmd = nil
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop Redis test server: %v", err)
		}
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("Redis test server did not stop")
	}
}

func (s *realRedisServer) kill(t *testing.T) {
	t.Helper()
	if s.cmd == nil {
		return
	}
	cmd := s.cmd
	s.cmd = nil
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("hard-killed Redis exited successfully")
	}
}
