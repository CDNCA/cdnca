//go:build integration

package identityverificationhttp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateDraftCommitAckLossConvergesWithoutQuarantine(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	fixture := newHTTPIntegrationFixture(t)
	proxy := newPostgresCommitAckProxy(t, ctx, fixture.pool.Config())
	proxyPool := proxy.pool(t, ctx, fixture.pool.Config())
	defer func() {
		cancel()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		if err := proxy.close(cleanupCtx); err != nil {
			t.Errorf("stop PostgreSQL commit acknowledgment proxy before pool close: %v", err)
		}
		proxyPool.Close()
	}()

	core, err := identityverification.NewIAMService(proxyPool, audit.New(proxyPool), fixture.iam,
		identityverification.Config{Clock: fixture.clock.now, ReviewTTL: 2 * time.Hour,
			RetentionPeriod: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	service := testService(t, core, fixture.reader, fixture.registry)
	handler, err := newHandler(service, fixture.authenticate, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	token := integrationToken('k')
	fixture.registry.add(fixture.applicant.Actor, token,
		integrationPersonalEvidence(identityverification.KindPersonalInitial, bytesOf(32, 0x91), 0x92))
	body := `{"kind":"personal_initial","evidence_token":"` + token + `"}`

	proxy.arm()
	created := integrationRequestContext(ctx, handler, fixture.rawToken("applicant"), http.MethodPost, apiPrefix+"/cases", body,
		"commit-ack-loss", 0)
	if !proxy.dropped.Load() {
		t.Fatal("PostgreSQL proxy did not drop the COMMIT acknowledgment")
	}
	if created.Code != http.StatusOK {
		t.Errorf("create after COMMIT acknowledgment loss = %d %s", created.Code, created.Body.String())
	}

	var caseID uuid.UUID
	if err := fixture.pool.QueryRow(ctx, `SELECT settlement.case_id
		FROM identity_verification_evidence_settlements settlement
		JOIN identity_verification_write_requests write_request
		  ON write_request.id=settlement.write_request_id
		WHERE write_request.tenant_scope_id=$1 AND write_request.actor_user_id=$2
		  AND write_request.operation='identity_verification.create_draft'
		  AND write_request.idempotency_key='commit-ack-loss'
		  AND write_request.completed_at IS NOT NULL`, fixture.applicant.ScopeID,
		fixture.applicant.UserID).Scan(&caseID); err != nil {
		t.Fatalf("durable create binding after lost acknowledgment: %v", err)
	}
	assertHTTPCreateFactCounts(t, ctx, fixture.pool, fixture.applicant, "commit-ack-loss", 1)

	fixture.registry.mu.Lock()
	quarantined := false
	for _, binding := range fixture.registry.bindings {
		if binding.key == "commit-ack-loss" {
			quarantined = binding.quarantined
		}
	}
	fixture.registry.mu.Unlock()
	if quarantined {
		t.Error("durably bound reservation was quarantined after lost COMMIT acknowledgment")
	}

	replayed := integrationRequestContext(ctx, handler, fixture.rawToken("applicant"), http.MethodPost, apiPrefix+"/cases", body,
		"commit-ack-loss", 0)
	if replayed.Code != http.StatusOK {
		t.Errorf("same-key retry after lost acknowledgment = %d %s", replayed.Code, replayed.Body.String())
	} else if item := decodeCase(t, replayed); !item.Replayed || item.ID != caseID {
		t.Errorf("same-key retry after lost acknowledgment = %#v", item)
	}
	assertHTTPCreateFactCounts(t, ctx, fixture.pool, fixture.applicant, "commit-ack-loss", 1)
}

func assertHTTPCreateFactCounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, actor integrationActor,
	key string, expected int,
) {
	t.Helper()
	var cases, settlements, writes int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM identity_verification_cases
		 WHERE tenant_scope_id=$1 AND applicant_user_id=$2),
		(SELECT count(*) FROM identity_verification_evidence_settlements
		 WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3),
		(SELECT count(*) FROM identity_verification_write_requests
		 WHERE tenant_scope_id=$1 AND actor_user_id=$2
		   AND operation='identity_verification.create_draft' AND idempotency_key=$3)`,
		actor.ScopeID, actor.UserID, key).Scan(&cases, &settlements, &writes); err != nil {
		t.Fatal(err)
	}
	if cases != expected || settlements != expected || writes != expected {
		t.Fatalf("create facts after commit acknowledgment loss = cases:%d settlements:%d writes:%d",
			cases, settlements, writes)
	}
}

type postgresCommitAckProxy struct {
	listener    net.Listener
	upstream    string
	ctx         context.Context
	cancel      context.CancelFunc
	armed       atomic.Bool
	dropped     atomic.Bool
	wait        sync.WaitGroup
	done        chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closing     bool
}

func newPostgresCommitAckProxy(
	t *testing.T,
	parent context.Context,
	config *pgxpool.Config,
) *postgresCommitAckProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	proxy := &postgresCommitAckProxy{
		listener: listener,
		upstream: net.JoinHostPort(config.ConnConfig.Host, strconv.Itoa(int(config.ConnConfig.Port))),
		ctx:      ctx, cancel: cancel, done: make(chan struct{}), connections: make(map[net.Conn]struct{}),
	}
	proxy.wait.Add(1)
	go proxy.accept()
	go func() {
		proxy.wait.Wait()
		close(proxy.done)
	}()
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cleanupCancel()
		if err := proxy.close(cleanupCtx); err != nil {
			t.Errorf("close PostgreSQL commit acknowledgment proxy: %v", err)
		}
	})
	return proxy
}

func (proxy *postgresCommitAckProxy) arm() {
	proxy.armed.Store(true)
}

func (proxy *postgresCommitAckProxy) pool(
	t *testing.T,
	ctx context.Context,
	base *pgxpool.Config,
) *pgxpool.Pool {
	t.Helper()
	config := base.Copy()
	address := proxy.listener.Addr().(*net.TCPAddr)
	config.ConnConfig.Host = "127.0.0.1"
	config.ConnConfig.Port = uint16(address.Port)
	config.MinConns = 0
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func (proxy *postgresCommitAckProxy) accept() {
	defer proxy.wait.Done()
	for {
		client, err := proxy.listener.Accept()
		if err != nil {
			return
		}
		if !proxy.track(client) {
			return
		}
		proxy.wait.Add(1)
		go func() {
			defer proxy.wait.Done()
			defer proxy.untrack(client)
			proxy.handle(client)
		}()
	}
}

func (proxy *postgresCommitAckProxy) handle(client net.Conn) {
	upstream, err := (&net.Dialer{}).DialContext(proxy.ctx, "tcp", proxy.upstream)
	if err != nil {
		_ = client.Close()
		return
	}
	if !proxy.track(upstream) {
		_ = client.Close()
		return
	}
	defer proxy.untrack(upstream)
	defer client.Close()
	defer upstream.Close()
	var dropAck atomic.Bool
	frontendDone := make(chan struct{})
	go func() {
		_ = proxy.forwardFrontend(client, upstream, &dropAck)
		close(frontendDone)
	}()
	_ = proxy.forwardBackend(upstream, client, &dropAck)
	_ = client.Close()
	_ = upstream.Close()
	<-frontendDone
}

func (proxy *postgresCommitAckProxy) track(connection net.Conn) bool {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.closing {
		_ = connection.Close()
		return false
	}
	proxy.connections[connection] = struct{}{}
	return true
}

func (proxy *postgresCommitAckProxy) untrack(connection net.Conn) {
	proxy.mu.Lock()
	delete(proxy.connections, connection)
	proxy.mu.Unlock()
}

func (proxy *postgresCommitAckProxy) close(ctx context.Context) error {
	proxy.cancel()
	proxy.mu.Lock()
	proxy.closing = true
	connections := make([]net.Conn, 0, len(proxy.connections))
	for connection := range proxy.connections {
		connections = append(connections, connection)
	}
	proxy.mu.Unlock()
	_ = proxy.listener.Close()
	for _, connection := range connections {
		_ = connection.Close()
	}
	select {
	case <-proxy.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("proxy workers did not finish: %w", ctx.Err())
	}
}

func (proxy *postgresCommitAckProxy) forwardFrontend(client, upstream net.Conn, dropAck *atomic.Bool) error {
	length, payload, err := readStartupPacket(client)
	if err != nil {
		return err
	}
	if err := writeAll(upstream, length); err != nil {
		return err
	}
	if err := writeAll(upstream, payload); err != nil {
		return err
	}
	// Only the COMMIT of the create transaction (the one that writes the
	// evidence settlement) loses its acknowledgment: CreateDraft first commits
	// a read-only IAM authorization transaction before reserving evidence.
	writesSettlement := false
	for {
		messageType, frameLength, framePayload, err := readTypedPacket(client)
		if err != nil {
			return err
		}
		statement := strings.TrimSpace(strings.TrimSuffix(string(framePayload), "\x00"))
		if messageType == 'Q' && strings.EqualFold(statement, "begin") {
			writesSettlement = false
		}
		if (messageType == 'Q' || messageType == 'P') &&
			strings.Contains(string(framePayload), "INSERT INTO identity_verification_evidence_settlements") {
			writesSettlement = true
		}
		if messageType == 'Q' && strings.EqualFold(statement, "commit") && writesSettlement &&
			proxy.armed.CompareAndSwap(true, false) {
			dropAck.Store(true)
		}
		if err := writeTypedPacket(upstream, messageType, frameLength, framePayload); err != nil {
			return err
		}
	}
}

func (proxy *postgresCommitAckProxy) forwardBackend(upstream, client net.Conn, dropAck *atomic.Bool) error {
	for {
		messageType, frameLength, framePayload, err := readTypedPacket(upstream)
		if err != nil {
			return err
		}
		if messageType == 'Z' && dropAck.Load() {
			proxy.dropped.Store(true)
			return nil
		}
		if err := writeTypedPacket(client, messageType, frameLength, framePayload); err != nil {
			return err
		}
	}
}

func readStartupPacket(connection net.Conn) ([]byte, []byte, error) {
	length := make([]byte, 4)
	if _, err := io.ReadFull(connection, length); err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(length)
	if size < 8 || size > 16*1024*1024 {
		return nil, nil, errors.New("invalid PostgreSQL startup packet")
	}
	payload := make([]byte, int(size)-4)
	_, err := io.ReadFull(connection, payload)
	return length, payload, err
}

func readTypedPacket(connection net.Conn) (byte, []byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(connection, header); err != nil {
		return 0, nil, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size < 4 || size > 16*1024*1024 {
		return 0, nil, nil, errors.New("invalid PostgreSQL protocol packet")
	}
	payload := make([]byte, int(size)-4)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return 0, nil, nil, err
	}
	return header[0], header[1:], payload, nil
}

func writeTypedPacket(connection net.Conn, messageType byte, length, payload []byte) error {
	if err := writeAll(connection, []byte{messageType}); err != nil {
		return err
	}
	if err := writeAll(connection, length); err != nil {
		return err
	}
	return writeAll(connection, payload)
}

func writeAll(connection net.Conn, value []byte) error {
	for len(value) > 0 {
		written, err := connection.Write(value)
		if err != nil {
			return err
		}
		value = value[written:]
	}
	return nil
}
