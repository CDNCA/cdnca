package entitlementguard

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// dropCommitAckConn lets PostgreSQL commit, then loses its COMMIT answer
// (report B, LIC-REC-03: auth-lifecycle-acceptance-20261028).
type dropCommitAckConn struct {
	net.Conn
	armed   *atomic.Bool
	dropped *atomic.Bool
	drop    bool
}

func (conn *dropCommitAckConn) Write(payload []byte) (int, error) {
	n, err := conn.Conn.Write(payload)
	if err == nil && n == len(payload) && bytes.Contains(bytes.ToLower(payload), []byte("commit\x00")) &&
		conn.armed.CompareAndSwap(true, false) {
		conn.drop = true
	}
	return n, err
}

func (conn *dropCommitAckConn) Read(payload []byte) (int, error) {
	if !conn.drop {
		return conn.Conn.Read(payload)
	}
	var received []byte
	buffer := make([]byte, 4096)
	for len(received) < 65536 {
		n, err := conn.Conn.Read(buffer)
		received = append(received, buffer[:n]...)
		if bytes.Contains(received, []byte("COMMIT\x00")) {
			conn.dropped.Store(true)
			_ = conn.Conn.Close()
			return 0, io.ErrUnexpectedEOF
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, io.ErrUnexpectedEOF
}

func TestInstallLostCommitAcknowledgementIsUnknownAndRecoverable(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, integrationLease(fixture.now, 1), fixture.now)
	config := fixture.pool.Config()
	config.MaxConns = 1
	baseDial := config.ConnConfig.DialFunc
	if baseDial == nil {
		baseDial = (&net.Dialer{}).DialContext
	}
	var armed, dropped atomic.Bool
	config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := baseDial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &dropCommitAckConn{Conn: conn, armed: &armed, dropped: &dropped}, nil
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
	lease := integrationLease(fixture.now, 2)
	bundle := InstallBundle{InstallationID: lease.InstallationID, SignedLease: signIntegrationLease(t, lease, fixture.signer)}
	armed.Store(true)
	_, err = NewService(pool, fixture.trust).Install(t.Context(), bundle, fixture.now)
	if !dropped.Load() {
		t.Fatalf("fault was not injected: %v", err)
	}
	if !errors.Is(err, ErrInstallOutcomeUnknown) {
		t.Fatalf("Install() after lost COMMIT answer = %v, want ErrInstallOutcomeUnknown", err)
	}
	var serial int64
	if err := fixture.pool.QueryRow(t.Context(),
		`SELECT current_serial FROM control_installation_entitlement WHERE singleton`).Scan(&serial); err != nil {
		t.Fatal(err)
	}
	if serial != 2 {
		t.Fatalf("re-read current_serial = %d, want persisted 2", serial)
	}
	if recovered, err := NewService(fixture.pool, fixture.trust).Install(t.Context(), bundle, fixture.now); err != nil || recovered.Serial != 2 {
		t.Fatalf("same signed lease replay = (%+v, %v), want serial 2", recovered, err)
	}
}

// A refusal inside the transaction rolls back: definitely not installed.
func TestInstallRefusedBeforeCommitIsNotUnknown(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, integrationLease(fixture.now, 2), fixture.now)
	lease := integrationLease(fixture.now, 1)
	_, err := NewService(fixture.pool, fixture.trust).Install(t.Context(),
		InstallBundle{InstallationID: lease.InstallationID, SignedLease: signIntegrationLease(t, lease, fixture.signer)}, fixture.now)
	if !errors.Is(err, ErrStaleLease) || errors.Is(err, ErrInstallOutcomeUnknown) {
		t.Fatalf("stale Install() = %v, want ErrStaleLease and not unknown", err)
	}
}
