package gatewaytunnel

// Node identity rejection: the gateway answered the tunnel upgrade 401, or
// the mTLS handshake ended with a TLS alert refusing the node certificate.
// Retrying every few seconds cannot help (the node is not registered on that
// control plane, or the control plane rebuilt its node CA), so callers back
// off up to IdentityRetryMaximum and log one operator hint per
// IdentityLogInterval. Network errors and 5xx keep the normal backoff.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// ErrNodeIdentityRejected marks a dial the gateway refused because of the
// node certificate.
var ErrNodeIdentityRejected = errors.New("gateway rejected the node identity")

const (
	IdentityRetryInitial = 30 * time.Second
	IdentityRetryMaximum = 5 * time.Minute
	IdentityLogInterval  = 10 * time.Minute
)

// rejectingAlerts are the alerts a TLS server sends when it does not accept
// the client certificate (crypto/tls processCertsFromClient). An expired
// certificate is not here: the agent recovers that one itself (GW-02).
var rejectingAlerts = map[string]bool{
	"tls: unknown certificate authority": true,
	"tls: bad certificate":               true,
	"tls: certificate revoked":           true,
}

// IdentityRejected reports whether err carries a node identity rejection.
func IdentityRejected(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNodeIdentityRejected) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil && rejectingAlerts[opErr.Err.Error()]
}

// IdentityRetry is the backoff for rejected dials: IdentityRetryInitial,
// doubling to IdentityRetryMaximum; Reset after any established session or
// renewed certificate restores the normal reconnect rhythm at once.
type IdentityRetry struct{ next time.Duration }

// Delay returns the wait before the next dial; jitter (may be nil) spreads
// it and the result never exceeds IdentityRetryMaximum.
func (r *IdentityRetry) Delay(jitter func(time.Duration) time.Duration) time.Duration {
	if r.next <= 0 {
		r.next = IdentityRetryInitial
	}
	base := r.next
	r.next = min(2*r.next, IdentityRetryMaximum)
	delay := base
	if jitter != nil {
		delay = jitter(base)
	}
	if delay <= 0 || delay > IdentityRetryMaximum {
		delay = min(base, IdentityRetryMaximum)
	}
	return delay
}

func (r *IdentityRetry) Reset() { r.next = 0 }

var identityLog = struct {
	mu   sync.Mutex
	last time.Time
	now  func() time.Time
}{now: time.Now}

// LogIdentityRejected writes the operator hint at most once per
// IdentityLogInterval for the whole agent (gateway session and telemetry
// share it); it reports whether it logged.
func LogIdentityRejected(component string, retryIn time.Duration, err error) bool {
	identityLog.mu.Lock()
	now := identityLog.now()
	if !identityLog.last.IsZero() && now.Sub(identityLog.last) < IdentityLogInterval {
		identityLog.mu.Unlock()
		return false
	}
	identityLog.last = now
	identityLog.mu.Unlock()
	slog.Error("主控拒绝了本节点证书（未在该主控注册或主控已重建身份），请在主控重新安装此节点",
		"component", component, "retry_in", retryIn.String(), "error", err)
	return true
}

// DialWatch ends one blocking gRPC dial at its first identity rejection
// instead of letting gRPC retry until the handshake timeout, and lets the
// caller return an error that IdentityRejected recognizes (gRPC flattens the
// connection error into text when the dial context ends).
type DialWatch struct {
	cancel   context.CancelFunc
	mu       sync.Mutex
	rejected error
}

// NewDialWatch derives the dial context; call Stop when the dial returns.
func NewDialWatch(ctx context.Context) (context.Context, *DialWatch) {
	ctx, cancel := context.WithCancel(ctx)
	return ctx, &DialWatch{cancel: cancel}
}

func (w *DialWatch) observe(err error) {
	if !IdentityRejected(err) {
		return
	}
	w.mu.Lock()
	if w.rejected == nil {
		w.rejected = err
	}
	w.mu.Unlock()
	w.cancel()
}

// Stop releases the dial context.
func (w *DialWatch) Stop() { w.cancel() }

// Err returns err, or the recorded rejection wrapped with
// ErrNodeIdentityRejected when the dial failed after one.
func (w *DialWatch) Err(err error) error {
	if err == nil {
		return nil
	}
	w.mu.Lock()
	rejected := w.rejected
	w.mu.Unlock()
	if rejected == nil {
		return err
	}
	if errors.Is(rejected, ErrNodeIdentityRejected) {
		return rejected
	}
	return errors.Join(ErrNodeIdentityRejected, rejected)
}

// Dialer wraps a gRPC context dialer (the ws tunnel) so a 401 upgrade is
// observed.
func (w *DialWatch) Dialer(dial func(context.Context, string) (net.Conn, error)) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, address string) (net.Conn, error) {
		conn, err := dial(ctx, address)
		w.observe(err)
		return conn, err
	}
}

// Credentials wraps the mTLS transport credentials so a refusing TLS alert,
// in the handshake or on the first read after it (TLS 1.3 verifies the
// client certificate after the client finished), is observed.
func (w *DialWatch) Credentials(inner credentials.TransportCredentials) credentials.TransportCredentials {
	return &watchedCredentials{TransportCredentials: inner, watch: w}
}

type watchedCredentials struct {
	credentials.TransportCredentials
	watch *DialWatch
}

func (c *watchedCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, raw)
	if err != nil {
		c.watch.observe(err)
		return conn, info, err
	}
	return &watchedConn{Conn: conn, watch: c.watch}, info, nil
}

func (c *watchedCredentials) Clone() credentials.TransportCredentials {
	return &watchedCredentials{TransportCredentials: c.TransportCredentials.Clone(), watch: c.watch}
}

type watchedConn struct {
	net.Conn
	watch *DialWatch
}

func (c *watchedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.watch.observe(err)
	}
	return n, err
}
