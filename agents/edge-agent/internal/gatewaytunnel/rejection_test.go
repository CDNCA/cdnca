package gatewaytunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type alertError string

func (e alertError) Error() string { return string(e) }

func TestIdentityRejectedClassification(t *testing.T) {
	remote := func(alert string) error {
		return fmt.Errorf("transport: %w", &net.OpError{Op: "remote error", Err: alertError(alert)})
	}
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"sentinel":          {fmt.Errorf("upgrade 401: %w", ErrNodeIdentityRejected), true},
		"joined":            {errors.Join(errors.New("direct"), fmt.Errorf("ws: %w", ErrNodeIdentityRejected)), true},
		"unknown authority": {remote("tls: unknown certificate authority"), true},
		"bad certificate":   {remote("tls: bad certificate"), true},
		"revoked":           {remote("tls: certificate revoked"), true},
		"expired":           {remote("tls: expired certificate"), false},
		"handshake failure": {remote("tls: handshake failure"), false},
		"local read error":  {&net.OpError{Op: "read", Err: alertError("tls: bad certificate")}, false},
		"refused":           {&net.OpError{Op: "dial", Err: errors.New("connection refused")}, false},
		"nil":               {nil, false},
	} {
		if got := IdentityRejected(tc.err); got != tc.want {
			t.Errorf("%s: IdentityRejected = %v, want %v", name, got, tc.want)
		}
	}
}

func TestIdentityRetryGrowsToMaximumAndResets(t *testing.T) {
	var retry IdentityRetry
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, expected := range want {
		if got := retry.Delay(nil); got != expected {
			t.Fatalf("delay %d = %v, want %v", i, got, expected)
		}
	}
	// Jitter above the maximum is clamped; a broken jitter falls back to the base.
	if got := retry.Delay(func(d time.Duration) time.Duration { return d * 6 / 5 }); got != IdentityRetryMaximum {
		t.Fatalf("jittered delay at the maximum = %v", got)
	}
	retry.Reset()
	if got := retry.Delay(func(time.Duration) time.Duration { return -1 }); got != IdentityRetryInitial {
		t.Fatalf("delay after Reset = %v, want %v", got, IdentityRetryInitial)
	}
}

func TestLogIdentityRejectedOncePerInterval(t *testing.T) {
	clock := time.Now()
	identityLog.mu.Lock()
	saved := identityLog.now
	identityLog.now, identityLog.last = func() time.Time { return clock }, time.Time{}
	identityLog.mu.Unlock()
	t.Cleanup(func() {
		identityLog.mu.Lock()
		identityLog.now, identityLog.last = saved, time.Time{}
		identityLog.mu.Unlock()
	})
	if !LogIdentityRejected("gateway", time.Minute, ErrNodeIdentityRejected) {
		t.Fatal("first rejection not logged")
	}
	clock = clock.Add(IdentityLogInterval - time.Second)
	if LogIdentityRejected("telemetry", time.Minute, ErrNodeIdentityRejected) {
		t.Fatal("rejection logged again inside the interval")
	}
	clock = clock.Add(time.Second)
	if !LogIdentityRejected("gateway", time.Minute, ErrNodeIdentityRejected) {
		t.Fatal("rejection not logged after the interval")
	}
}

func dialTunnelStatus(t *testing.T, status int, path string) error {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthenticated", status)
	}))
	t.Cleanup(server.Close)
	roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, DialConfig{Address: server.Listener.Addr().String(), Host: "example.com", Path: path, Roots: roots})
	if err == nil {
		_ = conn.Close()
		t.Fatalf("status %d upgrade succeeded", status)
	}
	return err
}

func TestDialMarksOnlyTunnel401AsIdentityRejection(t *testing.T) {
	if err := dialTunnelStatus(t, http.StatusUnauthorized, TunnelPath); !errors.Is(err, ErrNodeIdentityRejected) {
		t.Fatalf("tunnel 401 = %v, want ErrNodeIdentityRejected", err)
	}
	for _, tc := range []struct {
		status int
		path   string
	}{{http.StatusServiceUnavailable, TunnelPath}, {http.StatusBadGateway, TunnelPath}, {http.StatusUnauthorized, EnrollmentPath}} {
		if err := dialTunnelStatus(t, tc.status, tc.path); IdentityRejected(err) {
			t.Errorf("%d on %s classified as identity rejection: %v", tc.status, tc.path, err)
		}
	}
}

func TestDialWatchStopsAtFirstRejection(t *testing.T) {
	ctx, watch := NewDialWatch(context.Background())
	defer watch.Stop()
	dial := watch.Dialer(func(context.Context, string) (net.Conn, error) {
		return nil, fmt.Errorf("gateway tunnel upgrade 401: %w", ErrNodeIdentityRejected)
	})
	if _, err := dial(ctx, "x"); !errors.Is(err, ErrNodeIdentityRejected) {
		t.Fatalf("dial error = %v", err)
	}
	if ctx.Err() == nil {
		t.Fatal("dial context still live after a rejection")
	}
	if err := watch.Err(context.Canceled); !errors.Is(err, ErrNodeIdentityRejected) {
		t.Fatalf("Err = %v, want the rejection", err)
	}
	other, otherWatch := NewDialWatch(context.Background())
	defer otherWatch.Stop()
	_, _ = otherWatch.Dialer(func(context.Context, string) (net.Conn, error) { return nil, errors.New("connection refused") })(other, "x")
	if other.Err() != nil || IdentityRejected(otherWatch.Err(errors.New("deadline"))) {
		t.Fatal("network error ended the dial or was classified as a rejection")
	}
}
